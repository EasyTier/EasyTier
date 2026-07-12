package host

import (
	"context"
	"errors"
	"net"

	"github.com/tetratelabs/wazero/api"
)

// BridgeConfig supplies host resources already authorized for core use. The
// bridge owns every supplied connection and closes it during Close.
type BridgeConfig struct {
	TCPStreams map[uint64]net.Conn
	UDPSockets map[uint64]net.PacketConn
}

func NewBridge(config BridgeConfig) *Bridge {
	handles := config.TCPStreams
	packets := config.UDPSockets
	if handles == nil {
		handles = make(map[uint64]net.Conn)
	}
	bridge := &Bridge{
		handles:             handles,
		packets:             make(map[uint64]*opaquePacketState, len(packets)),
		listeners:           make(map[uint64]*opaqueTCPListenerState),
		reads:               make(map[uint64]*opaqueReadOperation),
		writes:              make(map[uint64]*opaqueWriteOperation),
		udpReads:            make(map[uint64]*opaqueUDPReadWaiter),
		udpWrites:           make(map[uint64]*opaqueUDPWriteWaiter),
		tcpAccepts:          make(map[uint64]*opaqueTCPAcceptWaiter),
		creates:             make(map[uint64]*opaqueCreateOperation),
		dns:                 make(map[uint64]*opaqueDNSOperation),
		dnsResolver:         unsupportedOpaqueDNSResolver{},
		environment:         make(map[uint64]*opaqueEnvironmentOperation),
		environmentResolver: unsupportedOpaqueEnvironment{},
		packetSinks:         make(map[uint64]*opaquePacketSinkState),
		packetWrites:        make(map[uint64]*opaquePacketWriteWaiter),
		nextHandle:          1 << 48,
		completion:          make(chan struct{}, 1),
	}
	for handle, connection := range packets {
		state := newOpaquePacketState(connection)
		bridge.packets[handle] = state
		bridge.workers.Add(1)
		go bridge.runUDPSends(handle, state)
	}
	return bridge
}

func newOpaqueBridge(
	handles map[uint64]net.Conn,
	packets map[uint64]net.PacketConn,
) *Bridge {
	return NewBridge(BridgeConfig{TCPStreams: handles, UDPSockets: packets})
}

// Completion returns a coalescing notification channel. A notification means
// at least one host operation may be ready for another core drive.
func (b *Bridge) Completion() <-chan struct{} {
	return b.completion
}

// Close releases bridge-owned resources and waits for their workers to exit.
func (b *Bridge) Close() {
	b.close()
}

func (b *opaqueBridge) cancelOperation(
	_ context.Context,
	_ api.Module,
	operation uint64,
) int32 {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.reads[operation]; exists {
		delete(b.reads, operation)
		return 0
	}
	if _, exists := b.writes[operation]; exists {
		delete(b.writes, operation)
		return 0
	}
	if _, exists := b.udpReads[operation]; exists {
		delete(b.udpReads, operation)
		return 0
	}
	if _, exists := b.udpWrites[operation]; exists {
		delete(b.udpWrites, operation)
		return 0
	}
	if create, exists := b.creates[operation]; exists {
		delete(b.creates, operation)
		if create.cancel != nil {
			create.cancel()
		}
		if create.connection != nil {
			_ = create.connection.Close()
		}
		if create.packet != nil {
			_ = create.packet.Close()
		}
		if create.listener != nil {
			_ = create.listener.Close()
		}
		return 0
	}
	if _, exists := b.tcpAccepts[operation]; exists {
		delete(b.tcpAccepts, operation)
		return 0
	}
	if dns, exists := b.dns[operation]; exists {
		delete(b.dns, operation)
		dns.cancel()
		return 0
	}
	if environment, exists := b.environment[operation]; exists {
		delete(b.environment, operation)
		environment.cancel()
		b.signalCompletion()
		return 0
	}
	if _, exists := b.packetWrites[operation]; exists {
		delete(b.packetWrites, operation)
		return 0
	}
	return opaqueHostInvalid
}

func (b *opaqueBridge) closeHandle(
	_ context.Context,
	_ api.Module,
	handle uint64,
) int32 {
	b.mu.Lock()
	connection, exists := b.handles[handle]
	if exists {
		delete(b.handles, handle)
	}
	packet, packetExists := b.packets[handle]
	if packetExists {
		delete(b.packets, handle)
	}
	listener, listenerExists := b.listeners[handle]
	if listenerExists {
		delete(b.listeners, handle)
	}
	b.mu.Unlock()

	if !exists && !packetExists && !listenerExists {
		return 0
	}
	if exists {
		if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			return opaqueHostIOError
		}
	}
	if packetExists {
		packet.closeAfterQueuedSends()
	}
	if listenerExists {
		closeErr := listener.listener.Close()
		for _, accepted := range listener.accepted {
			_ = accepted.Close()
		}
		if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			return opaqueHostIOError
		}
	}
	return 0
}

func (b *opaqueBridge) close() {
	b.mu.Lock()
	connections := make([]net.Conn, 0, len(b.handles))
	for _, connection := range b.handles {
		connections = append(connections, connection)
	}
	packets := make([]*opaquePacketState, 0, len(b.packets))
	for _, packet := range b.packets {
		packets = append(packets, packet)
	}
	listeners := make([]*opaqueTCPListenerState, 0, len(b.listeners))
	for _, listener := range b.listeners {
		listeners = append(listeners, listener)
	}
	b.listeners = make(map[uint64]*opaqueTCPListenerState)
	creates := make([]*opaqueCreateOperation, 0, len(b.creates))
	for _, create := range b.creates {
		creates = append(creates, create)
	}
	b.creates = make(map[uint64]*opaqueCreateOperation)
	dns := make([]*opaqueDNSOperation, 0, len(b.dns))
	for _, operation := range b.dns {
		dns = append(dns, operation)
	}
	b.dns = make(map[uint64]*opaqueDNSOperation)
	environment := make([]*opaqueEnvironmentOperation, 0, len(b.environment))
	for _, operation := range b.environment {
		environment = append(environment, operation)
	}
	b.environment = make(map[uint64]*opaqueEnvironmentOperation)
	b.packetSinks = make(map[uint64]*opaquePacketSinkState)
	b.packetWrites = make(map[uint64]*opaquePacketWriteWaiter)
	b.mu.Unlock()

	for _, connection := range connections {
		_ = connection.Close()
	}
	for _, packet := range packets {
		packet.closeAfterQueuedSends()
	}
	for _, listener := range listeners {
		_ = listener.listener.Close()
		for _, accepted := range listener.accepted {
			_ = accepted.Close()
		}
	}
	for _, create := range creates {
		if create.cancel != nil {
			create.cancel()
		}
		if create.connection != nil {
			_ = create.connection.Close()
		}
		if create.packet != nil {
			_ = create.packet.Close()
		}
		if create.listener != nil {
			_ = create.listener.Close()
		}
	}
	for _, operation := range dns {
		operation.cancel()
	}
	for _, operation := range environment {
		operation.cancel()
	}
	b.workers.Wait()
}
