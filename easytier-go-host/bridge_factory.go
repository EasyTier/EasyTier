package host

// Socket factory operations create host-owned TCP streams and UDP sessions.

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"unicode/utf8"

	"github.com/tetratelabs/wazero/api"
)

const (
	socketAddressLen      = 27
	tcpSocketResultLen    = 62
	boundSocketResultLen  = 35
	factoryTCPProgress    = 1 << 5
	factoryUDPProgress    = 1 << 6
	maxFactoryOptionsSize = 4096
)

func (b *opaqueBridge) startTCPConnect(
	_ context.Context,
	module api.Module,
	operation uint64,
	optionsPointer uint32,
	optionsLength uint32,
) int32 {
	options, ok := readOwnedOptions(module, optionsPointer, optionsLength)
	if !ok {
		return opaqueHostMemory
	}
	decoded, err := decodeTCPConnectOptions(options)
	if err != nil {
		return opaqueHostInvalid
	}

	dialContext, cancel := context.WithCancel(context.Background())
	create := &opaqueCreateOperation{cancel: cancel}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		cancel()
		return opaqueHostInvalid
	}
	if _, duplicate := b.creates[operation]; duplicate {
		b.mu.Unlock()
		cancel()
		return opaqueHostInvalid
	}
	b.creates[operation] = create
	b.workers.Add(1)
	b.mu.Unlock()

	go func() {
		defer b.workers.Done()
		connection, err := b.socketFactory.ConnectTCP(dialContext, decoded)

		b.mu.Lock()
		if b.creates[operation] != create {
			b.mu.Unlock()
			if connection != nil {
				_ = connection.Close()
			}
			return
		}
		create.connection = connection
		create.err = err
		create.done = true
		if connection != nil {
			create.localAddr = connection.LocalAddr()
			create.peerAddr = connection.RemoteAddr()
		}
		b.mu.Unlock()
		b.signalCompletion()
	}()
	return 0
}

func (b *opaqueBridge) takeTCPConnect(
	_ context.Context,
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultLength uint32,
) int32 {
	if resultLength != tcpSocketResultLen {
		b.discardCreateOperation(operation)
		return opaqueHostMemory
	}
	if _, ok := module.Memory().Read(resultPointer, resultLength); !ok {
		b.discardCreateOperation(operation)
		return opaqueHostMemory
	}

	b.mu.Lock()
	create, exists := b.creates[operation]
	if !exists {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	if !create.done {
		b.mu.Unlock()
		return opaqueHostPending
	}
	delete(b.creates, operation)
	if create.cancel != nil {
		create.cancel()
	}
	if create.err != nil || create.connection == nil {
		connection := create.connection
		b.mu.Unlock()
		if connection != nil {
			_ = connection.Close()
		}
		return opaqueHostIOError
	}
	handle := b.allocateHandleLocked()
	encoded, err := encodeTCPSocketResult(handle, create.localAddr, create.peerAddr)
	if err != nil || !module.Memory().Write(resultPointer, encoded[:]) {
		connection := create.connection
		b.mu.Unlock()
		_ = connection.Close()
		return opaqueHostMemory
	}
	b.handles[handle] = create.connection
	b.mu.Unlock()
	return 0
}

func (b *opaqueBridge) startUDPBind(
	_ context.Context,
	module api.Module,
	operation uint64,
	optionsPointer uint32,
	optionsLength uint32,
) int32 {
	options, ok := readOwnedOptions(module, optionsPointer, optionsLength)
	if !ok {
		return opaqueHostMemory
	}
	decoded, err := decodeUDPBindOptions(options)
	if err != nil {
		return opaqueHostInvalid
	}
	bindContext, cancel := context.WithCancel(context.Background())
	create := &opaqueCreateOperation{cancel: cancel}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		cancel()
		return opaqueHostInvalid
	}
	if _, duplicate := b.creates[operation]; duplicate {
		b.mu.Unlock()
		cancel()
		return opaqueHostInvalid
	}
	b.creates[operation] = create
	b.workers.Add(1)
	b.mu.Unlock()

	go func() {
		defer b.workers.Done()
		packet, err := b.socketFactory.BindUDP(bindContext, decoded)

		b.mu.Lock()
		if b.creates[operation] != create {
			b.mu.Unlock()
			if packet != nil {
				_ = packet.Close()
			}
			return
		}
		create.packet = packet
		create.err = err
		create.done = true
		if packet != nil {
			create.localAddr = packet.LocalAddr()
		}
		b.mu.Unlock()
		b.signalCompletion()
	}()
	return 0
}

func (b *opaqueBridge) takeUDPBind(
	_ context.Context,
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultLength uint32,
) int32 {
	if resultLength != boundSocketResultLen {
		b.discardCreateOperation(operation)
		return opaqueHostMemory
	}
	if _, ok := module.Memory().Read(resultPointer, resultLength); !ok {
		b.discardCreateOperation(operation)
		return opaqueHostMemory
	}

	b.mu.Lock()
	create, exists := b.creates[operation]
	if !exists {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	if !create.done {
		b.mu.Unlock()
		return opaqueHostPending
	}
	delete(b.creates, operation)
	if create.cancel != nil {
		create.cancel()
	}
	if create.err != nil || create.packet == nil {
		packet := create.packet
		b.mu.Unlock()
		if packet != nil {
			_ = packet.Close()
		}
		return opaqueHostIOError
	}
	handle := b.allocateHandleLocked()
	encoded, err := encodeBoundSocketResult(handle, create.localAddr)
	if err != nil || !module.Memory().Write(resultPointer, encoded[:]) {
		b.mu.Unlock()
		_ = create.packet.Close()
		return opaqueHostMemory
	}
	state := newOpaquePacketState(create.packet)
	b.packets[handle] = state
	b.workers.Add(1)
	b.mu.Unlock()
	go b.runUDPSends(handle, state)
	return 0
}

func (b *opaqueBridge) discardCreateOperation(operation uint64) {
	b.mu.Lock()
	create := b.creates[operation]
	delete(b.creates, operation)
	b.mu.Unlock()
	if create == nil {
		return
	}
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

func readOwnedOptions(module api.Module, pointer, length uint32) ([]byte, bool) {
	if length > maxFactoryOptionsSize {
		return nil, false
	}
	options, ok := module.Memory().Read(pointer, length)
	if !ok {
		return nil, false
	}
	return append([]byte(nil), options...), true
}

func decodeTCPConnectOptions(encoded []byte) (TCPConnectOptions, error) {
	if len(encoded) < 75 || encoded[0] != 2 {
		return TCPConnectOptions{}, fmt.Errorf("invalid TCP connect options")
	}
	remote, err := decodeSocketAddress(encoded[1:28], false)
	if err != nil || remote == nil {
		return TCPConnectOptions{}, fmt.Errorf("invalid TCP remote address")
	}
	local, err := decodeSocketAddress(encoded[28:55], true)
	if err != nil {
		return TCPConnectOptions{}, err
	}
	context, remainder, err := decodeSocketContext(encoded[55:])
	if err != nil {
		return TCPConnectOptions{}, fmt.Errorf("invalid TCP socket context: %w", err)
	}
	if len(remainder) < 9 {
		return TCPConnectOptions{}, fmt.Errorf("truncated TCP bind policy")
	}
	bind, err := decodeTCPBindPolicy(
		udpToTCPAddr(local), context, remainder[0], remainder[1], remainder[2], remainder[4:],
	)
	if err != nil {
		return TCPConnectOptions{}, err
	}
	if remainder[3] > byte(TCPConnectDataPlane) {
		return TCPConnectOptions{}, fmt.Errorf("invalid TCP purpose")
	}
	return TCPConnectOptions{
		RemoteAddr: &net.TCPAddr{IP: remote.IP, Port: remote.Port, Zone: remote.Zone},
		Bind:       bind,
		Purpose:    TCPConnectPurpose(remainder[3]),
	}, nil
}

func decodeUDPBindOptions(encoded []byte) (UDPBindOptions, error) {
	if len(encoded) < 48 || encoded[0] != 2 {
		return UDPBindOptions{}, fmt.Errorf("invalid UDP bind options")
	}
	local, err := decodeSocketAddress(encoded[1:28], true)
	if err != nil {
		return UDPBindOptions{}, err
	}
	context, remainder, err := decodeSocketContext(encoded[28:])
	if err != nil {
		return UDPBindOptions{}, fmt.Errorf("invalid UDP socket context: %w", err)
	}
	if len(remainder) < 9 {
		return UDPBindOptions{}, fmt.Errorf("truncated UDP bind policy")
	}
	reuseAddr, err := decodeWireBool("UDP reuse_addr", remainder[0])
	if err != nil {
		return UDPBindOptions{}, err
	}
	reusePort, err := decodeWireBool("UDP reuse_port", remainder[1])
	if err != nil {
		return UDPBindOptions{}, err
	}
	onlyV6, err := decodeWireBool("UDP only_v6", remainder[2])
	if err != nil {
		return UDPBindOptions{}, err
	}
	if remainder[3] > byte(UDPBindPortLease) {
		return UDPBindOptions{}, fmt.Errorf("invalid UDP purpose")
	}
	device, err := decodeBindDevice(remainder[4:])
	if err != nil {
		return UDPBindOptions{}, err
	}
	return UDPBindOptions{
		Context:    context,
		LocalAddr:  local,
		BindDevice: device,
		ReuseAddr:  reuseAddr,
		ReusePort:  reusePort,
		OnlyV6:     onlyV6,
		Purpose:    UDPBindPurpose(remainder[3]),
	}, nil
}

func decodeTCPBindPolicy(
	localAddr *net.TCPAddr,
	context SocketContext,
	reuseMode byte,
	reusePortByte byte,
	onlyV6Byte byte,
	deviceBytes []byte,
) (TCPBindOptions, error) {
	var reuseAddr *bool
	switch reuseMode {
	case 0:
	case 1:
		value := false
		reuseAddr = &value
	case 2:
		value := true
		reuseAddr = &value
	default:
		return TCPBindOptions{}, fmt.Errorf("invalid TCP reuse_addr")
	}
	reusePort, err := decodeWireBool("TCP reuse_port", reusePortByte)
	if err != nil {
		return TCPBindOptions{}, err
	}
	onlyV6, err := decodeWireBool("TCP only_v6", onlyV6Byte)
	if err != nil {
		return TCPBindOptions{}, err
	}
	device, err := decodeBindDevice(deviceBytes)
	if err != nil {
		return TCPBindOptions{}, err
	}
	return TCPBindOptions{
		Context:    context,
		LocalAddr:  localAddr,
		BindDevice: device,
		ReuseAddr:  reuseAddr,
		ReusePort:  reusePort,
		OnlyV6:     onlyV6,
	}, nil
}

func decodeSocketContext(encoded []byte) (SocketContext, []byte, error) {
	if len(encoded) < 11 || encoded[0] > byte(IPVersionBoth) {
		return SocketContext{}, nil, fmt.Errorf("invalid IP version")
	}
	mark, err := decodeSocketMark(encoded[1], encoded[2:6])
	if err != nil {
		return SocketContext{}, nil, err
	}
	if encoded[6] > 1 {
		return SocketContext{}, nil, fmt.Errorf("invalid netns presence")
	}
	length := int(binary.BigEndian.Uint32(encoded[7:11]))
	if length > len(encoded)-11 || (encoded[6] == 0 && length != 0) {
		return SocketContext{}, nil, fmt.Errorf("invalid netns length")
	}
	var netns *string
	if encoded[6] == 1 {
		token := encoded[11 : 11+length]
		if !utf8.Valid(token) {
			return SocketContext{}, nil, fmt.Errorf("netns token is not UTF-8")
		}
		value := string(token)
		netns = &value
	}
	return SocketContext{
		IPVersion:  IPVersion(encoded[0]),
		SocketMark: mark,
		NetNS:      netns,
	}, encoded[11+length:], nil
}

func decodeSocketMark(present byte, encoded []byte) (*uint32, error) {
	if present > 1 || len(encoded) != 4 || (present == 0 && binary.BigEndian.Uint32(encoded) != 0) {
		return nil, fmt.Errorf("invalid socket mark encoding")
	}
	if present == 0 {
		return nil, nil
	}
	mark := binary.BigEndian.Uint32(encoded)
	return &mark, nil
}

func decodeWireBool(name string, encoded byte) (bool, error) {
	if encoded > 1 {
		return false, fmt.Errorf("invalid %s", name)
	}
	return encoded == 1, nil
}

func decodeBindDevice(encoded []byte) (*string, error) {
	if len(encoded) < 5 || encoded[0] > 1 {
		return nil, fmt.Errorf("invalid bind device encoding")
	}
	length := int(binary.BigEndian.Uint32(encoded[1:5]))
	if len(encoded) != 5+length || (encoded[0] == 0 && length != 0) {
		return nil, fmt.Errorf("invalid bind device length")
	}
	if encoded[0] == 0 {
		return nil, nil
	}
	device := string(encoded[5:])
	return &device, nil
}

func decodeSocketAddress(encoded []byte, optional bool) (*net.UDPAddr, error) {
	if len(encoded) != socketAddressLen {
		return nil, fmt.Errorf("invalid socket address length")
	}
	if optional && encoded[0] == 0 {
		for _, value := range encoded[1:] {
			if value != 0 {
				return nil, fmt.Errorf("noncanonical absent socket address")
			}
		}
		return nil, nil
	}
	metadata := make([]byte, udpMetadataLen)
	copy(metadata, encoded)
	address, _, flowinfo, _, err := decodeUDPMetadata(metadata)
	if err == nil && flowinfo != 0 {
		return nil, fmt.Errorf("IPv6 flowinfo is outside this PoC")
	}
	return address, err
}

func udpToTCPAddr(address *net.UDPAddr) *net.TCPAddr {
	if address == nil {
		return nil
	}
	return &net.TCPAddr{IP: address.IP, Port: address.Port, Zone: address.Zone}
}

func encodeTCPSocketResult(handle uint64, localAddr, peerAddr net.Addr) ([tcpSocketResultLen]byte, error) {
	var encoded [tcpSocketResultLen]byte
	binary.BigEndian.PutUint64(encoded[:8], handle)
	local, err := encodeNetAddr(localAddr)
	if err != nil {
		return encoded, err
	}
	peer, err := encodeNetAddr(peerAddr)
	if err != nil {
		return encoded, err
	}
	copy(encoded[8:35], local[:])
	copy(encoded[35:], peer[:])
	return encoded, nil
}

func encodeBoundSocketResult(handle uint64, localAddr net.Addr) ([boundSocketResultLen]byte, error) {
	var encoded [boundSocketResultLen]byte
	binary.BigEndian.PutUint64(encoded[:8], handle)
	local, err := encodeNetAddr(localAddr)
	if err != nil {
		return encoded, err
	}
	copy(encoded[8:], local[:])
	return encoded, nil
}

func encodeNetAddr(address net.Addr) ([socketAddressLen]byte, error) {
	var encoded [socketAddressLen]byte
	var udpAddr *net.UDPAddr
	switch address := address.(type) {
	case *net.TCPAddr:
		udpAddr = &net.UDPAddr{IP: address.IP, Port: address.Port, Zone: address.Zone}
	case *net.UDPAddr:
		udpAddr = address
	default:
		return encoded, fmt.Errorf("unsupported socket address %T", address)
	}
	metadata, err := encodeUDPMetadata(udpAddr, nil, 0)
	if err != nil {
		return encoded, err
	}
	copy(encoded[:], metadata[:socketAddressLen])
	return encoded, nil
}
