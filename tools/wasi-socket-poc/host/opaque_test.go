package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

const (
	opaqueTimerProgress        = 1 << 0
	opaqueSecondSocketProgress = 1 << 1
	opaquePendingReadCompleted = 1 << 2
	opaquePendingReadIsolated  = 1 << 3
	opaqueDone                 = 1 << 4
	opaqueError                = 1 << 31

	opaqueHostPending = -1
	opaqueHostInvalid = -2
	opaqueHostIOError = -3
	opaqueHostMemory  = -4
)

type opaqueReadOperation struct {
	handle uint64
	done   bool
	data   []byte
	err    error
}

type opaqueWriteOperation struct {
	done bool
	err  error
}

type opaqueBridge struct {
	mu          sync.Mutex
	handles     map[uint64]net.Conn
	packets     map[uint64]*opaquePacketState
	listeners   map[uint64]*opaqueTCPListenerState
	reads       map[uint64]*opaqueReadOperation
	writes      map[uint64]*opaqueWriteOperation
	udpReads    map[uint64]*opaqueUDPReadWaiter
	udpWrites   map[uint64]*opaqueUDPWriteWaiter
	tcpAccepts  map[uint64]*opaqueTCPAcceptWaiter
	creates     map[uint64]*opaqueCreateOperation
	dns         map[uint64]*opaqueDNSOperation
	dnsResolver opaqueDNSResolver
	nextHandle  uint64
	completion  chan struct{}
	workers     sync.WaitGroup
}

func newOpaqueBridge(
	handles map[uint64]net.Conn,
	packets map[uint64]net.PacketConn,
) *opaqueBridge {
	if handles == nil {
		handles = make(map[uint64]net.Conn)
	}
	bridge := &opaqueBridge{
		handles:     handles,
		packets:     make(map[uint64]*opaquePacketState, len(packets)),
		listeners:   make(map[uint64]*opaqueTCPListenerState),
		reads:       make(map[uint64]*opaqueReadOperation),
		writes:      make(map[uint64]*opaqueWriteOperation),
		udpReads:    make(map[uint64]*opaqueUDPReadWaiter),
		udpWrites:   make(map[uint64]*opaqueUDPWriteWaiter),
		tcpAccepts:  make(map[uint64]*opaqueTCPAcceptWaiter),
		creates:     make(map[uint64]*opaqueCreateOperation),
		dns:         make(map[uint64]*opaqueDNSOperation),
		dnsResolver: systemOpaqueDNSResolver{},
		nextHandle:  1 << 48,
		completion:  make(chan struct{}, 1),
	}
	for handle, connection := range packets {
		state := newOpaquePacketState(connection)
		bridge.packets[handle] = state
		bridge.workers.Add(1)
		go bridge.runUDPSends(handle, state)
	}
	return bridge
}

func (b *opaqueBridge) startRead(
	_ context.Context,
	_ api.Module,
	handle uint64,
	operation uint64,
	capacity uint32,
) int32 {
	b.mu.Lock()
	connection, exists := b.handles[handle]
	if !exists || capacity == 0 {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	if _, duplicate := b.reads[operation]; duplicate {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	result := &opaqueReadOperation{handle: handle}
	b.reads[operation] = result
	b.workers.Add(1)
	b.mu.Unlock()

	go func() {
		defer b.workers.Done()

		buffer := make([]byte, capacity)
		n, err := connection.Read(buffer)

		b.mu.Lock()
		result.data = buffer[:n]
		result.err = err
		result.done = true
		b.mu.Unlock()
		b.signalCompletion()
	}()

	return 0
}

func (b *opaqueBridge) takeRead(
	_ context.Context,
	module api.Module,
	operation uint64,
	destination uint32,
	capacity uint32,
) int32 {
	b.mu.Lock()
	result, exists := b.reads[operation]
	if !exists {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	if !result.done {
		b.mu.Unlock()
		return opaqueHostPending
	}
	delete(b.reads, operation)
	data, err := result.data, result.err
	b.mu.Unlock()

	if uint32(len(data)) > capacity {
		return opaqueHostMemory
	}
	if len(data) > 0 {
		if !module.Memory().Write(destination, data) {
			return opaqueHostMemory
		}
		return int32(len(data))
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return opaqueHostIOError
	}
	return 0
}

func (b *opaqueBridge) startWrite(
	_ context.Context,
	module api.Module,
	handle uint64,
	operation uint64,
	source uint32,
	length uint32,
) int32 {
	buffer, ok := module.Memory().Read(source, length)
	if !ok {
		return opaqueHostMemory
	}
	buffer = append([]byte(nil), buffer...)

	b.mu.Lock()
	connection, exists := b.handles[handle]
	if !exists {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	if _, duplicate := b.writes[operation]; duplicate {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	result := &opaqueWriteOperation{}
	b.writes[operation] = result
	b.workers.Add(1)
	b.mu.Unlock()

	go func() {
		defer b.workers.Done()

		written := 0
		var err error
		for written < len(buffer) {
			var n int
			n, err = connection.Write(buffer[written:])
			written += n
			if err != nil {
				break
			}
			if n == 0 {
				err = io.ErrShortWrite
				break
			}
		}

		b.mu.Lock()
		result.err = err
		result.done = true
		b.mu.Unlock()
		b.signalCompletion()
	}()

	return 0
}

func (b *opaqueBridge) takeWrite(
	_ context.Context,
	_ api.Module,
	operation uint64,
) int32 {
	b.mu.Lock()
	result, exists := b.writes[operation]
	if !exists {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	if !result.done {
		b.mu.Unlock()
		return opaqueHostPending
	}
	delete(b.writes, operation)
	err := result.err
	b.mu.Unlock()

	if err != nil {
		return opaqueHostIOError
	}
	return 0
}

func (b *opaqueBridge) signalCompletion() {
	select {
	case b.completion <- struct{}{}:
	default:
	}
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

func (b *opaqueBridge) readInFlight(handle uint64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, operation := range b.reads {
		if operation.handle == handle && !operation.done {
			return true
		}
	}
	return false
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
	b.workers.Wait()
}

func TestOpaqueSocketBridgeDrivesTokio(t *testing.T) {
	const (
		pendingHandle uint64 = 1<<40 | 1
		activeHandle  uint64 = 1<<40 | 2
	)
	pendingHost, pendingPeer := net.Pipe()
	activeHost, activePeer := net.Pipe()
	bridge := newOpaqueBridge(
		map[uint64]net.Conn{
			pendingHandle: pendingHost,
			activeHandle:  activeHost,
		},
		nil,
	)
	defer bridge.close()
	defer pendingPeer.Close()
	defer activePeer.Close()
	wasm := buildGuest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runtimeConfig := wazero.NewRuntimeConfig().WithCloseOnContextDone(true)
	runtime := wazero.NewRuntimeWithConfig(ctx, runtimeConfig)
	defer runtime.Close(ctx)
	instantiateOpaqueHost(t, ctx, runtime, bridge)
	wasi_snapshot_preview1.MustInstantiate(ctx, runtime)

	compiled, err := runtime.CompileModule(ctx, wasm)
	if err != nil {
		t.Fatalf("compile guest: %v", err)
	}
	moduleConfig := wazero.NewModuleConfig().
		WithStartFunctions("_initialize").
		WithSysWalltime().
		WithSysNanotime().
		WithSysNanosleep()
	module, err := runtime.InstantiateModule(ctx, compiled, moduleConfig)
	if err != nil {
		t.Fatalf("instantiate guest: %v", err)
	}

	initResult, err := module.ExportedFunction("init_opaque_probe").Call(
		ctx,
		pendingHandle,
		activeHandle,
	)
	if err != nil {
		t.Fatalf("initialize opaque probe: %v", err)
	}
	if len(initResult) != 1 || int32(initResult[0]) != 0 {
		t.Fatalf("unexpected opaque probe initialization result: %v", initResult)
	}

	driveCalls := 0
	drive := func() uint32 {
		results, err := module.ExportedFunction("drive_opaque_probe").Call(ctx)
		if err != nil {
			t.Fatalf("drive opaque probe: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("unexpected opaque probe result count: %d", len(results))
		}
		status := uint32(results[0])
		driveCalls++
		if status&opaqueError != 0 {
			t.Fatalf("opaque probe failed at stage %d", status&^opaqueError)
		}
		return status
	}

	status := drive()
	if !bridge.readInFlight(pendingHandle) {
		t.Fatal("pending connection read was not in flight after initial drive")
	}
	if !bridge.readInFlight(activeHandle) {
		t.Fatal("active connection read was not in flight after initial drive")
	}

	echo := make(chan error, 1)
	readyToReadEcho := make(chan struct{})
	allowEchoRead := make(chan struct{})
	go func() {
		if err := activePeer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			echo <- err
			return
		}
		want := []byte{0x5a}
		if _, err := activePeer.Write(want); err != nil {
			echo <- fmt.Errorf("write active connection: %w", err)
			return
		}
		close(readyToReadEcho)
		select {
		case <-allowEchoRead:
		case <-ctx.Done():
			echo <- ctx.Err()
			return
		}
		got := make([]byte, len(want))
		if _, err := io.ReadFull(activePeer, got); err != nil {
			echo <- fmt.Errorf("read active connection: %w", err)
			return
		}
		if got[0] != want[0] {
			echo <- fmt.Errorf("echo mismatch: got %x, want %x", got, want)
			return
		}
		echo <- nil
	}()

	waitForCompletion := func(stage string) {
		select {
		case <-bridge.completion:
		case <-ctx.Done():
			t.Fatalf("waiting for %s completion: %v", stage, ctx.Err())
		}
	}

	waitForCompletion("active read")
	status = drive()
	if status&opaqueSecondSocketProgress != 0 {
		t.Fatal("active socket completed before its write was released")
	}
	select {
	case <-readyToReadEcho:
	case <-ctx.Done():
		t.Fatalf("waiting for peer to finish its write: %v", ctx.Err())
	}
	close(allowEchoRead)

	waitForCompletion("active write")
	status = drive()
	if status&opaqueSecondSocketProgress == 0 {
		t.Fatal("active socket did not progress after read and write completions")
	}
	completionDriveCalls := 2

	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for status&opaqueDone == 0 {
		select {
		case <-ticker.C:
			status = drive()
		case <-ctx.Done():
			t.Fatalf("waiting for Tokio timer progress: %v", ctx.Err())
		}
	}

	wantStatus := uint32(
		opaqueTimerProgress |
			opaqueSecondSocketProgress |
			opaquePendingReadIsolated |
			opaqueDone,
	)
	if status != wantStatus {
		t.Fatalf("opaque probe status 0x%x, want 0x%x", status, wantStatus)
	}
	if status&opaquePendingReadCompleted != 0 {
		t.Fatal("permanently pending read unexpectedly completed")
	}
	select {
	case err := <-echo:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatalf("waiting for active connection echo: %v", ctx.Err())
	}

	t.Logf(
		"opaque net.Conn bridge passed: status=0x%x, drives=%d, completion drives=%d",
		status,
		driveCalls,
		completionDriveCalls,
	)
}

func instantiateOpaqueHost(
	t *testing.T,
	ctx context.Context,
	runtime wazero.Runtime,
	bridge *opaqueBridge,
) {
	t.Helper()

	_, err := runtime.NewHostModuleBuilder("easytier_host").
		NewFunctionBuilder().WithFunc(bridge.startRead).Export("start_read").
		NewFunctionBuilder().WithFunc(bridge.takeRead).Export("take_read").
		NewFunctionBuilder().WithFunc(bridge.startWrite).Export("start_write").
		NewFunctionBuilder().WithFunc(bridge.takeWrite).Export("take_write").
		NewFunctionBuilder().WithFunc(bridge.startUDPRecv).Export("start_udp_recv").
		NewFunctionBuilder().WithFunc(bridge.takeUDPRecv).Export("take_udp_recv").
		NewFunctionBuilder().WithFunc(bridge.tryUDPSend).Export("try_udp_send").
		NewFunctionBuilder().WithFunc(bridge.startUDPSendReady).Export("start_udp_send_ready").
		NewFunctionBuilder().WithFunc(bridge.takeUDPSendReady).Export("take_udp_send_ready").
		NewFunctionBuilder().WithFunc(bridge.startTCPConnect).Export("start_tcp_connect").
		NewFunctionBuilder().WithFunc(bridge.takeTCPConnect).Export("take_tcp_connect").
		NewFunctionBuilder().WithFunc(bridge.startUDPBind).Export("start_udp_bind").
		NewFunctionBuilder().WithFunc(bridge.takeUDPBind).Export("take_udp_bind").
		NewFunctionBuilder().WithFunc(bridge.startTCPBind).Export("start_tcp_bind").
		NewFunctionBuilder().WithFunc(bridge.takeTCPBind).Export("take_tcp_bind").
		NewFunctionBuilder().WithFunc(bridge.startTCPAccept).Export("start_tcp_accept").
		NewFunctionBuilder().WithFunc(bridge.takeTCPAccept).Export("take_tcp_accept").
		NewFunctionBuilder().WithFunc(bridge.startDNSResolve).Export("start_dns_resolve").
		NewFunctionBuilder().WithFunc(bridge.takeDNSResolve).Export("take_dns_resolve").
		NewFunctionBuilder().WithFunc(bridge.startDNSTXT).Export("start_dns_txt").
		NewFunctionBuilder().WithFunc(bridge.takeDNSTXT).Export("take_dns_txt").
		NewFunctionBuilder().WithFunc(bridge.startDNSSRV).Export("start_dns_srv").
		NewFunctionBuilder().WithFunc(bridge.takeDNSSRV).Export("take_dns_srv").
		NewFunctionBuilder().WithFunc(bridge.cancelOperation).Export("cancel_operation").
		NewFunctionBuilder().WithFunc(bridge.closeHandle).Export("close").
		Instantiate(ctx)
	if err != nil {
		t.Fatalf("instantiate opaque socket host module: %v", err)
	}
}
