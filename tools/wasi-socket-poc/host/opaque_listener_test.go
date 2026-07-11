package host

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

type opaqueTCPListenerState struct {
	listener      net.Listener
	accepted      []net.Conn
	acceptRunning bool
	acceptErr     error
}

type opaqueTCPAcceptWaiter struct {
	handle uint64
	ready  bool
}

func (b *opaqueBridge) startTCPBind(
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
	localAddr, err := decodeTCPListenOptions(options)
	if err != nil {
		return opaqueHostInvalid
	}
	listenContext, cancel := context.WithCancel(context.Background())
	create := &opaqueCreateOperation{cancel: cancel}
	b.mu.Lock()
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
		listener, err := (&net.ListenConfig{}).Listen(listenContext, "tcp", localAddr.String())
		b.mu.Lock()
		if b.creates[operation] != create {
			b.mu.Unlock()
			if listener != nil {
				_ = listener.Close()
			}
			return
		}
		create.listener = listener
		create.err = err
		create.done = true
		if listener != nil {
			create.localAddr = listener.Addr()
		}
		b.mu.Unlock()
		b.signalCompletion()
	}()
	return 0
}

func (b *opaqueBridge) takeTCPBind(
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
	defer b.mu.Unlock()
	create, exists := b.creates[operation]
	if !exists {
		return opaqueHostInvalid
	}
	if !create.done {
		return opaqueHostPending
	}
	delete(b.creates, operation)
	if create.cancel != nil {
		create.cancel()
	}
	if create.err != nil || create.listener == nil {
		return opaqueHostIOError
	}
	handle := b.allocateHandleLocked()
	encoded, err := encodeBoundSocketResult(handle, create.localAddr)
	if err != nil || !module.Memory().Write(resultPointer, encoded[:]) {
		_ = create.listener.Close()
		return opaqueHostMemory
	}
	b.listeners[handle] = &opaqueTCPListenerState{listener: create.listener}
	return 0
}

func (b *opaqueBridge) startTCPAccept(
	_ context.Context,
	_ api.Module,
	handle uint64,
	operation uint64,
) int32 {
	b.mu.Lock()
	state, exists := b.listeners[handle]
	if !exists {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	if _, duplicate := b.tcpAccepts[operation]; duplicate {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	waiter := &opaqueTCPAcceptWaiter{
		handle: handle,
		ready:  len(state.accepted) > 0 || state.acceptErr != nil,
	}
	b.tcpAccepts[operation] = waiter
	startWorker := !waiter.ready && !state.acceptRunning
	if startWorker {
		state.acceptRunning = true
		b.workers.Add(1)
	}
	b.mu.Unlock()
	if startWorker {
		go b.runTCPAccept(handle, state)
	}
	if waiter.ready {
		b.signalCompletion()
	}
	return 0
}

func (b *opaqueBridge) runTCPAccept(handle uint64, state *opaqueTCPListenerState) {
	defer b.workers.Done()
	connection, err := state.listener.Accept()
	b.mu.Lock()
	if b.listeners[handle] != state {
		b.mu.Unlock()
		if connection != nil {
			_ = connection.Close()
		}
		return
	}
	state.acceptRunning = false
	if err != nil {
		state.acceptErr = err
	} else {
		state.accepted = append(state.accepted, connection)
	}
	for _, waiter := range b.tcpAccepts {
		if waiter.handle == handle {
			waiter.ready = true
		}
	}
	b.mu.Unlock()
	b.signalCompletion()
}

func (b *opaqueBridge) takeTCPAccept(
	_ context.Context,
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultLength uint32,
) int32 {
	if resultLength != tcpSocketResultLen {
		b.discardTCPAcceptWaiter(operation)
		return opaqueHostMemory
	}
	if _, ok := module.Memory().Read(resultPointer, resultLength); !ok {
		b.discardTCPAcceptWaiter(operation)
		return opaqueHostMemory
	}
	b.mu.Lock()
	waiter, exists := b.tcpAccepts[operation]
	if !exists {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	state, exists := b.listeners[waiter.handle]
	if !exists {
		delete(b.tcpAccepts, operation)
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	if len(state.accepted) == 0 {
		if state.acceptErr == nil {
			b.mu.Unlock()
			return opaqueHostPending
		}
		state.acceptErr = nil
		delete(b.tcpAccepts, operation)
		startWorker := !state.acceptRunning && hasTCPAcceptWaiter(b, waiter.handle)
		if startWorker {
			state.acceptRunning = true
			b.workers.Add(1)
		}
		b.mu.Unlock()
		if startWorker {
			go b.runTCPAccept(waiter.handle, state)
		}
		return opaqueHostIOError
	}
	connection := state.accepted[0]
	state.accepted = state.accepted[1:]
	delete(b.tcpAccepts, operation)
	handle := b.allocateHandleLocked()
	encoded, err := encodeTCPSocketResult(handle, connection.LocalAddr(), connection.RemoteAddr())
	if err != nil || !module.Memory().Write(resultPointer, encoded[:]) {
		startWorker := !state.acceptRunning && hasTCPAcceptWaiter(b, waiter.handle)
		if startWorker {
			state.acceptRunning = true
			b.workers.Add(1)
		}
		b.mu.Unlock()
		_ = connection.Close()
		if startWorker {
			go b.runTCPAccept(waiter.handle, state)
		}
		return opaqueHostMemory
	}
	b.handles[handle] = connection
	startWorker := len(state.accepted) == 0 && !state.acceptRunning && hasTCPAcceptWaiter(b, waiter.handle)
	if startWorker {
		state.acceptRunning = true
		b.workers.Add(1)
	}
	b.mu.Unlock()
	if startWorker {
		go b.runTCPAccept(waiter.handle, state)
	}
	return 0
}

func hasTCPAcceptWaiter(b *opaqueBridge, handle uint64) bool {
	for _, waiter := range b.tcpAccepts {
		if waiter.handle == handle {
			return true
		}
	}
	return false
}

func (b *opaqueBridge) discardTCPAcceptWaiter(operation uint64) {
	b.mu.Lock()
	delete(b.tcpAccepts, operation)
	b.mu.Unlock()
}

func decodeTCPListenOptions(encoded []byte) (*net.TCPAddr, error) {
	if len(encoded) < 42 || encoded[0] != 1 {
		return nil, fmt.Errorf("invalid TCP listen options")
	}
	local, err := decodeSocketAddress(encoded[1:28], false)
	if err != nil || local == nil {
		return nil, fmt.Errorf("invalid TCP listen address")
	}
	if err := validatePoCBindOptions(encoded[28], encoded[29:33], encoded[33], encoded[34], encoded[35]); err != nil {
		return nil, err
	}
	if encoded[36] > 3 {
		return nil, fmt.Errorf("invalid TCP listen purpose")
	}
	device, err := decodeBindDevice(encoded[37:])
	if err != nil {
		return nil, err
	}
	if device != nil {
		return nil, fmt.Errorf("bind device policy is outside this PoC")
	}
	return &net.TCPAddr{IP: local.IP, Port: local.Port, Zone: local.Zone}, nil
}

func TestDecodeTCPProxyNatListenPurpose(t *testing.T) {
	encoded := make([]byte, 42)
	encoded[0] = 1
	local, err := encodeNetAddr(&net.TCPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	copy(encoded[1:28], local[:])
	encoded[36] = 3
	if _, err := decodeTCPListenOptions(encoded); err != nil {
		t.Fatalf("decode proxy NAT TCP listen options: %v", err)
	}
}

func TestOpaqueListenerAcceptsCoreStream(t *testing.T) {
	port := reserveTCPPort(t)
	bridge := newOpaqueBridge(nil, nil)
	defer bridge.close()
	wasm := buildGuest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runtime := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
	defer runtime.Close(ctx)
	instantiateOpaqueHost(t, ctx, runtime, bridge)
	wasi_snapshot_preview1.MustInstantiate(ctx, runtime)
	compiled, err := runtime.CompileModule(ctx, wasm)
	if err != nil {
		t.Fatalf("compile guest: %v", err)
	}
	module, err := runtime.InstantiateModule(
		ctx,
		compiled,
		wazero.NewModuleConfig().WithStartFunctions("_initialize").WithSysWalltime().WithSysNanotime().WithSysNanosleep(),
	)
	if err != nil {
		t.Fatalf("instantiate guest: %v", err)
	}
	results, err := module.ExportedFunction("init_listener_probe").Call(ctx, uint64(port))
	if err != nil || len(results) != 1 || int32(results[0]) != 0 {
		t.Fatalf("initialize listener probe: results=%v err=%v", results, err)
	}

	peerDone := make(chan error, 1)
	go func() {
		address := fmt.Sprintf("127.0.0.1:%d", port)
		var connection net.Conn
		var err error
		for connection == nil && ctx.Err() == nil {
			connection, err = net.DialTimeout("tcp4", address, 50*time.Millisecond)
			if err != nil {
				time.Sleep(5 * time.Millisecond)
			}
		}
		if connection == nil {
			peerDone <- fmt.Errorf("dial listener: %w", err)
			return
		}
		defer connection.Close()
		if _, err := connection.Write([]byte("listener")); err != nil {
			peerDone <- err
			return
		}
		buffer := make([]byte, 8)
		_, err = io.ReadFull(connection, buffer)
		if err == nil && string(buffer) != "listener" {
			err = fmt.Errorf("listener echo %q", buffer)
		}
		peerDone <- err
	}()

	status := uint32(0)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for status&opaqueDone == 0 {
		select {
		case <-bridge.completion:
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("wait for listener probe: %v", ctx.Err())
		}
		results, err := module.ExportedFunction("drive_listener_probe").Call(ctx)
		if err != nil || len(results) != 1 {
			t.Fatalf("drive listener probe: results=%v err=%v", results, err)
		}
		status = uint32(results[0])
		if status&opaqueError != 0 {
			t.Fatalf("listener probe failed with status 0x%x", status)
		}
	}
	select {
	case err := <-peerDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatalf("wait for listener peer: %v", ctx.Err())
	}
}
