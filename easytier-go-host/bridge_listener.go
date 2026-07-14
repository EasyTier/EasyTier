package host

// TCP listeners remain host-owned and yield accepted streams to core.

import (
	"context"
	"fmt"
	"net"

	"github.com/tetratelabs/wazero/api"
)

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
	decoded, err := decodeTCPListenOptions(options)
	if err != nil {
		return opaqueHostInvalid
	}
	listenContext, cancel := context.WithCancel(context.Background())
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
		listener, err := b.socketFactory.ListenTCP(listenContext, decoded)
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
	if create.err != nil || create.listener == nil {
		listener := create.listener
		b.mu.Unlock()
		if listener != nil {
			_ = listener.Close()
		}
		return opaqueHostIOError
	}
	handle := b.allocateHandleLocked()
	encoded, err := encodeBoundSocketResult(handle, create.localAddr)
	if err != nil || !module.Memory().Write(resultPointer, encoded[:]) {
		listener := create.listener
		b.mu.Unlock()
		_ = listener.Close()
		return opaqueHostMemory
	}
	b.listeners[handle] = &opaqueTCPListenerState{listener: create.listener}
	b.mu.Unlock()
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

func decodeTCPListenOptions(encoded []byte) (TCPListenOptions, error) {
	if len(encoded) < 48 || encoded[0] != 2 {
		return TCPListenOptions{}, fmt.Errorf("invalid TCP listen options")
	}
	local, err := decodeSocketAddress(encoded[1:28], false)
	if err != nil || local == nil {
		return TCPListenOptions{}, fmt.Errorf("invalid TCP listen address")
	}
	context, remainder, err := decodeSocketContext(encoded[28:])
	if err != nil {
		return TCPListenOptions{}, fmt.Errorf("invalid TCP listen socket context: %w", err)
	}
	if len(remainder) < 9 {
		return TCPListenOptions{}, fmt.Errorf("truncated TCP listen bind policy")
	}
	bind, err := decodeTCPBindPolicy(
		&net.TCPAddr{IP: local.IP, Port: local.Port, Zone: local.Zone},
		context, remainder[0], remainder[1], remainder[2], remainder[4:],
	)
	if err != nil {
		return TCPListenOptions{}, err
	}
	if remainder[3] > 3 {
		return TCPListenOptions{}, fmt.Errorf("invalid TCP listen purpose")
	}
	return TCPListenOptions{
		Bind:    bind,
		Purpose: TCPListenPurpose(remainder[3]),
	}, nil
}
