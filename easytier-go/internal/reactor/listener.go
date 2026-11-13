package reactor

import "net"

type listenerState struct {
	listener      net.Listener
	accepted      []net.Conn
	acceptRunning bool
	acceptErr     error
}

type acceptWaiter struct {
	handle uint64
	ready  bool
}

func (reactor *Reactor) StartTCPAccept(handle, operation uint64) error {
	reactor.mu.Lock()
	state, exists := reactor.listeners[handle]
	if !exists {
		reactor.mu.Unlock()
		return ErrInvalid
	}
	if err := reactor.claimOperationLocked(operation, operationAccept); err != nil {
		reactor.mu.Unlock()
		return err
	}
	waiter := &acceptWaiter{
		handle: handle,
		ready:  len(state.accepted) > 0 || state.acceptErr != nil,
	}
	reactor.accepts[operation] = waiter
	startWorker := !waiter.ready && !state.acceptRunning
	if startWorker {
		state.acceptRunning = true
		reactor.workers.Add(1)
	}
	reactor.mu.Unlock()

	if startWorker {
		go reactor.runTCPAccept(handle, state)
	}
	if waiter.ready {
		reactor.signalCompletion()
	}
	return nil
}

func (reactor *Reactor) runTCPAccept(handle uint64, state *listenerState) {
	defer reactor.workers.Done()
	connection, err := state.listener.Accept()

	reactor.mu.Lock()
	if reactor.listeners[handle] != state {
		reactor.mu.Unlock()
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
	for _, waiter := range reactor.accepts {
		if waiter.handle == handle {
			waiter.ready = true
		}
	}
	reactor.mu.Unlock()
	reactor.signalCompletion()
}

func (reactor *Reactor) TakeTCPAccept(operation uint64) (StreamResult, error) {
	reactor.mu.Lock()
	waiter, exists := reactor.accepts[operation]
	if !exists || reactor.operations[operation] != operationAccept {
		reactor.mu.Unlock()
		return StreamResult{}, ErrInvalid
	}
	state, exists := reactor.listeners[waiter.handle]
	if !exists {
		delete(reactor.accepts, operation)
		reactor.releaseOperationLocked(operation, operationAccept)
		reactor.mu.Unlock()
		return StreamResult{}, ErrInvalid
	}
	if len(state.accepted) == 0 {
		if state.acceptErr == nil {
			reactor.mu.Unlock()
			return StreamResult{}, ErrPending
		}
		err := state.acceptErr
		state.acceptErr = nil
		delete(reactor.accepts, operation)
		reactor.releaseOperationLocked(operation, operationAccept)
		startWorker := !state.acceptRunning && reactor.hasAcceptWaiterLocked(waiter.handle)
		if startWorker {
			state.acceptRunning = true
			reactor.workers.Add(1)
		}
		reactor.mu.Unlock()
		if startWorker {
			go reactor.runTCPAccept(waiter.handle, state)
		}
		return StreamResult{}, err
	}

	connection := state.accepted[0]
	state.accepted[0] = nil
	state.accepted = state.accepted[1:]
	delete(reactor.accepts, operation)
	reactor.releaseOperationLocked(operation, operationAccept)
	handle := reactor.allocateHandleLocked()
	reactor.streams[handle] = newStreamState(connection)
	startWorker := len(state.accepted) == 0 &&
		!state.acceptRunning &&
		reactor.hasAcceptWaiterLocked(waiter.handle)
	if startWorker {
		state.acceptRunning = true
		reactor.workers.Add(1)
	}
	result := StreamResult{
		Handle: handle,
		Local:  connection.LocalAddr(),
		Peer:   connection.RemoteAddr(),
	}
	reactor.mu.Unlock()
	if startWorker {
		go reactor.runTCPAccept(waiter.handle, state)
	}
	return result, nil
}

func (reactor *Reactor) hasAcceptWaiterLocked(handle uint64) bool {
	for _, waiter := range reactor.accepts {
		if waiter.handle == handle {
			return true
		}
	}
	return false
}
