package reactor

import (
	"fmt"
	"net"
	"sync"
)

const (
	udpReceiveQueueCapacity = 64
	udpSendQueueCapacity    = 64
)

type Datagram struct {
	Data []byte
	Peer *net.UDPAddr
}

type udpSend struct {
	data []byte
	peer *net.UDPAddr
}

type datagramState struct {
	connection     net.PacketConn
	receiveBuffer  []byte
	received       []Datagram
	receiveRunning bool
	receiveErr     error
	sendQueue      chan udpSend
	sendErr        error
	closeOnce      sync.Once
}

type udpReadWaiter struct {
	handle uint64
	ready  bool
}

type udpWriteWaiter struct {
	handle uint64
	ready  bool
}

func newDatagramState(connection net.PacketConn) *datagramState {
	return &datagramState{
		connection: connection,
		sendQueue:  make(chan udpSend, udpSendQueueCapacity),
	}
}

func (state *datagramState) closeAfterQueuedSends() {
	state.closeOnce.Do(func() {
		close(state.sendQueue)
	})
}

func (state *datagramState) closeNow() {
	state.closeOnce.Do(func() {
		close(state.sendQueue)
	})
	_ = state.connection.Close()
}

func (reactor *Reactor) runUDPSends(handle uint64, state *datagramState) {
	defer reactor.workers.Done()
	defer reactor.finishUDPSends(state)
	defer state.connection.Close()

	for request := range state.sendQueue {
		reactor.mu.Lock()
		ready := false
		for _, waiter := range reactor.udpWrites {
			if waiter.handle == handle {
				waiter.ready = true
				ready = true
			}
		}
		reactor.mu.Unlock()
		if ready {
			reactor.signalCompletion()
		}

		n, err := state.connection.WriteTo(request.data, request.peer)
		if err == nil && n != len(request.data) {
			err = fmt.Errorf("short UDP write: %d of %d", n, len(request.data))
		}
		if err != nil {
			reactor.mu.Lock()
			ready := false
			if reactor.datagrams[handle] == state {
				state.sendErr = err
				for _, waiter := range reactor.udpWrites {
					if waiter.handle == handle {
						waiter.ready = true
						ready = true
					}
				}
			}
			reactor.mu.Unlock()
			if ready {
				reactor.signalCompletion()
			}
		}
	}
}

func (reactor *Reactor) finishUDPSends(state *datagramState) {
	reactor.mu.Lock()
	delete(reactor.drainingDatagrams, state)
	reactor.mu.Unlock()
}

func (reactor *Reactor) StartUDPReceive(handle, operation uint64) error {
	reactor.mu.Lock()
	state, exists := reactor.datagrams[handle]
	if !exists {
		reactor.mu.Unlock()
		return ErrInvalid
	}
	if err := reactor.claimOperationLocked(operation, operationUDPRead); err != nil {
		reactor.mu.Unlock()
		return err
	}
	waiter := &udpReadWaiter{
		handle: handle,
		ready:  len(state.received) > 0 || state.receiveErr != nil,
	}
	reactor.udpReads[operation] = waiter
	startWorker := state.receiveErr == nil &&
		len(state.received) < udpReceiveQueueCapacity &&
		!state.receiveRunning
	if startWorker {
		state.receiveRunning = true
		reactor.workers.Add(1)
	}
	reactor.mu.Unlock()

	if startWorker {
		go reactor.runUDPReceive(handle, state)
	}
	if waiter.ready {
		reactor.signalCompletion()
	}
	return nil
}

func (reactor *Reactor) runUDPReceive(handle uint64, state *datagramState) {
	defer reactor.workers.Done()
	if state.receiveBuffer == nil {
		state.receiveBuffer = make([]byte, 65535)
	}
	buffer := state.receiveBuffer
	for {
		n, peer, err := state.connection.ReadFrom(buffer)

		var udpPeer *net.UDPAddr
		if err == nil {
			var ok bool
			udpPeer, ok = peer.(*net.UDPAddr)
			if !ok {
				err = fmt.Errorf("unsupported UDP peer address %T", peer)
			}
		}

		reactor.mu.Lock()
		if reactor.datagrams[handle] != state {
			reactor.mu.Unlock()
			return
		}
		if err != nil {
			state.receiveErr = err
		} else {
			state.received = append(state.received, Datagram{
				Data: append([]byte(nil), buffer[:n]...),
				Peer: cloneUDPAddr(udpPeer),
			})
		}
		ready := false
		for _, waiter := range reactor.udpReads {
			if waiter.handle == handle {
				waiter.ready = true
				ready = true
			}
		}
		continueReceiving := err == nil &&
			ready &&
			len(state.received) < udpReceiveQueueCapacity
		if !continueReceiving {
			state.receiveRunning = false
		}
		reactor.mu.Unlock()
		if ready {
			reactor.signalCompletion()
		}
		if !continueReceiving {
			return
		}
	}
}

func (reactor *Reactor) TakeUDPReceive(operation uint64, capacity uint32) (Datagram, error) {
	reactor.mu.Lock()
	waiter, exists := reactor.udpReads[operation]
	if !exists || reactor.operations[operation] != operationUDPRead {
		reactor.mu.Unlock()
		return Datagram{}, ErrInvalid
	}
	state, exists := reactor.datagrams[waiter.handle]
	if !exists {
		delete(reactor.udpReads, operation)
		reactor.releaseOperationLocked(operation, operationUDPRead)
		reactor.mu.Unlock()
		return Datagram{}, ErrInvalid
	}
	if len(state.received) == 0 {
		if state.receiveErr == nil {
			reactor.mu.Unlock()
			return Datagram{}, ErrPending
		}
		err := state.receiveErr
		state.receiveErr = nil
		delete(reactor.udpReads, operation)
		reactor.releaseOperationLocked(operation, operationUDPRead)
		startWorker := len(state.received) < udpReceiveQueueCapacity &&
			!state.receiveRunning &&
			reactor.hasUDPReadWaiterLocked(waiter.handle)
		if startWorker {
			state.receiveRunning = true
			reactor.workers.Add(1)
		}
		reactor.mu.Unlock()
		if startWorker {
			go reactor.runUDPReceive(waiter.handle, state)
		}
		return Datagram{}, err
	}

	datagram := state.received[0]
	state.received[0] = Datagram{}
	state.received = state.received[1:]
	delete(reactor.udpReads, operation)
	reactor.releaseOperationLocked(operation, operationUDPRead)
	startWorker := len(state.received) < udpReceiveQueueCapacity &&
		!state.receiveRunning &&
		reactor.hasUDPReadWaiterLocked(waiter.handle)
	if startWorker {
		state.receiveRunning = true
		reactor.workers.Add(1)
	}
	reactor.mu.Unlock()

	if startWorker {
		go reactor.runUDPReceive(waiter.handle, state)
	}
	if uint32(len(datagram.Data)) > capacity {
		datagram.Data = datagram.Data[:capacity]
	}
	return datagram, nil
}

func (reactor *Reactor) TryUDPSend(handle uint64, data []byte, peer *net.UDPAddr) error {
	if peer == nil || len(data) > 65535 {
		return ErrInvalid
	}
	reactor.mu.Lock()
	defer reactor.mu.Unlock()
	state, exists := reactor.datagrams[handle]
	if !exists {
		return ErrInvalid
	}
	if state.sendErr != nil {
		return state.sendErr
	}
	if len(state.sendQueue) >= cap(state.sendQueue) {
		return ErrWouldBlock
	}
	state.sendQueue <- udpSend{
		data: append([]byte(nil), data...),
		peer: cloneUDPAddr(peer),
	}
	return nil
}

func (reactor *Reactor) StartUDPSendReady(handle, operation uint64) error {
	reactor.mu.Lock()
	state, exists := reactor.datagrams[handle]
	if !exists {
		reactor.mu.Unlock()
		return ErrInvalid
	}
	if err := reactor.claimOperationLocked(operation, operationUDPWrite); err != nil {
		reactor.mu.Unlock()
		return err
	}
	waiter := &udpWriteWaiter{
		handle: handle,
		ready:  len(state.sendQueue) < cap(state.sendQueue) || state.sendErr != nil,
	}
	reactor.udpWrites[operation] = waiter
	ready := waiter.ready
	reactor.mu.Unlock()
	if ready {
		reactor.signalCompletion()
	}
	return nil
}

func (reactor *Reactor) TakeUDPSendReady(operation uint64) error {
	reactor.mu.Lock()
	waiter, exists := reactor.udpWrites[operation]
	if !exists || reactor.operations[operation] != operationUDPWrite {
		reactor.mu.Unlock()
		return ErrInvalid
	}
	if !waiter.ready {
		reactor.mu.Unlock()
		return ErrPending
	}
	delete(reactor.udpWrites, operation)
	reactor.releaseOperationLocked(operation, operationUDPWrite)
	state, exists := reactor.datagrams[waiter.handle]
	if !exists {
		reactor.mu.Unlock()
		return ErrInvalid
	}
	err := state.sendErr
	reactor.mu.Unlock()
	return err
}

func (reactor *Reactor) hasUDPReadWaiterLocked(handle uint64) bool {
	for _, waiter := range reactor.udpReads {
		if waiter.handle == handle {
			return true
		}
	}
	return false
}

func cloneUDPAddr(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   append(net.IP(nil), address.IP...),
		Port: address.Port,
		Zone: address.Zone,
	}
}
