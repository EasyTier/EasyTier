package reactor

import (
	"context"
	"fmt"
	"net"

	"github.com/EasyTier/EasyTier/easytier-go/platform"
)

type createOperation struct {
	kind       createKind
	done       bool
	cancel     context.CancelFunc
	connection net.Conn
	datagram   net.PacketConn
	listener   net.Listener
	localAddr  net.Addr
	peerAddr   net.Addr
	err        error
}

type createKind uint8

const (
	createTCPConnect createKind = iota + 1
	createUDPBind
	createTCPListen
)

func (operation *createOperation) resource() ioResource {
	switch {
	case operation.connection != nil:
		return operation.connection
	case operation.datagram != nil:
		return operation.datagram
	case operation.listener != nil:
		return operation.listener
	default:
		return nil
	}
}

type StreamResult struct {
	Handle uint64
	Local  net.Addr
	Peer   net.Addr
}

type BoundResult struct {
	Handle uint64
	Local  net.Addr
}

func (reactor *Reactor) beginCreate(
	operation uint64,
	kind createKind,
) (*createOperation, context.Context, error) {
	ctx, cancel := context.WithCancel(reactor.ctx)
	create := &createOperation{kind: kind, cancel: cancel}
	reactor.mu.Lock()
	if err := reactor.claimOperationLocked(operation, operationCreate); err != nil {
		reactor.mu.Unlock()
		cancel()
		return nil, nil, err
	}
	reactor.creates[operation] = create
	reactor.workers.Add(1)
	reactor.mu.Unlock()
	return create, ctx, nil
}

func (reactor *Reactor) StartTCPConnect(
	operation uint64,
	options platform.TCPConnectOptions,
) error {
	if reactor.services.Sockets == nil {
		return fmt.Errorf("TCP connect: no socket factory configured")
	}
	create, ctx, err := reactor.beginCreate(operation, createTCPConnect)
	if err != nil {
		return err
	}
	go func() {
		defer reactor.workers.Done()
		connection, connectErr := reactor.services.Sockets.ConnectTCP(ctx, options)

		reactor.mu.Lock()
		if reactor.creates[operation] != create {
			reactor.mu.Unlock()
			if connection != nil {
				_ = connection.Close()
			}
			return
		}
		create.connection = connection
		create.err = connectErr
		create.done = true
		if connection != nil {
			create.localAddr = connection.LocalAddr()
			create.peerAddr = connection.RemoteAddr()
		}
		reactor.mu.Unlock()
		reactor.signalCompletion()
	}()
	return nil
}

func (reactor *Reactor) TakeTCPConnect(operation uint64) (StreamResult, error) {
	reactor.mu.Lock()
	create, exists := reactor.creates[operation]
	if !exists ||
		create.kind != createTCPConnect ||
		reactor.operations[operation] != operationCreate {
		reactor.mu.Unlock()
		return StreamResult{}, ErrInvalid
	}
	if !create.done {
		reactor.mu.Unlock()
		return StreamResult{}, ErrPending
	}
	delete(reactor.creates, operation)
	reactor.releaseOperationLocked(operation, operationCreate)
	create.cancel()
	if create.err != nil || create.connection == nil {
		connection := create.connection
		err := create.err
		reactor.mu.Unlock()
		if connection != nil {
			_ = connection.Close()
		}
		if err == nil {
			err = fmt.Errorf("socket factory returned no TCP connection")
		}
		return StreamResult{}, err
	}
	handle := reactor.allocateHandleLocked()
	reactor.streams[handle] = newStreamState(create.connection)
	result := StreamResult{Handle: handle, Local: create.localAddr, Peer: create.peerAddr}
	create.connection = nil
	reactor.mu.Unlock()
	return result, nil
}

func (reactor *Reactor) StartUDPBind(
	operation uint64,
	options platform.UDPBindOptions,
) error {
	if reactor.services.Sockets == nil {
		return fmt.Errorf("UDP bind: no socket factory configured")
	}
	create, ctx, err := reactor.beginCreate(operation, createUDPBind)
	if err != nil {
		return err
	}
	go func() {
		defer reactor.workers.Done()
		connection, bindErr := reactor.services.Sockets.BindUDP(ctx, options)

		reactor.mu.Lock()
		if reactor.creates[operation] != create {
			reactor.mu.Unlock()
			if connection != nil {
				_ = connection.Close()
			}
			return
		}
		create.datagram = connection
		create.err = bindErr
		create.done = true
		if connection != nil {
			create.localAddr = connection.LocalAddr()
		}
		reactor.mu.Unlock()
		reactor.signalCompletion()
	}()
	return nil
}

func (reactor *Reactor) TakeUDPBind(operation uint64) (BoundResult, error) {
	reactor.mu.Lock()
	create, exists := reactor.creates[operation]
	if !exists ||
		create.kind != createUDPBind ||
		reactor.operations[operation] != operationCreate {
		reactor.mu.Unlock()
		return BoundResult{}, ErrInvalid
	}
	if !create.done {
		reactor.mu.Unlock()
		return BoundResult{}, ErrPending
	}
	delete(reactor.creates, operation)
	reactor.releaseOperationLocked(operation, operationCreate)
	create.cancel()
	if create.err != nil || create.datagram == nil {
		connection := create.datagram
		err := create.err
		reactor.mu.Unlock()
		if connection != nil {
			_ = connection.Close()
		}
		if err == nil {
			err = fmt.Errorf("socket factory returned no UDP socket")
		}
		return BoundResult{}, err
	}
	handle := reactor.allocateHandleLocked()
	state := newDatagramState(create.datagram)
	reactor.datagrams[handle] = state
	result := BoundResult{Handle: handle, Local: create.localAddr}
	create.datagram = nil
	reactor.workers.Add(1)
	reactor.mu.Unlock()
	go reactor.runUDPSends(handle, state)
	return result, nil
}

func (reactor *Reactor) StartTCPListen(
	operation uint64,
	options platform.TCPListenOptions,
) error {
	if reactor.services.Sockets == nil {
		return fmt.Errorf("TCP listen: no socket factory configured")
	}
	create, ctx, err := reactor.beginCreate(operation, createTCPListen)
	if err != nil {
		return err
	}
	go func() {
		defer reactor.workers.Done()
		listener, listenErr := reactor.services.Sockets.ListenTCP(ctx, options)

		reactor.mu.Lock()
		if reactor.creates[operation] != create {
			reactor.mu.Unlock()
			if listener != nil {
				_ = listener.Close()
			}
			return
		}
		create.listener = listener
		create.err = listenErr
		create.done = true
		if listener != nil {
			create.localAddr = listener.Addr()
		}
		reactor.mu.Unlock()
		reactor.signalCompletion()
	}()
	return nil
}

func (reactor *Reactor) TakeTCPListen(operation uint64) (BoundResult, error) {
	reactor.mu.Lock()
	create, exists := reactor.creates[operation]
	if !exists ||
		create.kind != createTCPListen ||
		reactor.operations[operation] != operationCreate {
		reactor.mu.Unlock()
		return BoundResult{}, ErrInvalid
	}
	if !create.done {
		reactor.mu.Unlock()
		return BoundResult{}, ErrPending
	}
	delete(reactor.creates, operation)
	reactor.releaseOperationLocked(operation, operationCreate)
	create.cancel()
	if create.err != nil || create.listener == nil {
		listener := create.listener
		err := create.err
		reactor.mu.Unlock()
		if listener != nil {
			_ = listener.Close()
		}
		if err == nil {
			err = fmt.Errorf("socket factory returned no TCP listener")
		}
		return BoundResult{}, err
	}
	handle := reactor.allocateHandleLocked()
	reactor.listeners[handle] = &listenerState{listener: create.listener}
	result := BoundResult{Handle: handle, Local: create.localAddr}
	create.listener = nil
	reactor.mu.Unlock()
	return result, nil
}
