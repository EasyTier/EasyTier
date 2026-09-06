package reactor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/EasyTier/EasyTier/easytier-go/internal/contextutil"
	"github.com/EasyTier/EasyTier/easytier-go/platform"
)

var (
	ErrInvalid    = errors.New("invalid host operation")
	ErrPending    = errors.New("host operation is pending")
	ErrWouldBlock = errors.New("host operation would block")
)

type operationKind uint8

const (
	operationRead operationKind = iota + 1
	operationWrite
	operationUDPRead
	operationUDPWrite
	operationCreate
	operationAccept
	operationDNS
	operationEnvironment
	operationPacketWrite
	operationManagement
)

type Options struct {
	Services         platform.Services
	InitialStreams   map[uint64]net.Conn
	InitialDatagrams map[uint64]net.PacketConn
	Management       ManagementHandler
}

type Reactor struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu         sync.Mutex
	closed     bool
	closeDone  chan struct{}
	completion chan struct{}
	workers    sync.WaitGroup
	nextHandle uint64

	services          platform.Services
	managementHandler ManagementHandler

	operations        map[uint64]operationKind
	streams           map[uint64]*streamState
	datagrams         map[uint64]*datagramState
	drainingDatagrams map[*datagramState]struct{}
	listeners         map[uint64]*listenerState
	reads             map[uint64]*readOperation
	writes            map[uint64]*writeOperation
	udpReads          map[uint64]*udpReadWaiter
	udpWrites         map[uint64]*udpWriteWaiter
	accepts           map[uint64]*acceptWaiter
	creates           map[uint64]*createOperation
	dns               map[uint64]*dnsOperation
	environments      map[uint64]*environmentOperation
	eventSinks        map[uint64]eventSink
	packetSinks       map[uint64]*packetSink
	packetWrites      map[uint64]*packetWriteWaiter
	management        map[uint64]*managementOperation
}

func New(parent context.Context, options Options) *Reactor {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(contextutil.WithoutCancel(parent))
	reactor := &Reactor{
		ctx:               ctx,
		cancel:            cancel,
		closeDone:         make(chan struct{}),
		completion:        make(chan struct{}, 1),
		nextHandle:        1 << 48,
		services:          options.Services,
		managementHandler: options.Management,
		operations:        make(map[uint64]operationKind),
		streams:           make(map[uint64]*streamState, len(options.InitialStreams)),
		datagrams:         make(map[uint64]*datagramState, len(options.InitialDatagrams)),
		drainingDatagrams: make(map[*datagramState]struct{}),
		listeners:         make(map[uint64]*listenerState),
		reads:             make(map[uint64]*readOperation),
		writes:            make(map[uint64]*writeOperation),
		udpReads:          make(map[uint64]*udpReadWaiter),
		udpWrites:         make(map[uint64]*udpWriteWaiter),
		accepts:           make(map[uint64]*acceptWaiter),
		creates:           make(map[uint64]*createOperation),
		dns:               make(map[uint64]*dnsOperation),
		environments:      make(map[uint64]*environmentOperation),
		eventSinks:        make(map[uint64]eventSink),
		packetSinks:       make(map[uint64]*packetSink),
		packetWrites:      make(map[uint64]*packetWriteWaiter),
		management:        make(map[uint64]*managementOperation),
	}
	for handle, connection := range options.InitialStreams {
		reactor.streams[handle] = newStreamState(connection)
	}
	for handle, connection := range options.InitialDatagrams {
		state := newDatagramState(connection)
		reactor.datagrams[handle] = state
		reactor.workers.Add(1)
		go reactor.runUDPSends(handle, state)
	}
	return reactor
}

func (reactor *Reactor) Completions() <-chan struct{} {
	return reactor.completion
}

func (reactor *Reactor) signalCompletion() {
	select {
	case reactor.completion <- struct{}{}:
	default:
	}
}

func (reactor *Reactor) claimOperationLocked(id uint64, kind operationKind) error {
	if reactor.closed {
		return ErrInvalid
	}
	if _, exists := reactor.operations[id]; exists {
		return ErrInvalid
	}
	reactor.operations[id] = kind
	return nil
}

func (reactor *Reactor) releaseOperationLocked(id uint64, kind operationKind) bool {
	if reactor.operations[id] != kind {
		return false
	}
	delete(reactor.operations, id)
	return true
}

func (reactor *Reactor) allocateHandleLocked() uint64 {
	reactor.nextHandle++
	return reactor.nextHandle
}

func (reactor *Reactor) CancelOperation(id uint64) error {
	reactor.mu.Lock()
	kind, exists := reactor.operations[id]
	if !exists {
		reactor.mu.Unlock()
		return nil
	}
	delete(reactor.operations, id)

	var cancel context.CancelFunc
	var resource ioResource
	var readTask streamReadTask
	var signalCompletion bool
	switch kind {
	case operationRead:
		readTask, signalCompletion = reactor.cancelStreamReadLocked(id)
	case operationWrite:
		reactor.cancelStreamWriteLocked(id)
	case operationUDPRead:
		delete(reactor.udpReads, id)
	case operationUDPWrite:
		delete(reactor.udpWrites, id)
	case operationAccept:
		delete(reactor.accepts, id)
	case operationCreate:
		create := reactor.creates[id]
		delete(reactor.creates, id)
		if create != nil {
			cancel = create.cancel
			resource = create.resource()
		}
	case operationDNS:
		operation := reactor.dns[id]
		delete(reactor.dns, id)
		if operation != nil {
			cancel = operation.cancel
		}
	case operationEnvironment:
		operation := reactor.environments[id]
		delete(reactor.environments, id)
		if operation != nil {
			cancel = operation.cancel
		}
	case operationPacketWrite:
		delete(reactor.packetWrites, id)
	case operationManagement:
		operation := reactor.management[id]
		delete(reactor.management, id)
		if operation != nil {
			cancel = operation.cancel
		}
	default:
		reactor.mu.Unlock()
		return fmt.Errorf("%w: unknown operation kind %d", ErrInvalid, kind)
	}
	reactor.mu.Unlock()
	readTask.launch(reactor)
	if signalCompletion {
		reactor.signalCompletion()
	}
	if cancel != nil {
		cancel()
	}
	if resource != nil {
		_ = resource.Close()
	}
	return nil
}

type ioResource interface {
	Close() error
}

func (reactor *Reactor) CloseHandle(handle uint64) error {
	reactor.mu.Lock()
	stream := reactor.streams[handle]
	delete(reactor.streams, handle)
	streamCompletion := false
	if stream != nil {
		streamCompletion = reactor.closeStreamLocked(stream)
	}
	datagram := reactor.datagrams[handle]
	delete(reactor.datagrams, handle)
	if datagram != nil {
		reactor.drainingDatagrams[datagram] = struct{}{}
	}
	listener := reactor.listeners[handle]
	delete(reactor.listeners, handle)
	reactor.mu.Unlock()
	if streamCompletion {
		reactor.signalCompletion()
	}

	if stream == nil && datagram == nil && listener == nil {
		return nil
	}
	var closeErrors []error
	if stream != nil {
		if err := stream.connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErrors = append(closeErrors, err)
		}
	}
	if datagram != nil {
		datagram.closeAfterQueuedSends()
	}
	if listener != nil {
		if err := listener.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErrors = append(closeErrors, err)
		}
		for _, connection := range listener.accepted {
			_ = connection.Close()
		}
	}
	return errors.Join(closeErrors...)
}

func (reactor *Reactor) Close() {
	reactor.mu.Lock()
	if reactor.closed {
		done := reactor.closeDone
		reactor.mu.Unlock()
		<-done
		return
	}
	reactor.closed = true
	reactor.cancel()

	streams := reactor.streams
	datagrams := reactor.datagrams
	drainingDatagrams := reactor.drainingDatagrams
	listeners := reactor.listeners
	creates := reactor.creates
	dnsOperations := reactor.dns
	environmentOperations := reactor.environments
	managementOperations := reactor.management
	for _, stream := range streams {
		stream.shutdownLocked()
	}

	reactor.operations = make(map[uint64]operationKind)
	reactor.streams = make(map[uint64]*streamState)
	reactor.datagrams = make(map[uint64]*datagramState)
	reactor.drainingDatagrams = make(map[*datagramState]struct{})
	reactor.listeners = make(map[uint64]*listenerState)
	reactor.reads = make(map[uint64]*readOperation)
	reactor.writes = make(map[uint64]*writeOperation)
	reactor.udpReads = make(map[uint64]*udpReadWaiter)
	reactor.udpWrites = make(map[uint64]*udpWriteWaiter)
	reactor.accepts = make(map[uint64]*acceptWaiter)
	reactor.creates = make(map[uint64]*createOperation)
	reactor.dns = make(map[uint64]*dnsOperation)
	reactor.environments = make(map[uint64]*environmentOperation)
	reactor.eventSinks = make(map[uint64]eventSink)
	reactor.packetSinks = make(map[uint64]*packetSink)
	reactor.packetWrites = make(map[uint64]*packetWriteWaiter)
	reactor.management = make(map[uint64]*managementOperation)
	reactor.mu.Unlock()

	for _, stream := range streams {
		_ = stream.connection.Close()
	}
	for _, datagram := range datagrams {
		datagram.closeNow()
	}
	for datagram := range drainingDatagrams {
		datagram.closeNow()
	}
	for _, listener := range listeners {
		_ = listener.listener.Close()
		for _, connection := range listener.accepted {
			_ = connection.Close()
		}
	}
	for _, create := range creates {
		create.cancel()
		if resource := create.resource(); resource != nil {
			_ = resource.Close()
		}
	}
	for _, operation := range dnsOperations {
		operation.cancel()
	}
	for _, operation := range environmentOperations {
		operation.cancel()
	}
	for _, operation := range managementOperations {
		operation.cancel()
	}
	reactor.workers.Wait()
	close(reactor.closeDone)
}
