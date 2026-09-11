package reactor

import (
	"context"
	"fmt"
	"net"
)

type packetSink struct {
	capacity  int
	packets   [][]byte
	available chan struct{}
	closed    chan struct{}
}

type packetWriteWaiter struct {
	handle uint64
	ready  bool
}

func (reactor *Reactor) RegisterPacketSink(capacity int) (uint64, error) {
	if capacity <= 0 {
		return 0, fmt.Errorf("packet sink capacity must be positive")
	}
	reactor.mu.Lock()
	defer reactor.mu.Unlock()
	if reactor.closed {
		return 0, ErrInvalid
	}
	handle := reactor.allocateHandleLocked()
	reactor.packetSinks[handle] = &packetSink{
		capacity:  capacity,
		available: make(chan struct{}, 1),
		closed:    make(chan struct{}),
	}
	return handle, nil
}

func (reactor *Reactor) UnregisterPacketSink(handle uint64) {
	reactor.mu.Lock()
	sink := reactor.packetSinks[handle]
	if sink == nil {
		reactor.mu.Unlock()
		return
	}
	delete(reactor.packetSinks, handle)
	for operation, waiter := range reactor.packetWrites {
		if waiter.handle != handle {
			continue
		}
		delete(reactor.packetWrites, operation)
		reactor.releaseOperationLocked(operation, operationPacketWrite)
	}
	close(sink.closed)
	reactor.mu.Unlock()
}

func (reactor *Reactor) TryPacketWrite(handle uint64, packet []byte) error {
	reactor.mu.Lock()
	sink, exists := reactor.packetSinks[handle]
	if !exists {
		reactor.mu.Unlock()
		return ErrInvalid
	}
	if len(sink.packets) >= sink.capacity {
		reactor.mu.Unlock()
		return ErrWouldBlock
	}
	sink.packets = append(sink.packets, append([]byte(nil), packet...))
	available := sink.available
	reactor.mu.Unlock()
	select {
	case available <- struct{}{}:
	default:
	}
	return nil
}

func (reactor *Reactor) StartPacketWriteReady(handle, operation uint64) error {
	reactor.mu.Lock()
	sink, exists := reactor.packetSinks[handle]
	if !exists {
		reactor.mu.Unlock()
		return ErrInvalid
	}
	if err := reactor.claimOperationLocked(operation, operationPacketWrite); err != nil {
		reactor.mu.Unlock()
		return err
	}
	waiter := &packetWriteWaiter{
		handle: handle,
		ready:  len(sink.packets) < sink.capacity,
	}
	reactor.packetWrites[operation] = waiter
	ready := waiter.ready
	reactor.mu.Unlock()
	if ready {
		reactor.signalCompletion()
	}
	return nil
}

func (reactor *Reactor) TakePacketWriteReady(operation uint64) error {
	reactor.mu.Lock()
	waiter, exists := reactor.packetWrites[operation]
	if !exists || reactor.operations[operation] != operationPacketWrite {
		reactor.mu.Unlock()
		return ErrInvalid
	}
	if !waiter.ready {
		reactor.mu.Unlock()
		return ErrPending
	}
	delete(reactor.packetWrites, operation)
	reactor.releaseOperationLocked(operation, operationPacketWrite)
	reactor.mu.Unlock()
	return nil
}

func (reactor *Reactor) ReceivePacket(ctx context.Context, handle uint64) ([]byte, error) {
	for {
		reactor.mu.Lock()
		sink, exists := reactor.packetSinks[handle]
		if !exists {
			reactor.mu.Unlock()
			return nil, fmt.Errorf("receive packet: %w", net.ErrClosed)
		}
		if len(sink.packets) > 0 {
			packet := sink.packets[0]
			sink.packets[0] = nil
			sink.packets = sink.packets[1:]
			ready := false
			for _, waiter := range reactor.packetWrites {
				if waiter.handle == handle {
					waiter.ready = true
					ready = true
				}
			}
			reactor.mu.Unlock()
			if ready {
				reactor.signalCompletion()
			}
			return packet, nil
		}
		available := sink.available
		lifetimeDone := reactor.ctx.Done()
		reactor.mu.Unlock()

		select {
		case <-available:
		case <-sink.closed:
			return nil, fmt.Errorf("receive packet: %w", net.ErrClosed)
		case <-lifetimeDone:
			return nil, fmt.Errorf("receive packet: %w", reactor.ctx.Err())
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
