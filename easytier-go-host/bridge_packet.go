package host

// Packet sinks carry core egress into bounded host-owned queues.

import (
	"context"
	"fmt"

	"github.com/tetratelabs/wazero/api"
)

const maxHostPacketLen = 1024 * 1024

func (b *opaqueBridge) registerPacketSink(capacity int) (uint64, error) {
	if capacity <= 0 {
		return 0, fmt.Errorf("packet sink capacity must be positive")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, fmt.Errorf("bridge is closed")
	}
	handle := b.allocateHandleLocked()
	b.packetSinks[handle] = &opaquePacketSinkState{capacity: capacity}
	return handle, nil
}

// RegisterPacketSink allocates a bounded queue for core packet egress.
func (b *Bridge) RegisterPacketSink(capacity int) (uint64, error) {
	return b.registerPacketSink(capacity)
}

func (b *opaqueBridge) tryPacketWrite(
	_ context.Context,
	module api.Module,
	handle uint64,
	packetPointer uint32,
	packetLength uint32,
) int32 {
	if packetLength == 0 || packetLength > maxHostPacketLen {
		return opaqueHostInvalid
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	sink, exists := b.packetSinks[handle]
	if !exists {
		return opaqueHostInvalid
	}
	if len(sink.packets) >= sink.capacity {
		return opaqueHostWouldBlock
	}
	packet, ok := module.Memory().Read(packetPointer, packetLength)
	if !ok {
		return opaqueHostMemory
	}
	sink.packets = append(sink.packets, append([]byte(nil), packet...))
	return 0
}

func (b *opaqueBridge) startPacketWriteReady(
	_ context.Context,
	_ api.Module,
	handle uint64,
	operation uint64,
) int32 {
	b.mu.Lock()
	sink, exists := b.packetSinks[handle]
	if !exists {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	if _, duplicate := b.packetWrites[operation]; duplicate {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	waiter := &opaquePacketWriteWaiter{
		handle: handle,
		ready:  len(sink.packets) < sink.capacity,
	}
	ready := waiter.ready
	b.packetWrites[operation] = waiter
	b.mu.Unlock()
	if ready {
		b.signalCompletion()
	}
	return 0
}

func (b *opaqueBridge) takePacketWriteReady(
	_ context.Context,
	_ api.Module,
	operation uint64,
) int32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	waiter, exists := b.packetWrites[operation]
	if !exists {
		return opaqueHostInvalid
	}
	if !waiter.ready {
		return opaqueHostPending
	}
	delete(b.packetWrites, operation)
	return 0
}

func (b *opaqueBridge) consumePacket(handle uint64) ([]byte, error) {
	b.mu.Lock()
	sink, exists := b.packetSinks[handle]
	if !exists {
		b.mu.Unlock()
		return nil, fmt.Errorf("packet sink handle %d not found", handle)
	}
	if len(sink.packets) == 0 {
		b.mu.Unlock()
		return nil, fmt.Errorf("packet sink %d is empty", handle)
	}
	packet := sink.packets[0]
	sink.packets[0] = nil
	sink.packets = sink.packets[1:]
	for _, waiter := range b.packetWrites {
		if waiter.handle == handle {
			waiter.ready = true
		}
	}
	b.mu.Unlock()
	b.signalCompletion()
	return packet, nil
}

// ConsumePacket removes one core egress packet and wakes blocked writers.
func (b *Bridge) ConsumePacket(handle uint64) ([]byte, error) {
	return b.consumePacket(handle)
}
