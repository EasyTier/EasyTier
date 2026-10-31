package engine

import (
	"context"

	"github.com/metacubex/wazero/experimental"
)

// is64Bit reports whether the address space is large enough to reserve a
// full 4 GiB wasm32 linear memory up front.
const is64Bit = ^uintptr(0)>>63 == 1

// withGuestMemoryAllocator places the core's linear memory outside the Go
// heap on 64-bit platforms.
//
// wazero's default linear memory is a Go []byte that grows with append, so
// each memory.grow copies the whole guest heap into a fresh slice and leaves
// the old one for the GC. The guest heap is also the largest live object in
// the process, so GOGC lets the Go heap grow to about twice its size. A
// reserved mapping grows in place, stays outside GC accounting, and costs
// RSS only for the pages the guest has touched.
func withGuestMemoryAllocator(ctx context.Context) context.Context {
	if !is64Bit {
		return ctx
	}
	return experimental.WithMemoryAllocator(ctx, experimental.MemoryAllocatorFunc(newGuestMemory))
}

func newGuestMemory(capacity, max uint64) experimental.LinearMemory {
	if memory := reserveGuestMemory(max); memory != nil {
		return memory
	}
	return &heapMemory{buffer: make([]byte, 0, capacity), max: max}
}

// heapMemory grows the same way as wazero's built-in allocator. It backs the
// guest when the address space reservation fails.
type heapMemory struct {
	buffer []byte
	max    uint64
}

func (memory *heapMemory) Reallocate(size uint64) []byte {
	if size > memory.max {
		return nil
	}
	if size <= uint64(cap(memory.buffer)) {
		memory.buffer = memory.buffer[:size]
	} else {
		memory.buffer = append(memory.buffer[:cap(memory.buffer)], make([]byte, size-uint64(cap(memory.buffer)))...)
	}
	return memory.buffer
}

func (memory *heapMemory) Free() {
	memory.buffer = nil
}
