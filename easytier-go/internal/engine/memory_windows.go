//go:build windows

package engine

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// mappedMemory reserves the whole linear memory and commits pages as the
// guest grows into them. Newly committed pages are zero-filled, as
// memory.grow requires.
type mappedMemory struct {
	reserved  []byte
	committed uint64
}

func reserveGuestMemory(max uint64) *mappedMemory {
	if max == 0 || max > uint64(^uintptr(0)>>1) {
		return nil
	}
	address, err := windows.VirtualAlloc(0, uintptr(max), windows.MEM_RESERVE, windows.PAGE_NOACCESS)
	if err != nil {
		return nil
	}
	// The reservation is outside the Go heap.
	base := *(*unsafe.Pointer)(unsafe.Pointer(&address))
	return &mappedMemory{reserved: unsafe.Slice((*byte)(base), max)}
}

func (memory *mappedMemory) Reallocate(size uint64) []byte {
	if size > uint64(len(memory.reserved)) {
		return nil
	}
	if size > memory.committed {
		address := uintptr(unsafe.Pointer(unsafe.SliceData(memory.reserved))) + uintptr(memory.committed)
		if _, err := windows.VirtualAlloc(address, uintptr(size-memory.committed), windows.MEM_COMMIT, windows.PAGE_READWRITE); err != nil {
			return nil
		}
		memory.committed = size
	}
	return memory.reserved[:size:size]
}

func (memory *mappedMemory) Free() {
	if memory.reserved != nil {
		_ = windows.VirtualFree(uintptr(unsafe.Pointer(unsafe.SliceData(memory.reserved))), 0, windows.MEM_RELEASE)
		memory.reserved = nil
		memory.committed = 0
	}
}
