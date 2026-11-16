//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package engine

import (
	"golang.org/x/sys/unix"
)

// mappedMemory reserves the whole linear memory as an inaccessible mapping
// and makes pages readable and writable as the guest grows into them. Fresh
// anonymous pages are zero-filled, as memory.grow requires.
type mappedMemory struct {
	reserved  []byte
	committed uint64
}

func reserveGuestMemory(max uint64) *mappedMemory {
	if max == 0 || max > uint64(^uint(0)>>1) {
		return nil
	}
	reserved, err := unix.Mmap(-1, 0, int(max), unix.PROT_NONE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		return nil
	}
	return &mappedMemory{reserved: reserved}
}

func (memory *mappedMemory) Reallocate(size uint64) []byte {
	if size > uint64(len(memory.reserved)) {
		return nil
	}
	if size > memory.committed {
		if err := unix.Mprotect(memory.reserved[memory.committed:size], unix.PROT_READ|unix.PROT_WRITE); err != nil {
			return nil
		}
		memory.committed = size
	}
	return memory.reserved[:size:size]
}

func (memory *mappedMemory) Free() {
	if memory.reserved != nil {
		_ = unix.Munmap(memory.reserved)
		memory.reserved = nil
		memory.committed = 0
	}
}
