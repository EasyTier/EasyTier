package engine

import (
	"testing"
	"unsafe"
)

func TestGuestMemoryGrowsInPlaceWithZeroedPages(t *testing.T) {
	const page = 64 << 10
	memory := newGuestMemory(page, 1024*page)
	defer memory.Free()

	buffer := memory.Reallocate(2 * page)
	if len(buffer) != 2*page {
		t.Fatalf("length = %d, want %d", len(buffer), 2*page)
	}
	buffer[0], buffer[len(buffer)-1] = 1, 2

	grown := memory.Reallocate(8 * page)
	if len(grown) != 8*page {
		t.Fatalf("grown length = %d, want %d", len(grown), 8*page)
	}
	if grown[0] != 1 || grown[2*page-1] != 2 {
		t.Fatal("growth lost existing contents")
	}
	for i, b := range grown[2*page:] {
		if b != 0 {
			t.Fatalf("new byte %d = %d, want 0", 2*page+i, b)
		}
	}
	if _, onHeap := memory.(*heapMemory); !onHeap && unsafe.SliceData(grown) != unsafe.SliceData(buffer) {
		t.Fatal("mapped memory moved while growing")
	}
	if memory.Reallocate(1025*page) != nil {
		t.Fatal("growth past the maximum succeeded")
	}
}
