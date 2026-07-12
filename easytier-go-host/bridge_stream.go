package host

import (
	"context"
	"errors"
	"io"

	"github.com/tetratelabs/wazero/api"
)

const (
	opaqueHostPending = -1
	opaqueHostInvalid = -2
	opaqueHostIOError = -3
	opaqueHostMemory  = -4
)

func (b *opaqueBridge) startRead(
	_ context.Context,
	_ api.Module,
	handle uint64,
	operation uint64,
	capacity uint32,
) int32 {
	b.mu.Lock()
	connection, exists := b.handles[handle]
	if !exists || capacity == 0 {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	if _, duplicate := b.reads[operation]; duplicate {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	result := &opaqueReadOperation{handle: handle}
	b.reads[operation] = result
	b.workers.Add(1)
	b.mu.Unlock()

	go func() {
		defer b.workers.Done()

		buffer := make([]byte, capacity)
		n, err := connection.Read(buffer)

		b.mu.Lock()
		result.data = buffer[:n]
		result.err = err
		result.done = true
		b.mu.Unlock()
		b.signalCompletion()
	}()

	return 0
}

func (b *opaqueBridge) takeRead(
	_ context.Context,
	module api.Module,
	operation uint64,
	destination uint32,
	capacity uint32,
) int32 {
	b.mu.Lock()
	result, exists := b.reads[operation]
	if !exists {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	if !result.done {
		b.mu.Unlock()
		return opaqueHostPending
	}
	delete(b.reads, operation)
	data, err := result.data, result.err
	b.mu.Unlock()

	if uint32(len(data)) > capacity {
		return opaqueHostMemory
	}
	if len(data) > 0 {
		if !module.Memory().Write(destination, data) {
			return opaqueHostMemory
		}
		return int32(len(data))
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return opaqueHostIOError
	}
	return 0
}

func (b *opaqueBridge) startWrite(
	_ context.Context,
	module api.Module,
	handle uint64,
	operation uint64,
	source uint32,
	length uint32,
) int32 {
	buffer, ok := module.Memory().Read(source, length)
	if !ok {
		return opaqueHostMemory
	}
	buffer = append([]byte(nil), buffer...)

	b.mu.Lock()
	connection, exists := b.handles[handle]
	if !exists {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	if _, duplicate := b.writes[operation]; duplicate {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	result := &opaqueWriteOperation{}
	b.writes[operation] = result
	b.workers.Add(1)
	b.mu.Unlock()

	go func() {
		defer b.workers.Done()

		written := 0
		var err error
		for written < len(buffer) {
			var n int
			n, err = connection.Write(buffer[written:])
			written += n
			if err != nil {
				break
			}
			if n == 0 {
				err = io.ErrShortWrite
				break
			}
		}

		b.mu.Lock()
		result.err = err
		result.done = true
		b.mu.Unlock()
		b.signalCompletion()
	}()

	return 0
}

func (b *opaqueBridge) takeWrite(
	_ context.Context,
	_ api.Module,
	operation uint64,
) int32 {
	b.mu.Lock()
	result, exists := b.writes[operation]
	if !exists {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	if !result.done {
		b.mu.Unlock()
		return opaqueHostPending
	}
	delete(b.writes, operation)
	err := result.err
	b.mu.Unlock()

	if err != nil {
		return opaqueHostIOError
	}
	return 0
}

func (b *opaqueBridge) signalCompletion() {
	select {
	case b.completion <- struct{}{}:
	default:
	}
}
