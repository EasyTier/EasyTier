package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

const (
	opaqueTimerProgress        = 1 << 0
	opaqueSecondSocketProgress = 1 << 1
	opaquePendingReadCompleted = 1 << 2
	opaquePendingReadIsolated  = 1 << 3
	opaqueDone                 = 1 << 4
	opaqueError                = 1 << 31

	opaqueHostPending = -1
	opaqueHostInvalid = -2
	opaqueHostIOError = -3
	opaqueHostMemory  = -4
)

type opaqueReadOperation struct {
	done bool
	data []byte
	err  error
}

type opaqueWriteOperation struct {
	done bool
	n    int
	err  error
}

type opaqueBridge struct {
	mu         sync.Mutex
	handles    map[uint32]net.Conn
	reads      map[uint32]*opaqueReadOperation
	writes     map[uint32]*opaqueWriteOperation
	completion chan struct{}
	workers    sync.WaitGroup
}

func newOpaqueBridge(handles map[uint32]net.Conn) *opaqueBridge {
	return &opaqueBridge{
		handles:    handles,
		reads:      make(map[uint32]*opaqueReadOperation),
		writes:     make(map[uint32]*opaqueWriteOperation),
		completion: make(chan struct{}, 1),
	}
}

func (b *opaqueBridge) startRead(
	_ context.Context,
	_ api.Module,
	handle uint32,
	operation uint32,
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
	result := &opaqueReadOperation{}
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
	operation uint32,
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
	handle uint32,
	operation uint32,
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

		n, err := connection.Write(buffer)

		b.mu.Lock()
		result.n = n
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
	operation uint32,
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
	n, err := result.n, result.err
	b.mu.Unlock()

	if n > 0 {
		return int32(n)
	}
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

func (b *opaqueBridge) close() {
	b.mu.Lock()
	connections := make([]net.Conn, 0, len(b.handles))
	for _, connection := range b.handles {
		connections = append(connections, connection)
	}
	b.mu.Unlock()

	for _, connection := range connections {
		_ = connection.Close()
	}
	b.workers.Wait()
}

func TestOpaqueSocketBridgeDrivesTokio(t *testing.T) {
	pendingHost, pendingPeer := net.Pipe()
	activeHost, activePeer := net.Pipe()
	bridge := newOpaqueBridge(map[uint32]net.Conn{
		1: pendingHost,
		2: activeHost,
	})
	defer bridge.close()
	defer pendingPeer.Close()
	defer activePeer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runtimeConfig := wazero.NewRuntimeConfig().WithCloseOnContextDone(true)
	runtime := wazero.NewRuntimeWithConfig(ctx, runtimeConfig)
	defer runtime.Close(ctx)
	instantiateOpaqueHost(t, ctx, runtime, bridge)
	wasi_snapshot_preview1.MustInstantiate(ctx, runtime)

	compiled, err := runtime.CompileModule(ctx, buildGuest(t))
	if err != nil {
		t.Fatalf("compile guest: %v", err)
	}
	moduleConfig := wazero.NewModuleConfig().
		WithStartFunctions("_initialize").
		WithSysWalltime().
		WithSysNanotime().
		WithSysNanosleep()
	module, err := runtime.InstantiateModule(ctx, compiled, moduleConfig)
	if err != nil {
		t.Fatalf("instantiate guest: %v", err)
	}

	echo := make(chan error, 1)
	go func() {
		if err := activePeer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			echo <- err
			return
		}
		want := []byte{0x5a}
		if _, err := activePeer.Write(want); err != nil {
			echo <- fmt.Errorf("write active connection: %w", err)
			return
		}
		got := make([]byte, len(want))
		if _, err := io.ReadFull(activePeer, got); err != nil {
			echo <- fmt.Errorf("read active connection: %w", err)
			return
		}
		if got[0] != want[0] {
			echo <- fmt.Errorf("echo mismatch: got %x, want %x", got, want)
			return
		}
		echo <- nil
	}()

	initResult, err := module.ExportedFunction("init_opaque_probe").Call(ctx, 1, 2)
	if err != nil {
		t.Fatalf("initialize opaque probe: %v", err)
	}
	if len(initResult) != 1 || int32(initResult[0]) != 0 {
		t.Fatalf("unexpected opaque probe initialization result: %v", initResult)
	}

	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	driveCalls := 0
	var status uint32
	for status&opaqueDone == 0 {
		results, err := module.ExportedFunction("drive_opaque_probe").Call(ctx)
		if err != nil {
			t.Fatalf("drive opaque probe: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("unexpected opaque probe result count: %d", len(results))
		}
		status = uint32(results[0])
		driveCalls++
		if status&opaqueError != 0 {
			t.Fatalf("opaque probe failed at stage %d", status&^opaqueError)
		}
		if status&opaqueDone != 0 {
			break
		}

		select {
		case <-bridge.completion:
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("waiting to drive opaque probe: %v", ctx.Err())
		}
	}

	wantStatus := uint32(
		opaqueTimerProgress |
			opaqueSecondSocketProgress |
			opaquePendingReadIsolated |
			opaqueDone,
	)
	if status != wantStatus {
		t.Fatalf("opaque probe status 0x%x, want 0x%x", status, wantStatus)
	}
	if status&opaquePendingReadCompleted != 0 {
		t.Fatal("permanently pending read unexpectedly completed")
	}
	select {
	case err := <-echo:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatalf("waiting for active connection echo: %v", ctx.Err())
	}

	t.Logf(
		"opaque net.Conn bridge passed: status=0x%x, serialized drive calls=%d",
		status,
		driveCalls,
	)
}

func instantiateOpaqueHost(
	t *testing.T,
	ctx context.Context,
	runtime wazero.Runtime,
	bridge *opaqueBridge,
) {
	t.Helper()

	_, err := runtime.NewHostModuleBuilder("easytier_host").
		NewFunctionBuilder().WithFunc(bridge.startRead).Export("start_read").
		NewFunctionBuilder().WithFunc(bridge.takeRead).Export("take_read").
		NewFunctionBuilder().WithFunc(bridge.startWrite).Export("start_write").
		NewFunctionBuilder().WithFunc(bridge.takeWrite).Export("take_write").
		Instantiate(ctx)
	if err != nil {
		t.Fatalf("instantiate opaque socket host module: %v", err)
	}
}
