package host

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

const (
	opaqueTimerProgress        = 1 << 0
	opaqueSecondSocketProgress = 1 << 1
	opaquePendingReadCompleted = 1 << 2
	opaquePendingReadIsolated  = 1 << 3
	opaqueDone                 = 1 << 4
	opaqueError                = 1 << 31
)

func (b *opaqueBridge) readInFlight(handle uint64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, operation := range b.reads {
		if operation.handle == handle && !operation.done {
			return true
		}
	}
	return false
}

func TestOpaqueSocketBridgeDrivesTokio(t *testing.T) {
	const (
		pendingHandle uint64 = 1<<40 | 1
		activeHandle  uint64 = 1<<40 | 2
	)
	pendingHost, pendingPeer := net.Pipe()
	activeHost, activePeer := net.Pipe()
	bridge := newOpaqueBridge(
		map[uint64]net.Conn{
			pendingHandle: pendingHost,
			activeHandle:  activeHost,
		},
		nil,
	)
	defer bridge.close()
	defer pendingPeer.Close()
	defer activePeer.Close()
	wasm := buildGuest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runtimeConfig := wazero.NewRuntimeConfig().WithCloseOnContextDone(true)
	runtime := wazero.NewRuntimeWithConfig(ctx, runtimeConfig)
	defer runtime.Close(ctx)
	instantiateOpaqueHost(t, ctx, runtime, bridge)
	wasi_snapshot_preview1.MustInstantiate(ctx, runtime)

	compiled, err := runtime.CompileModule(ctx, wasm)
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

	initResult, err := module.ExportedFunction("init_opaque_probe").Call(
		ctx,
		pendingHandle,
		activeHandle,
	)
	if err != nil {
		t.Fatalf("initialize opaque probe: %v", err)
	}
	if len(initResult) != 1 || int32(initResult[0]) != 0 {
		t.Fatalf("unexpected opaque probe initialization result: %v", initResult)
	}

	driveCalls := 0
	drive := func() uint32 {
		results, err := module.ExportedFunction("drive_opaque_probe").Call(ctx)
		if err != nil {
			t.Fatalf("drive opaque probe: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("unexpected opaque probe result count: %d", len(results))
		}
		status := uint32(results[0])
		driveCalls++
		if status&opaqueError != 0 {
			t.Fatalf("opaque probe failed at stage %d", status&^opaqueError)
		}
		return status
	}

	status := drive()
	if !bridge.readInFlight(pendingHandle) {
		t.Fatal("pending connection read was not in flight after initial drive")
	}
	if !bridge.readInFlight(activeHandle) {
		t.Fatal("active connection read was not in flight after initial drive")
	}

	echo := make(chan error, 1)
	readyToReadEcho := make(chan struct{})
	allowEchoRead := make(chan struct{})
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
		close(readyToReadEcho)
		select {
		case <-allowEchoRead:
		case <-ctx.Done():
			echo <- ctx.Err()
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

	waitForCompletion := func(stage string) {
		select {
		case <-bridge.completion:
		case <-ctx.Done():
			t.Fatalf("waiting for %s completion: %v", stage, ctx.Err())
		}
	}

	waitForCompletion("active read")
	status = drive()
	if status&opaqueSecondSocketProgress != 0 {
		t.Fatal("active socket completed before its write was released")
	}
	select {
	case <-readyToReadEcho:
	case <-ctx.Done():
		t.Fatalf("waiting for peer to finish its write: %v", ctx.Err())
	}
	close(allowEchoRead)

	waitForCompletion("active write")
	status = drive()
	if status&opaqueSecondSocketProgress == 0 {
		t.Fatal("active socket did not progress after read and write completions")
	}
	completionDriveCalls := 2

	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for status&opaqueDone == 0 {
		select {
		case <-ticker.C:
			status = drive()
		case <-ctx.Done():
			t.Fatalf("waiting for Tokio timer progress: %v", ctx.Err())
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
		"opaque net.Conn bridge passed: status=0x%x, drives=%d, completion drives=%d",
		status,
		driveCalls,
		completionDriveCalls,
	)
}

func instantiateOpaqueHost(
	t *testing.T,
	ctx context.Context,
	runtime wazero.Runtime,
	bridge *opaqueBridge,
) {
	t.Helper()

	if err := bridge.instantiateHost(ctx, runtime); err != nil {
		t.Fatalf("instantiate opaque socket host module: %v", err)
	}
}
