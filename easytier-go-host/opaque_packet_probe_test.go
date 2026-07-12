package host

import (
	"context"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

func TestOpaquePacketSinkBackpressure(t *testing.T) {
	bridge := newOpaqueBridge(nil, nil)
	defer bridge.close()
	handle, err := bridge.registerPacketSink(1)
	if err != nil {
		t.Fatalf("register packet sink: %v", err)
	}
	wasm := buildGuest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runtime := wazero.NewRuntimeWithConfig(
		ctx,
		wazero.NewRuntimeConfig().WithCloseOnContextDone(true),
	)
	defer runtime.Close(ctx)
	instantiateOpaqueHost(t, ctx, runtime, bridge)
	wasi_snapshot_preview1.MustInstantiate(ctx, runtime)
	compiled, err := runtime.CompileModule(ctx, wasm)
	if err != nil {
		t.Fatalf("compile guest: %v", err)
	}
	module, err := runtime.InstantiateModule(
		ctx,
		compiled,
		wazero.NewModuleConfig().
			WithStartFunctions("_initialize").
			WithSysWalltime().
			WithSysNanotime().
			WithSysNanosleep(),
	)
	if err != nil {
		t.Fatalf("instantiate guest: %v", err)
	}
	results, err := module.ExportedFunction("init_packet_probe").Call(ctx, handle)
	if err != nil || len(results) != 1 || int32(results[0]) != 0 {
		t.Fatalf("initialize packet probe: results=%v err=%v", results, err)
	}

	results, err = module.ExportedFunction("drive_packet_probe").Call(ctx)
	if err != nil || len(results) != 1 || uint32(results[0]) != 0 {
		t.Fatalf("bootstrap packet probe: results=%v err=%v", results, err)
	}
	bridge.mu.Lock()
	queued := len(bridge.packetSinks[handle].packets)
	waiters := len(bridge.packetWrites)
	waiterReady := false
	for _, waiter := range bridge.packetWrites {
		waiterReady = waiter.ready
	}
	bridge.mu.Unlock()
	if queued != 1 || waiters != 1 || waiterReady {
		t.Fatalf(
			"packet backpressure state: queued=%d waiters=%d ready=%t",
			queued,
			waiters,
			waiterReady,
		)
	}
	select {
	case <-bridge.completion:
		t.Fatal("packet readiness completed while sink was still full")
	default:
	}

	first, err := bridge.consumePacket(handle)
	if err != nil {
		t.Fatalf("consume first packet: %v", err)
	}
	if string(first) != "first-packet" {
		t.Fatalf("first packet %q", first)
	}
	select {
	case <-bridge.completion:
	case <-ctx.Done():
		t.Fatalf("wait for packet write readiness: %v", ctx.Err())
	}
	results, err = module.ExportedFunction("drive_packet_probe").Call(ctx)
	if err != nil || len(results) != 1 {
		t.Fatalf("complete packet probe: results=%v err=%v", results, err)
	}
	status := uint32(results[0])
	if status != opaqueDone {
		t.Fatalf("packet probe status 0x%x, want DONE", status)
	}
	second, err := bridge.consumePacket(handle)
	if err != nil {
		t.Fatalf("consume second packet: %v", err)
	}
	if string(second) != "second-packet" {
		t.Fatalf("second packet %q", second)
	}
	bridge.mu.Lock()
	queued = len(bridge.packetSinks[handle].packets)
	waiters = len(bridge.packetWrites)
	bridge.mu.Unlock()
	if queued != 0 || waiters != 0 {
		t.Fatalf("packet sink did not drain: queued=%d waiters=%d", queued, waiters)
	}
}
