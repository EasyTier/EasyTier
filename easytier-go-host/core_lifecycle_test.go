package host

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

const (
	coreStateRunning = 2
	coreStateStopped = 4
)

func TestCoreInstanceLifecycle(t *testing.T) {
	bridge := newOpaqueBridge(nil, nil)
	defer bridge.close()
	wasm := buildCore(t)
	config, err := os.ReadFile(filepath.Join("testdata", "minimal_core_instance.json"))
	if err != nil {
		t.Fatalf("read core instance fixture: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runtime, _, core, _ := instantiateCoreModule(t, ctx, wasm, bridge, config)
	defer runtime.Close(ctx)

	dropped := false
	defer func() {
		if !dropped {
			_ = core.Drop(ctx)
		}
	}()

	if err := core.Start(ctx); err != nil {
		t.Fatalf("start core instance: %v", err)
	}
	if err := core.DriveUntil(ctx, bridge.completion, CoreStateRunning); err != nil {
		t.Fatalf("drive core instance until running: %v", err)
	}

	deadline, err := core.NextDeadline(ctx)
	if err != nil {
		t.Fatalf("query running core deadline: %v", err)
	}
	if deadline < 0 {
		t.Fatalf("running instance returned error deadline: %d", deadline)
	}
	if bridge.environmentCallCount() != 0 {
		t.Fatalf("minimal config unexpectedly used environment operations: %d", bridge.environmentCallCount())
	}

	if err := core.Stop(ctx); err != nil {
		t.Fatalf("stop core instance: %v", err)
	}
	if err := core.DriveUntil(ctx, bridge.completion, CoreStateStopped); err != nil {
		t.Fatalf("drive core instance until stopped: %v", err)
	}
	if err := core.Drop(ctx); err != nil {
		t.Fatalf("drop core instance: %v", err)
	}
	dropped = true
}

func TestCoreModuleAllowsOnlyOneLiveInstance(t *testing.T) {
	bridge := newOpaqueBridge(nil, nil)
	defer bridge.close()
	wasm := buildCore(t)
	config, err := os.ReadFile(filepath.Join("testdata", "minimal_core_instance.json"))
	if err != nil {
		t.Fatalf("read core instance fixture: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runtime, _, core, packetSink := instantiateCoreModule(t, ctx, wasm, bridge, config)
	defer runtime.Close(ctx)

	if _, err := core.coreModule.CreateInstance(ctx, config, packetSink); err == nil {
		t.Fatal("CoreModule created two live instances with one completion domain")
	}
	if err := core.Drop(ctx); err != nil {
		t.Fatalf("drop first core instance: %v", err)
	}
	replacement, err := core.coreModule.CreateInstance(ctx, config, packetSink)
	if err != nil {
		t.Fatalf("create replacement core instance: %v", err)
	}
	if err := replacement.Drop(ctx); err != nil {
		t.Fatalf("drop replacement core instance: %v", err)
	}
}

func instantiateCoreModule(
	t *testing.T,
	ctx context.Context,
	wasm []byte,
	bridge *opaqueBridge,
	config []byte,
) (wazero.Runtime, api.Module, *CoreInstance, uint64) {
	t.Helper()
	packetSink, err := bridge.registerPacketSink(16)
	if err != nil {
		t.Fatalf("register packet sink: %v", err)
	}
	runtime := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
	initialized := false
	defer func() {
		if !initialized {
			_ = runtime.Close(ctx)
		}
	}()
	instantiateOpaqueHost(t, ctx, runtime, bridge)
	wasi_snapshot_preview1.MustInstantiate(ctx, runtime)
	compiled, err := runtime.CompileModule(ctx, wasm)
	if err != nil {
		t.Fatalf("compile easytier-core: %v", err)
	}
	moduleOwner, err := InstantiateCoreModule(
		ctx,
		runtime,
		compiled,
		wazero.NewModuleConfig().
			WithStartFunctions("_initialize").
			WithSysWalltime().
			WithSysNanotime().
			WithSysNanosleep(),
	)
	if err != nil {
		t.Fatalf("instantiate easytier-core: %v", err)
	}
	core, err := moduleOwner.CreateInstance(ctx, config, packetSink)
	if err != nil {
		t.Fatalf("create core instance: %v", err)
	}
	initialized = true
	return runtime, moduleOwner.module, core, packetSink
}

func driveCoreUntil(
	t *testing.T,
	ctx context.Context,
	module api.Module,
	bridge *opaqueBridge,
	handle uint64,
	wanted int32,
) {
	t.Helper()
	for {
		state := driveCoreOnce(t, ctx, module, handle)
		if state == wanted {
			return
		}

		deadline := coreDeadline(t, ctx, module, handle)
		if deadline < 0 {
			t.Fatalf("query core deadline: status=%d core_error=%s", deadline, coreError(t, ctx, module, handle))
		}
		if deadline == math.MaxInt64 {
			select {
			case <-bridge.completion:
			case <-ctx.Done():
				t.Fatalf("wait for core completion: %v", ctx.Err())
			}
			continue
		}
		timer := time.NewTimer(time.Duration(deadline) * time.Millisecond)
		select {
		case <-bridge.completion:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			t.Fatalf("wait for core deadline: %v", ctx.Err())
		}
	}
}

func driveCoreOnce(t *testing.T, ctx context.Context, module api.Module, handle uint64) int32 {
	t.Helper()
	results, err := module.ExportedFunction("easytier_instance_drive").Call(ctx, handle)
	if err != nil {
		t.Fatalf("drive core instance: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("drive core instance returned %d values", len(results))
	}
	state := int32(results[0])
	if state < 0 {
		t.Fatalf("drive core instance: %s", coreError(t, ctx, module, handle))
	}
	return state
}

func coreDeadline(t *testing.T, ctx context.Context, module api.Module, handle uint64) int64 {
	t.Helper()
	results, err := module.ExportedFunction("easytier_instance_next_deadline_millis").Call(ctx, handle)
	if err != nil || len(results) != 1 {
		t.Fatalf("query core deadline: results=%v error=%v", results, err)
	}
	return int64(results[0])
}

func coreCallStatus(t *testing.T, ctx context.Context, module api.Module, handle uint64, name string) {
	t.Helper()
	results, err := module.ExportedFunction(name).Call(ctx, handle)
	if err != nil || len(results) != 1 || int32(results[0]) != 0 {
		t.Fatalf("%s: results=%v error=%v core_error=%s", name, results, err, coreError(t, ctx, module, handle))
	}
}

func coreAllocate(t *testing.T, ctx context.Context, module api.Module, length uint32) uint32 {
	t.Helper()
	results, err := module.ExportedFunction("easytier_buffer_alloc").Call(ctx, uint64(length))
	if err != nil || len(results) != 1 || results[0] == 0 {
		t.Fatalf("allocate core guest buffer: results=%v error=%v", results, err)
	}
	return uint32(results[0])
}

func coreFree(t *testing.T, ctx context.Context, module api.Module, pointer uint32) {
	t.Helper()
	results, err := module.ExportedFunction("easytier_buffer_free").Call(ctx, uint64(pointer))
	if err != nil || len(results) != 1 || int32(results[0]) != 0 {
		t.Fatalf("free core guest buffer: results=%v error=%v", results, err)
	}
}

func coreError(t *testing.T, ctx context.Context, module api.Module, handle uint64) string {
	t.Helper()
	lengthResult, err := module.ExportedFunction("easytier_instance_error_len").Call(ctx, handle)
	if err != nil || len(lengthResult) != 1 {
		return fmt.Sprintf("read error length: results=%v error=%v", lengthResult, err)
	}
	length := uint32(lengthResult[0])
	if length == 0 {
		return "<no core error>"
	}
	pointer := coreAllocate(t, ctx, module, length)
	defer coreFree(t, ctx, module, pointer)
	copyResult, err := module.ExportedFunction("easytier_instance_error_copy").Call(
		ctx,
		handle,
		uint64(pointer),
		uint64(length),
	)
	if err != nil || len(copyResult) != 1 || int32(copyResult[0]) < 0 {
		return fmt.Sprintf("copy core error: results=%v error=%v", copyResult, err)
	}
	encoded, ok := module.Memory().Read(pointer, length)
	if !ok {
		return "read copied core error: invalid guest memory"
	}
	return string(encoded)
}

func buildCore(t *testing.T) []byte {
	t.Helper()
	hostDir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolve host directory: %v", err)
	}
	repositoryDir := filepath.Clean(filepath.Join(hostDir, ".."))
	command := exec.Command(
		"cargo",
		"build",
		"--release",
		"--target",
		"wasm32-wasip1",
		"-p",
		"easytier-core",
	)
	command.Dir = repositoryDir
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build easytier-core wasm: %v\n%s", err, output)
	}
	wasmPath := filepath.Join(
		repositoryDir,
		"target",
		"wasm32-wasip1",
		"release",
		"easytier_core.wasm",
	)
	wasm, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatalf("read easytier-core artifact %s: %v", wasmPath, err)
	}
	return wasm
}
