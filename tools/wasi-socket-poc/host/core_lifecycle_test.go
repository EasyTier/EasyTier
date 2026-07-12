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
	packetSink, err := bridge.registerPacketSink(1)
	if err != nil {
		t.Fatalf("register packet sink: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runtime := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
	defer runtime.Close(ctx)
	instantiateOpaqueHost(t, ctx, runtime, bridge)
	wasi_snapshot_preview1.MustInstantiate(ctx, runtime)

	compiled, err := runtime.CompileModule(ctx, wasm)
	if err != nil {
		t.Fatalf("compile easytier-core: %v", err)
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
		t.Fatalf("instantiate easytier-core: %v", err)
	}

	config, err := os.ReadFile(filepath.Join("testdata", "minimal_core_instance.json"))
	if err != nil {
		t.Fatalf("read core instance fixture: %v", err)
	}
	configPointer := coreAllocate(t, ctx, module, uint32(len(config)))
	if !module.Memory().Write(configPointer, config) {
		t.Fatal("write core instance fixture to guest memory")
	}
	createResult, err := module.ExportedFunction("easytier_instance_create").Call(
		ctx,
		uint64(configPointer),
		uint64(len(config)),
		packetSink,
	)
	coreFree(t, ctx, module, configPointer)
	if err != nil {
		t.Fatalf("create core instance: %v", err)
	}
	if len(createResult) != 1 || createResult[0] == 0 {
		t.Fatalf("create core instance: %s", coreError(t, ctx, module, 0))
	}
	handle := createResult[0]
	dropped := false
	defer func() {
		if !dropped {
			_, _ = module.ExportedFunction("easytier_instance_drop").Call(ctx, handle)
		}
	}()

	coreCallStatus(t, ctx, module, handle, "easytier_instance_start")
	driveCoreUntil(t, ctx, module, bridge, handle, coreStateRunning)

	deadline := coreDeadline(t, ctx, module, handle)
	if deadline < 0 {
		t.Fatalf("running instance returned error deadline: %d", deadline)
	}
	if bridge.environmentCallCount() != 0 {
		t.Fatalf("minimal config unexpectedly used environment operations: %d", bridge.environmentCallCount())
	}

	coreCallStatus(t, ctx, module, handle, "easytier_instance_stop")
	driveCoreUntil(t, ctx, module, bridge, handle, coreStateStopped)
	coreCallStatus(t, ctx, module, handle, "easytier_instance_drop")
	dropped = true
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
		if state == wanted {
			return
		}

		// Starting and stopping tasks can leave more immediately runnable work.
		// Drive them again before sleeping on external I/O or a timer.
		if state == 1 || state == 3 {
			continue
		}
		deadline := coreDeadline(t, ctx, module, handle)
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
	repositoryDir := filepath.Clean(filepath.Join(hostDir, "..", "..", ".."))
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
