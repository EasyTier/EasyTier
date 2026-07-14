package host

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

type probeOpaqueEnvironment struct {
	mu            sync.Mutex
	localRequests []string
	started       chan string
	release       chan struct{}
}

func (environment *probeOpaqueEnvironment) awaitRelease(
	ctx context.Context,
	kind string,
) error {
	select {
	case environment.started <- kind:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-environment.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (environment *probeOpaqueEnvironment) LocalAddrForRemote(
	ctx context.Context,
	remote *net.UDPAddr,
) (net.Addr, error) {
	environment.mu.Lock()
	environment.localRequests = append(environment.localRequests, remote.String())
	environment.mu.Unlock()
	if err := environment.awaitRelease(ctx, "local"); err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 40000}, nil
}

func (environment *probeOpaqueEnvironment) requests() []string {
	environment.mu.Lock()
	defer environment.mu.Unlock()
	return append([]string(nil), environment.localRequests...)
}

func TestOpaqueEnvironmentDrivesCoreServices(t *testing.T) {
	environment := &probeOpaqueEnvironment{
		started: make(chan string, 1),
		release: make(chan struct{}),
	}
	bridge := newOpaqueBridge(nil, nil)
	bridge.environmentResolver = environment
	defer bridge.close()
	wasm := buildGuest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runtime := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
	defer runtime.Close(ctx)
	instantiateOpaqueHost(t, ctx, runtime, bridge)
	wasi_snapshot_preview1.MustInstantiate(ctx, runtime)
	compiled, err := runtime.CompileModule(ctx, wasm)
	if err != nil {
		t.Fatalf("compile environment guest: %v", err)
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
		t.Fatalf("instantiate environment guest: %v", err)
	}
	results, err := module.ExportedFunction("init_environment_probe").Call(ctx)
	if err != nil || len(results) != 1 || int32(results[0]) != 0 {
		t.Fatalf("initialize environment probe: results=%v error=%v", results, err)
	}

	drive := func() uint32 {
		t.Helper()
		results, err := module.ExportedFunction("drive_environment_probe").Call(ctx)
		if err != nil || len(results) != 1 {
			t.Fatalf("drive environment probe: results=%v error=%v", results, err)
		}
		status := uint32(results[0])
		if status&opaqueError != 0 {
			t.Fatalf("environment probe failed with status 0x%x", status)
		}
		return status
	}
	status := drive()
	for _, expected := range []string{"local"} {
		if status&opaqueDone != 0 {
			t.Fatalf("environment probe completed before %s operation", expected)
		}
		select {
		case actual := <-environment.started:
			if actual != expected {
				t.Fatalf("unexpected environment operation: got=%s want=%s", actual, expected)
			}
		case <-ctx.Done():
			t.Fatalf("wait for %s environment operation: %v", expected, ctx.Err())
		}
		environment.release <- struct{}{}
		select {
		case <-bridge.completion:
		case <-ctx.Done():
			t.Fatalf("wait for %s environment completion: %v", expected, ctx.Err())
		}
		status = drive()
	}
	if status&opaqueDone == 0 {
		t.Fatalf("environment probe did not complete: status=0x%x", status)
	}

	local := environment.requests()
	if fmt.Sprint(local) != "[203.0.113.2:443]" {
		t.Fatalf("unexpected environment requests: local=%v", local)
	}
	if bridge.environmentCallCount() != 1 {
		t.Fatalf("unexpected environment call count: %d", bridge.environmentCallCount())
	}
}
