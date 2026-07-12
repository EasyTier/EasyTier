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
	mu                sync.Mutex
	expectedUDPHandle uint64
	localRequests     []string
	udpRequests       []uint64
	tcpRequests       []uint16
	started           chan string
	release           chan struct{}
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

func (environment *probeOpaqueEnvironment) localAddrForRemote(
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

func (environment *probeOpaqueEnvironment) udpPortMapping(
	ctx context.Context,
	handle uint64,
) (net.Addr, error) {
	environment.mu.Lock()
	environment.udpRequests = append(environment.udpRequests, handle)
	environment.mu.Unlock()
	if handle != environment.expectedUDPHandle {
		return nil, fmt.Errorf("unexpected UDP handle %d", handle)
	}
	if err := environment.awaitRelease(ctx, "udp"); err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 45000}, nil
}

func (environment *probeOpaqueEnvironment) tcpPortMapping(
	ctx context.Context,
	port uint16,
) (net.Addr, error) {
	environment.mu.Lock()
	environment.tcpRequests = append(environment.tcpRequests, port)
	environment.mu.Unlock()
	if err := environment.awaitRelease(ctx, "tcp"); err != nil {
		return nil, err
	}
	return &net.TCPAddr{IP: net.ParseIP("198.51.100.11"), Port: int(port)}, nil
}

func (environment *probeOpaqueEnvironment) requests() ([]string, []uint64, []uint16) {
	environment.mu.Lock()
	defer environment.mu.Unlock()
	return append([]string(nil), environment.localRequests...),
		append([]uint64(nil), environment.udpRequests...),
		append([]uint16(nil), environment.tcpRequests...)
}

func TestOpaqueEnvironmentDrivesCoreServices(t *testing.T) {
	const udpHandle uint64 = 1<<44 | 7
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("create environment UDP socket: %v", err)
	}
	environment := &probeOpaqueEnvironment{
		expectedUDPHandle: udpHandle,
		started:           make(chan string, 1),
		release:           make(chan struct{}),
	}
	bridge := newOpaqueBridge(nil, map[uint64]net.PacketConn{udpHandle: packet})
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
	results, err := module.ExportedFunction("init_environment_probe").Call(ctx, udpHandle)
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
	for _, expected := range []string{"local", "udp", "tcp"} {
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

	local, udp, tcp := environment.requests()
	if fmt.Sprint(local) != "[203.0.113.2:443]" ||
		fmt.Sprint(udp) != fmt.Sprintf("[%d]", udpHandle) ||
		fmt.Sprint(tcp) != "[11010]" {
		t.Fatalf("unexpected environment requests: local=%v udp=%v tcp=%v", local, udp, tcp)
	}
	if bridge.environmentCallCount() != 3 {
		t.Fatalf("unexpected environment call count: %d", bridge.environmentCallCount())
	}
}
