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

func TestDecodeTCPProxyNatListenPurpose(t *testing.T) {
	encoded := make([]byte, 42)
	encoded[0] = 1
	local, err := encodeNetAddr(&net.TCPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	copy(encoded[1:28], local[:])
	encoded[36] = 3
	options, err := decodeTCPListenOptions(encoded)
	if err != nil {
		t.Fatalf("decode proxy NAT TCP listen options: %v", err)
	}
	if options.Purpose != TCPListenProxyNAT {
		t.Fatalf("decoded TCP listen purpose %d, want ProxyNAT", options.Purpose)
	}
}

func TestOpaqueListenerAcceptsCoreStream(t *testing.T) {
	port := reserveTCPPort(t)
	socketFactory := &recordingSocketFactory{inner: NetSocketFactory{}}
	bridge := NewBridge(BridgeConfig{SocketFactory: socketFactory})
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
		t.Fatalf("compile guest: %v", err)
	}
	module, err := runtime.InstantiateModule(
		ctx,
		compiled,
		wazero.NewModuleConfig().WithStartFunctions("_initialize").WithSysWalltime().WithSysNanotime().WithSysNanosleep(),
	)
	if err != nil {
		t.Fatalf("instantiate guest: %v", err)
	}
	results, err := module.ExportedFunction("init_listener_probe").Call(ctx, uint64(port))
	if err != nil || len(results) != 1 || int32(results[0]) != 0 {
		t.Fatalf("initialize listener probe: results=%v err=%v", results, err)
	}

	peerDone := make(chan error, 1)
	go func() {
		address := fmt.Sprintf("127.0.0.1:%d", port)
		var connection net.Conn
		var err error
		for connection == nil && ctx.Err() == nil {
			connection, err = net.DialTimeout("tcp4", address, 50*time.Millisecond)
			if err != nil {
				time.Sleep(5 * time.Millisecond)
			}
		}
		if connection == nil {
			peerDone <- fmt.Errorf("dial listener: %w", err)
			return
		}
		defer connection.Close()
		if _, err := connection.Write([]byte("listener")); err != nil {
			peerDone <- err
			return
		}
		buffer := make([]byte, 8)
		_, err = io.ReadFull(connection, buffer)
		if err == nil && string(buffer) != "listener" {
			err = fmt.Errorf("listener echo %q", buffer)
		}
		peerDone <- err
	}()

	status := uint32(0)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for status&opaqueDone == 0 {
		select {
		case <-bridge.completion:
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("wait for listener probe: %v", ctx.Err())
		}
		results, err := module.ExportedFunction("drive_listener_probe").Call(ctx)
		if err != nil || len(results) != 1 {
			t.Fatalf("drive listener probe: results=%v err=%v", results, err)
		}
		status = uint32(results[0])
		if status&opaqueError != 0 {
			t.Fatalf("listener probe failed with status 0x%x", status)
		}
	}
	select {
	case err := <-peerDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatalf("wait for listener peer: %v", ctx.Err())
	}
	_, _, listenCalls := socketFactory.calls()
	if len(listenCalls) != 1 || listenCalls[0].Purpose != TCPListenManual {
		t.Fatalf("unexpected TCP listener factory calls: %#v", listenCalls)
	}
}
