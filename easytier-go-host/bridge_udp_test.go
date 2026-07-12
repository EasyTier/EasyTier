package host

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

func TestUDPMetadataABI(t *testing.T) {
	expected := [udpMetadataLen]byte{
		0x04, 0xc0, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2b, 0x05, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xc6, 0x33, 0x64, 0x02, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	encoded, err := encodeUDPMetadata(
		&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 11013},
		net.IPv4(198, 51, 100, 2),
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	if encoded != expected {
		t.Fatalf("UDP metadata mismatch:\n got %x\nwant %x", encoded, expected)
	}
	peer, optionalIP, flowinfo, optionalIfindex, err := decodeUDPMetadata(expected[:])
	if err != nil {
		t.Fatal(err)
	}
	if peer.String() != "192.0.2.1:11013" || !optionalIP.Equal(net.IPv4(198, 51, 100, 2)) || flowinfo != 0 || optionalIfindex != 0 {
		t.Fatalf("unexpected decoded metadata: peer=%v optional=%v flowinfo=%d ifindex=%d", peer, optionalIP, flowinfo, optionalIfindex)
	}
}

func TestOpaqueUDPBridgeDrivesCoreSocket(t *testing.T) {
	const udpHandle uint64 = 1<<40 | 3
	hostPacket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen host UDP: %v", err)
	}
	peerPacket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		hostPacket.Close()
		t.Fatalf("listen peer UDP: %v", err)
	}
	bridge := newOpaqueBridge(nil, map[uint64]net.PacketConn{udpHandle: hostPacket})
	defer bridge.close()
	defer peerPacket.Close()
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

	results, err := module.ExportedFunction("init_udp_probe").Call(ctx, udpHandle)
	if err != nil || len(results) != 1 || int32(results[0]) != 0 {
		t.Fatalf("initialize UDP probe: results=%v err=%v", results, err)
	}
	driveUDP := func() uint32 {
		results, err := module.ExportedFunction("drive_udp_probe").Call(ctx)
		if err != nil || len(results) != 1 {
			t.Fatalf("drive UDP probe: results=%v err=%v", results, err)
		}
		return uint32(results[0])
	}
	if status := driveUDP(); status != 0 {
		t.Fatalf("unexpected initial UDP status 0x%x", status)
	}

	if err := peerPacket.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := peerPacket.WriteTo([]byte("udp"), hostPacket.LocalAddr()); err != nil {
		t.Fatalf("send UDP probe payload: %v", err)
	}
	select {
	case <-bridge.completion:
	case <-ctx.Done():
		t.Fatalf("wait for UDP receive completion: %v", ctx.Err())
	}
	status := driveUDP()
	if status != opaqueDone {
		t.Fatalf("UDP probe status 0x%x, want 0x%x", status, opaqueDone)
	}

	buffer := make([]byte, 16)
	n, source, err := peerPacket.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("read UDP echo: %v", err)
	}
	if string(buffer[:n]) != "udp" {
		t.Fatalf("UDP echo %q, want %q", buffer[:n], "udp")
	}
	if source.String() != hostPacket.LocalAddr().String() {
		t.Fatalf("UDP echo source %v, want %v", source, hostPacket.LocalAddr())
	}
}
