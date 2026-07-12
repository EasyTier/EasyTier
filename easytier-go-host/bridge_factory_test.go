package host

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

func TestDecodeTCPProxyNatPurpose(t *testing.T) {
	encoded := make([]byte, 69)
	encoded[0] = 1
	remote, err := encodeNetAddr(&net.TCPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 11013})
	if err != nil {
		t.Fatal(err)
	}
	copy(encoded[1:28], remote[:])
	encoded[63] = 4
	options, err := decodeTCPConnectOptions(encoded)
	if err != nil {
		t.Fatalf("decode proxy NAT TCP connect options: %v", err)
	}
	if options.Purpose != TCPConnectProxyNAT {
		t.Fatalf("decoded TCP purpose %d, want ProxyNAT", options.Purpose)
	}
}

func TestDecodeUDPProxyNatPurpose(t *testing.T) {
	encoded := make([]byte, 42)
	encoded[0] = 1
	encoded[36] = 4
	options, err := decodeUDPBindOptions(encoded)
	if err != nil {
		t.Fatalf("decode proxy NAT UDP bind options: %v", err)
	}
	if options.Purpose != UDPBindProxyNAT {
		t.Fatalf("decoded UDP purpose %d, want ProxyNAT", options.Purpose)
	}
}

func TestDecodeTCPBindPolicyForCustomFactory(t *testing.T) {
	encoded := make([]byte, 72)
	encoded[0] = 1
	remote, err := encodeNetAddr(&net.TCPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 11013})
	if err != nil {
		t.Fatal(err)
	}
	copy(encoded[1:28], remote[:])
	encoded[55] = 1
	binary.BigEndian.PutUint32(encoded[56:60], 7)
	encoded[60] = 2
	encoded[61] = 1
	encoded[62] = 1
	encoded[63] = byte(TCPConnectManual)
	encoded[64] = 1
	binary.BigEndian.PutUint32(encoded[65:69], 3)
	copy(encoded[69:], "tun")

	options, err := decodeTCPConnectOptions(encoded)
	if err != nil {
		t.Fatalf("decode TCP bind policy: %v", err)
	}
	if options.Bind.SocketMark == nil || *options.Bind.SocketMark != 7 ||
		options.Bind.BindDevice == nil || *options.Bind.BindDevice != "tun" ||
		options.Bind.ReuseAddr == nil || !*options.Bind.ReuseAddr ||
		!options.Bind.ReusePort || !options.Bind.OnlyV6 {
		t.Fatalf("unexpected TCP bind policy: %#v", options.Bind)
	}
	if _, err := (NetSocketFactory{}).ConnectTCP(context.Background(), options); err == nil {
		t.Fatal("NetSocketFactory accepted a non-default TCP bind policy")
	}
}

func TestDecodeUDPBindPolicyForCustomFactory(t *testing.T) {
	encoded := make([]byte, 45)
	encoded[0] = 1
	encoded[28] = 1
	binary.BigEndian.PutUint32(encoded[29:33], 9)
	encoded[33] = 1
	encoded[34] = 1
	encoded[35] = 1
	encoded[36] = byte(UDPBindProxyNAT)
	encoded[37] = 1
	binary.BigEndian.PutUint32(encoded[38:42], 3)
	copy(encoded[42:], "tun")

	options, err := decodeUDPBindOptions(encoded)
	if err != nil {
		t.Fatalf("decode UDP bind policy: %v", err)
	}
	if options.SocketMark == nil || *options.SocketMark != 9 ||
		options.BindDevice == nil || *options.BindDevice != "tun" ||
		!options.ReuseAddr || !options.ReusePort || !options.OnlyV6 {
		t.Fatalf("unexpected UDP bind policy: %#v", options)
	}
	if _, err := (NetSocketFactory{}).BindUDP(context.Background(), options); err == nil {
		t.Fatal("NetSocketFactory accepted a non-default UDP bind policy")
	}
}

func TestOpaqueFactoryCreatesSocketsForCore(t *testing.T) {
	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen TCP echo: %v", err)
	}
	defer tcpListener.Close()
	udpEcho, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen UDP echo: %v", err)
	}
	defer udpEcho.Close()

	tcpDone := make(chan error, 1)
	go func() {
		connection, err := tcpListener.Accept()
		if err != nil {
			tcpDone <- err
			return
		}
		defer connection.Close()
		buffer := make([]byte, 11)
		if _, err := io.ReadFull(connection, buffer); err == nil {
			_, err = connection.Write(buffer)
		}
		tcpDone <- err
	}()
	udpDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 64)
		n, peer, err := udpEcho.ReadFrom(buffer)
		if err == nil {
			_, err = udpEcho.WriteTo(buffer[:n], peer)
		}
		udpDone <- err
	}()

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

	tcpPort := tcpListener.Addr().(*net.TCPAddr).Port
	udpPort := udpEcho.LocalAddr().(*net.UDPAddr).Port
	results, err := module.ExportedFunction("init_factory_probe").Call(ctx, uint64(tcpPort), uint64(udpPort))
	if err != nil || len(results) != 1 || int32(results[0]) != 0 {
		t.Fatalf("initialize factory probe: results=%v err=%v", results, err)
	}
	wantStatus := uint32(opaqueDone | factoryTCPProgress | factoryUDPProgress)
	status := uint32(0)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for status&opaqueDone == 0 {
		select {
		case <-bridge.completion:
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("wait for factory probe: %v", ctx.Err())
		}
		results, err := module.ExportedFunction("drive_factory_probe").Call(ctx)
		if err != nil || len(results) != 1 {
			t.Fatalf("drive factory probe: results=%v err=%v", results, err)
		}
		status = uint32(results[0])
		if status&opaqueError != 0 {
			t.Fatalf("factory probe failed with status 0x%x", status)
		}
	}
	if status != wantStatus {
		t.Fatalf("factory status 0x%x, want 0x%x", status, wantStatus)
	}
	for name, done := range map[string]<-chan error{"TCP": tcpDone, "UDP": udpDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s echo: %v", name, err)
			}
		case <-ctx.Done():
			t.Fatalf("wait for %s echo: %v", name, ctx.Err())
		}
	}
	tcpCalls, udpCalls, _ := socketFactory.calls()
	if len(tcpCalls) != 1 || tcpCalls[0].Purpose != TCPConnectDirect {
		t.Fatalf("unexpected TCP factory calls: %#v", tcpCalls)
	}
	if len(udpCalls) != 1 || udpCalls[0].Purpose != UDPBindDirect {
		t.Fatalf("unexpected UDP factory calls: %#v", udpCalls)
	}
}

func TestFactoryRejectsUnsupportedTransportAndFlowinfo(t *testing.T) {
	base := make([]byte, 69)
	base[0] = 1
	remote, err := encodeNetAddr(&net.TCPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 11013})
	if err != nil {
		t.Fatal(err)
	}
	copy(base[1:28], remote[:])
	base[63] = 1
	options, err := decodeTCPConnectOptions(base)
	if err != nil || options.Purpose != TCPConnectFake {
		t.Fatalf("decode FakeTCP purpose: options=%#v error=%v", options, err)
	}
	if _, err := (NetSocketFactory{}).ConnectTCP(context.Background(), options); err == nil {
		t.Fatal("NetSocketFactory accepted FakeTCP as ordinary TCP")
	}

	remote, err = encodeNetAddr(&net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 11013})
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(remote[19:23], 7)
	copy(base[1:28], remote[:])
	base[63] = 0
	if _, err := decodeTCPConnectOptions(base); err == nil {
		t.Fatal("nonzero IPv6 flowinfo was silently discarded")
	}
}

func TestDiscardCreateOperationCancelsAndCloses(t *testing.T) {
	bridge := newOpaqueBridge(nil, nil)
	connection, peer := net.Pipe()
	defer peer.Close()
	createContext, cancel := context.WithCancel(context.Background())
	bridge.creates[77] = &opaqueCreateOperation{
		cancel:     cancel,
		connection: connection,
	}
	bridge.discardCreateOperation(77)
	if _, exists := bridge.creates[77]; exists {
		t.Fatal("discarded create operation remains registered")
	}
	select {
	case <-createContext.Done():
	default:
		t.Fatal("discarded create operation was not canceled")
	}
	if _, err := connection.Write([]byte{1}); err == nil {
		t.Fatal("discarded completed connection remains open")
	}
}
