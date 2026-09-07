package hostabi

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/easytier-go/internal/contextutil"
	"github.com/EasyTier/EasyTier/easytier-go/internal/reactor"
	"github.com/EasyTier/EasyTier/easytier-go/platform"
	"github.com/metacubex/wazero"
	"github.com/metacubex/wazero/api"
	"github.com/metacubex/wazero/imports/wasi_snapshot_preview1"
)

const (
	probeTimerProgress        = 1 << 0
	probeSecondSocketProgress = 1 << 1
	probePendingReadCompleted = 1 << 2
	probePendingReadIsolated  = 1 << 3
	probeDone                 = 1 << 4
	probeError                = 1 << 31
)

func TestStreamABIConformance(t *testing.T) {
	const (
		pendingHandle uint64 = 1<<40 | 1
		activeHandle  uint64 = 1<<40 | 2
	)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pendingHost, pendingPeer := net.Pipe()
	activeHost, activePeer := net.Pipe()
	defer pendingPeer.Close()
	defer activePeer.Close()
	hostReactor := reactor.New(ctx, reactor.Options{
		InitialStreams: map[uint64]net.Conn{
			pendingHandle: pendingHost,
			activeHandle:  activeHost,
		},
	})
	defer hostReactor.Close()
	module := instantiateProbe(t, ctx, hostReactor)

	results, err := module.ExportedFunction("init_opaque_probe").Call(
		ctx,
		pendingHandle,
		activeHandle,
	)
	requireStatus(t, "initialize stream probe", results, err, 0)
	status := driveProbe(t, ctx, module, "drive_opaque_probe")

	echo := make(chan error, 1)
	go func() {
		if err := activePeer.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			echo <- err
			return
		}
		if _, err := activePeer.Write([]byte{0x5a}); err != nil {
			echo <- err
			return
		}
		got := make([]byte, 1)
		if _, err := io.ReadFull(activePeer, got); err != nil {
			echo <- err
			return
		}
		if got[0] != 0x5a {
			echo <- fmt.Errorf("echo = %x, want 5a", got)
			return
		}
		echo <- nil
	}()

	for status&probeSecondSocketProgress == 0 {
		waitCompletion(t, ctx, hostReactor)
		status = driveProbe(t, ctx, module, "drive_opaque_probe")
	}
	for status&probeDone == 0 {
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-hostReactor.Completions():
			stopTimer(timer)
		case <-timer.C:
		case <-ctx.Done():
			stopTimer(timer)
			t.Fatalf("wait for stream probe: %v", ctx.Err())
		}
		status = driveProbe(t, ctx, module, "drive_opaque_probe")
	}
	want := uint32(
		probeTimerProgress |
			probeSecondSocketProgress |
			probePendingReadIsolated |
			probeDone,
	)
	if status != want || status&probePendingReadCompleted != 0 {
		t.Fatalf("stream probe status = 0x%x, want 0x%x", status, want)
	}
	select {
	case err := <-echo:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatalf("wait for stream echo: %v", ctx.Err())
	}
}

func TestUDPABIConformance(t *testing.T) {
	const handle uint64 = 1<<40 | 3
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	hostPacket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen host UDP: %v", err)
	}
	peerPacket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		hostPacket.Close()
		t.Fatalf("listen peer UDP: %v", err)
	}
	defer peerPacket.Close()
	writes := make(chan packetWrite, 1)
	hostReactor := reactor.New(ctx, reactor.Options{
		InitialDatagrams: map[uint64]net.PacketConn{handle: &recordingPacketConn{
			PacketConn: hostPacket,
			writes:     writes,
		}},
	})
	defer hostReactor.Close()
	module := instantiateProbe(t, ctx, hostReactor)

	results, err := module.ExportedFunction("init_udp_probe").Call(ctx, handle)
	requireStatus(t, "initialize UDP probe", results, err, 0)
	if status := driveProbe(t, ctx, module, "drive_udp_probe"); status != 0 {
		t.Fatalf("initial UDP status = 0x%x", status)
	}
	if err := peerPacket.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := peerPacket.WriteTo([]byte("udp"), hostPacket.LocalAddr()); err != nil {
		t.Fatalf("send UDP payload: %v", err)
	}
	waitCompletion(t, ctx, hostReactor)
	if status := driveProbe(t, ctx, module, "drive_udp_probe"); status != probeDone {
		t.Fatalf("UDP probe status = 0x%x, want 0x%x", status, probeDone)
	}
	select {
	case write := <-writes:
		if write.err != nil {
			t.Fatalf("host UDP write to %v: %v", write.peer, write.err)
		}
		if write.peer.String() != peerPacket.LocalAddr().String() {
			t.Fatalf("host UDP peer = %v, want %v", write.peer, peerPacket.LocalAddr())
		}
	case <-ctx.Done():
		t.Fatalf("wait for host UDP write: %v", ctx.Err())
	}
	buffer := make([]byte, 16)
	n, source, err := peerPacket.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("read UDP echo: %v", err)
	}
	if string(buffer[:n]) != "udp" || source.String() != hostPacket.LocalAddr().String() {
		t.Fatalf("UDP echo = %q from %v", buffer[:n], source)
	}
}

type packetWrite struct {
	peer net.Addr
	err  error
}

type recordingPacketConn struct {
	net.PacketConn
	writes chan<- packetWrite
}

func (connection *recordingPacketConn) WriteTo(
	packet []byte,
	peer net.Addr,
) (int, error) {
	written, err := connection.PacketConn.WriteTo(packet, peer)
	connection.writes <- packetWrite{peer: peer, err: err}
	return written, err
}

type probeDNSResolver struct {
	mu             sync.Mutex
	queries        []platform.DNSQuery
	addressStarted chan struct{}
	releaseAddress chan struct{}
	startOnce      sync.Once
}

func (resolver *probeDNSResolver) record(query platform.DNSQuery) {
	resolver.mu.Lock()
	resolver.queries = append(resolver.queries, query)
	resolver.mu.Unlock()
}

func (resolver *probeDNSResolver) LookupIP(
	ctx context.Context,
	query platform.DNSQuery,
) ([]netip.Addr, error) {
	resolver.record(query)
	resolver.startOnce.Do(func() { close(resolver.addressStarted) })
	select {
	case <-resolver.releaseAddress:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
	}, nil
}

func (resolver *probeDNSResolver) LookupTXT(
	_ context.Context,
	query platform.DNSQuery,
) (string, error) {
	resolver.record(query)
	return "tcp://peer.example:11010", nil
}

func (resolver *probeDNSResolver) LookupSRV(
	_ context.Context,
	query platform.DNSQuery,
) ([]*net.SRV, error) {
	resolver.record(query)
	return []*net.SRV{{
		Target:   "peer.example.",
		Port:     11010,
		Priority: 10,
		Weight:   20,
	}}, nil
}

func TestDNSABIConformance(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	resolver := &probeDNSResolver{
		addressStarted: make(chan struct{}),
		releaseAddress: make(chan struct{}),
	}
	hostReactor := reactor.New(ctx, reactor.Options{
		Services: platform.Services{DNS: resolver},
	})
	defer hostReactor.Close()
	module := instantiateProbe(t, ctx, hostReactor)

	results, err := module.ExportedFunction("init_dns_probe").Call(ctx)
	requireStatus(t, "initialize DNS probe", results, err, 0)
	if status := driveProbe(t, ctx, module, "drive_dns_probe"); status != 0 {
		t.Fatalf("initial DNS status = 0x%x", status)
	}
	select {
	case <-resolver.addressStarted:
	case <-ctx.Done():
		t.Fatalf("wait for DNS lookup: %v", ctx.Err())
	}
	select {
	case <-hostReactor.Completions():
		t.Fatal("DNS completed before resolver release")
	default:
	}
	close(resolver.releaseAddress)

	status := uint32(0)
	for status&probeDone == 0 {
		waitCompletion(t, ctx, hostReactor)
		status = driveProbe(t, ctx, module, "drive_dns_probe")
	}
	resolver.mu.Lock()
	queries := append([]platform.DNSQuery(nil), resolver.queries...)
	resolver.mu.Unlock()
	if len(queries) != 3 {
		t.Fatalf("DNS query count = %d, want 3", len(queries))
	}
	assertDNSQuery(t, queries[0], "peer.example", 0, uint32Pointer(7), stringPointer("mihomo"))
	assertDNSQuery(t, queries[1], "_easytier.example", 4, nil, nil)
	assertDNSQuery(t, queries[2], "_easytier._udp.example", 6, uint32Pointer(9), stringPointer(""))
}

type probeEnvironment struct {
	mu       sync.Mutex
	remote   *net.UDPAddr
	context  platform.SocketContext
	started  chan struct{}
	released chan struct{}
}

func (environment *probeEnvironment) LocalAddrForRemote(
	ctx context.Context,
	remote *net.UDPAddr,
	socketContext platform.SocketContext,
) (net.Addr, error) {
	environment.mu.Lock()
	environment.remote = remote
	environment.context = socketContext
	environment.mu.Unlock()
	close(environment.started)
	select {
	case <-environment.released:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 40000}, nil
}

func TestEnvironmentABIConformance(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	environment := &probeEnvironment{
		started:  make(chan struct{}),
		released: make(chan struct{}),
	}
	hostReactor := reactor.New(ctx, reactor.Options{
		Services: platform.Services{Environment: environment},
	})
	defer hostReactor.Close()
	module := instantiateProbe(t, ctx, hostReactor)

	results, err := module.ExportedFunction("init_environment_probe").Call(ctx)
	requireStatus(t, "initialize environment probe", results, err, 0)
	if status := driveProbe(t, ctx, module, "drive_environment_probe"); status != 0 {
		t.Fatalf("initial environment status = 0x%x", status)
	}
	select {
	case <-environment.started:
	case <-ctx.Done():
		t.Fatalf("wait for environment operation: %v", ctx.Err())
	}
	close(environment.released)
	waitCompletion(t, ctx, hostReactor)
	if status := driveProbe(t, ctx, module, "drive_environment_probe"); status != probeDone {
		t.Fatalf("environment status = 0x%x, want 0x%x", status, probeDone)
	}
	environment.mu.Lock()
	defer environment.mu.Unlock()
	if environment.remote.String() != "203.0.113.2:443" ||
		environment.context.IPVersion != platform.IPVersionBoth ||
		environment.context.SocketMark != nil ||
		environment.context.NetNS != nil {
		t.Fatalf(
			"environment request = remote %v, context %#v",
			environment.remote,
			environment.context,
		)
	}
}

func TestPacketABIBackpressure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	hostReactor := reactor.New(ctx, reactor.Options{})
	defer hostReactor.Close()
	handle, err := hostReactor.RegisterPacketSink(1)
	if err != nil {
		t.Fatalf("register packet sink: %v", err)
	}
	module := instantiateProbe(t, ctx, hostReactor)
	results, err := module.ExportedFunction("init_packet_probe").Call(ctx, handle)
	requireStatus(t, "initialize packet probe", results, err, 0)
	if status := driveProbe(t, ctx, module, "drive_packet_probe"); status != 0 {
		t.Fatalf("initial packet status = 0x%x", status)
	}
	select {
	case <-hostReactor.Completions():
		t.Fatal("packet writer became ready while sink was full")
	default:
	}
	first, err := hostReactor.ReceivePacket(ctx, handle)
	if err != nil || string(first) != "first-packet" {
		t.Fatalf("first packet = %q, error %v", first, err)
	}
	waitCompletion(t, ctx, hostReactor)
	if status := driveProbe(t, ctx, module, "drive_packet_probe"); status != probeDone {
		t.Fatalf("packet status = 0x%x, want 0x%x", status, probeDone)
	}
	second, err := hostReactor.ReceivePacket(ctx, handle)
	if err != nil || string(second) != "second-packet" {
		t.Fatalf("second packet = %q, error %v", second, err)
	}
}

func TestUDPMetadataWireFormat(t *testing.T) {
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
		t.Fatalf("UDP metadata = %x, want %x", encoded, expected)
	}
}

func instantiateProbe(
	t *testing.T,
	ctx context.Context,
	hostReactor *reactor.Reactor,
) api.Module {
	t.Helper()
	runtime := wazero.NewRuntimeWithConfig(
		ctx,
		wazero.NewRuntimeConfig().WithCloseOnContextDone(true),
	)
	t.Cleanup(func() {
		if err := runtime.Close(contextutil.WithoutCancel(ctx)); err != nil {
			t.Errorf("close probe runtime: %v", err)
		}
	})
	adapter, err := New(hostReactor)
	if err != nil {
		t.Fatalf("create host ABI adapter: %v", err)
	}
	if err := adapter.Instantiate(ctx, runtime); err != nil {
		t.Fatalf("instantiate host ABI: %v", err)
	}
	wasi_snapshot_preview1.MustInstantiate(ctx, runtime)
	wasm, err := os.ReadFile(filepath.Join("..", "..", "testdata", "wasi_socket_guest.wasm"))
	if err != nil {
		t.Fatalf("read probe WASM: %v", err)
	}
	compiled, err := runtime.CompileModule(ctx, wasm)
	if err != nil {
		t.Fatalf("compile probe WASM: %v", err)
	}
	t.Cleanup(func() { _ = compiled.Close(contextutil.WithoutCancel(ctx)) })
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
		t.Fatalf("instantiate probe WASM: %v", err)
	}
	return module
}

func driveProbe(
	t *testing.T,
	ctx context.Context,
	module api.Module,
	export string,
) uint32 {
	t.Helper()
	results, err := module.ExportedFunction(export).Call(ctx)
	if err != nil || len(results) != 1 {
		t.Fatalf("%s: results=%v error=%v", export, results, err)
	}
	status := uint32(results[0])
	if status&probeError != 0 {
		t.Fatalf("%s failed with status 0x%x", export, status)
	}
	return status
}

func requireStatus(
	t *testing.T,
	operation string,
	results []uint64,
	err error,
	want int32,
) {
	t.Helper()
	if err != nil || len(results) != 1 || int32(results[0]) != want {
		t.Fatalf("%s: results=%v error=%v want=%d", operation, results, err, want)
	}
}

func waitCompletion(
	t *testing.T,
	ctx context.Context,
	hostReactor *reactor.Reactor,
) {
	t.Helper()
	select {
	case <-hostReactor.Completions():
	case <-ctx.Done():
		t.Fatalf("wait for host completion: %v", ctx.Err())
	}
}

func assertDNSQuery(
	t *testing.T,
	query platform.DNSQuery,
	host string,
	ipVersion uint8,
	mark *uint32,
	netns *string,
) {
	t.Helper()
	if query.Host != host ||
		query.IPVersion != ipVersion ||
		!equalPointer(query.SocketMark, mark) ||
		!equalPointer(query.NetNS, netns) {
		t.Fatalf("DNS query = %#v", query)
	}
}

func equalPointer[T comparable](left, right *T) bool {
	return left == nil && right == nil ||
		left != nil && right != nil && *left == *right
}

func uint32Pointer(value uint32) *uint32 {
	return &value
}

func stringPointer(value string) *string {
	return &value
}

func stopTimer(timer *time.Timer) {
	if timer == nil || timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}
