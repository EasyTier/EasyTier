package host

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

type probeDNSResolver struct {
	mu             sync.Mutex
	queries        []decodedDNSQuery
	addressStarted chan struct{}
	releaseAddress chan struct{}
	startOnce      sync.Once
}

func (r *probeDNSResolver) record(query decodedDNSQuery) {
	r.mu.Lock()
	r.queries = append(r.queries, query)
	r.mu.Unlock()
}

func (r *probeDNSResolver) lookupIP(ctx context.Context, query decodedDNSQuery) ([]netip.Addr, error) {
	r.record(query)
	r.startOnce.Do(func() { close(r.addressStarted) })
	select {
	case <-r.releaseAddress:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}, nil
}

func (r *probeDNSResolver) lookupTXT(_ context.Context, query decodedDNSQuery) (string, error) {
	r.record(query)
	return "tcp://peer.example:11010", nil
}

func (r *probeDNSResolver) lookupSRV(_ context.Context, query decodedDNSQuery) ([]*net.SRV, error) {
	r.record(query)
	return []*net.SRV{{
		Target:   "peer.example.",
		Port:     11010,
		Priority: 10,
		Weight:   20,
	}}, nil
}

func (r *probeDNSResolver) recorded() []decodedDNSQuery {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]decodedDNSQuery(nil), r.queries...)
}

func TestOpaqueDNSDrivesCoreResolver(t *testing.T) {
	resolver := &probeDNSResolver{
		addressStarted: make(chan struct{}),
		releaseAddress: make(chan struct{}),
	}
	bridge := newOpaqueBridge(nil, nil)
	bridge.dnsResolver = resolver
	defer bridge.close()
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
	results, err := module.ExportedFunction("init_dns_probe").Call(ctx)
	if err != nil || len(results) != 1 || int32(results[0]) != 0 {
		t.Fatalf("initialize DNS probe: results=%v err=%v", results, err)
	}

	results, err = module.ExportedFunction("drive_dns_probe").Call(ctx)
	if err != nil || len(results) != 1 || uint32(results[0]) != 0 {
		t.Fatalf("bootstrap DNS probe: results=%v err=%v", results, err)
	}
	select {
	case <-resolver.addressStarted:
	case <-ctx.Done():
		t.Fatalf("wait for pending address query: %v", ctx.Err())
	}
	select {
	case <-bridge.completion:
		t.Fatal("DNS completion arrived before resolver release")
	default:
	}
	close(resolver.releaseAddress)

	status := uint32(0)
	for status&opaqueDone == 0 {
		select {
		case <-bridge.completion:
		case <-ctx.Done():
			t.Fatalf("wait for DNS probe: %v", ctx.Err())
		}
		results, err = module.ExportedFunction("drive_dns_probe").Call(ctx)
		if err != nil || len(results) != 1 {
			t.Fatalf("drive DNS probe: results=%v err=%v", results, err)
		}
		status = uint32(results[0])
		if status&opaqueError != 0 {
			t.Fatalf("DNS probe failed with status 0x%x", status)
		}
	}

	queries := resolver.recorded()
	if len(queries) != 3 {
		t.Fatalf("recorded %d DNS queries, want 3", len(queries))
	}
	assertDNSQuery(t, queries[0], "peer.example", 0, uint32Pointer(7), stringPointer("mihomo"))
	assertDNSQuery(t, queries[1], "_easytier.example", 4, nil, nil)
	assertDNSQuery(t, queries[2], "_easytier._udp.example", 6, uint32Pointer(9), stringPointer(""))
}

func assertDNSQuery(
	t *testing.T,
	query decodedDNSQuery,
	host string,
	ipVersion uint8,
	mark *uint32,
	netns *string,
) {
	t.Helper()
	if query.host != host || query.ipVersion != ipVersion || !equalPointer(query.socketMark, mark) || !equalPointer(query.netns, netns) {
		t.Fatalf("unexpected DNS query: %#v", query)
	}
}

func equalPointer[T comparable](left, right *T) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}

func uint32Pointer(value uint32) *uint32 {
	return &value
}

func stringPointer(value string) *string {
	return &value
}
