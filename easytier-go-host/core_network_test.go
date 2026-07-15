package host

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

type coreNetworkInstance struct {
	bridge     *opaqueBridge
	runtime    wazero.Runtime
	module     api.Module
	handle     uint64
	packetSink uint64
	dropped    bool
}

type coreNetworkDNSResolver struct {
	mu                  sync.Mutex
	queries             []string
	successfulIPQueries []string
}

func (resolver *coreNetworkDNSResolver) record(query DNSQuery) {
	resolver.mu.Lock()
	resolver.queries = append(resolver.queries, query.Host)
	resolver.mu.Unlock()
}

func (resolver *coreNetworkDNSResolver) LookupIP(
	_ context.Context,
	query DNSQuery,
) ([]netip.Addr, error) {
	resolver.record(query)
	address, err := netip.ParseAddr(query.Host)
	if err != nil {
		return nil, fmt.Errorf("network test does not resolve hostname %q", query.Host)
	}
	resolver.mu.Lock()
	resolver.successfulIPQueries = append(resolver.successfulIPQueries, query.Host)
	resolver.mu.Unlock()
	return []netip.Addr{address}, nil
}

func (resolver *coreNetworkDNSResolver) LookupTXT(
	_ context.Context,
	query DNSQuery,
) (string, error) {
	resolver.record(query)
	return "", fmt.Errorf("network test does not resolve TXT %q", query.Host)
}

func (resolver *coreNetworkDNSResolver) LookupSRV(
	_ context.Context,
	query DNSQuery,
) ([]*net.SRV, error) {
	resolver.record(query)
	return nil, fmt.Errorf("network test does not resolve SRV %q", query.Host)
}

func (resolver *coreNetworkDNSResolver) recorded() []string {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return append([]string(nil), resolver.queries...)
}

func (resolver *coreNetworkDNSResolver) resolvedIP(host string) bool {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	for _, query := range resolver.successfulIPQueries {
		if query == host {
			return true
		}
	}
	return false
}

func TestTwoCoreInstancesConnectAndExchangePacket(t *testing.T) {
	wasm := buildCore(t)
	fixture, err := os.ReadFile(filepath.Join("testdata", "minimal_core_instance.json"))
	if err != nil {
		t.Fatalf("read core instance fixture: %v", err)
	}
	serverConfig := coreNetworkConfig(t, fixture, 1, "10.144.0.1", 0, false)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server := newCoreNetworkInstance(t, ctx, wasm, serverConfig)
	defer server.close(t, ctx)
	server.start(t, ctx)
	port := server.bridge.tcpListenerPort(t)

	clientConfig := coreNetworkConfig(t, fixture, 2, "10.144.0.2", port, true)
	client := newCoreNetworkInstance(t, ctx, wasm, clientConfig)
	defer client.close(t, ctx)

	client.start(t, ctx)
	packet := ipv4Packet(net.IPv4(10, 144, 0, 2), net.IPv4(10, 144, 0, 1), []byte("go-host-core"))
	driveCoreNetworkUntilPacket(t, ctx, server, client, packet)

	serverHandles, serverListeners := server.bridge.hostResourceCounts()
	clientHandles, _ := client.bridge.hostResourceCounts()
	if serverListeners != 1 || serverHandles == 0 || clientHandles == 0 {
		t.Fatalf(
			"peer connection did not use host resources: server handles=%d listeners=%d client handles=%d",
			serverHandles,
			serverListeners,
			clientHandles,
		)
	}
	if server.bridge.environmentCallCount() != 0 || client.bridge.environmentCallCount() != 0 {
		t.Fatal("P2P-disabled network unexpectedly used environment operations")
	}
	if resolver := client.bridge.dnsResolver.(*coreNetworkDNSResolver); !resolver.resolvedIP("127.0.0.1") {
		t.Fatalf("client did not resolve 127.0.0.1 through Go host: queries=%v", resolver.recorded())
	}

	client.stop(t, ctx)
	server.stop(t, ctx)
	client.drop(t, ctx)
	server.drop(t, ctx)
	if handles, listeners := server.bridge.hostResourceCounts(); handles != 0 || listeners != 0 {
		t.Fatalf("server host resources leaked: handles=%d listeners=%d", handles, listeners)
	}
	if handles, listeners := client.bridge.hostResourceCounts(); handles != 0 || listeners != 0 {
		t.Fatalf("client host resources leaked: handles=%d listeners=%d", handles, listeners)
	}
}

func newCoreNetworkInstance(
	t *testing.T,
	ctx context.Context,
	wasm []byte,
	config []byte,
) *coreNetworkInstance {
	t.Helper()
	bridge := newOpaqueBridge(nil, nil)
	initialized := false
	defer func() {
		if !initialized {
			bridge.close()
		}
	}()
	resolver := &coreNetworkDNSResolver{}
	bridge.dnsResolver = resolver
	runtime, module, core, packetSink, _ := instantiateCoreModule(t, ctx, wasm, bridge, config)
	initialized = true
	return &coreNetworkInstance{
		bridge:     bridge,
		runtime:    runtime,
		module:     module,
		handle:     core.Handle(),
		packetSink: packetSink,
	}
}

func (instance *coreNetworkInstance) start(t *testing.T, ctx context.Context) {
	t.Helper()
	coreCallStatus(t, ctx, instance.module, instance.handle, "easytier_instance_start")
	driveCoreUntil(t, ctx, instance.module, instance.bridge, instance.handle, coreStateRunning)
}

func (instance *coreNetworkInstance) stop(t *testing.T, ctx context.Context) {
	t.Helper()
	coreCallStatus(t, ctx, instance.module, instance.handle, "easytier_instance_stop")
	driveCoreUntil(t, ctx, instance.module, instance.bridge, instance.handle, coreStateStopped)
}

func (instance *coreNetworkInstance) drop(t *testing.T, ctx context.Context) {
	t.Helper()
	if instance.dropped {
		return
	}
	coreCallStatus(t, ctx, instance.module, instance.handle, "easytier_instance_drop")
	instance.dropped = true
}

func (instance *coreNetworkInstance) close(t *testing.T, ctx context.Context) {
	t.Helper()
	if !instance.dropped {
		_, _ = instance.module.ExportedFunction("easytier_instance_drop").Call(ctx, instance.handle)
	}
	_ = instance.runtime.Close(ctx)
	instance.bridge.close()
}

func (b *opaqueBridge) hostResourceCounts() (int, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.handles), len(b.listeners)
}

func (b *opaqueBridge) tcpListenerPort(t *testing.T) int {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.listeners) != 1 {
		t.Fatalf("expected one host TCP listener, got %d", len(b.listeners))
	}
	for _, listener := range b.listeners {
		address, ok := listener.listener.Addr().(*net.TCPAddr)
		if !ok {
			t.Fatalf("host listener returned %T address", listener.listener.Addr())
		}
		return address.Port
	}
	t.Fatal("host TCP listener disappeared")
	return 0
}

func driveCoreNetworkUntilPacket(
	t *testing.T,
	ctx context.Context,
	server *coreNetworkInstance,
	client *coreNetworkInstance,
	packet []byte,
) {
	t.Helper()
	nextInjection := time.Now()
	injections := 0
	exchangeTimeout := time.NewTimer(10 * time.Second)
	defer stopCoreTimer(exchangeTimeout)
	for {
		driveCoreOnce(t, ctx, server.module, server.handle)
		driveCoreOnce(t, ctx, client.module, client.handle)
		if received, err := server.bridge.consumePacket(server.packetSink); err == nil {
			if string(received) != string(packet) {
				t.Fatalf("unexpected host packet: got=%x want=%x", received, packet)
			}
			return
		}

		now := time.Now()
		if !now.Before(nextInjection) {
			sendCorePacket(t, ctx, client.module, client.handle, packet)
			injections++
			nextInjection = now.Add(100 * time.Millisecond)
		}
		serverDeadline := checkedCoreDeadline(t, ctx, server)
		clientDeadline := checkedCoreDeadline(t, ctx, client)
		wait := time.Until(nextInjection)
		wait = minCoreWait(wait, serverDeadline)
		wait = minCoreWait(wait, clientDeadline)
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-server.bridge.completion:
			stopCoreTimer(timer)
		case <-client.bridge.completion:
			stopCoreTimer(timer)
		case <-timer.C:
		case <-exchangeTimeout.C:
			stopCoreTimer(timer)
			serverHandles, serverListeners := server.bridge.hostResourceCounts()
			clientHandles, clientListeners := client.bridge.hostResourceCounts()
			serverDeadline := checkedCoreDeadline(t, ctx, server)
			clientDeadline := checkedCoreDeadline(t, ctx, client)
			t.Fatalf(
				"core packet exchange timed out after %d injections: server handles=%d listeners=%d deadline=%d client handles=%d listeners=%d deadline=%d environment_calls=%d dns_queries=%v",
				injections,
				serverHandles,
				serverListeners,
				serverDeadline,
				clientHandles,
				clientListeners,
				clientDeadline,
				client.bridge.environmentCallCount(),
				client.bridge.dnsResolver.(*coreNetworkDNSResolver).recorded(),
			)
		case <-ctx.Done():
			stopCoreTimer(timer)
			t.Fatalf("wait for core packet exchange: %v", ctx.Err())
		}
	}
}

func checkedCoreDeadline(
	t *testing.T,
	ctx context.Context,
	instance *coreNetworkInstance,
) int64 {
	t.Helper()
	deadline := coreDeadline(t, ctx, instance.module, instance.handle)
	if deadline < 0 {
		t.Fatalf(
			"query core deadline: status=%d core_error=%s",
			deadline,
			coreError(t, ctx, instance.module, instance.handle),
		)
	}
	return deadline
}

func minCoreWait(current time.Duration, deadline int64) time.Duration {
	if deadline == math.MaxInt64 {
		return current
	}
	return min(current, time.Duration(deadline)*time.Millisecond)
}

func stopCoreTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func sendCorePacket(
	t *testing.T,
	ctx context.Context,
	module api.Module,
	handle uint64,
	packet []byte,
) {
	t.Helper()
	pointer := coreAllocate(t, ctx, module, uint32(len(packet)))
	if !module.Memory().Write(pointer, packet) {
		coreFree(t, ctx, module, pointer)
		t.Fatal("write host packet to guest memory")
	}
	results, err := module.ExportedFunction("easytier_instance_send_packet").Call(
		ctx,
		handle,
		uint64(pointer),
		uint64(len(packet)),
	)
	coreFree(t, ctx, module, pointer)
	if err != nil || len(results) != 1 || int32(results[0]) != 0 {
		t.Fatalf(
			"send host packet: results=%v error=%v core_error=%s",
			results,
			err,
			coreError(t, ctx, module, handle),
		)
	}
}

func coreNetworkConfig(
	t *testing.T,
	fixture []byte,
	peerID uint32,
	virtualIPv4 string,
	port int,
	connect bool,
) []byte {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal(fixture, &config); err != nil {
		t.Fatalf("decode core fixture: %v", err)
	}
	instance := jsonObject(t, config, "instance")
	peer := jsonObject(t, instance, "peer")
	snapshot := jsonObject(t, peer, "snapshot")
	runtime := jsonObject(t, snapshot, "runtime")
	core := jsonObject(t, runtime, "core")
	node := jsonObject(t, core, "node")
	node["peer_id"] = peerID
	node["hostname"] = fmt.Sprintf("go-wasi-%d", peerID)
	node["network_name"] = "default"
	routes := jsonObject(t, core, "routes")
	routes["ipv4"] = map[string]any{"address": virtualIPv4, "prefix_len": 24}

	connectivity := jsonObject(t, instance, "connectivity")
	url := fmt.Sprintf("tcp://127.0.0.1:%d", port)
	if connect {
		connectivity["initial_peers"] = []string{url}
		connectivity["listeners"] = nil
	} else {
		connectivity["initial_peers"] = []any{}
		connectivity["listeners"] = map[string]any{
			"urls":        []string{url},
			"enable_ipv6": false,
			"socket_context": map[string]any{
				"ip_version":  "Both",
				"socket_mark": nil,
				"netns":       nil,
			},
		}
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("encode core network config: %v", err)
	}
	return encoded
}

func jsonObject(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := parent[key].(map[string]any)
	if !ok {
		t.Fatalf("core fixture field %q is not an object", key)
	}
	return value
}

func ipv4Packet(source, destination net.IP, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 1
	copy(packet[12:16], source.To4())
	copy(packet[16:20], destination.To4())
	copy(packet[20:], payload)
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:20]))
	return packet
}

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for index := 0; index < len(header); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[index : index+2]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
