package host

import (
	"context"
	"net"
	"testing"
)

func TestNewBridgeSnapshotsTCPStreams(t *testing.T) {
	const handle uint64 = 41
	connection, peer := net.Pipe()
	defer peer.Close()
	streams := map[uint64]net.Conn{handle: connection}
	bridge := NewBridge(BridgeConfig{TCPStreams: streams})
	defer bridge.Close()

	delete(streams, handle)
	bridge.mu.Lock()
	_, exists := bridge.handles[handle]
	bridge.mu.Unlock()
	if !exists {
		t.Fatal("bridge TCP resource table aliases the caller's map")
	}
}

func TestBridgeCloseClearsResourcesAndRejectsNewWork(t *testing.T) {
	const handle uint64 = 42
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("create UDP socket: %v", err)
	}
	bridge := NewBridge(BridgeConfig{
		UDPSockets: map[uint64]net.PacketConn{handle: packet},
	})
	bridge.Close()
	bridge.Close()

	bridge.mu.Lock()
	closed := bridge.closed
	packetCount := len(bridge.packets)
	bridge.mu.Unlock()
	if !closed || packetCount != 0 {
		t.Fatalf("closed bridge retained resources: closed=%v packets=%d", closed, packetCount)
	}
	if status := bridge.startUDPSendReady(context.Background(), nil, handle, 1); status != opaqueHostInvalid {
		t.Fatalf("closed bridge accepted UDP work: %d", status)
	}
	if _, err := bridge.RegisterPacketSink(1); err == nil {
		t.Fatal("closed bridge registered a packet sink")
	}
	started := false
	status := bridge.startEnvironmentOperation(2, func(context.Context) (net.Addr, error) {
		started = true
		return nil, nil
	})
	if status != opaqueHostInvalid || started {
		t.Fatalf("closed bridge started environment work: status=%d started=%v", status, started)
	}
	if err := bridge.InstantiateHost(context.Background(), nil); err == nil {
		t.Fatal("closed bridge instantiated a host module")
	}
}
