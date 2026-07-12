package host_test

import (
	"testing"

	corehost "github.com/easytier/easytier/tools/wasi-socket-poc/host"
)

func TestBridgePublicPacketLifecycle(t *testing.T) {
	bridge := corehost.NewBridge(corehost.BridgeConfig{})
	defer bridge.Close()
	if bridge.Completion() == nil {
		t.Fatal("bridge returned a nil completion channel")
	}
	handle, err := bridge.RegisterPacketSink(1)
	if err != nil {
		t.Fatalf("register packet sink: %v", err)
	}
	if _, err := bridge.ConsumePacket(handle); err == nil {
		t.Fatal("empty packet sink unexpectedly returned a packet")
	}
}
