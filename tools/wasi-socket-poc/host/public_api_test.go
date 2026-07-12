package host_test

import (
	"context"
	"net"
	"net/netip"
	"testing"

	corehost "github.com/easytier/easytier/tools/wasi-socket-poc/host"
)

type publicDNSResolver struct{}

func (publicDNSResolver) LookupIP(context.Context, corehost.DNSQuery) ([]netip.Addr, error) {
	return nil, nil
}

func (publicDNSResolver) LookupTXT(context.Context, corehost.DNSQuery) (string, error) {
	return "", nil
}

func (publicDNSResolver) LookupSRV(context.Context, corehost.DNSQuery) ([]*net.SRV, error) {
	return nil, nil
}

type publicConnectorEnvironment struct{}

func (publicConnectorEnvironment) LocalAddrForRemote(
	context.Context,
	*net.UDPAddr,
) (net.Addr, error) {
	return nil, nil
}

func (publicConnectorEnvironment) UDPPortMapping(context.Context, uint64) (net.Addr, error) {
	return nil, nil
}

func (publicConnectorEnvironment) TCPPortMapping(context.Context, uint16) (net.Addr, error) {
	return nil, nil
}

var _ corehost.DNSResolver = publicDNSResolver{}
var _ corehost.ConnectorEnvironment = publicConnectorEnvironment{}

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

func TestBridgePublicPolicyInjection(t *testing.T) {
	bridge := corehost.NewBridge(corehost.BridgeConfig{
		DNSResolver:          publicDNSResolver{},
		ConnectorEnvironment: publicConnectorEnvironment{},
	})
	bridge.Close()
}
