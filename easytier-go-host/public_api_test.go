package host_test

import (
	"context"
	"net"
	"net/netip"
	"testing"

	corehost "github.com/easytier/easytier/easytier-go-host"
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

type publicSocketFactory struct{}

func (publicSocketFactory) ConnectTCP(
	context.Context,
	corehost.TCPConnectOptions,
) (net.Conn, error) {
	return nil, nil
}

func (publicSocketFactory) BindUDP(
	context.Context,
	corehost.UDPBindOptions,
) (net.PacketConn, error) {
	return nil, nil
}

func (publicSocketFactory) ListenTCP(
	context.Context,
	corehost.TCPListenOptions,
) (net.Listener, error) {
	return nil, nil
}

var _ corehost.DNSResolver = publicDNSResolver{}
var _ corehost.ConnectorEnvironment = publicConnectorEnvironment{}
var _ corehost.SocketFactory = publicSocketFactory{}

func TestBridgePublicPacketLifecycle(t *testing.T) {
	bridge := corehost.NewBridge(corehost.BridgeConfig{})
	defer bridge.Close()
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
		SocketFactory:        publicSocketFactory{},
		DNSResolver:          publicDNSResolver{},
		ConnectorEnvironment: publicConnectorEnvironment{},
	})
	bridge.Close()
}
