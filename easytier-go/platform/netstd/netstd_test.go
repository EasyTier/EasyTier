package netstd

import (
	"context"
	"net"
	"testing"

	"github.com/EasyTier/EasyTier/easytier-go/platform"
)

func TestDNSResolverNormalizesIPv4Literal(t *testing.T) {
	addresses, err := (DNSResolver{}).LookupIP(
		context.Background(),
		platform.DNSQuery{Host: "127.0.0.1"},
	)
	if err != nil {
		t.Fatalf("resolve IPv4 literal: %v", err)
	}
	if len(addresses) != 1 || !addresses[0].Is4() {
		t.Fatalf("resolved addresses = %v, want one canonical IPv4", addresses)
	}
}

func TestSocketFactoryReusesTCPSourcePort(t *testing.T) {
	firstServer := listenTCP4(t)
	defer firstServer.Close()
	secondServer := listenTCP4(t)
	defer secondServer.Close()
	sourcePort := unusedTCP4Port(t)

	reuse := true
	bind := platform.TCPBindOptions{
		Context:   platform.SocketContext{IPVersion: platform.IPVersionV4},
		LocalAddr: &net.TCPAddr{IP: net.IPv4zero, Port: sourcePort},
		ReuseAddr: &reuse,
		ReusePort: true,
		OnlyV6:    true,
	}
	first := connectTCP(t, firstServer, bind, platform.TCPConnectSTUNProbe)
	defer first.Close()
	second := connectTCP(t, secondServer, bind, platform.TCPConnectSTUNProbe)
	defer second.Close()

	if first.LocalAddr().(*net.TCPAddr).Port != sourcePort ||
		second.LocalAddr().(*net.TCPAddr).Port != sourcePort {
		t.Fatalf("source ports = %v, %v, want %d",
			first.LocalAddr(), second.LocalAddr(), sourcePort)
	}
}

func TestSocketFactoryAcceptsOnlyV6ForIPv4HolePunchListener(t *testing.T) {
	listener, err := (SocketFactory{}).ListenTCP(
		context.Background(),
		platform.TCPListenOptions{
			Bind: platform.TCPBindOptions{
				Context:   platform.SocketContext{IPVersion: platform.IPVersionV4},
				LocalAddr: &net.TCPAddr{IP: net.IPv4zero},
				OnlyV6:    true,
			},
			Purpose: platform.TCPListenHolePunch,
		},
	)
	if err != nil {
		t.Fatalf("listen for IPv4 TCP hole punch: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("close TCP hole punch listener: %v", err)
	}
}

func listenTCP4(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on loopback: %v", err)
	}
	return listener
}

func unusedTCP4Port(t *testing.T) int {
	t.Helper()
	listener := listenTCP4(t)
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release source port: %v", err)
	}
	return port
}

func connectTCP(
	t *testing.T,
	server net.Listener,
	bind platform.TCPBindOptions,
	purpose platform.TCPConnectPurpose,
) net.Conn {
	t.Helper()
	connection, err := (SocketFactory{}).ConnectTCP(
		context.Background(),
		platform.TCPConnectOptions{
			RemoteAddr: server.Addr().(*net.TCPAddr),
			Bind:       bind,
			Purpose:    purpose,
		},
	)
	if err != nil {
		t.Fatalf("connect TCP socket: %v", err)
	}
	return connection
}
