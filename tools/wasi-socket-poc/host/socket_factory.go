package host

import (
	"context"
	"net"
)

type TCPConnectPurpose uint8

const (
	TCPConnectDirect TCPConnectPurpose = iota
	TCPConnectFake
	TCPConnectHolePunch
	TCPConnectManual
	TCPConnectProxyNAT
)

type UDPBindPurpose uint8

const (
	UDPBindHolePunchControl UDPBindPurpose = iota
	UDPBindHolePunchCandidate
	UDPBindDirect
	UDPBindPortBoundListener
	UDPBindProxyNAT
)

type TCPListenPurpose uint8

const (
	TCPListenDirect TCPListenPurpose = iota
	TCPListenHolePunch
	TCPListenManual
	TCPListenProxyNAT
)

type TCPConnectOptions struct {
	RemoteAddr *net.TCPAddr
	LocalAddr  *net.TCPAddr
	Purpose    TCPConnectPurpose
}

type UDPBindOptions struct {
	LocalAddr *net.UDPAddr
	Purpose   UDPBindPurpose
}

type TCPListenOptions struct {
	LocalAddr *net.TCPAddr
	Purpose   TCPListenPurpose
}

// SocketFactory owns only socket creation. The bridge retains every returned
// resource and drives its read, write, accept, cancellation, and close paths.
type SocketFactory interface {
	ConnectTCP(context.Context, TCPConnectOptions) (net.Conn, error)
	BindUDP(context.Context, UDPBindOptions) (net.PacketConn, error)
	ListenTCP(context.Context, TCPListenOptions) (net.Listener, error)
}

// NetSocketFactory implements SocketFactory with the Go standard library.
type NetSocketFactory struct{}

func (NetSocketFactory) ConnectTCP(
	ctx context.Context,
	options TCPConnectOptions,
) (net.Conn, error) {
	dialer := net.Dialer{LocalAddr: options.LocalAddr}
	return dialer.DialContext(ctx, "tcp", options.RemoteAddr.String())
}

func (NetSocketFactory) BindUDP(
	_ context.Context,
	options UDPBindOptions,
) (net.PacketConn, error) {
	network := "udp4"
	if options.LocalAddr != nil && options.LocalAddr.IP.To4() == nil {
		network = "udp6"
	}
	return net.ListenUDP(network, options.LocalAddr)
}

func (NetSocketFactory) ListenTCP(
	ctx context.Context,
	options TCPListenOptions,
) (net.Listener, error) {
	return (&net.ListenConfig{}).Listen(ctx, "tcp", options.LocalAddr.String())
}
