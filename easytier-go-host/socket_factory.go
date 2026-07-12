package host

import (
	"context"
	"fmt"
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

type TCPBindOptions struct {
	LocalAddr  *net.TCPAddr
	SocketMark *uint32
	BindDevice *string
	ReuseAddr  *bool
	ReusePort  bool
	OnlyV6     bool
}

type TCPConnectOptions struct {
	RemoteAddr *net.TCPAddr
	Bind       TCPBindOptions
	Purpose    TCPConnectPurpose
}

type UDPBindOptions struct {
	LocalAddr  *net.UDPAddr
	SocketMark *uint32
	BindDevice *string
	ReuseAddr  bool
	ReusePort  bool
	OnlyV6     bool
	Purpose    UDPBindPurpose
}

type TCPListenOptions struct {
	Bind    TCPBindOptions
	Purpose TCPListenPurpose
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
	if options.Purpose == TCPConnectFake {
		return nil, fmt.Errorf("FakeTCP is not supported by NetSocketFactory")
	}
	if err := validateNetTCPBindOptions(options.Bind); err != nil {
		return nil, err
	}
	dialer := net.Dialer{LocalAddr: options.Bind.LocalAddr}
	return dialer.DialContext(ctx, "tcp", options.RemoteAddr.String())
}

func (NetSocketFactory) BindUDP(
	_ context.Context,
	options UDPBindOptions,
) (net.PacketConn, error) {
	if options.SocketMark != nil || options.BindDevice != nil || options.ReuseAddr ||
		options.ReusePort || options.OnlyV6 {
		return nil, fmt.Errorf("non-default UDP bind policy is not supported by NetSocketFactory")
	}
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
	if err := validateNetTCPBindOptions(options.Bind); err != nil {
		return nil, err
	}
	return (&net.ListenConfig{}).Listen(ctx, "tcp", options.Bind.LocalAddr.String())
}

func validateNetTCPBindOptions(options TCPBindOptions) error {
	if options.SocketMark != nil || options.BindDevice != nil || options.ReuseAddr != nil ||
		options.ReusePort || options.OnlyV6 {
		return fmt.Errorf("non-default TCP bind policy is not supported by NetSocketFactory")
	}
	return nil
}
