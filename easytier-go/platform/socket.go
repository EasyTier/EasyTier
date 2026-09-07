package platform

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
	TCPConnectSTUNProbe
	TCPConnectSocks5
	TCPConnectPortForward
	TCPConnectDataPlane
)

type UDPBindPurpose uint8

const (
	UDPBindHolePunchControl UDPBindPurpose = iota
	UDPBindHolePunchCandidate
	UDPBindDirect
	UDPBindPortBoundListener
	UDPBindProxyNAT
	UDPBindSTUNProbe
	UDPBindSocks5
	UDPBindPortForward
	UDPBindPortLease
)

type TCPListenPurpose uint8

const (
	TCPListenDirect TCPListenPurpose = iota
	TCPListenHolePunch
	TCPListenManual
	TCPListenProxyNAT
	TCPListenSocks5
	TCPListenPortForward
	TCPListenPortLease
)

type IPVersion uint8

const (
	IPVersionV4 IPVersion = iota
	IPVersionV6
	IPVersionBoth
)

type SocketContext struct {
	IPVersion  IPVersion
	SocketMark *uint32
	NetNS      *string
}

type TCPBindOptions struct {
	Context    SocketContext
	LocalAddr  *net.TCPAddr
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
	Context    SocketContext
	LocalAddr  *net.UDPAddr
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

// SocketFactory creates sockets authorized for one EasyTier instance.
// The host runtime owns every resource returned after a successful call.
type SocketFactory interface {
	ConnectTCP(context.Context, TCPConnectOptions) (net.Conn, error)
	BindUDP(context.Context, UDPBindOptions) (net.PacketConn, error)
	ListenTCP(context.Context, TCPListenOptions) (net.Listener, error)
}
