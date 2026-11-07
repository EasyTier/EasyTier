package platform

import (
	"context"
	"net"
	"net/netip"
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

// BindConfig is the common TCP/UDP socket configuration supplied by core.
// Nil ReuseAddr selects the host default; explicit false and true always win.
type BindConfig struct {
	Context     SocketContext
	NeedProtect bool
	LocalAddr   *netip.AddrPort
	BindDevice  *string
	ReuseAddr   *bool
	ReusePort   bool
	OnlyV6      bool
}

type TCPConnectOptions struct {
	RemoteAddr *net.TCPAddr
	Bind       BindConfig
	Purpose    TCPConnectPurpose
}

type TCPListenOptions struct {
	Bind    BindConfig
	Purpose TCPListenPurpose
}

// SocketFactory creates sockets authorized for one EasyTier instance.
// The host runtime owns every resource returned after a successful call.
type SocketFactory interface {
	ConnectTCP(context.Context, TCPConnectOptions) (net.Conn, error)
	BindUDP(context.Context, BindConfig) (net.PacketConn, error)
	ListenTCP(context.Context, TCPListenOptions) (net.Listener, error)
}
