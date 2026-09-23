package platform

import (
	"context"
	"net"
	"net/netip"
)

type ConnectorEnvironment interface {
	LocalAddrForRemote(context.Context, *net.UDPAddr, SocketContext) (net.Addr, error)
}

// EnvironmentSnapshot is the host-observed network state captured when an
// EasyTier instance is created. Core remains responsible for all policy
// decisions made from these facts.
//
// TODO: Split static declarations from dynamic network facts and add a
// versioned, event-driven host ABI update path. This snapshot is currently
// frozen at CreateInstance, so long-lived instances do not observe interface,
// address, or preferred-source changes.
type EnvironmentSnapshot struct {
	PublicIPv4           *netip.Addr
	InterfaceIPv4s       []netip.Addr
	PublicIPv6           *netip.Addr
	InterfaceIPv6s       []netip.Addr
	MappedListeners      []string
	LocalIPs             []netip.Addr
	ProtectedTCPPorts    []uint16
	PreferredIPv6Sources []PreferredIPv6Source
}

type PreferredIPv6Source struct {
	IP      netip.Addr
	IfIndex uint32
}

type Services struct {
	Sockets     SocketFactory
	DNS         DNSResolver
	Environment ConnectorEnvironment
	Snapshot    EnvironmentSnapshot
}
