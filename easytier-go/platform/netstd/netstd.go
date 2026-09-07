package netstd

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/EasyTier/EasyTier/easytier-go/platform"
)

// SocketFactory implements platform.SocketFactory with the Go standard
// library and the socket controls required by EasyTier hole punching.
type SocketFactory struct{}

func (SocketFactory) ConnectTCP(
	ctx context.Context,
	options platform.TCPConnectOptions,
) (net.Conn, error) {
	if options.Purpose == platform.TCPConnectFake {
		return nil, fmt.Errorf("FakeTCP is not supported by netstd")
	}
	if err := validateTCPBindOptions(options.Bind); err != nil {
		return nil, err
	}
	dialer := net.Dialer{
		LocalAddr: options.Bind.LocalAddr,
		Control:   tcpControl(options.Bind),
	}
	connection, err := dialer.DialContext(ctx, "tcp", options.RemoteAddr.String())
	if err != nil {
		return nil, err
	}
	if options.Purpose == platform.TCPConnectSTUNProbe {
		if err := connection.(*net.TCPConn).SetLinger(0); err != nil {
			_ = connection.Close()
			return nil, fmt.Errorf("set TCP STUN probe linger: %w", err)
		}
	}
	return connection, nil
}

func (SocketFactory) BindUDP(
	_ context.Context,
	options platform.UDPBindOptions,
) (net.PacketConn, error) {
	if options.Context.SocketMark != nil || options.Context.NetNS != nil ||
		options.BindDevice != nil || options.ReuseAddr || options.ReusePort {
		return nil, fmt.Errorf("non-default UDP bind policy is not supported by netstd")
	}
	return net.ListenUDP(udpNetwork(options), options.LocalAddr)
}

func (SocketFactory) ListenTCP(
	ctx context.Context,
	options platform.TCPListenOptions,
) (net.Listener, error) {
	if err := validateTCPBindOptions(options.Bind); err != nil {
		return nil, err
	}
	config := net.ListenConfig{Control: tcpControl(options.Bind)}
	return config.Listen(ctx, "tcp", options.Bind.LocalAddr.String())
}

func udpNetwork(options platform.UDPBindOptions) string {
	if options.LocalAddr != nil && options.LocalAddr.IP.To4() != nil {
		return "udp4"
	}
	if options.OnlyV6 {
		return "udp6"
	}
	if options.LocalAddr != nil && len(options.LocalAddr.IP) != 0 {
		return "udp"
	}
	if options.Context.IPVersion == platform.IPVersionV4 {
		return "udp4"
	}
	return "udp"
}

func validateTCPBindOptions(options platform.TCPBindOptions) error {
	if options.Context.SocketMark != nil || options.Context.NetNS != nil ||
		options.BindDevice != nil {
		return fmt.Errorf("non-default TCP bind policy is not supported by netstd")
	}
	return nil
}

func tcpControl(
	options platform.TCPBindOptions,
) func(string, string, syscall.RawConn) error {
	return func(network, _ string, connection syscall.RawConn) error {
		var socketErr error
		if err := connection.Control(func(descriptor uintptr) {
			socketErr = applyTCPSocketOptions(descriptor, network, options)
		}); err != nil {
			return err
		}
		return socketErr
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

type DNSResolver struct {
	Resolver *net.Resolver
}

func (resolver DNSResolver) configured() *net.Resolver {
	if resolver.Resolver != nil {
		return resolver.Resolver
	}
	return net.DefaultResolver
}

func (resolver DNSResolver) LookupIP(
	ctx context.Context,
	query platform.DNSQuery,
) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(query.Host); err == nil {
		return []netip.Addr{address.Unmap()}, nil
	}
	network := "ip"
	switch query.IPVersion {
	case 4:
		network = "ip4"
	case 6:
		network = "ip6"
	}
	addresses, err := resolver.configured().LookupNetIP(ctx, network, query.Host)
	if err != nil {
		return nil, err
	}
	for index := range addresses {
		addresses[index] = addresses[index].Unmap()
	}
	return addresses, nil
}

func (resolver DNSResolver) LookupTXT(
	ctx context.Context,
	query platform.DNSQuery,
) (string, error) {
	records, err := resolver.configured().LookupTXT(ctx, query.Host)
	if err != nil {
		return "", err
	}
	if len(records) == 0 {
		return "", fmt.Errorf("DNS TXT query for %q returned no records", query.Host)
	}
	return records[0], nil
}

func (resolver DNSResolver) LookupSRV(
	ctx context.Context,
	query platform.DNSQuery,
) ([]*net.SRV, error) {
	_, records, err := resolver.configured().LookupSRV(ctx, "", "", query.Host)
	return records, err
}

type ConnectorEnvironment struct{}

func (ConnectorEnvironment) LocalAddrForRemote(
	ctx context.Context,
	remote *net.UDPAddr,
	socketContext platform.SocketContext,
) (net.Addr, error) {
	if socketContext.SocketMark != nil || socketContext.NetNS != nil {
		return nil, fmt.Errorf("non-default connector context is not supported by netstd")
	}
	network := "udp"
	if remote.IP.To4() != nil {
		network = "udp4"
	} else if remote.IP.To16() != nil {
		network = "udp6"
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, network, remote.String())
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	return connection.LocalAddr(), nil
}

func Services() platform.Services {
	return platform.Services{
		Sockets:     SocketFactory{},
		DNS:         DNSResolver{},
		Environment: ConnectorEnvironment{},
	}
}
