package host

import (
	"context"
	"net"
	"sync"
)

type recordingSocketFactory struct {
	inner  SocketFactory
	mu     sync.Mutex
	tcp    []TCPConnectOptions
	udp    []UDPBindOptions
	listen []TCPListenOptions
}

func (factory *recordingSocketFactory) ConnectTCP(
	ctx context.Context,
	options TCPConnectOptions,
) (net.Conn, error) {
	factory.mu.Lock()
	factory.tcp = append(factory.tcp, options)
	factory.mu.Unlock()
	return factory.inner.ConnectTCP(ctx, options)
}

func (factory *recordingSocketFactory) BindUDP(
	ctx context.Context,
	options UDPBindOptions,
) (net.PacketConn, error) {
	factory.mu.Lock()
	factory.udp = append(factory.udp, options)
	factory.mu.Unlock()
	return factory.inner.BindUDP(ctx, options)
}

func (factory *recordingSocketFactory) ListenTCP(
	ctx context.Context,
	options TCPListenOptions,
) (net.Listener, error) {
	factory.mu.Lock()
	factory.listen = append(factory.listen, options)
	factory.mu.Unlock()
	return factory.inner.ListenTCP(ctx, options)
}

func (factory *recordingSocketFactory) calls() (
	[]TCPConnectOptions,
	[]UDPBindOptions,
	[]TCPListenOptions,
) {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	return append([]TCPConnectOptions(nil), factory.tcp...),
		append([]UDPBindOptions(nil), factory.udp...),
		append([]TCPListenOptions(nil), factory.listen...)
}
