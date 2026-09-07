package engine

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/EasyTier/EasyTier/easytier-go/internal/coreabi"
)

type packetConn struct {
	instance *Instance
	resource coreabi.ResourceID
	local    netip.AddrPort

	readMu  sync.Mutex
	writeMu sync.Mutex

	closed    atomic.Bool
	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

type datagramConn struct {
	packet *packetConn
	peer   netip.AddrPort
}

var _ net.Conn = (*datagramConn)(nil)

func newPacketConn(
	instance *Instance,
	result coreabi.OperationResult,
) *packetConn {
	return &packetConn{
		instance:  instance,
		resource:  result.Resource,
		local:     result.Local,
		closeDone: make(chan struct{}),
	}
}

func (conn *packetConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	conn.readMu.Lock()
	defer conn.readMu.Unlock()
	if conn.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	maximum := len(buffer)
	if maximum > maxDataPlaneTransfer {
		maximum = maxDataPlaneTransfer
	}
	result, err := conn.instance.performOperation(
		context.Background(),
		coreabi.OperationUDPReceive,
		func(
			callCtx context.Context,
			core dataPlaneCore,
		) (coreabi.OperationID, error) {
			return core.SubmitUDPReceive(
				callCtx,
				conn.resource,
				uint32(maximum),
			)
		},
	)
	if err != nil {
		return 0, nil, normalizeDeadlineError(err)
	}
	n := copy(buffer, result.Data)
	peer := net.UDPAddrFromAddrPort(result.Peer)
	if result.Truncated {
		return n, peer, io.ErrShortBuffer
	}
	return n, peer, nil
}

func (conn *packetConn) WriteTo(buffer []byte, address net.Addr) (int, error) {
	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()
	if conn.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(buffer) > maxDataPlaneTransfer {
		return 0, syscall.EMSGSIZE
	}
	peer, err := udpAddrPort(address)
	if err != nil {
		return 0, err
	}
	result, err := conn.instance.performOperation(
		context.Background(),
		coreabi.OperationUDPSend,
		func(
			callCtx context.Context,
			core dataPlaneCore,
		) (coreabi.OperationID, error) {
			return core.SubmitUDPSend(
				callCtx,
				conn.resource,
				peer,
				buffer,
			)
		},
	)
	if err != nil {
		return 0, normalizeDeadlineError(err)
	}
	if result.Length != len(buffer) {
		return result.Length, io.ErrShortWrite
	}
	return result.Length, nil
}

func (conn *packetConn) Close() error {
	conn.closeOnce.Do(func() {
		conn.closed.Store(true)
		conn.closeErr = conn.instance.closeDataPlaneResource(conn.resource)
		close(conn.closeDone)
	})
	<-conn.closeDone
	return conn.closeErr
}

func (conn *packetConn) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(conn.local)
}

func (conn *packetConn) SetDeadline(deadline time.Time) error {
	if conn.closed.Load() {
		return net.ErrClosed
	}
	return conn.instance.setDataPlaneResourceDeadline(
		conn.resource,
		coreabi.DeadlineRead|coreabi.DeadlineWrite,
		deadline,
	)
}

func (conn *packetConn) SetReadDeadline(deadline time.Time) error {
	if conn.closed.Load() {
		return net.ErrClosed
	}
	return conn.instance.setDataPlaneResourceDeadline(
		conn.resource,
		coreabi.DeadlineRead,
		deadline,
	)
}

func (conn *packetConn) SetWriteDeadline(deadline time.Time) error {
	if conn.closed.Load() {
		return net.ErrClosed
	}
	return conn.instance.setDataPlaneResourceDeadline(
		conn.resource,
		coreabi.DeadlineWrite,
		deadline,
	)
}

func udpAddrPort(address net.Addr) (netip.AddrPort, error) {
	if address == nil {
		return netip.AddrPort{}, &net.AddrError{
			Err: "address is nil",
		}
	}
	udp, ok := address.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, &net.AddrError{
			Err:  "address is not UDP",
			Addr: address.String(),
		}
	}
	peer := udp.AddrPort()
	if peer.IsValid() {
		peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	}
	if !peer.IsValid() || !peer.Addr().Is4() {
		return netip.AddrPort{}, &net.AddrError{
			Err:  "EasyTier data plane requires an IPv4 address",
			Addr: address.String(),
		}
	}
	return peer, nil
}

func (instance *Instance) ListenPacket(port uint16) (net.PacketConn, error) {
	result, err := instance.performOperation(
		context.Background(),
		coreabi.OperationUDPBind,
		func(
			ctx context.Context,
			core dataPlaneCore,
		) (coreabi.OperationID, error) {
			return core.SubmitUDPBind(ctx, port, ^uint64(0))
		},
	)
	if err != nil {
		return nil, err
	}
	return newPacketConn(instance, result), nil
}

func (instance *Instance) DialUDP(
	ctx context.Context,
	peer netip.AddrPort,
) (net.Conn, error) {
	timeout, err := contextTimeoutMillis(ctx)
	if err != nil {
		return nil, normalizeDeadlineError(err)
	}
	result, err := instance.performOperation(
		ctx,
		coreabi.OperationUDPBind,
		func(
			callCtx context.Context,
			core dataPlaneCore,
		) (coreabi.OperationID, error) {
			return core.SubmitUDPBind(callCtx, 0, timeout)
		},
	)
	if err != nil {
		return nil, normalizeDeadlineError(err)
	}
	return &datagramConn{
		packet: newPacketConn(instance, result),
		peer:   peer,
	}, nil
}

func (conn *datagramConn) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	for {
		n, source, err := conn.packet.ReadFrom(buffer)
		if source == nil {
			return n, err
		}
		sourcePeer, addressErr := udpAddrPort(source)
		if addressErr != nil {
			return 0, addressErr
		}
		if sourcePeer != conn.peer {
			continue
		}
		return n, err
	}
}

func (conn *datagramConn) Write(buffer []byte) (int, error) {
	return conn.packet.WriteTo(buffer, net.UDPAddrFromAddrPort(conn.peer))
}

func (conn *datagramConn) Close() error {
	return conn.packet.Close()
}

func (conn *datagramConn) LocalAddr() net.Addr {
	return conn.packet.LocalAddr()
}

func (conn *datagramConn) RemoteAddr() net.Addr {
	return net.UDPAddrFromAddrPort(conn.peer)
}

func (conn *datagramConn) SetDeadline(deadline time.Time) error {
	return conn.packet.SetDeadline(deadline)
}

func (conn *datagramConn) SetReadDeadline(deadline time.Time) error {
	return conn.packet.SetReadDeadline(deadline)
}

func (conn *datagramConn) SetWriteDeadline(deadline time.Time) error {
	return conn.packet.SetWriteDeadline(deadline)
}
