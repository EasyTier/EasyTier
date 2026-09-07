package engine

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/EasyTier/EasyTier/easytier-go/internal/coreabi"
)

type streamListener struct {
	instance *Instance
	resource coreabi.ResourceID
	local    netip.AddrPort

	closed    atomic.Bool
	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

func (listener *streamListener) Accept() (net.Conn, error) {
	if listener.closed.Load() {
		return nil, net.ErrClosed
	}
	result, err := listener.instance.performOperation(
		context.Background(),
		coreabi.OperationTCPAccept,
		func(
			ctx context.Context,
			core dataPlaneCore,
		) (coreabi.OperationID, error) {
			return core.SubmitTCPAccept(
				ctx,
				listener.resource,
				^uint64(0),
			)
		},
	)
	if err != nil {
		return nil, err
	}
	return newStreamConn(listener.instance, result), nil
}

func (listener *streamListener) Close() error {
	listener.closeOnce.Do(func() {
		listener.closed.Store(true)
		listener.closeErr = listener.instance.closeDataPlaneResource(
			listener.resource,
		)
		close(listener.closeDone)
	})
	<-listener.closeDone
	return listener.closeErr
}

func (listener *streamListener) Addr() net.Addr {
	return net.TCPAddrFromAddrPort(listener.local)
}

func (instance *Instance) Listen(port uint16) (net.Listener, error) {
	result, err := instance.performOperation(
		context.Background(),
		coreabi.OperationTCPBind,
		func(
			ctx context.Context,
			core dataPlaneCore,
		) (coreabi.OperationID, error) {
			return core.SubmitTCPBind(ctx, port, ^uint64(0))
		},
	)
	if err != nil {
		return nil, err
	}
	return &streamListener{
		instance:  instance,
		resource:  result.Resource,
		local:     result.Local,
		closeDone: make(chan struct{}),
	}, nil
}
