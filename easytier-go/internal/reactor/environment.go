package reactor

import (
	"context"
	"fmt"
	"net"

	"github.com/EasyTier/EasyTier/easytier-go/platform"
)

type environmentOperation struct {
	cancel context.CancelFunc
	done   bool
	result net.Addr
	err    error
}

func (reactor *Reactor) StartLocalAddrForRemote(
	operation uint64,
	remote *net.UDPAddr,
	socketContext platform.SocketContext,
) error {
	if reactor.services.Environment == nil {
		return fmt.Errorf("environment operation: no connector environment configured")
	}
	ctx, cancel := context.WithCancel(reactor.ctx)
	result := &environmentOperation{cancel: cancel}
	reactor.mu.Lock()
	if err := reactor.claimOperationLocked(operation, operationEnvironment); err != nil {
		reactor.mu.Unlock()
		cancel()
		return err
	}
	reactor.environments[operation] = result
	reactor.workers.Add(1)
	reactor.mu.Unlock()

	go func() {
		defer reactor.workers.Done()
		address, resolveErr := reactor.services.Environment.LocalAddrForRemote(
			ctx,
			remote,
			socketContext,
		)
		reactor.mu.Lock()
		if reactor.environments[operation] != result {
			reactor.mu.Unlock()
			return
		}
		result.result = address
		result.err = resolveErr
		result.done = true
		reactor.mu.Unlock()
		reactor.signalCompletion()
	}()
	return nil
}

func (reactor *Reactor) TakeLocalAddrForRemote(operation uint64) (net.Addr, error) {
	reactor.mu.Lock()
	result, exists := reactor.environments[operation]
	if !exists || reactor.operations[operation] != operationEnvironment {
		reactor.mu.Unlock()
		return nil, ErrInvalid
	}
	if !result.done {
		reactor.mu.Unlock()
		return nil, ErrPending
	}
	delete(reactor.environments, operation)
	reactor.releaseOperationLocked(operation, operationEnvironment)
	result.cancel()
	address, err := result.result, result.err
	reactor.mu.Unlock()
	if err == nil && address == nil {
		err = fmt.Errorf("connector environment returned no address")
	}
	return address, err
}
