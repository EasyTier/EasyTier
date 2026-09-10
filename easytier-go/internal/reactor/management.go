package reactor

import (
	"context"
	"fmt"
)

type ManagementHandler func(context.Context, []byte) []byte

type managementOperation struct {
	cancel context.CancelFunc
	done   bool
	result []byte
}

func (reactor *Reactor) StartManagement(operation uint64, request []byte) error {
	if reactor.managementHandler == nil {
		return fmt.Errorf("management operation: no handler configured")
	}
	ctx, cancel := context.WithCancel(reactor.ctx)
	state := &managementOperation{cancel: cancel}
	reactor.mu.Lock()
	if err := reactor.claimOperationLocked(operation, operationManagement); err != nil {
		reactor.mu.Unlock()
		cancel()
		return err
	}
	reactor.management[operation] = state
	reactor.workers.Add(1)
	reactor.mu.Unlock()

	go func() {
		defer reactor.workers.Done()
		result := reactor.managementHandler(ctx, request)
		reactor.mu.Lock()
		if reactor.management[operation] != state {
			reactor.mu.Unlock()
			return
		}
		state.done = true
		state.result = result
		reactor.mu.Unlock()
		reactor.signalCompletion()
	}()
	return nil
}

func (reactor *Reactor) ManagementResult(operation uint64) ([]byte, error) {
	reactor.mu.Lock()
	defer reactor.mu.Unlock()
	state, exists := reactor.management[operation]
	if !exists || reactor.operations[operation] != operationManagement {
		return nil, ErrInvalid
	}
	if !state.done {
		return nil, ErrPending
	}
	return state.result, nil
}

func (reactor *Reactor) FinishManagement(operation uint64) error {
	reactor.mu.Lock()
	defer reactor.mu.Unlock()
	state, exists := reactor.management[operation]
	if !exists || !state.done ||
		!reactor.releaseOperationLocked(operation, operationManagement) {
		return ErrInvalid
	}
	delete(reactor.management, operation)
	state.cancel()
	return nil
}
