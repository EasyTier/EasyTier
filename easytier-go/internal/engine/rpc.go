package engine

import (
	"context"
	"fmt"
	"net"

	"github.com/EasyTier/EasyTier/easytier-go/internal/coreabi"
)

type rpcCore interface {
	SubmitRPC(
		context.Context,
		[]byte,
	) (coreabi.RPCOperationID, error)
	TakeRPCResponse(
		context.Context,
		coreabi.RPCOperationID,
	) ([]byte, bool, error)
	FreeRPCOperation(context.Context, coreabi.RPCOperationID) error
}

type rpcCommandKind uint8

const (
	rpcSubmit rpcCommandKind = iota + 1
	rpcFree
)

type rpcCommand struct {
	kind      rpcCommandKind
	request   []byte
	operation coreabi.RPCOperationID
	response  chan rpcCommandResponse
}

type rpcCommandResponse struct {
	ticket    rpcTicket
	outcome   rpcOutcome
	completed bool
	err       error
}

type rpcTicket struct {
	id     coreabi.RPCOperationID
	result <-chan rpcOutcome
}

type rpcOutcome struct {
	response []byte
	err      error
}

type pendingRPC struct {
	result chan rpcOutcome
}

func (instance *Instance) RPC(
	ctx context.Context,
	encodedRequest []byte,
) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("submit EasyTier RPC with nil context")
	}
	response := make(chan rpcCommandResponse, 1)
	request := rpcCommand{
		kind:     rpcSubmit,
		request:  encodedRequest,
		response: response,
	}
	select {
	case instance.rpcCommands <- request:
	case <-instance.done:
		return nil, net.ErrClosed
	case <-instance.closeRequested:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	var ticket rpcTicket
	select {
	case submitted := <-response:
		if submitted.err != nil {
			return nil, submitted.err
		}
		if submitted.completed {
			return submitted.outcome.response, submitted.outcome.err
		}
		ticket = submitted.ticket
	case <-instance.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		// The driver has accepted the request and may already have submitted
		// it. Wait for its operation ID so cancellation cannot leak it.
		select {
		case submitted := <-response:
			if submitted.err != nil {
				return nil, submitted.err
			}
			if submitted.completed {
				return submitted.outcome.response, submitted.outcome.err
			}
			ticket = submitted.ticket
		case <-instance.done:
			return nil, net.ErrClosed
		}
		return instance.freeRPCAndWait(ctx, ticket)
	}

	select {
	case outcome := <-ticket.result:
		return outcome.response, outcome.err
	case <-ctx.Done():
		return instance.freeRPCAndWait(ctx, ticket)
	case <-instance.done:
		return nil, net.ErrClosed
	case <-instance.closeRequested:
		return nil, net.ErrClosed
	}
}

func (instance *Instance) freeRPCAndWait(
	cancelled context.Context,
	ticket rpcTicket,
) ([]byte, error) {
	response := make(chan rpcCommandResponse, 1)
	request := rpcCommand{
		kind:      rpcFree,
		operation: ticket.id,
		response:  response,
	}
	select {
	case instance.rpcCommands <- request:
	case outcome := <-ticket.result:
		return outcome.response, outcome.err
	case <-instance.done:
		return nil, net.ErrClosed
	case <-instance.closeRequested:
		return nil, net.ErrClosed
	}
	select {
	case result := <-response:
		if result.err != nil {
			return nil, result.err
		}
	case outcome := <-ticket.result:
		return outcome.response, outcome.err
	case <-instance.done:
		return nil, net.ErrClosed
	case <-instance.closeRequested:
		return nil, net.ErrClosed
	}
	select {
	case outcome := <-ticket.result:
		return outcome.response, outcome.err
	default:
		return nil, cancelled.Err()
	}
}

func (instance *Instance) handleRPCCommand(
	request rpcCommand,
) rpcCommandResponse {
	instance.host.guestMu.Lock()
	defer instance.host.guestMu.Unlock()
	switch request.kind {
	case rpcSubmit:
		operation, err := instance.rpc.SubmitRPC(
			instance.ctx,
			request.request,
		)
		if err != nil {
			return rpcCommandResponse{err: err}
		}
		result := make(chan rpcOutcome, 1)
		instance.pendingRPCs[operation] = &pendingRPC{result: result}
		return rpcCommandResponse{ticket: rpcTicket{
			id:     operation,
			result: result,
		}}
	case rpcFree:
		if _, exists := instance.pendingRPCs[request.operation]; !exists {
			return rpcCommandResponse{}
		}
		if err := instance.rpc.FreeRPCOperation(
			instance.ctx,
			request.operation,
		); err != nil {
			return rpcCommandResponse{err: err}
		}
		delete(instance.pendingRPCs, request.operation)
		return rpcCommandResponse{}
	default:
		return rpcCommandResponse{
			err: fmt.Errorf("unknown RPC command %d", request.kind),
		}
	}
}

// takeRPCResponses runs with host.guestMu held.
func (instance *Instance) takeRPCResponses() error {
	if instance.rpc == nil || len(instance.pendingRPCs) == 0 {
		return nil
	}
	for operation, pending := range instance.pendingRPCs {
		response, ready, err := instance.rpc.TakeRPCResponse(
			instance.ctx,
			operation,
		)
		if err != nil {
			return err
		}
		if !ready {
			continue
		}
		delete(instance.pendingRPCs, operation)
		pending.result <- rpcOutcome{response: response}
	}
	return nil
}

func (instance *Instance) failPendingRPCs(err error) {
	for operation, pending := range instance.pendingRPCs {
		pending.result <- rpcOutcome{err: err}
		delete(instance.pendingRPCs, operation)
	}
}
