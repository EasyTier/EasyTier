package engine

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"github.com/EasyTier/EasyTier/easytier-go/internal/coreabi"
)

const dataPlaneCompletionBatch = 64

type dataPlaneCore interface {
	SubmitTCPConnect(
		context.Context,
		netip.AddrPort,
		uint64,
	) (coreabi.OperationID, error)
	SubmitTCPBind(
		context.Context,
		uint16,
		uint64,
	) (coreabi.OperationID, error)
	SubmitTCPAccept(
		context.Context,
		coreabi.ResourceID,
		uint64,
	) (coreabi.OperationID, error)
	SubmitTCPRead(
		context.Context,
		coreabi.ResourceID,
		uint32,
	) (coreabi.OperationID, error)
	SubmitTCPWrite(
		context.Context,
		coreabi.ResourceID,
		[]byte,
	) (coreabi.OperationID, error)
	SubmitUDPBind(
		context.Context,
		uint16,
		uint64,
	) (coreabi.OperationID, error)
	SubmitUDPReceive(
		context.Context,
		coreabi.ResourceID,
		uint32,
	) (coreabi.OperationID, error)
	SubmitUDPSend(
		context.Context,
		coreabi.ResourceID,
		netip.AddrPort,
		[]byte,
	) (coreabi.OperationID, error)
	SetResourceDeadline(
		context.Context,
		coreabi.ResourceID,
		coreabi.DeadlineDirection,
		uint64,
	) error
	DrainCompletions(context.Context, uint32) ([]coreabi.Completion, error)
	TakeResult(
		context.Context,
		coreabi.Completion,
	) (coreabi.OperationResult, error)
	CancelOperation(context.Context, coreabi.OperationID) error
	CloseResource(context.Context, coreabi.ResourceID) error
}

type dataPlaneCommandKind uint8

const (
	dataPlaneSubmit dataPlaneCommandKind = iota + 1
	dataPlaneCancel
	dataPlaneCloseResource
	dataPlaneSetDeadline
)

type dataPlaneCommand struct {
	kind      dataPlaneCommandKind
	operation coreabi.OperationID
	resource  coreabi.ResourceID
	direction coreabi.DeadlineDirection
	deadline  time.Time
	submit    func(context.Context, dataPlaneCore) (coreabi.OperationID, error)
	opKind    coreabi.OperationKind
	response  chan dataPlaneCommandResponse
}

type dataPlaneCommandResponse struct {
	ticket    operationTicket
	outcome   operationOutcome
	completed bool
	err       error
}

type operationTicket struct {
	id     coreabi.OperationID
	result <-chan operationOutcome
}

type operationOutcome struct {
	result coreabi.OperationResult
	err    error
}

type pendingOperation struct {
	kind   coreabi.OperationKind
	result chan operationOutcome
}

func (instance *Instance) performOperation(
	ctx context.Context,
	kind coreabi.OperationKind,
	submit func(context.Context, dataPlaneCore) (coreabi.OperationID, error),
) (coreabi.OperationResult, error) {
	if ctx == nil {
		return coreabi.OperationResult{}, fmt.Errorf(
			"submit EasyTier data plane operation with nil context",
		)
	}
	response := make(chan dataPlaneCommandResponse, 1)
	request := dataPlaneCommand{
		kind:     dataPlaneSubmit,
		submit:   submit,
		opKind:   kind,
		response: response,
	}
	select {
	case instance.dataPlaneCommands <- request:
	case <-instance.done:
		return coreabi.OperationResult{}, net.ErrClosed
	case <-instance.closeRequested:
		return coreabi.OperationResult{}, net.ErrClosed
	case <-ctx.Done():
		return coreabi.OperationResult{}, ctx.Err()
	}

	var ticket operationTicket
	select {
	case submitted := <-response:
		if submitted.err != nil {
			return coreabi.OperationResult{}, mapDataPlaneError(submitted.err)
		}
		if submitted.completed {
			return submitted.outcome.result, mapDataPlaneError(submitted.outcome.err)
		}
		ticket = submitted.ticket
	case <-instance.done:
		return coreabi.OperationResult{}, net.ErrClosed
	case <-instance.closeRequested:
		return coreabi.OperationResult{}, net.ErrClosed
	case <-ctx.Done():
		// The driver may already have submitted the operation. Wait for its
		// response so that cancellation always targets the actual operation.
		select {
		case submitted := <-response:
			if submitted.err != nil {
				return coreabi.OperationResult{}, mapDataPlaneError(submitted.err)
			}
			if submitted.completed {
				return submitted.outcome.result, mapDataPlaneError(
					submitted.outcome.err,
				)
			}
			ticket = submitted.ticket
		case <-instance.done:
			return coreabi.OperationResult{}, net.ErrClosed
		case <-instance.closeRequested:
			return coreabi.OperationResult{}, net.ErrClosed
		}
		return instance.cancelAndWait(ctx, ticket)
	}

	select {
	case outcome := <-ticket.result:
		return outcome.result, mapDataPlaneError(outcome.err)
	case <-ctx.Done():
		return instance.cancelAndWait(ctx, ticket)
	case <-instance.done:
		return coreabi.OperationResult{}, net.ErrClosed
	case <-instance.closeRequested:
		return coreabi.OperationResult{}, net.ErrClosed
	}
}

func (instance *Instance) cancelAndWait(
	cancelled context.Context,
	ticket operationTicket,
) (coreabi.OperationResult, error) {
	response := make(chan dataPlaneCommandResponse, 1)
	request := dataPlaneCommand{
		kind:      dataPlaneCancel,
		operation: ticket.id,
		response:  response,
	}
	select {
	case instance.dataPlaneCommands <- request:
	case outcome := <-ticket.result:
		return outcome.result, mapDataPlaneError(outcome.err)
	case <-instance.done:
		return coreabi.OperationResult{}, net.ErrClosed
	case <-instance.closeRequested:
		return coreabi.OperationResult{}, net.ErrClosed
	}
	select {
	case result := <-response:
		if result.err != nil {
			return coreabi.OperationResult{}, mapDataPlaneError(result.err)
		}
	case outcome := <-ticket.result:
		return cancelledOutcome(cancelled, outcome)
	case <-instance.done:
		return coreabi.OperationResult{}, net.ErrClosed
	case <-instance.closeRequested:
		return coreabi.OperationResult{}, net.ErrClosed
	}

	select {
	case outcome := <-ticket.result:
		return cancelledOutcome(cancelled, outcome)
	case <-instance.done:
		return coreabi.OperationResult{}, net.ErrClosed
	case <-instance.closeRequested:
		return coreabi.OperationResult{}, net.ErrClosed
	}
}

func cancelledOutcome(
	cancelled context.Context,
	outcome operationOutcome,
) (coreabi.OperationResult, error) {
	var dataPlaneErr *coreabi.DataPlaneError
	if errors.As(outcome.err, &dataPlaneErr) &&
		dataPlaneErr.Kind == coreabi.ErrorCancelled {
		return coreabi.OperationResult{}, cancelled.Err()
	}
	return outcome.result, mapDataPlaneError(outcome.err)
}

func (instance *Instance) closeDataPlaneResource(
	resource coreabi.ResourceID,
) error {
	response := make(chan dataPlaneCommandResponse, 1)
	request := dataPlaneCommand{
		kind:     dataPlaneCloseResource,
		resource: resource,
		response: response,
	}
	select {
	case instance.dataPlaneCommands <- request:
	case <-instance.done:
		return net.ErrClosed
	case <-instance.closeRequested:
		return net.ErrClosed
	}
	select {
	case result := <-response:
		return mapDataPlaneError(result.err)
	case <-instance.done:
		return net.ErrClosed
	case <-instance.closeRequested:
		return net.ErrClosed
	}
}

func (instance *Instance) setDataPlaneResourceDeadline(
	resource coreabi.ResourceID,
	direction coreabi.DeadlineDirection,
	deadline time.Time,
) error {
	response := make(chan dataPlaneCommandResponse, 1)
	request := dataPlaneCommand{
		kind:      dataPlaneSetDeadline,
		resource:  resource,
		direction: direction,
		deadline:  deadline,
		response:  response,
	}
	select {
	case instance.dataPlaneCommands <- request:
	case <-instance.done:
		return net.ErrClosed
	case <-instance.closeRequested:
		return net.ErrClosed
	}
	select {
	case result := <-response:
		return mapDataPlaneError(result.err)
	case <-instance.done:
		return net.ErrClosed
	case <-instance.closeRequested:
		return net.ErrClosed
	}
}

func (instance *Instance) handleDataPlaneCommand(
	request dataPlaneCommand,
) dataPlaneCommandResponse {
	instance.host.guestMu.Lock()
	defer instance.host.guestMu.Unlock()
	switch request.kind {
	case dataPlaneSubmit:
		operation, err := request.submit(instance.ctx, instance.dataPlane)
		if err != nil {
			return dataPlaneCommandResponse{err: err}
		}
		result := make(chan operationOutcome, 1)
		instance.pendingOperations[operation] = &pendingOperation{
			kind:   request.opKind,
			result: result,
		}
		return dataPlaneCommandResponse{ticket: operationTicket{
			id:     operation,
			result: result,
		}}
	case dataPlaneCancel:
		if _, exists := instance.pendingOperations[request.operation]; !exists {
			return dataPlaneCommandResponse{}
		}
		return dataPlaneCommandResponse{
			err: instance.dataPlane.CancelOperation(
				instance.ctx,
				request.operation,
			),
		}
	case dataPlaneCloseResource:
		return dataPlaneCommandResponse{
			err: instance.dataPlane.CloseResource(
				instance.ctx,
				request.resource,
			),
		}
	case dataPlaneSetDeadline:
		return dataPlaneCommandResponse{
			err: instance.dataPlane.SetResourceDeadline(
				instance.ctx,
				request.resource,
				request.direction,
				resourceDeadlineTimeoutMillis(request.deadline),
			),
		}
	default:
		return dataPlaneCommandResponse{
			err: fmt.Errorf("unknown data plane command %d", request.kind),
		}
	}
}

func (instance *Instance) drainDataPlaneCompletions() (bool, error) {
	if instance.dataPlane == nil || len(instance.pendingOperations) == 0 {
		return false, nil
	}
	completions, err := instance.dataPlane.DrainCompletions(
		instance.ctx,
		dataPlaneCompletionBatch,
	)
	if err != nil {
		return false, err
	}
	for _, completion := range completions {
		pending := instance.pendingOperations[completion.Operation]
		if pending == nil {
			return false, fmt.Errorf(
				"EasyTier completed unknown data plane operation %d",
				completion.Operation,
			)
		}
		if pending.kind != completion.Kind {
			return false, fmt.Errorf(
				"EasyTier completed operation %d as kind %d, want %d",
				completion.Operation,
				completion.Kind,
				pending.kind,
			)
		}
		result, resultErr := instance.dataPlane.TakeResult(
			instance.ctx,
			completion,
		)
		if err := validateCompletionResult(completion, resultErr); err != nil {
			return false, err
		}
		delete(instance.pendingOperations, completion.Operation)
		pending.result <- operationOutcome{result: result, err: resultErr}
	}
	return len(completions) == dataPlaneCompletionBatch, nil
}

func validateCompletionResult(
	completion coreabi.Completion,
	resultErr error,
) error {
	var dataPlaneErr *coreabi.DataPlaneError
	if completion.Status == coreabi.ErrorNone {
		if resultErr != nil {
			return fmt.Errorf(
				"take successful data plane operation %d: %w",
				completion.Operation,
				resultErr,
			)
		}
		return nil
	}
	if !errors.As(resultErr, &dataPlaneErr) {
		return fmt.Errorf(
			"take failed data plane operation %d with status %d: %w",
			completion.Operation,
			completion.Status,
			resultErr,
		)
	}
	if dataPlaneErr.Kind != completion.Status {
		return fmt.Errorf(
			"data plane operation %d status %d disagrees with result %d",
			completion.Operation,
			completion.Status,
			dataPlaneErr.Kind,
		)
	}
	return nil
}

func (instance *Instance) failPendingOperations(err error) {
	for operation, pending := range instance.pendingOperations {
		pending.result <- operationOutcome{err: err}
		delete(instance.pendingOperations, operation)
	}
}

func timeoutFromDeadline(deadline time.Time) (uint64, error) {
	if deadline.IsZero() {
		return math.MaxUint64, nil
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0, os.ErrDeadlineExceeded
	}
	millis := remaining / time.Millisecond
	if remaining%time.Millisecond != 0 {
		millis++
	}
	return uint64(millis), nil
}

func resourceDeadlineTimeoutMillis(deadline time.Time) uint64 {
	if deadline.IsZero() {
		return math.MaxUint64
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0
	}
	millis := remaining / time.Millisecond
	if remaining%time.Millisecond != 0 {
		millis++
	}
	return uint64(millis)
}

func contextTimeoutMillis(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	deadline, exists := ctx.Deadline()
	if !exists {
		return math.MaxUint64, nil
	}
	return timeoutFromDeadline(deadline)
}

func mapDataPlaneError(err error) error {
	if err == nil {
		return nil
	}
	var dataPlaneErr *coreabi.DataPlaneError
	if !errors.As(err, &dataPlaneErr) {
		return err
	}
	switch dataPlaneErr.Kind {
	case coreabi.ErrorCancelled:
		return context.Canceled
	case coreabi.ErrorDeadlineExceeded:
		return os.ErrDeadlineExceeded
	case coreabi.ErrorInstanceStopped, coreabi.ErrorHandleClosed:
		return net.ErrClosed
	case coreabi.ErrorNoOverlayRoute, coreabi.ErrorPathNotReady:
		return syscall.ENETUNREACH
	case coreabi.ErrorAddressFamilyUnsupported:
		return syscall.EAFNOSUPPORT
	case coreabi.ErrorAddressInUse:
		return syscall.EADDRINUSE
	case coreabi.ErrorConnectionRefused:
		return syscall.ECONNREFUSED
	case coreabi.ErrorNetworkChanged:
		return syscall.ENETRESET
	case coreabi.ErrorResourceLimit:
		return syscall.ENOBUFS
	case coreabi.ErrorBufferTooSmall:
		return syscall.EMSGSIZE
	default:
		return err
	}
}
