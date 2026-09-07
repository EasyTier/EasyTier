package engine

import (
	"bytes"
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/easytier-go/internal/coreabi"
)

type readyRPC struct {
	response []byte
	taken    []coreabi.RPCOperationID
}

func (*readyRPC) SubmitRPC(
	context.Context,
	[]byte,
) (coreabi.RPCOperationID, error) {
	return 0, errors.New("unexpected RPC submission")
}

func (rpc *readyRPC) TakeRPCResponse(
	_ context.Context,
	operation coreabi.RPCOperationID,
) ([]byte, bool, error) {
	rpc.taken = append(rpc.taken, operation)
	return append([]byte(nil), rpc.response...), true, nil
}

func (*readyRPC) FreeRPCOperation(
	context.Context,
	coreabi.RPCOperationID,
) error {
	return errors.New("unexpected RPC free")
}

func TestDriveTakesReadyRPCResponse(t *testing.T) {
	core := &recordingCore{}
	rpc := &readyRPC{response: []byte{1, 2, 3}}
	result := make(chan rpcOutcome, 1)
	instance := &Instance{
		host: &Host{},
		ctx:  context.Background(),
		core: core,
		rpc:  rpc,
		pendingRPCs: map[coreabi.RPCOperationID]*pendingRPC{
			9: {result: result},
		},
		running: make(chan struct{}),
		stopped: make(chan struct{}),
	}

	deadline, err := instance.drive(false)
	if err != nil {
		t.Fatalf("drive RPC response: %v", err)
	}
	if deadline != math.MaxInt64 {
		t.Fatalf("next deadline = %d, want no deadline", deadline)
	}
	outcome := <-result
	if outcome.err != nil {
		t.Fatalf("RPC outcome: %v", outcome.err)
	}
	if !bytes.Equal(outcome.response, rpc.response) {
		t.Fatalf("RPC response = %x, want %x", outcome.response, rpc.response)
	}
	if len(instance.pendingRPCs) != 0 {
		t.Fatalf("pending RPCs = %d, want 0", len(instance.pendingRPCs))
	}
	if len(rpc.taken) != 1 || rpc.taken[0] != 9 {
		t.Fatalf("taken RPCs = %v, want [9]", rpc.taken)
	}
}

func TestRPCCancellationFreesSubmittedOperation(t *testing.T) {
	instance := &Instance{
		rpcCommands:    make(chan rpcCommand),
		closeRequested: make(chan struct{}),
		done:           make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	callResult := make(chan error, 1)
	go func() {
		_, err := instance.RPC(ctx, []byte{1, 2, 3})
		callResult <- err
	}()

	var submit rpcCommand
	select {
	case submit = <-instance.rpcCommands:
	case <-time.After(time.Second):
		t.Fatal("RPC did not enqueue submission")
	}
	result := make(chan rpcOutcome, 1)
	cancel()
	submit.response <- rpcCommandResponse{ticket: rpcTicket{
		id:     17,
		result: result,
	}}

	var free rpcCommand
	select {
	case free = <-instance.rpcCommands:
	case <-time.After(time.Second):
		t.Fatal("RPC cancellation did not enqueue free")
	}
	if free.kind != rpcFree || free.operation != 17 {
		t.Fatalf(
			"RPC cancellation command = (kind=%d, operation=%d)",
			free.kind,
			free.operation,
		)
	}
	free.response <- rpcCommandResponse{}

	select {
	case err := <-callResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled RPC error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled RPC did not return")
	}
}
