package coreabi

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"github.com/metacubex/wazero/api"
	"github.com/metacubex/wazero/experimental/wazerotest"
)

func TestValidateRPCABI(t *testing.T) {
	for _, test := range []struct {
		name    string
		version uint32
		wantErr bool
	}{
		{name: "supported", version: RPCABIVersion},
		{name: "unsupported", version: RPCABIVersion + 1, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			version := exportTestFunction(
				"easytier_rpc_abi_version",
				func(context.Context, api.Module) uint32 {
					return test.version
				},
			)
			core := &Core{
				module:    wazerotest.NewModule(nil, version),
				functions: make(map[string]guestFunction),
			}
			err := core.validateRPCABI(context.Background())
			if (err != nil) != test.wantErr {
				t.Fatalf(
					"validate RPC ABI version %d: err=%v, wantErr=%v",
					test.version,
					err,
					test.wantErr,
				)
			}
		})
	}
}

func TestRPCRequestResponseAndFree(t *testing.T) {
	memory := wazerotest.NewMemory(64 * 1024)
	nextPointer := uint32(1024)
	var submitted []byte
	var freed RPCOperationID
	response := []byte{0x0a, 0x02, 0x08, 0x01}

	allocate := exportTestFunction(
		"easytier_buffer_alloc",
		func(_ context.Context, _ api.Module, length uint32) uint32 {
			pointer := nextPointer
			nextPointer += length + 8
			return pointer
		},
	)
	free := exportTestFunction(
		"easytier_buffer_free",
		func(context.Context, api.Module, uint32) int32 {
			return 0
		},
	)
	submit := exportTestFunction(
		"easytier_rpc_request_submit",
		func(
			_ context.Context,
			module api.Module,
			_ uint64,
			requestPointer uint32,
			requestLength uint32,
			operationPointer uint32,
		) int32 {
			wire, _ := module.Memory().Read(requestPointer, requestLength)
			submitted = append([]byte(nil), wire...)
			var operation [rpcOperationIDBytes]byte
			binary.BigEndian.PutUint64(operation[:], 41)
			module.Memory().Write(operationPointer, operation[:])
			return 0
		},
	)
	take := exportTestFunction(
		"easytier_rpc_response_take",
		func(
			_ context.Context,
			module api.Module,
			_ uint64,
			_ uint64,
			output uint32,
			capacity uint32,
		) int32 {
			if output == 0 && capacity == 0 {
				return int32(len(response))
			}
			module.Memory().Write(output, response)
			return int32(len(response))
		},
	)
	freeOperation := exportTestFunction(
		"easytier_rpc_operation_free",
		func(
			_ context.Context,
			_ api.Module,
			_ uint64,
			operation uint64,
		) int32 {
			freed = RPCOperationID(operation)
			return 0
		},
	)
	core := &Core{
		module: wazerotest.NewModule(
			memory,
			allocate,
			free,
			submit,
			take,
			freeOperation,
		),
		functions: make(map[string]guestFunction),
		handle:    7,
	}

	request := []byte{0x0a, 0x01, 0x00}
	operation, err := core.SubmitRPC(context.Background(), request)
	if err != nil {
		t.Fatalf("submit RPC: %v", err)
	}
	if operation != 41 {
		t.Fatalf("RPC operation = %d, want 41", operation)
	}
	if !bytes.Equal(submitted, request) {
		t.Fatalf("submitted RPC = %x, want %x", submitted, request)
	}
	got, ready, err := core.TakeRPCResponse(context.Background(), operation)
	if err != nil {
		t.Fatalf("take RPC response: %v", err)
	}
	if !ready {
		t.Fatal("RPC response remained pending")
	}
	if !bytes.Equal(got, response) {
		t.Fatalf("RPC response = %x, want %x", got, response)
	}
	if err := core.FreeRPCOperation(context.Background(), 52); err != nil {
		t.Fatalf("free RPC operation: %v", err)
	}
	if freed != 52 {
		t.Fatalf("freed RPC operation = %d, want 52", freed)
	}
}

func TestTakeRPCResponseReportsPending(t *testing.T) {
	take := exportTestFunction(
		"easytier_rpc_response_take",
		func(
			context.Context,
			api.Module,
			uint64,
			uint64,
			uint32,
			uint32,
		) int32 {
			return rpcStatusPending
		},
	)
	core := &Core{
		module:    wazerotest.NewModule(nil, take),
		functions: make(map[string]guestFunction),
		handle:    7,
	}
	response, ready, err := core.TakeRPCResponse(context.Background(), 1)
	if err != nil {
		t.Fatalf("take pending RPC response: %v", err)
	}
	if ready || response != nil {
		t.Fatalf("pending RPC response = (%x, %v), want (nil, false)", response, ready)
	}
}

func exportTestFunction(name string, implementation any) *wazerotest.Function {
	function := wazerotest.NewFunction(implementation)
	function.ExportNames = []string{name}
	return function
}
