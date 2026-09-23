package coreabi

import (
	"context"
	"encoding/binary"
	"fmt"
)

const (
	RPCABIVersion = 2

	rpcStatusPending    int32 = -6
	maxRPCMessageBytes        = 16 * 1024 * 1024
	rpcOperationIDBytes       = 8
)

type RPCOperationID uint64

func (core *Core) validateRPCABI(ctx context.Context) error {
	version, err := core.callOne(ctx, "easytier_rpc_abi_version")
	if err != nil {
		return err
	}
	if version != RPCABIVersion {
		return fmt.Errorf(
			"unsupported EasyTier RPC ABI version %d, want %d",
			version,
			RPCABIVersion,
		)
	}
	return nil
}

func (core *Core) SubmitRPC(
	ctx context.Context,
	encodedRequest []byte,
) (operation RPCOperationID, err error) {
	if len(encodedRequest) == 0 {
		return 0, fmt.Errorf("submit empty RPC request")
	}
	if len(encodedRequest) > maxRPCMessageBytes {
		return 0, fmt.Errorf(
			"RPC request length %d exceeds limit %d",
			len(encodedRequest),
			maxRPCMessageBytes,
		)
	}
	requestPointer, err := core.allocate(ctx, uint32(len(encodedRequest)))
	if err != nil {
		return 0, err
	}
	defer core.cleanupBuffer(ctx, requestPointer, &err)
	if !core.module.Memory().Write(requestPointer, encodedRequest) {
		return 0, fmt.Errorf("write RPC request to guest memory")
	}
	operationPointer, err := core.allocate(ctx, rpcOperationIDBytes)
	if err != nil {
		return 0, err
	}
	defer core.cleanupBuffer(ctx, operationPointer, &err)

	result, err := core.callOne(
		ctx,
		"easytier_rpc_request_submit",
		core.handle,
		uint64(requestPointer),
		uint64(len(encodedRequest)),
		uint64(operationPointer),
	)
	if err != nil {
		return 0, err
	}
	if status := int32(result); status != 0 {
		return 0, core.statusError(ctx, "submit EasyTier RPC request", status)
	}
	wire, ok := core.module.Memory().Read(
		operationPointer,
		rpcOperationIDBytes,
	)
	if !ok {
		return 0, fmt.Errorf("read RPC operation ID from guest memory")
	}
	operation = RPCOperationID(binary.BigEndian.Uint64(wire))
	if operation == 0 {
		return 0, fmt.Errorf("EasyTier RPC submit returned zero operation ID")
	}
	return operation, nil
}

func (core *Core) TakeRPCResponse(
	ctx context.Context,
	operation RPCOperationID,
) (response []byte, ready bool, err error) {
	result, err := core.callOne(
		ctx,
		"easytier_rpc_response_take",
		core.handle,
		uint64(operation),
		0,
		0,
	)
	if err != nil {
		return nil, false, err
	}
	required := int32(result)
	if required == rpcStatusPending {
		return nil, false, nil
	}
	if required < 0 {
		return nil, false, core.statusError(
			ctx,
			"probe EasyTier RPC response",
			required,
		)
	}
	if required > maxRPCMessageBytes {
		return nil, false, fmt.Errorf(
			"RPC response length %d exceeds limit %d",
			required,
			maxRPCMessageBytes,
		)
	}

	capacity := uint32(required)
	if capacity == 0 {
		// A non-zero output pointer distinguishes consumption from a size probe.
		capacity = 1
	}
	outputPointer, err := core.allocate(ctx, capacity)
	if err != nil {
		return nil, false, err
	}
	defer core.cleanupBuffer(ctx, outputPointer, &err)
	result, err = core.callOne(
		ctx,
		"easytier_rpc_response_take",
		core.handle,
		uint64(operation),
		uint64(outputPointer),
		uint64(capacity),
	)
	if err != nil {
		return nil, false, err
	}
	length := int32(result)
	if length == rpcStatusPending {
		return nil, false, nil
	}
	if length < 0 {
		return nil, false, core.statusError(
			ctx,
			"take EasyTier RPC response",
			length,
		)
	}
	if uint32(length) > capacity {
		return nil, false, fmt.Errorf(
			"RPC response grew from %d to %d bytes",
			required,
			length,
		)
	}
	if length == 0 {
		return []byte{}, true, nil
	}
	wire, ok := core.module.Memory().Read(outputPointer, uint32(length))
	if !ok {
		return nil, false, fmt.Errorf("read RPC response from guest memory")
	}
	return append([]byte(nil), wire...), true, nil
}

func (core *Core) FreeRPCOperation(
	ctx context.Context,
	operation RPCOperationID,
) error {
	result, err := core.callOne(
		ctx,
		"easytier_rpc_operation_free",
		core.handle,
		uint64(operation),
	)
	if err != nil {
		return err
	}
	if status := int32(result); status != 0 {
		return core.statusError(ctx, "free EasyTier RPC operation", status)
	}
	return nil
}
