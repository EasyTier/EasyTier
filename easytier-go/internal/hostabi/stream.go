package hostabi

import (
	"context"

	"github.com/metacubex/wazero/api"
)

var (
	takeReadParameterTypes = []api.ValueType{
		api.ValueTypeI64,
		api.ValueTypeI32,
		api.ValueTypeI32,
	}
	startWriteParameterTypes = []api.ValueType{
		api.ValueTypeI64,
		api.ValueTypeI64,
		api.ValueTypeI32,
		api.ValueTypeI32,
	}
)

func (adapter *Adapter) startReadFunction() api.GoModuleFunction {
	return api.GoModuleFunc(func(ctx context.Context, module api.Module, stack []uint64) {
		stack[0] = api.EncodeI32(adapter.startRead(
			ctx,
			module,
			stack[0],
			stack[1],
			api.DecodeU32(stack[2]),
		))
	})
}

func (adapter *Adapter) takeReadFunction() api.GoModuleFunction {
	return api.GoModuleFunc(func(ctx context.Context, module api.Module, stack []uint64) {
		stack[0] = api.EncodeI32(adapter.takeRead(
			ctx,
			module,
			stack[0],
			api.DecodeU32(stack[1]),
			api.DecodeU32(stack[2]),
		))
	})
}

func (adapter *Adapter) startWriteFunction() api.GoModuleFunction {
	return api.GoModuleFunc(func(ctx context.Context, module api.Module, stack []uint64) {
		stack[0] = api.EncodeI32(adapter.startWrite(
			ctx,
			module,
			stack[0],
			stack[1],
			api.DecodeU32(stack[2]),
			api.DecodeU32(stack[3]),
		))
	})
}

func (adapter *Adapter) takeWriteFunction() api.GoModuleFunction {
	return api.GoModuleFunc(func(ctx context.Context, module api.Module, stack []uint64) {
		stack[0] = api.EncodeI32(adapter.takeWrite(
			ctx,
			module,
			stack[0],
		))
	})
}

func (adapter *Adapter) startRead(
	_ context.Context,
	_ api.Module,
	handle uint64,
	operation uint64,
	capacity uint32,
) int32 {
	return operationStatus(adapter.reactor.StartRead(handle, operation, capacity))
}

func (adapter *Adapter) takeRead(
	_ context.Context,
	module api.Module,
	operation uint64,
	destination uint32,
	capacity uint32,
) int32 {
	data, err := adapter.reactor.TakeRead(operation)
	if err != nil {
		return operationStatus(err)
	}
	if uint32(len(data)) > capacity {
		return statusMemory
	}
	if len(data) > 0 && !module.Memory().Write(destination, data) {
		return statusMemory
	}
	return int32(len(data))
}

func (adapter *Adapter) startWrite(
	_ context.Context,
	module api.Module,
	handle uint64,
	operation uint64,
	source uint32,
	length uint32,
) int32 {
	data, ok := module.Memory().Read(source, length)
	if !ok {
		return statusMemory
	}
	return operationStatus(adapter.reactor.StartWrite(handle, operation, data))
}

func (adapter *Adapter) takeWrite(
	_ context.Context,
	_ api.Module,
	operation uint64,
) int32 {
	return operationStatus(adapter.reactor.TakeWrite(operation))
}

func (adapter *Adapter) cancelOperation(
	_ context.Context,
	_ api.Module,
	operation uint64,
) int32 {
	return operationStatus(adapter.reactor.CancelOperation(operation))
}

func (adapter *Adapter) closeHandle(
	_ context.Context,
	_ api.Module,
	handle uint64,
) int32 {
	return operationStatus(adapter.reactor.CloseHandle(handle))
}
