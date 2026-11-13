package hostabi

import (
	"context"

	"github.com/metacubex/wazero/api"
)

const maxHostPacketLen = 1024 * 1024

var tryPacketWriteParameterTypes = []api.ValueType{
	api.ValueTypeI64,
	api.ValueTypeI32,
	api.ValueTypeI32,
}

func (adapter *Adapter) tryPacketWriteFunction() api.GoModuleFunction {
	return api.GoModuleFunc(func(ctx context.Context, module api.Module, stack []uint64) {
		stack[0] = api.EncodeI32(adapter.tryPacketWrite(
			ctx,
			module,
			stack[0],
			api.DecodeU32(stack[1]),
			api.DecodeU32(stack[2]),
		))
	})
}

func (adapter *Adapter) startPacketWriteReadyFunction() api.GoModuleFunction {
	return api.GoModuleFunc(func(ctx context.Context, module api.Module, stack []uint64) {
		stack[0] = api.EncodeI32(adapter.startPacketWriteReady(
			ctx,
			module,
			stack[0],
			stack[1],
		))
	})
}

func (adapter *Adapter) takePacketWriteReadyFunction() api.GoModuleFunction {
	return api.GoModuleFunc(func(ctx context.Context, module api.Module, stack []uint64) {
		stack[0] = api.EncodeI32(adapter.takePacketWriteReady(
			ctx,
			module,
			stack[0],
		))
	})
}

func (adapter *Adapter) tryPacketWrite(
	_ context.Context,
	module api.Module,
	handle uint64,
	packetPointer uint32,
	packetLength uint32,
) int32 {
	if packetLength == 0 || packetLength > maxHostPacketLen {
		return statusInvalid
	}
	packet, ok := module.Memory().Read(packetPointer, packetLength)
	if !ok {
		return statusMemory
	}
	return operationStatus(adapter.reactor.TryPacketWrite(handle, packet))
}

func (adapter *Adapter) startPacketWriteReady(
	_ context.Context,
	_ api.Module,
	handle uint64,
	operation uint64,
) int32 {
	return operationStatus(adapter.reactor.StartPacketWriteReady(handle, operation))
}

func (adapter *Adapter) takePacketWriteReady(
	_ context.Context,
	_ api.Module,
	operation uint64,
) int32 {
	return operationStatus(adapter.reactor.TakePacketWriteReady(operation))
}
