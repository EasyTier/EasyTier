package hostabi

import (
	"context"

	"github.com/metacubex/wazero/api"
)

const (
	maxHostEventKindLen    = 64
	maxHostEventMessageLen = 64 * 1024
)

var emitEventParameterTypes = []api.ValueType{
	api.ValueTypeI64,
	api.ValueTypeI32,
	api.ValueTypeI32,
	api.ValueTypeI32,
	api.ValueTypeI32,
}

func (adapter *Adapter) emitEventFunction() api.GoModuleFunction {
	return api.GoModuleFunc(func(
		_ context.Context,
		module api.Module,
		stack []uint64,
	) {
		stack[0] = api.EncodeI32(adapter.emitEvent(
			module,
			stack[0],
			api.DecodeU32(stack[1]),
			api.DecodeU32(stack[2]),
			api.DecodeU32(stack[3]),
			api.DecodeU32(stack[4]),
		))
	})
}

func (adapter *Adapter) emitEvent(
	module api.Module,
	handle uint64,
	kindPointer uint32,
	kindLength uint32,
	messagePointer uint32,
	messageLength uint32,
) int32 {
	if kindLength == 0 || kindLength > maxHostEventKindLen ||
		messageLength == 0 || messageLength > maxHostEventMessageLen {
		return statusInvalid
	}
	kind, ok := module.Memory().Read(kindPointer, kindLength)
	if !ok {
		return statusMemory
	}
	message, ok := module.Memory().Read(messagePointer, messageLength)
	if !ok {
		return statusMemory
	}
	return operationStatus(adapter.reactor.TryEventWrite(
		handle,
		string(kind),
		string(message),
	))
}
