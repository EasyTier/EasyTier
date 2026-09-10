package hostabi

import (
	"context"

	"github.com/metacubex/wazero/api"
)

var (
	startUDPReceiveParameterTypes = []api.ValueType{
		api.ValueTypeI64,
		api.ValueTypeI64,
		api.ValueTypeI32,
	}
	takeUDPReceiveParameterTypes = []api.ValueType{
		api.ValueTypeI64,
		api.ValueTypeI32,
		api.ValueTypeI32,
		api.ValueTypeI32,
		api.ValueTypeI32,
	}
	tryUDPSendParameterTypes = []api.ValueType{
		api.ValueTypeI64,
		api.ValueTypeI32,
		api.ValueTypeI32,
		api.ValueTypeI32,
		api.ValueTypeI32,
	}
	handleOperationParameterTypes = []api.ValueType{
		api.ValueTypeI64,
		api.ValueTypeI64,
	}
	operationParameterTypes = []api.ValueType{api.ValueTypeI64}
)

func (adapter *Adapter) startUDPReceiveFunction() api.GoModuleFunction {
	return api.GoModuleFunc(func(ctx context.Context, module api.Module, stack []uint64) {
		stack[0] = api.EncodeI32(adapter.startUDPReceive(
			ctx,
			module,
			stack[0],
			stack[1],
			api.DecodeU32(stack[2]),
		))
	})
}

func (adapter *Adapter) takeUDPReceiveFunction() api.GoModuleFunction {
	return api.GoModuleFunc(func(ctx context.Context, module api.Module, stack []uint64) {
		stack[0] = api.EncodeI32(adapter.takeUDPReceive(
			ctx,
			module,
			stack[0],
			api.DecodeU32(stack[1]),
			api.DecodeU32(stack[2]),
			api.DecodeU32(stack[3]),
			api.DecodeU32(stack[4]),
		))
	})
}

func (adapter *Adapter) tryUDPSendFunction() api.GoModuleFunction {
	return api.GoModuleFunc(func(ctx context.Context, module api.Module, stack []uint64) {
		stack[0] = api.EncodeI32(adapter.tryUDPSend(
			ctx,
			module,
			stack[0],
			api.DecodeU32(stack[1]),
			api.DecodeU32(stack[2]),
			api.DecodeU32(stack[3]),
			api.DecodeU32(stack[4]),
		))
	})
}

func (adapter *Adapter) startUDPSendReadyFunction() api.GoModuleFunction {
	return api.GoModuleFunc(func(ctx context.Context, module api.Module, stack []uint64) {
		stack[0] = api.EncodeI32(adapter.startUDPSendReady(
			ctx,
			module,
			stack[0],
			stack[1],
		))
	})
}

func (adapter *Adapter) takeUDPSendReadyFunction() api.GoModuleFunction {
	return api.GoModuleFunc(func(ctx context.Context, module api.Module, stack []uint64) {
		stack[0] = api.EncodeI32(adapter.takeUDPSendReady(
			ctx,
			module,
			stack[0],
		))
	})
}

func (adapter *Adapter) startUDPReceive(
	_ context.Context,
	_ api.Module,
	handle uint64,
	operation uint64,
	_ uint32,
) int32 {
	return operationStatus(adapter.reactor.StartUDPReceive(handle, operation))
}

func (adapter *Adapter) takeUDPReceive(
	_ context.Context,
	module api.Module,
	operation uint64,
	destination uint32,
	capacity uint32,
	metadataDestination uint32,
	metadataLength uint32,
) int32 {
	if metadataLength != udpMetadataLen {
		return statusMemory
	}
	if _, ok := module.Memory().Read(destination, capacity); !ok {
		return statusMemory
	}
	if _, ok := module.Memory().Read(metadataDestination, metadataLength); !ok {
		return statusMemory
	}
	datagram, err := adapter.reactor.TakeUDPReceive(operation, capacity)
	if err != nil {
		return operationStatus(err)
	}
	if len(datagram.Data) > 0 && !module.Memory().Write(destination, datagram.Data) {
		return statusMemory
	}
	metadata, err := encodeUDPMetadata(datagram.Peer, nil, 0)
	if err != nil {
		return statusInvalid
	}
	if !module.Memory().Write(metadataDestination, metadata[:]) {
		return statusMemory
	}
	return int32(len(datagram.Data))
}

func (adapter *Adapter) tryUDPSend(
	_ context.Context,
	module api.Module,
	handle uint64,
	source uint32,
	length uint32,
	metadataSource uint32,
	metadataLength uint32,
) int32 {
	if metadataLength != udpMetadataLen || length > 65535 {
		return statusMemory
	}
	metadata, ok := module.Memory().Read(metadataSource, metadataLength)
	if !ok {
		return statusMemory
	}
	peer, sourceIP, flowinfo, sourceIfindex, err := decodeUDPMetadata(metadata)
	if err != nil || sourceIP != nil || flowinfo != 0 || sourceIfindex != 0 {
		return statusInvalid
	}
	data, ok := module.Memory().Read(source, length)
	if !ok {
		return statusMemory
	}
	return operationStatus(adapter.reactor.TryUDPSend(handle, data, peer))
}

func (adapter *Adapter) startUDPSendReady(
	_ context.Context,
	_ api.Module,
	handle uint64,
	operation uint64,
) int32 {
	return operationStatus(adapter.reactor.StartUDPSendReady(handle, operation))
}

func (adapter *Adapter) takeUDPSendReady(
	_ context.Context,
	_ api.Module,
	operation uint64,
) int32 {
	return operationStatus(adapter.reactor.TakeUDPSendReady(operation))
}
