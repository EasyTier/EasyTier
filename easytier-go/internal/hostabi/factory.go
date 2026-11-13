package hostabi

import (
	"context"

	"github.com/metacubex/wazero/api"
)

func (adapter *Adapter) startTCPConnect(
	_ context.Context,
	module api.Module,
	operation uint64,
	optionsPointer uint32,
	optionsLength uint32,
) int32 {
	encoded, ok := readOwnedOptions(module, optionsPointer, optionsLength)
	if !ok {
		return statusMemory
	}
	options, err := decodeTCPConnectOptions(encoded)
	if err != nil {
		return statusInvalid
	}
	return operationStatus(adapter.reactor.StartTCPConnect(operation, options))
}

func (adapter *Adapter) takeTCPConnect(
	_ context.Context,
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultLength uint32,
) int32 {
	if !validResultMemory(module, resultPointer, resultLength, tcpSocketResultLen) {
		_ = adapter.reactor.CancelOperation(operation)
		return statusMemory
	}
	result, err := adapter.reactor.TakeTCPConnect(operation)
	if err != nil {
		return connectStatus(err)
	}
	encoded, err := encodeTCPSocketResult(result.Handle, result.Local, result.Peer)
	if err != nil || !module.Memory().Write(resultPointer, encoded[:]) {
		_ = adapter.reactor.CloseHandle(result.Handle)
		return statusMemory
	}
	return 0
}

func (adapter *Adapter) startUDPBind(
	_ context.Context,
	module api.Module,
	operation uint64,
	optionsPointer uint32,
	optionsLength uint32,
) int32 {
	encoded, ok := readOwnedOptions(module, optionsPointer, optionsLength)
	if !ok {
		return statusMemory
	}
	options, err := decodeUDPBindOptions(encoded)
	if err != nil {
		return statusInvalid
	}
	return operationStatus(adapter.reactor.StartUDPBind(operation, options))
}

func (adapter *Adapter) takeUDPBind(
	_ context.Context,
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultLength uint32,
) int32 {
	if !validResultMemory(module, resultPointer, resultLength, boundSocketResultLen) {
		_ = adapter.reactor.CancelOperation(operation)
		return statusMemory
	}
	result, err := adapter.reactor.TakeUDPBind(operation)
	if err != nil {
		return operationStatus(err)
	}
	encoded, err := encodeBoundSocketResult(result.Handle, result.Local)
	if err != nil || !module.Memory().Write(resultPointer, encoded[:]) {
		_ = adapter.reactor.CloseHandle(result.Handle)
		return statusMemory
	}
	return 0
}

func (adapter *Adapter) startTCPListen(
	_ context.Context,
	module api.Module,
	operation uint64,
	optionsPointer uint32,
	optionsLength uint32,
) int32 {
	encoded, ok := readOwnedOptions(module, optionsPointer, optionsLength)
	if !ok {
		return statusMemory
	}
	options, err := decodeTCPListenOptions(encoded)
	if err != nil {
		return statusInvalid
	}
	return operationStatus(adapter.reactor.StartTCPListen(operation, options))
}

func (adapter *Adapter) takeTCPListen(
	_ context.Context,
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultLength uint32,
) int32 {
	if !validResultMemory(module, resultPointer, resultLength, boundSocketResultLen) {
		_ = adapter.reactor.CancelOperation(operation)
		return statusMemory
	}
	result, err := adapter.reactor.TakeTCPListen(operation)
	if err != nil {
		return operationStatus(err)
	}
	encoded, err := encodeBoundSocketResult(result.Handle, result.Local)
	if err != nil || !module.Memory().Write(resultPointer, encoded[:]) {
		_ = adapter.reactor.CloseHandle(result.Handle)
		return statusMemory
	}
	return 0
}

func validResultMemory(
	module api.Module,
	pointer uint32,
	length uint32,
	expected uint32,
) bool {
	if length != expected {
		return false
	}
	_, ok := module.Memory().Read(pointer, length)
	return ok
}
