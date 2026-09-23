package hostabi

import (
	"context"

	"github.com/metacubex/wazero/api"
)

func (adapter *Adapter) startTCPAccept(
	_ context.Context,
	_ api.Module,
	handle uint64,
	operation uint64,
) int32 {
	return operationStatus(adapter.reactor.StartTCPAccept(handle, operation))
}

func (adapter *Adapter) takeTCPAccept(
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
	result, err := adapter.reactor.TakeTCPAccept(operation)
	if err != nil {
		return operationStatus(err)
	}
	encoded, err := encodeTCPSocketResult(result.Handle, result.Local, result.Peer)
	if err != nil || !module.Memory().Write(resultPointer, encoded[:]) {
		_ = adapter.reactor.CloseHandle(result.Handle)
		return statusMemory
	}
	return 0
}
