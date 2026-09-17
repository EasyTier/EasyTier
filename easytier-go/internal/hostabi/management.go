package hostabi

import (
	"context"

	"github.com/metacubex/wazero/api"
)

const maxManagementMessageLen = 16 * 1024 * 1024

func (adapter *Adapter) startManagement(
	_ context.Context,
	module api.Module,
	operation uint64,
	requestPointer uint32,
	requestLength uint32,
) int32 {
	if requestLength == 0 || requestLength > maxManagementMessageLen {
		return statusInvalid
	}
	request, ok := module.Memory().Read(requestPointer, requestLength)
	if !ok {
		return statusMemory
	}
	return operationStatus(
		adapter.reactor.StartManagement(operation, append([]byte(nil), request...)),
	)
}

func (adapter *Adapter) takeManagement(
	_ context.Context,
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultCapacity uint32,
) int32 {
	result, err := adapter.reactor.ManagementResult(operation)
	if err != nil {
		return operationStatus(err)
	}
	if len(result) > maxManagementMessageLen {
		_ = adapter.reactor.CancelOperation(operation)
		return statusInvalid
	}
	if resultCapacity < uint32(len(result)) {
		return int32(len(result))
	}
	if err := adapter.reactor.FinishManagement(operation); err != nil {
		return operationStatus(err)
	}
	if !module.Memory().Write(resultPointer, result) {
		return statusMemory
	}
	return int32(len(result))
}
