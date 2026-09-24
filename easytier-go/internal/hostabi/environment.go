package hostabi

import (
	"context"

	"github.com/metacubex/wazero/api"
)

func (adapter *Adapter) startLocalAddrForRemote(
	_ context.Context,
	module api.Module,
	operation uint64,
	remotePointer uint32,
	remoteLength uint32,
	contextPointer uint32,
	contextLength uint32,
) int32 {
	if remoteLength != socketAddressLen {
		return statusInvalid
	}
	encoded, ok := module.Memory().Read(remotePointer, remoteLength)
	if !ok {
		return statusMemory
	}
	remote, err := decodeSocketAddress(append([]byte(nil), encoded...), false)
	if err != nil {
		return statusInvalid
	}
	encodedContext, ok := readOwnedOptions(module, contextPointer, contextLength)
	if !ok {
		return statusMemory
	}
	socketContext, remainder, err := decodeSocketContext(encodedContext)
	if err != nil || len(remainder) != 0 {
		return statusInvalid
	}
	return operationStatus(
		adapter.reactor.StartLocalAddrForRemote(operation, remote, socketContext),
	)
}

func (adapter *Adapter) takeLocalAddrForRemote(
	_ context.Context,
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultLength uint32,
) int32 {
	if !validResultMemory(module, resultPointer, resultLength, socketAddressLen) {
		_ = adapter.reactor.CancelOperation(operation)
		return statusMemory
	}
	address, err := adapter.reactor.TakeLocalAddrForRemote(operation)
	if err != nil {
		return operationStatus(err)
	}
	encoded, err := encodeNetAddr(address)
	if err != nil {
		return statusInvalid
	}
	if !module.Memory().Write(resultPointer, encoded[:]) {
		return statusMemory
	}
	return 0
}
