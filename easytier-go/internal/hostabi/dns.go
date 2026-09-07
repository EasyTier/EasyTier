package hostabi

import (
	"context"

	"github.com/EasyTier/EasyTier/easytier-go/internal/reactor"
	"github.com/metacubex/wazero/api"
)

const maxDNSQueryLen = 4096

func (adapter *Adapter) startDNSAddress(
	_ context.Context,
	module api.Module,
	operation uint64,
	queryPointer uint32,
	queryLength uint32,
) int32 {
	return adapter.startDNS(module, operation, queryPointer, queryLength, reactor.DNSAddress)
}

func (adapter *Adapter) startDNSTXT(
	_ context.Context,
	module api.Module,
	operation uint64,
	queryPointer uint32,
	queryLength uint32,
) int32 {
	return adapter.startDNS(module, operation, queryPointer, queryLength, reactor.DNSTXT)
}

func (adapter *Adapter) startDNSSRV(
	_ context.Context,
	module api.Module,
	operation uint64,
	queryPointer uint32,
	queryLength uint32,
) int32 {
	return adapter.startDNS(module, operation, queryPointer, queryLength, reactor.DNSSRV)
}

func (adapter *Adapter) startDNS(
	module api.Module,
	operation uint64,
	queryPointer uint32,
	queryLength uint32,
	kind reactor.DNSKind,
) int32 {
	if queryLength == 0 || queryLength > maxDNSQueryLen {
		return statusInvalid
	}
	encoded, ok := module.Memory().Read(queryPointer, queryLength)
	if !ok {
		return statusMemory
	}
	query, err := decodeDNSQuery(append([]byte(nil), encoded...))
	if err != nil {
		return statusInvalid
	}
	return operationStatus(adapter.reactor.StartDNS(operation, kind, query))
}

func (adapter *Adapter) takeDNSAddress(
	_ context.Context,
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultCapacity uint32,
) int32 {
	return adapter.takeDNS(module, operation, resultPointer, resultCapacity, reactor.DNSAddress)
}

func (adapter *Adapter) takeDNSTXT(
	_ context.Context,
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultCapacity uint32,
) int32 {
	return adapter.takeDNS(module, operation, resultPointer, resultCapacity, reactor.DNSTXT)
}

func (adapter *Adapter) takeDNSSRV(
	_ context.Context,
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultCapacity uint32,
) int32 {
	return adapter.takeDNS(module, operation, resultPointer, resultCapacity, reactor.DNSSRV)
}

func (adapter *Adapter) takeDNS(
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultCapacity uint32,
	kind reactor.DNSKind,
) int32 {
	result, err := adapter.reactor.DNSResult(operation)
	if err != nil {
		return operationStatus(err)
	}
	if result.Kind != kind {
		return statusInvalid
	}
	var encoded []byte
	switch kind {
	case reactor.DNSAddress:
		encoded, err = encodeDNSAddresses(result.Addresses)
	case reactor.DNSTXT:
		encoded, err = encodeDNSTXT(result.Text)
	case reactor.DNSSRV:
		encoded, err = encodeDNSSRV(result.Records)
	default:
		return statusInvalid
	}
	if err != nil {
		_ = adapter.reactor.FinishDNS(operation)
		return statusInvalid
	}
	if resultCapacity < uint32(len(encoded)) {
		return int32(len(encoded))
	}
	if err := adapter.reactor.FinishDNS(operation); err != nil {
		return operationStatus(err)
	}
	if !module.Memory().Write(resultPointer, encoded) {
		return statusMemory
	}
	return int32(len(encoded))
}
