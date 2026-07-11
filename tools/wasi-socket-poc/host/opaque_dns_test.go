package host

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/tetratelabs/wazero/api"
)

const (
	maxDNSQueryLen = 4096
)

type opaqueDNSResolver interface {
	lookupIP(context.Context, decodedDNSQuery) ([]netip.Addr, error)
	lookupTXT(context.Context, decodedDNSQuery) (string, error)
	lookupSRV(context.Context, decodedDNSQuery) ([]*net.SRV, error)
}

type systemOpaqueDNSResolver struct{}

func (systemOpaqueDNSResolver) lookupIP(ctx context.Context, query decodedDNSQuery) ([]netip.Addr, error) {
	network := "ip"
	if query.ipVersion == 4 {
		network = "ip4"
	} else if query.ipVersion == 6 {
		network = "ip6"
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, network, query.host)
	if err != nil {
		return nil, err
	}
	return addresses, nil
}

func (systemOpaqueDNSResolver) lookupTXT(ctx context.Context, query decodedDNSQuery) (string, error) {
	records, err := net.DefaultResolver.LookupTXT(ctx, query.host)
	if err != nil {
		return "", err
	}
	if len(records) == 0 {
		return "", fmt.Errorf("DNS TXT query returned no records")
	}
	return records[0], nil
}

func (systemOpaqueDNSResolver) lookupSRV(ctx context.Context, query decodedDNSQuery) ([]*net.SRV, error) {
	_, records, err := net.DefaultResolver.LookupSRV(ctx, "", "", query.host)
	return records, err
}

type opaqueDNSOperation struct {
	cancel context.CancelFunc
	done   bool
	result []byte
	err    error
}

type opaqueDNSKind uint8

const (
	opaqueDNSAddress opaqueDNSKind = iota
	opaqueDNSTXT
	opaqueDNSSRV
)

func (b *opaqueBridge) startDNSResolve(
	_ context.Context,
	module api.Module,
	operation uint64,
	queryPointer uint32,
	queryLength uint32,
) int32 {
	return b.startDNS(module, operation, queryPointer, queryLength, opaqueDNSAddress)
}

func (b *opaqueBridge) startDNSTXT(
	_ context.Context,
	module api.Module,
	operation uint64,
	queryPointer uint32,
	queryLength uint32,
) int32 {
	return b.startDNS(module, operation, queryPointer, queryLength, opaqueDNSTXT)
}

func (b *opaqueBridge) startDNSSRV(
	_ context.Context,
	module api.Module,
	operation uint64,
	queryPointer uint32,
	queryLength uint32,
) int32 {
	return b.startDNS(module, operation, queryPointer, queryLength, opaqueDNSSRV)
}

func (b *opaqueBridge) startDNS(
	module api.Module,
	operation uint64,
	queryPointer uint32,
	queryLength uint32,
	kind opaqueDNSKind,
) int32 {
	if queryLength == 0 || queryLength > maxDNSQueryLen {
		return opaqueHostInvalid
	}
	encoded, ok := module.Memory().Read(queryPointer, queryLength)
	if !ok {
		return opaqueHostMemory
	}
	query, err := decodeDNSQuery(append([]byte(nil), encoded...))
	if err != nil {
		return opaqueHostInvalid
	}
	resolveContext, cancel := context.WithCancel(context.Background())
	dns := &opaqueDNSOperation{cancel: cancel}
	b.mu.Lock()
	if _, duplicate := b.dns[operation]; duplicate {
		b.mu.Unlock()
		cancel()
		return opaqueHostInvalid
	}
	b.dns[operation] = dns
	b.workers.Add(1)
	b.mu.Unlock()

	go func() {
		defer b.workers.Done()
		var result []byte
		var err error
		switch kind {
		case opaqueDNSAddress:
			var addresses []netip.Addr
			addresses, err = b.dnsResolver.lookupIP(resolveContext, query)
			if err == nil {
				result, err = encodeDNSAddresses(addresses)
			}
		case opaqueDNSTXT:
			var text string
			text, err = b.dnsResolver.lookupTXT(resolveContext, query)
			if err == nil {
				result, err = encodeDNSTXT(text)
			}
		case opaqueDNSSRV:
			var records []*net.SRV
			records, err = b.dnsResolver.lookupSRV(resolveContext, query)
			if err == nil {
				result, err = encodeDNSSRV(records)
			}
		default:
			err = fmt.Errorf("unsupported DNS query kind")
		}

		b.mu.Lock()
		if b.dns[operation] != dns {
			b.mu.Unlock()
			return
		}
		dns.done = true
		dns.result = result
		dns.err = err
		b.mu.Unlock()
		b.signalCompletion()
	}()
	return 0
}

func (b *opaqueBridge) takeDNSResolve(
	_ context.Context,
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultCapacity uint32,
) int32 {
	return b.takeDNS(module, operation, resultPointer, resultCapacity)
}

func (b *opaqueBridge) takeDNSTXT(
	_ context.Context,
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultCapacity uint32,
) int32 {
	return b.takeDNS(module, operation, resultPointer, resultCapacity)
}

func (b *opaqueBridge) takeDNSSRV(
	_ context.Context,
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultCapacity uint32,
) int32 {
	return b.takeDNS(module, operation, resultPointer, resultCapacity)
}

func (b *opaqueBridge) takeDNS(
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultCapacity uint32,
) int32 {
	b.mu.Lock()
	dns, exists := b.dns[operation]
	if !exists {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	if !dns.done {
		b.mu.Unlock()
		return opaqueHostPending
	}
	if dns.err != nil {
		delete(b.dns, operation)
		b.mu.Unlock()
		return opaqueHostIOError
	}
	required := len(dns.result)
	if required == 0 || required > maxDNSResultLen {
		delete(b.dns, operation)
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	if resultCapacity < uint32(required) {
		b.mu.Unlock()
		return int32(required)
	}
	result := dns.result
	delete(b.dns, operation)
	b.mu.Unlock()
	if !module.Memory().Write(resultPointer, result) {
		return opaqueHostMemory
	}
	return int32(required)
}
