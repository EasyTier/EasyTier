package reactor

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/EasyTier/EasyTier/easytier-go/platform"
)

type DNSKind uint8

const (
	DNSAddress DNSKind = iota
	DNSTXT
	DNSSRV
)

type DNSResult struct {
	Kind      DNSKind
	Addresses []netip.Addr
	Text      string
	Records   []*net.SRV
}

type dnsOperation struct {
	kind   DNSKind
	cancel context.CancelFunc
	done   bool
	result DNSResult
	err    error
}

func (reactor *Reactor) StartDNS(
	operation uint64,
	kind DNSKind,
	query platform.DNSQuery,
) error {
	if reactor.services.DNS == nil {
		return fmt.Errorf("DNS operation: no resolver configured")
	}
	ctx, cancel := context.WithCancel(reactor.ctx)
	result := &dnsOperation{kind: kind, cancel: cancel}
	reactor.mu.Lock()
	if err := reactor.claimOperationLocked(operation, operationDNS); err != nil {
		reactor.mu.Unlock()
		cancel()
		return err
	}
	reactor.dns[operation] = result
	reactor.workers.Add(1)
	reactor.mu.Unlock()

	go func() {
		defer reactor.workers.Done()
		var value DNSResult
		var resolveErr error
		switch kind {
		case DNSAddress:
			value.Addresses, resolveErr = reactor.services.DNS.LookupIP(ctx, query)
		case DNSTXT:
			value.Text, resolveErr = reactor.services.DNS.LookupTXT(ctx, query)
		case DNSSRV:
			value.Records, resolveErr = reactor.services.DNS.LookupSRV(ctx, query)
		default:
			resolveErr = fmt.Errorf("unsupported DNS query kind %d", kind)
		}

		reactor.mu.Lock()
		if reactor.dns[operation] != result {
			reactor.mu.Unlock()
			return
		}
		result.done = true
		result.result = value
		result.err = resolveErr
		reactor.mu.Unlock()
		reactor.signalCompletion()
	}()
	return nil
}

func (reactor *Reactor) DNSResult(operation uint64) (DNSResult, error) {
	reactor.mu.Lock()
	result, exists := reactor.dns[operation]
	if !exists || reactor.operations[operation] != operationDNS {
		reactor.mu.Unlock()
		return DNSResult{}, ErrInvalid
	}
	if !result.done {
		reactor.mu.Unlock()
		return DNSResult{}, ErrPending
	}
	if result.err != nil {
		delete(reactor.dns, operation)
		reactor.releaseOperationLocked(operation, operationDNS)
		result.cancel()
		err := result.err
		reactor.mu.Unlock()
		return DNSResult{}, err
	}
	value := DNSResult{
		Kind:      result.kind,
		Addresses: append([]netip.Addr(nil), result.result.Addresses...),
		Text:      result.result.Text,
		Records:   append([]*net.SRV(nil), result.result.Records...),
	}
	reactor.mu.Unlock()
	return value, nil
}

func (reactor *Reactor) FinishDNS(operation uint64) error {
	reactor.mu.Lock()
	result, exists := reactor.dns[operation]
	if !exists || !result.done || reactor.operations[operation] != operationDNS {
		reactor.mu.Unlock()
		return ErrInvalid
	}
	delete(reactor.dns, operation)
	reactor.releaseOperationLocked(operation, operationDNS)
	result.cancel()
	reactor.mu.Unlock()
	return nil
}
