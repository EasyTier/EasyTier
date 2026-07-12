package host

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/tetratelabs/wazero/api"
)

type unsupportedOpaqueEnvironment struct{}

func (unsupportedOpaqueEnvironment) localAddrForRemote(
	context.Context,
	*net.UDPAddr,
) (net.Addr, error) {
	return nil, fmt.Errorf("no Go connector environment was injected")
}

func (unsupportedOpaqueEnvironment) udpPortMapping(
	context.Context,
	uint64,
) (net.Addr, error) {
	return nil, fmt.Errorf("no Go connector environment was injected")
}

func (unsupportedOpaqueEnvironment) tcpPortMapping(
	context.Context,
	uint16,
) (net.Addr, error) {
	return nil, fmt.Errorf("no Go connector environment was injected")
}

func (b *opaqueBridge) environmentCallCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.environmentCalls
}

func (b *opaqueBridge) startLocalAddrForRemote(
	_ context.Context,
	module api.Module,
	operation uint64,
	remotePointer uint32,
	remoteLength uint32,
) int32 {
	if remoteLength != socketAddressLen {
		return opaqueHostInvalid
	}
	encoded, ok := module.Memory().Read(remotePointer, remoteLength)
	if !ok {
		return opaqueHostMemory
	}
	remote, err := decodeSocketAddress(append([]byte(nil), encoded...), false)
	if err != nil {
		return opaqueHostInvalid
	}
	return b.startEnvironmentOperation(operation, func(ctx context.Context) (net.Addr, error) {
		return b.environmentResolver.localAddrForRemote(ctx, remote)
	})
}

func (b *opaqueBridge) takeLocalAddrForRemote(
	_ context.Context,
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultLength uint32,
) int32 {
	return b.takeEnvironmentOperation(module, operation, resultPointer, resultLength)
}

func (b *opaqueBridge) startUDPPortMapping(
	_ context.Context,
	_ api.Module,
	operation uint64,
	handle uint64,
) int32 {
	b.mu.Lock()
	_, exists := b.packets[handle]
	b.mu.Unlock()
	if !exists {
		return opaqueHostInvalid
	}
	return b.startEnvironmentOperation(operation, func(ctx context.Context) (net.Addr, error) {
		return b.environmentResolver.udpPortMapping(ctx, handle)
	})
}

func (b *opaqueBridge) takeUDPPortMapping(
	_ context.Context,
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultLength uint32,
) int32 {
	return b.takeEnvironmentOperation(module, operation, resultPointer, resultLength)
}

func (b *opaqueBridge) startTCPPortMapping(
	_ context.Context,
	_ api.Module,
	operation uint64,
	localPort uint32,
) int32 {
	if localPort > 0xffff {
		return opaqueHostInvalid
	}
	return b.startEnvironmentOperation(operation, func(ctx context.Context) (net.Addr, error) {
		return b.environmentResolver.tcpPortMapping(ctx, uint16(localPort))
	})
}

func (b *opaqueBridge) takeTCPPortMapping(
	_ context.Context,
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultLength uint32,
) int32 {
	return b.takeEnvironmentOperation(module, operation, resultPointer, resultLength)
}

func (b *opaqueBridge) startEnvironmentOperation(
	operation uint64,
	run func(context.Context) (net.Addr, error),
) int32 {
	operationContext, cancel := context.WithCancel(context.Background())
	result := &opaqueEnvironmentOperation{cancel: cancel}
	b.mu.Lock()
	if _, duplicate := b.environment[operation]; duplicate {
		b.mu.Unlock()
		cancel()
		return opaqueHostInvalid
	}
	b.environmentCalls++
	b.environment[operation] = result
	b.workers.Add(1)
	b.mu.Unlock()

	go func() {
		defer b.workers.Done()
		address, err := run(operationContext)
		b.mu.Lock()
		if b.environment[operation] != result {
			b.mu.Unlock()
			return
		}
		result.address = address
		result.err = err
		result.done = true
		b.mu.Unlock()
		b.signalCompletion()
	}()
	return 0
}

func (b *opaqueBridge) takeEnvironmentOperation(
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultLength uint32,
) int32 {
	if resultLength != socketAddressLen {
		return opaqueHostMemory
	}
	if _, ok := module.Memory().Read(resultPointer, resultLength); !ok {
		return opaqueHostMemory
	}
	b.mu.Lock()
	result, exists := b.environment[operation]
	if !exists {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	if !result.done {
		b.mu.Unlock()
		return opaqueHostPending
	}
	delete(b.environment, operation)
	result.cancel()
	address, err := result.address, result.err
	b.mu.Unlock()
	if err != nil || address == nil {
		return opaqueHostIOError
	}
	encoded, err := encodeNetAddr(address)
	if err != nil {
		return opaqueHostInvalid
	}
	if !module.Memory().Write(resultPointer, encoded[:]) {
		return opaqueHostMemory
	}
	return 0
}

func TestOpaqueEnvironmentCancellationRemovesOwnedResult(t *testing.T) {
	bridge := newOpaqueBridge(nil, nil)
	defer bridge.close()
	cancelled := make(chan struct{})
	if status := bridge.startEnvironmentOperation(99, func(ctx context.Context) (net.Addr, error) {
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	}); status != 0 {
		t.Fatalf("start environment operation: %d", status)
	}
	if status := bridge.cancelOperation(context.Background(), nil, 99); status != 0 {
		t.Fatalf("cancel environment operation: %d", status)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("environment worker did not observe cancellation")
	}
	bridge.mu.Lock()
	_, exists := bridge.environment[99]
	bridge.mu.Unlock()
	if exists {
		t.Fatal("cancelled environment operation remained owned by bridge")
	}
	select {
	case <-bridge.completion:
	default:
		t.Fatal("environment cancellation did not signal completion")
	}
}
