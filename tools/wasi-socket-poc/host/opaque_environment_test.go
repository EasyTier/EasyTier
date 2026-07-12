package host

import (
	"context"

	"github.com/tetratelabs/wazero/api"
)

func (b *opaqueBridge) rejectEnvironmentCall() int32 {
	b.mu.Lock()
	b.environmentCalls++
	b.mu.Unlock()
	return opaqueHostIOError
}

func (b *opaqueBridge) environmentCallCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.environmentCalls
}

func (b *opaqueBridge) startLocalAddrForRemote(
	context.Context,
	api.Module,
	uint64,
	uint32,
	uint32,
) int32 {
	return b.rejectEnvironmentCall()
}

func (b *opaqueBridge) takeLocalAddrForRemote(
	context.Context,
	api.Module,
	uint64,
	uint32,
	uint32,
) int32 {
	return b.rejectEnvironmentCall()
}

func (b *opaqueBridge) startUDPPortMapping(
	context.Context,
	api.Module,
	uint64,
	uint64,
) int32 {
	return b.rejectEnvironmentCall()
}

func (b *opaqueBridge) takeUDPPortMapping(
	context.Context,
	api.Module,
	uint64,
	uint32,
	uint32,
) int32 {
	return b.rejectEnvironmentCall()
}

func (b *opaqueBridge) startTCPPortMapping(
	context.Context,
	api.Module,
	uint64,
	uint32,
) int32 {
	return b.rejectEnvironmentCall()
}

func (b *opaqueBridge) takeTCPPortMapping(
	context.Context,
	api.Module,
	uint64,
	uint32,
	uint32,
) int32 {
	return b.rejectEnvironmentCall()
}
