package host

import (
	"context"
	"fmt"

	"github.com/tetratelabs/wazero"
)

// CoreHostBinding ties one runtime's easytier_host imports to their owning
// Bridge. Its fields are private so callers cannot pair a core module with a
// different completion domain.
type CoreHostBinding struct {
	runtime wazero.Runtime
	bridge  *Bridge
}

func (b *opaqueBridge) instantiateHost(ctx context.Context, runtime wazero.Runtime) error {
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return fmt.Errorf("bridge is closed")
	}
	_, err := runtime.NewHostModuleBuilder("easytier_host").
		NewFunctionBuilder().WithFunc(b.startRead).Export("start_read").
		NewFunctionBuilder().WithFunc(b.takeRead).Export("take_read").
		NewFunctionBuilder().WithFunc(b.startWrite).Export("start_write").
		NewFunctionBuilder().WithFunc(b.takeWrite).Export("take_write").
		NewFunctionBuilder().WithFunc(b.startUDPRecv).Export("start_udp_recv").
		NewFunctionBuilder().WithFunc(b.takeUDPRecv).Export("take_udp_recv").
		NewFunctionBuilder().WithFunc(b.tryUDPSend).Export("try_udp_send").
		NewFunctionBuilder().WithFunc(b.startUDPSendReady).Export("start_udp_send_ready").
		NewFunctionBuilder().WithFunc(b.takeUDPSendReady).Export("take_udp_send_ready").
		NewFunctionBuilder().WithFunc(b.startTCPConnect).Export("start_tcp_connect").
		NewFunctionBuilder().WithFunc(b.takeTCPConnect).Export("take_tcp_connect").
		NewFunctionBuilder().WithFunc(b.startUDPBind).Export("start_udp_bind").
		NewFunctionBuilder().WithFunc(b.takeUDPBind).Export("take_udp_bind").
		NewFunctionBuilder().WithFunc(b.startTCPBind).Export("start_tcp_bind").
		NewFunctionBuilder().WithFunc(b.takeTCPBind).Export("take_tcp_bind").
		NewFunctionBuilder().WithFunc(b.startTCPAccept).Export("start_tcp_accept").
		NewFunctionBuilder().WithFunc(b.takeTCPAccept).Export("take_tcp_accept").
		NewFunctionBuilder().WithFunc(b.startDNSResolve).Export("start_dns_resolve").
		NewFunctionBuilder().WithFunc(b.takeDNSResolve).Export("take_dns_resolve").
		NewFunctionBuilder().WithFunc(b.startDNSTXT).Export("start_dns_txt").
		NewFunctionBuilder().WithFunc(b.takeDNSTXT).Export("take_dns_txt").
		NewFunctionBuilder().WithFunc(b.startDNSSRV).Export("start_dns_srv").
		NewFunctionBuilder().WithFunc(b.takeDNSSRV).Export("take_dns_srv").
		NewFunctionBuilder().WithFunc(b.startLocalAddrForRemote).Export("start_local_addr_for_remote").
		NewFunctionBuilder().WithFunc(b.takeLocalAddrForRemote).Export("take_local_addr_for_remote").
		NewFunctionBuilder().WithFunc(b.startUDPPortMapping).Export("start_udp_port_mapping").
		NewFunctionBuilder().WithFunc(b.takeUDPPortMapping).Export("take_udp_port_mapping").
		NewFunctionBuilder().WithFunc(b.startTCPPortMapping).Export("start_tcp_port_mapping").
		NewFunctionBuilder().WithFunc(b.takeTCPPortMapping).Export("take_tcp_port_mapping").
		NewFunctionBuilder().WithFunc(b.tryPacketWrite).Export("try_packet_write").
		NewFunctionBuilder().WithFunc(b.startPacketWriteReady).Export("start_packet_write_ready").
		NewFunctionBuilder().WithFunc(b.takePacketWriteReady).Export("take_packet_write_ready").
		NewFunctionBuilder().WithFunc(b.cancelOperation).Export("cancel_operation").
		NewFunctionBuilder().WithFunc(b.closeHandle).Export("close").
		Instantiate(ctx)
	return err
}

// BindCoreHost registers easytier_host and returns the binding required to
// instantiate the corresponding core module.
func (b *Bridge) BindCoreHost(
	ctx context.Context,
	runtime wazero.Runtime,
) (*CoreHostBinding, error) {
	if runtime == nil {
		return nil, fmt.Errorf("bind core host with nil runtime")
	}
	if err := b.instantiateHost(ctx, runtime); err != nil {
		return nil, err
	}
	return &CoreHostBinding{runtime: runtime, bridge: b}, nil
}
