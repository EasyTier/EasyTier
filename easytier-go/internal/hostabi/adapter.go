package hostabi

import (
	"context"
	"fmt"

	"github.com/EasyTier/EasyTier/easytier-go/internal/reactor"
	"github.com/metacubex/wazero"
)

const importModule = "easytier_host"

type Adapter struct {
	reactor *reactor.Reactor
	aeads   aeadCache
}

func New(runtime *reactor.Reactor) (*Adapter, error) {
	if runtime == nil {
		return nil, fmt.Errorf("create host ABI adapter with nil reactor")
	}
	return &Adapter{reactor: runtime}, nil
}

func (adapter *Adapter) Instantiate(ctx context.Context, runtime wazero.Runtime) error {
	if runtime == nil {
		return fmt.Errorf("instantiate host ABI with nil wazero runtime")
	}
	_, err := runtime.NewHostModuleBuilder(importModule).
		NewFunctionBuilder().
		WithGoModuleFunction(
			adapter.emitEventFunction(),
			emitEventParameterTypes,
			hostI32ResultTypes,
		).
		Export("emit_event").
		NewFunctionBuilder().
		WithGoModuleFunction(
			adapter.cryptoAEADFunction(false),
			cryptoAEADParameterTypes,
			hostI32ResultTypes,
		).
		Export("crypto_aead_seal").
		NewFunctionBuilder().
		WithGoModuleFunction(
			adapter.cryptoAEADFunction(true),
			cryptoAEADParameterTypes,
			hostI32ResultTypes,
		).
		Export("crypto_aead_open").
		NewFunctionBuilder().
		WithGoModuleFunction(
			adapter.startReadFunction(),
			startUDPReceiveParameterTypes,
			hostI32ResultTypes,
		).
		Export("start_read").
		NewFunctionBuilder().
		WithGoModuleFunction(
			adapter.takeReadFunction(),
			takeReadParameterTypes,
			hostI32ResultTypes,
		).
		Export("take_read").
		NewFunctionBuilder().
		WithGoModuleFunction(
			adapter.startWriteFunction(),
			startWriteParameterTypes,
			hostI32ResultTypes,
		).
		Export("start_write").
		NewFunctionBuilder().
		WithGoModuleFunction(
			adapter.takeWriteFunction(),
			operationParameterTypes,
			hostI32ResultTypes,
		).
		Export("take_write").
		NewFunctionBuilder().
		WithGoModuleFunction(
			adapter.startUDPReceiveFunction(),
			startUDPReceiveParameterTypes,
			hostI32ResultTypes,
		).
		Export("start_udp_recv").
		NewFunctionBuilder().
		WithGoModuleFunction(
			adapter.takeUDPReceiveFunction(),
			takeUDPReceiveParameterTypes,
			hostI32ResultTypes,
		).
		Export("take_udp_recv").
		NewFunctionBuilder().
		WithGoModuleFunction(
			adapter.tryUDPSendFunction(),
			tryUDPSendParameterTypes,
			hostI32ResultTypes,
		).
		Export("try_udp_send").
		NewFunctionBuilder().
		WithGoModuleFunction(
			adapter.startUDPSendReadyFunction(),
			handleOperationParameterTypes,
			hostI32ResultTypes,
		).
		Export("start_udp_send_ready").
		NewFunctionBuilder().
		WithGoModuleFunction(
			adapter.takeUDPSendReadyFunction(),
			operationParameterTypes,
			hostI32ResultTypes,
		).
		Export("take_udp_send_ready").
		NewFunctionBuilder().WithFunc(adapter.startTCPConnect).Export("start_tcp_connect").
		NewFunctionBuilder().WithFunc(adapter.takeTCPConnect).Export("take_tcp_connect").
		NewFunctionBuilder().WithFunc(adapter.startUDPBind).Export("start_udp_bind").
		NewFunctionBuilder().WithFunc(adapter.takeUDPBind).Export("take_udp_bind").
		NewFunctionBuilder().WithFunc(adapter.startTCPListen).Export("start_tcp_bind").
		NewFunctionBuilder().WithFunc(adapter.takeTCPListen).Export("take_tcp_bind").
		NewFunctionBuilder().WithFunc(adapter.startTCPAccept).Export("start_tcp_accept").
		NewFunctionBuilder().WithFunc(adapter.takeTCPAccept).Export("take_tcp_accept").
		NewFunctionBuilder().WithFunc(adapter.startDNSAddress).Export("start_dns_resolve").
		NewFunctionBuilder().WithFunc(adapter.takeDNSAddress).Export("take_dns_resolve").
		NewFunctionBuilder().WithFunc(adapter.startDNSTXT).Export("start_dns_txt").
		NewFunctionBuilder().WithFunc(adapter.takeDNSTXT).Export("take_dns_txt").
		NewFunctionBuilder().WithFunc(adapter.startDNSSRV).Export("start_dns_srv").
		NewFunctionBuilder().WithFunc(adapter.takeDNSSRV).Export("take_dns_srv").
		NewFunctionBuilder().WithFunc(adapter.startLocalAddrForRemote).Export("start_local_addr_for_remote").
		NewFunctionBuilder().WithFunc(adapter.takeLocalAddrForRemote).Export("take_local_addr_for_remote").
		NewFunctionBuilder().WithFunc(adapter.startManagement).Export("start_management_call").
		NewFunctionBuilder().WithFunc(adapter.takeManagement).Export("take_management_call").
		NewFunctionBuilder().
		WithGoModuleFunction(
			adapter.tryPacketWriteFunction(),
			tryPacketWriteParameterTypes,
			hostI32ResultTypes,
		).
		Export("try_packet_write").
		NewFunctionBuilder().
		WithGoModuleFunction(
			adapter.startPacketWriteReadyFunction(),
			handleOperationParameterTypes,
			hostI32ResultTypes,
		).
		Export("start_packet_write_ready").
		NewFunctionBuilder().
		WithGoModuleFunction(
			adapter.takePacketWriteReadyFunction(),
			operationParameterTypes,
			hostI32ResultTypes,
		).
		Export("take_packet_write_ready").
		NewFunctionBuilder().WithFunc(adapter.cancelOperation).Export("cancel_operation").
		NewFunctionBuilder().WithFunc(adapter.closeHandle).Export("close").
		Instantiate(ctx)
	return err
}
