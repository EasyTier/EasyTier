package coreabi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"

	"github.com/EasyTier/EasyTier/easytier-go/internal/contextutil"
)

const (
	DataPlaneABIVersion = 3

	DataPlaneCapability    uint64 = 1 << 0
	DataPlaneTCPCapability uint64 = 1 << 1
	DataPlaneUDPCapability uint64 = 1 << 2

	DeadlineRead  DeadlineDirection = 1 << 0
	DeadlineWrite DeadlineDirection = 1 << 1

	requiredDataPlaneCapabilities = DataPlaneCapability |
		DataPlaneTCPCapability |
		DataPlaneUDPCapability
)

type OperationID uint64
type ResourceID uint64
type DeadlineDirection uint32

type OperationKind uint16

const (
	OperationTCPConnect OperationKind = iota + 1
	OperationTCPBind
	OperationTCPAccept
	OperationTCPRead
	OperationTCPWrite
	OperationUDPBind
	OperationUDPReceive
	OperationUDPSend
)

func (kind OperationKind) valid() bool {
	return kind >= OperationTCPConnect && kind <= OperationUDPSend
}

type ErrorKind uint16

const (
	ErrorNone ErrorKind = iota
	ErrorCancelled
	ErrorDeadlineExceeded
	ErrorInstanceStopped
	ErrorHandleClosed
	ErrorNoOverlayRoute
	ErrorPathNotReady
	ErrorAddressFamilyUnsupported
	ErrorAddressInUse
	ErrorConnectionRefused
	ErrorNetworkChanged
	ErrorResourceLimit
	ErrorIO
	ErrorBufferTooSmall
)

func (kind ErrorKind) validCompletionStatus() bool {
	return kind <= ErrorBufferTooSmall
}

type DataPlaneError struct {
	Kind    ErrorKind
	Message string
}

func (err *DataPlaneError) Error() string {
	if err.Message == "" {
		return fmt.Sprintf("data plane error %d", err.Kind)
	}
	return err.Message
}

type Completion struct {
	Operation OperationID
	Kind      OperationKind
	Status    ErrorKind
}

type OperationResult struct {
	Kind      OperationKind
	Resource  ResourceID
	Local     netip.AddrPort
	Peer      netip.AddrPort
	Data      []byte
	Length    int
	EOF       bool
	Truncated bool
}

func (core *Core) validateDataPlaneABI(ctx context.Context) error {
	version, err := core.callOne(ctx, "easytier_data_plane_abi_version")
	if err != nil {
		return err
	}
	if version != DataPlaneABIVersion {
		return fmt.Errorf(
			"unsupported EasyTier data plane ABI version %d, want %d",
			version,
			DataPlaneABIVersion,
		)
	}
	capabilities, err := core.callOne(ctx, "easytier_data_plane_capabilities")
	if err != nil {
		return err
	}
	if missing := requiredDataPlaneCapabilities &^ capabilities; missing != 0 {
		return fmt.Errorf(
			"EasyTier data plane capabilities %#x are missing %#x",
			capabilities,
			missing,
		)
	}
	return nil
}

func (core *Core) SubmitTCPConnect(
	ctx context.Context,
	peer netip.AddrPort,
	timeoutMillis uint64,
) (OperationID, error) {
	wire, err := encodeSocketAddress(peer)
	if err != nil {
		return 0, err
	}
	return core.submitWithInput(
		ctx,
		"easytier_data_plane_tcp_connect_submit",
		wire[:],
		timeoutMillis,
	)
}

func (core *Core) SubmitTCPBind(
	ctx context.Context,
	port uint16,
	timeoutMillis uint64,
) (OperationID, error) {
	return core.submit(
		ctx,
		"easytier_data_plane_tcp_bind_submit",
		uint64(port),
		timeoutMillis,
	)
}

func (core *Core) SubmitTCPAccept(
	ctx context.Context,
	listener ResourceID,
	timeoutMillis uint64,
) (OperationID, error) {
	return core.submit(
		ctx,
		"easytier_data_plane_tcp_accept_submit",
		uint64(listener),
		timeoutMillis,
	)
}

func (core *Core) SubmitTCPRead(
	ctx context.Context,
	stream ResourceID,
	maximum uint32,
) (OperationID, error) {
	return core.submit(
		ctx,
		"easytier_data_plane_tcp_read_submit",
		uint64(stream),
		uint64(maximum),
	)
}

func (core *Core) SubmitTCPWrite(
	ctx context.Context,
	stream ResourceID,
	data []byte,
) (operation OperationID, err error) {
	if len(data) > maxDataPlaneTransferBytes {
		return 0, fmt.Errorf(
			"TCP write length %d exceeds data plane limit %d",
			len(data),
			maxDataPlaneTransferBytes,
		)
	}
	pointer, err := core.writeInput(ctx, data)
	if err != nil {
		return 0, err
	}
	if pointer != 0 {
		defer core.cleanupBuffer(ctx, pointer, &err)
	}
	return core.submit(
		ctx,
		"easytier_data_plane_tcp_write_submit",
		uint64(stream),
		uint64(pointer),
		uint64(len(data)),
	)
}

func (core *Core) SubmitUDPBind(
	ctx context.Context,
	port uint16,
	timeoutMillis uint64,
) (OperationID, error) {
	return core.submit(
		ctx,
		"easytier_data_plane_udp_bind_submit",
		uint64(port),
		timeoutMillis,
	)
}

func (core *Core) SubmitUDPReceive(
	ctx context.Context,
	socket ResourceID,
	maximum uint32,
) (OperationID, error) {
	return core.submit(
		ctx,
		"easytier_data_plane_udp_receive_submit",
		uint64(socket),
		uint64(maximum),
	)
}

func (core *Core) SubmitUDPSend(
	ctx context.Context,
	socket ResourceID,
	peer netip.AddrPort,
	data []byte,
) (operation OperationID, err error) {
	if len(data) > maxDataPlaneTransferBytes {
		return 0, fmt.Errorf(
			"UDP send length %d exceeds data plane limit %d",
			len(data),
			maxDataPlaneTransferBytes,
		)
	}
	address, err := encodeSocketAddress(peer)
	if err != nil {
		return 0, err
	}
	addressPointer, err := core.ensureDataPlaneAddress(ctx)
	if err != nil {
		return 0, err
	}
	if !core.module.Memory().Write(addressPointer, address[:]) {
		return 0, fmt.Errorf("write UDP peer address to guest memory")
	}
	var dataPointer uint32
	if len(data) != 0 {
		dataPointer, err = core.ensureDataPlaneInput(ctx, uint32(len(data)))
		if err != nil {
			return 0, err
		}
		if !core.module.Memory().Write(dataPointer, data) {
			return 0, fmt.Errorf("write UDP payload to guest memory")
		}
	}
	return core.submit(
		ctx,
		"easytier_data_plane_udp_send_submit",
		uint64(socket),
		uint64(addressPointer),
		uint64(dataPointer),
		uint64(len(data)),
	)
}

func (core *Core) SetResourceDeadline(
	ctx context.Context,
	resource ResourceID,
	direction DeadlineDirection,
	timeoutMillis uint64,
) error {
	result, err := core.callOne(
		ctx,
		"easytier_data_plane_resource_deadline_set",
		core.handle,
		uint64(resource),
		uint64(direction),
		timeoutMillis,
	)
	if err != nil {
		return err
	}
	if status := int32(result); status != 0 {
		return core.dataPlaneStatusError(
			ctx,
			"set data plane resource deadline",
			status,
		)
	}
	return nil
}

func (core *Core) submitWithInput(
	ctx context.Context,
	name string,
	input []byte,
	params ...uint64,
) (operation OperationID, err error) {
	pointer, err := core.writeInput(ctx, input)
	if err != nil {
		return 0, err
	}
	defer core.cleanupBuffer(ctx, pointer, &err)
	return core.submit(ctx, name, append([]uint64{uint64(pointer)}, params...)...)
}

func (core *Core) submit(
	ctx context.Context,
	name string,
	params ...uint64,
) (operation OperationID, err error) {
	pointer, err := core.ensureDataPlaneOutput(ctx, operationIDLength)
	if err != nil {
		return 0, err
	}
	callParams := make([]uint64, 0, len(params)+2)
	callParams = append(callParams, core.handle)
	callParams = append(callParams, params...)
	callParams = append(callParams, uint64(pointer))
	result, err := core.callOne(ctx, name, callParams...)
	if err != nil {
		return 0, err
	}
	if status := int32(result); status != 0 {
		return 0, core.dataPlaneStatusError(ctx, name, status)
	}
	wire, ok := core.module.Memory().Read(pointer, operationIDLength)
	if !ok {
		return 0, fmt.Errorf("read operation ID from guest memory")
	}
	operation = OperationID(binary.BigEndian.Uint64(wire))
	if operation == 0 {
		return 0, fmt.Errorf("%s returned zero operation ID", name)
	}
	return operation, nil
}

func (core *Core) DrainCompletions(
	ctx context.Context,
	maximum uint32,
) (completions []Completion, err error) {
	if maximum == 0 {
		return nil, nil
	}
	if uint64(maximum)*completionLength > math.MaxUint32 {
		return nil, fmt.Errorf("completion batch %d exceeds guest address space", maximum)
	}
	length := maximum * completionLength
	pointer, err := core.ensureDataPlaneOutput(ctx, length)
	if err != nil {
		return nil, err
	}
	result, err := core.callCached(
		ctx,
		"easytier_data_plane_completion_drain",
		&core.completionFunction,
		core.handle,
		uint64(pointer),
		uint64(maximum),
	)
	if err != nil {
		return nil, err
	}
	count := int32(result)
	if count < 0 {
		return nil, core.dataPlaneStatusError(
			ctx,
			"drain data plane completions",
			count,
		)
	}
	if uint32(count) > maximum {
		return nil, fmt.Errorf(
			"data plane drained %d completions into capacity %d",
			count,
			maximum,
		)
	}
	wire, ok := core.module.Memory().Read(
		pointer,
		uint32(count)*completionLength,
	)
	if !ok {
		return nil, fmt.Errorf("read data plane completions from guest memory")
	}
	return decodeCompletions(wire)
}

func (core *Core) TakeResult(
	ctx context.Context,
	completion Completion,
) (OperationResult, error) {
	result := OperationResult{Kind: completion.Kind}
	var err error
	switch completion.Kind {
	case OperationTCPConnect, OperationTCPAccept:
		result.Resource, result.Local, result.Peer, err =
			core.takeStreamResult(ctx, completion)
	case OperationTCPBind, OperationUDPBind:
		result.Resource, result.Local, err =
			core.takeBindResult(ctx, completion)
	case OperationTCPRead:
		result.Data, result.EOF, err = core.takeTCPReadResult(ctx, completion)
	case OperationTCPWrite:
		result.Length, err = core.takeLengthResult(
			ctx,
			completion,
			"easytier_data_plane_tcp_write_result_take",
		)
	case OperationUDPReceive:
		result.Data, result.Peer, result.Truncated, err =
			core.takeUDPReceiveResult(ctx, completion)
	case OperationUDPSend:
		result.Length, err = core.takeLengthResult(
			ctx,
			completion,
			"easytier_data_plane_udp_send_result_take",
		)
	default:
		return OperationResult{}, fmt.Errorf(
			"take unknown data plane operation kind %d",
			completion.Kind,
		)
	}
	return result, err
}

func (core *Core) takeStreamResult(
	ctx context.Context,
	completion Completion,
) (resource ResourceID, local, peer netip.AddrPort, err error) {
	name := "easytier_data_plane_tcp_connect_result_take"
	if completion.Kind == OperationTCPAccept {
		name = "easytier_data_plane_tcp_accept_result_take"
	}
	wire, err := core.takeFixedResult(ctx, completion, name, streamResultLength)
	if err != nil {
		return 0, netip.AddrPort{}, netip.AddrPort{}, err
	}
	return decodeStreamResult(wire)
}

func (core *Core) takeBindResult(
	ctx context.Context,
	completion Completion,
) (resource ResourceID, local netip.AddrPort, err error) {
	name := "easytier_data_plane_tcp_bind_result_take"
	if completion.Kind == OperationUDPBind {
		name = "easytier_data_plane_udp_bind_result_take"
	}
	wire, err := core.takeFixedResult(ctx, completion, name, bindResultLength)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	return decodeBindResult(wire)
}

func (core *Core) takeFixedResult(
	ctx context.Context,
	completion Completion,
	name string,
	length uint32,
) (wire []byte, err error) {
	pointer, err := core.ensureDataPlaneOutput(ctx, length)
	if err != nil {
		return nil, err
	}
	result, err := core.callOne(
		ctx,
		name,
		core.handle,
		uint64(completion.Operation),
		uint64(pointer),
	)
	if err != nil {
		return nil, err
	}
	if status := int32(result); status != 0 {
		return nil, core.dataPlaneStatusError(ctx, name, status)
	}
	bytes, ok := core.module.Memory().Read(pointer, length)
	if !ok {
		return nil, fmt.Errorf("read %s from guest memory", name)
	}
	return append([]byte(nil), bytes...), nil
}

func (core *Core) takeTCPReadResult(
	ctx context.Context,
	completion Completion,
) (data []byte, eof bool, err error) {
	data, metadata, err := core.takeVariableResult(
		ctx,
		completion,
		"easytier_data_plane_tcp_read_result_take",
		tcpReadMetadataLength,
	)
	if err != nil {
		return nil, false, err
	}
	if metadata[0] > 1 {
		return nil, false, fmt.Errorf(
			"data plane returned invalid TCP EOF flag %d",
			metadata[0],
		)
	}
	return data, metadata[0] == 1, nil
}

func (core *Core) takeUDPReceiveResult(
	ctx context.Context,
	completion Completion,
) (data []byte, peer netip.AddrPort, truncated bool, err error) {
	data, metadata, err := core.takeVariableResult(
		ctx,
		completion,
		"easytier_data_plane_udp_receive_result_take",
		udpReceiveMetadataLength,
	)
	if err != nil {
		return nil, netip.AddrPort{}, false, err
	}
	peer, err = decodeSocketAddress(metadata[:socketAddressLength])
	if err != nil {
		return nil, netip.AddrPort{}, false, err
	}
	if metadata[socketAddressLength] > 1 {
		return nil, netip.AddrPort{}, false, fmt.Errorf(
			"data plane returned invalid UDP truncation flag %d",
			metadata[socketAddressLength],
		)
	}
	return data, peer, metadata[socketAddressLength] == 1, nil
}

func (core *Core) takeVariableResult(
	ctx context.Context,
	completion Completion,
	name string,
	metadataLength uint32,
) (data, metadata []byte, err error) {
	capacity := uint32(maxDataPlaneTransferBytes)
	if completion.Kind == OperationUDPReceive {
		capacity = math.MaxUint16
	}
	dataPointer, err := core.ensureDataPlaneInput(ctx, capacity)
	if err != nil {
		return nil, nil, err
	}
	metadataPointer, err := core.ensureDataPlaneOutput(ctx, metadataLength)
	if err != nil {
		return nil, nil, err
	}
	result, err := core.callOne(
		ctx,
		name,
		core.handle,
		uint64(completion.Operation),
		uint64(dataPointer),
		uint64(capacity),
		uint64(metadataPointer),
	)
	if err != nil {
		return nil, nil, err
	}
	length := int32(result)
	if length < 0 {
		return nil, nil, core.dataPlaneStatusError(ctx, name, length)
	}
	if uint32(length) > capacity {
		return nil, nil, fmt.Errorf(
			"%s returned length %d into capacity %d",
			name,
			length,
			capacity,
		)
	}
	if length != 0 {
		bytes, ok := core.module.Memory().Read(dataPointer, uint32(length))
		if !ok {
			return nil, nil, fmt.Errorf("read %s payload from guest memory", name)
		}
		data = append([]byte(nil), bytes...)
	}
	bytes, ok := core.module.Memory().Read(metadataPointer, metadataLength)
	if !ok {
		return nil, nil, fmt.Errorf("read %s metadata from guest memory", name)
	}
	return data, append([]byte(nil), bytes...), nil
}

func (core *Core) takeLengthResult(
	ctx context.Context,
	completion Completion,
	name string,
) (int, error) {
	result, err := core.callOne(
		ctx,
		name,
		core.handle,
		uint64(completion.Operation),
	)
	if err != nil {
		return 0, err
	}
	length := int32(result)
	if length < 0 {
		return 0, core.dataPlaneStatusError(ctx, name, length)
	}
	return int(length), nil
}

func (core *Core) CancelOperation(
	ctx context.Context,
	operation OperationID,
) error {
	return core.dataPlaneCallStatus(
		ctx,
		"easytier_data_plane_operation_cancel",
		uint64(operation),
	)
}

func (core *Core) FreeOperation(
	ctx context.Context,
	operation OperationID,
) error {
	return core.dataPlaneCallStatus(
		ctx,
		"easytier_data_plane_operation_free",
		uint64(operation),
	)
}

func (core *Core) CloseResource(ctx context.Context, resource ResourceID) error {
	return core.dataPlaneCallStatus(
		ctx,
		"easytier_data_plane_resource_close",
		uint64(resource),
	)
}

func (core *Core) dataPlaneCallStatus(
	ctx context.Context,
	name string,
	params ...uint64,
) error {
	callParams := append([]uint64{core.handle}, params...)
	result, err := core.callOne(ctx, name, callParams...)
	if err != nil {
		return err
	}
	if status := int32(result); status != 0 {
		return core.dataPlaneStatusError(ctx, name, status)
	}
	return nil
}

func (core *Core) dataPlaneStatusError(
	ctx context.Context,
	operation string,
	status int32,
) error {
	if status >= 0 || status < -int32(ErrorBufferTooSmall) {
		return core.statusError(ctx, operation, status)
	}
	message, err := core.errorMessage(ctx, core.handle)
	if err != nil {
		return errors.Join(
			&DataPlaneError{Kind: ErrorKind(-status)},
			fmt.Errorf("%s: %w", operation, err),
		)
	}
	return &DataPlaneError{
		Kind:    ErrorKind(-status),
		Message: message,
	}
}

func (core *Core) writeInput(
	ctx context.Context,
	data []byte,
) (uint32, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if uint64(len(data)) > math.MaxUint32 {
		return 0, fmt.Errorf("guest input length %d exceeds wasm32", len(data))
	}
	pointer, err := core.allocate(ctx, uint32(len(data)))
	if err != nil {
		return 0, err
	}
	if !core.module.Memory().Write(pointer, data) {
		_ = core.free(contextutil.WithoutCancel(ctx), pointer)
		return 0, fmt.Errorf("write data plane input to guest memory")
	}
	return pointer, nil
}
