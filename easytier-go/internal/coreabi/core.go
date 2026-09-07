package coreabi

import (
	"context"
	"errors"
	"fmt"

	"github.com/EasyTier/EasyTier/easytier-go/internal/contextutil"
	"github.com/metacubex/wazero/api"
)

type State int32

const (
	StateCreated State = iota
	StateStarting
	StateRunning
	StateStopping
	StateStopped
)

type Core struct {
	module               api.Module
	functions            map[string]guestFunction
	driveFunction        guestFunction
	deadlineFunction     guestFunction
	completionFunction   guestFunction
	handle               uint64
	packetBuffer         uint32
	packetBufferCapacity uint32
	dataPlaneAddress     uint32
	dataPlaneInput       uint32
	dataPlaneInputSize   uint32
	dataPlaneOutput      uint32
	dataPlaneOutputSize  uint32
	dropped              bool
}

type guestFunction struct {
	call           api.Function
	parameterCount int
}

func New(module api.Module) (*Core, error) {
	if module == nil {
		return nil, fmt.Errorf("create core ABI with nil guest module")
	}
	core := &Core{
		module:    module,
		functions: make(map[string]guestFunction),
	}
	if err := core.validateDataPlaneABI(context.Background()); err != nil {
		return nil, fmt.Errorf("validate EasyTier data plane ABI: %w", err)
	}
	if err := core.validateRPCABI(context.Background()); err != nil {
		return nil, fmt.Errorf("validate EasyTier RPC ABI: %w", err)
	}
	return core, nil
}

func (core *Core) Create(
	ctx context.Context,
	configEnvelope []byte,
	packetSink uint64,
	eventSink uint64,
) (err error) {
	if core.handle != 0 || core.dropped {
		return fmt.Errorf("create EasyTier instance in used guest module")
	}
	pointer, err := core.allocate(ctx, uint32(len(configEnvelope)))
	if err != nil {
		return err
	}
	defer core.cleanupBuffer(ctx, pointer, &err)
	if !core.module.Memory().Write(pointer, configEnvelope) {
		return fmt.Errorf("write EasyTier config to guest memory")
	}
	result, err := core.callOne(
		ctx,
		"easytier_instance_create",
		uint64(pointer),
		uint64(len(configEnvelope)),
		packetSink,
		eventSink,
	)
	if err != nil {
		return err
	}
	if result == 0 {
		message, readErr := core.errorMessage(ctx, 0)
		if readErr != nil {
			return fmt.Errorf("create EasyTier instance: %w", readErr)
		}
		return fmt.Errorf("create EasyTier instance: %s", message)
	}
	core.handle = result
	return nil
}

func (core *Core) Start(ctx context.Context) error {
	return core.callStatus(ctx, "easytier_instance_start")
}

func (core *Core) Stop(ctx context.Context) error {
	return core.callStatus(ctx, "easytier_instance_stop")
}

func (core *Core) Drive(ctx context.Context) (State, error) {
	result, err := core.callCached(
		ctx,
		"easytier_instance_drive",
		&core.driveFunction,
		core.handle,
	)
	if err != nil {
		return 0, err
	}
	state := State(int32(result))
	if state < 0 {
		return 0, core.statusError(ctx, "drive EasyTier instance", int32(state))
	}
	return state, nil
}

func (core *Core) NotifyCompletions(ctx context.Context) error {
	return core.callStatus(ctx, "easytier_instance_notify_completions")
}

func (core *Core) State(ctx context.Context) (State, error) {
	result, err := core.callOne(ctx, "easytier_instance_state", core.handle)
	if err != nil {
		return 0, err
	}
	state := State(int32(result))
	if state < 0 {
		return 0, core.statusError(ctx, "query EasyTier state", int32(state))
	}
	return state, nil
}

func (core *Core) NextDeadline(ctx context.Context) (int64, error) {
	result, err := core.callCached(
		ctx,
		"easytier_instance_next_deadline_millis",
		&core.deadlineFunction,
		core.handle,
	)
	if err != nil {
		return 0, err
	}
	deadline := int64(result)
	if deadline < 0 {
		return 0, core.statusError(ctx, "query EasyTier deadline", int32(deadline))
	}
	return deadline, nil
}

func (core *Core) SendPacket(ctx context.Context, packet []byte) (err error) {
	if len(packet) == 0 {
		return fmt.Errorf("send empty packet to EasyTier instance")
	}
	pointer, err := core.ensurePacketBuffer(ctx, uint32(len(packet)))
	if err != nil {
		return err
	}
	if !core.module.Memory().Write(pointer, packet) {
		return fmt.Errorf("write packet to guest memory")
	}
	result, err := core.callOne(
		ctx,
		"easytier_instance_send_packet",
		core.handle,
		uint64(pointer),
		uint64(len(packet)),
	)
	if err != nil {
		return err
	}
	if status := int32(result); status != 0 {
		return core.statusError(ctx, "send packet to EasyTier instance", status)
	}
	return nil
}

func (core *Core) Drop(ctx context.Context) error {
	if core.dropped || core.handle == 0 {
		return nil
	}
	if err := core.callStatus(ctx, "easytier_instance_drop"); err != nil {
		return err
	}
	core.dropped = true
	core.handle = 0
	var releaseErr error
	if core.packetBuffer != 0 {
		err := core.free(ctx, core.packetBuffer)
		core.packetBuffer = 0
		core.packetBufferCapacity = 0
		if err != nil {
			releaseErr = errors.Join(
				releaseErr,
				fmt.Errorf("release EasyTier packet buffer: %w", err),
			)
		}
	}
	if core.dataPlaneInput != 0 {
		err := core.free(ctx, core.dataPlaneInput)
		core.dataPlaneInput = 0
		core.dataPlaneInputSize = 0
		if err != nil {
			releaseErr = errors.Join(
				releaseErr,
				fmt.Errorf("release EasyTier data plane input buffer: %w", err),
			)
		}
	}
	if core.dataPlaneAddress != 0 {
		err := core.free(ctx, core.dataPlaneAddress)
		core.dataPlaneAddress = 0
		if err != nil {
			releaseErr = errors.Join(
				releaseErr,
				fmt.Errorf("release EasyTier data plane address buffer: %w", err),
			)
		}
	}
	if core.dataPlaneOutput != 0 {
		err := core.free(ctx, core.dataPlaneOutput)
		core.dataPlaneOutput = 0
		core.dataPlaneOutputSize = 0
		if err != nil {
			releaseErr = errors.Join(
				releaseErr,
				fmt.Errorf("release EasyTier data plane output buffer: %w", err),
			)
		}
	}
	return releaseErr
}

func (core *Core) callStatus(ctx context.Context, name string) error {
	if core.dropped || core.handle == 0 {
		return fmt.Errorf("%s on unavailable EasyTier instance", name)
	}
	result, err := core.callOne(ctx, name, core.handle)
	if err != nil {
		return err
	}
	if status := int32(result); status != 0 {
		return core.statusError(ctx, name, status)
	}
	return nil
}

func (core *Core) statusError(
	ctx context.Context,
	operation string,
	status int32,
) error {
	message, err := core.errorMessage(ctx, core.handle)
	if err != nil {
		return fmt.Errorf("%s: status=%d: %w", operation, status, err)
	}
	return fmt.Errorf("%s: status=%d: %s", operation, status, message)
}

func (core *Core) errorMessage(
	ctx context.Context,
	handle uint64,
) (message string, err error) {
	length, err := core.callOne(ctx, "easytier_instance_error_len", handle)
	if err != nil {
		return "", err
	}
	if length == 0 {
		return "<no core error>", nil
	}
	pointer, err := core.allocate(ctx, uint32(length))
	if err != nil {
		return "", err
	}
	defer core.cleanupBuffer(ctx, pointer, &err)
	result, err := core.callOne(
		ctx,
		"easytier_instance_error_copy",
		handle,
		uint64(pointer),
		length,
	)
	if err != nil {
		return "", err
	}
	if status := int32(result); status < 0 {
		return "", fmt.Errorf("copy EasyTier error: status=%d", status)
	}
	encoded, ok := core.module.Memory().Read(pointer, uint32(length))
	if !ok {
		return "", fmt.Errorf("read EasyTier error from guest memory")
	}
	return string(encoded), nil
}

func (core *Core) allocate(ctx context.Context, length uint32) (uint32, error) {
	result, err := core.callOne(ctx, "easytier_buffer_alloc", uint64(length))
	if err != nil {
		return 0, err
	}
	if result == 0 {
		return 0, fmt.Errorf("allocate %d guest bytes", length)
	}
	return uint32(result), nil
}

func (core *Core) free(ctx context.Context, pointer uint32) error {
	result, err := core.callOne(ctx, "easytier_buffer_free", uint64(pointer))
	if err != nil {
		return err
	}
	if status := int32(result); status != 0 {
		return fmt.Errorf("free guest buffer: status=%d", status)
	}
	return nil
}

func (core *Core) ensurePacketBuffer(
	ctx context.Context,
	length uint32,
) (uint32, error) {
	if core.packetBufferCapacity >= length {
		return core.packetBuffer, nil
	}
	if core.packetBuffer != 0 {
		if err := core.free(ctx, core.packetBuffer); err != nil {
			return 0, fmt.Errorf("grow EasyTier packet buffer: %w", err)
		}
		core.packetBuffer = 0
		core.packetBufferCapacity = 0
	}
	pointer, err := core.allocate(ctx, length)
	if err != nil {
		return 0, err
	}
	core.packetBuffer = pointer
	core.packetBufferCapacity = length
	return pointer, nil
}

func (core *Core) ensureDataPlaneInput(
	ctx context.Context,
	length uint32,
) (uint32, error) {
	if core.dataPlaneInputSize >= length {
		return core.dataPlaneInput, nil
	}
	if core.dataPlaneInput != 0 {
		if err := core.free(ctx, core.dataPlaneInput); err != nil {
			return 0, fmt.Errorf("grow EasyTier data plane input buffer: %w", err)
		}
		core.dataPlaneInput = 0
		core.dataPlaneInputSize = 0
	}
	pointer, err := core.allocate(ctx, length)
	if err != nil {
		return 0, err
	}
	core.dataPlaneInput = pointer
	core.dataPlaneInputSize = length
	return pointer, nil
}

func (core *Core) ensureDataPlaneAddress(ctx context.Context) (uint32, error) {
	if core.dataPlaneAddress != 0 {
		return core.dataPlaneAddress, nil
	}
	pointer, err := core.allocate(ctx, socketAddressLength)
	if err != nil {
		return 0, err
	}
	core.dataPlaneAddress = pointer
	return pointer, nil
}

func (core *Core) ensureDataPlaneOutput(
	ctx context.Context,
	length uint32,
) (uint32, error) {
	if core.dataPlaneOutputSize >= length {
		return core.dataPlaneOutput, nil
	}
	if core.dataPlaneOutput != 0 {
		if err := core.free(ctx, core.dataPlaneOutput); err != nil {
			return 0, fmt.Errorf("grow EasyTier data plane output buffer: %w", err)
		}
		core.dataPlaneOutput = 0
		core.dataPlaneOutputSize = 0
	}
	pointer, err := core.allocate(ctx, length)
	if err != nil {
		return 0, err
	}
	core.dataPlaneOutput = pointer
	core.dataPlaneOutputSize = length
	return pointer, nil
}

func (core *Core) cleanupBuffer(
	ctx context.Context,
	pointer uint32,
	operationErr *error,
) {
	cleanupErr := core.free(contextutil.WithoutCancel(ctx), pointer)
	if *operationErr == nil && cleanupErr != nil {
		*operationErr = cleanupErr
	}
}

func (core *Core) callOne(
	ctx context.Context,
	name string,
	params ...uint64,
) (uint64, error) {
	function, err := core.resolveFunction(name)
	if err != nil {
		return 0, err
	}
	return callGuestFunction(ctx, name, function, params)
}

func (core *Core) callCached(
	ctx context.Context,
	name string,
	cached *guestFunction,
	params ...uint64,
) (uint64, error) {
	if cached.call == nil {
		function, err := core.resolveFunction(name)
		if err != nil {
			return 0, err
		}
		*cached = function
	}
	return callGuestFunction(ctx, name, *cached, params)
}

func (core *Core) resolveFunction(name string) (guestFunction, error) {
	function, exists := core.functions[name]
	if !exists {
		call := core.module.ExportedFunction(name)
		if call == nil {
			return guestFunction{}, fmt.Errorf(
				"EasyTier guest does not export %s",
				name,
			)
		}
		definition := call.Definition()
		if count := len(definition.ResultTypes()); count != 1 {
			return guestFunction{}, fmt.Errorf(
				"%s returned %d values",
				name,
				count,
			)
		}
		function = guestFunction{
			call:           call,
			parameterCount: len(definition.ParamTypes()),
		}
		core.functions[name] = function
	}
	return function, nil
}

func callGuestFunction(
	ctx context.Context,
	name string,
	function guestFunction,
	params []uint64,
) (uint64, error) {
	if len(params) != function.parameterCount {
		return 0, fmt.Errorf(
			"%s expected %d params, but passed %d",
			name,
			function.parameterCount,
			len(params),
		)
	}

	stack := params
	if len(stack) == 0 {
		stack = make([]uint64, 1)
	}
	if err := function.call.CallWithStack(ctx, stack); err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return stack[0], nil
}
