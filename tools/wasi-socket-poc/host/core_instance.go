package host

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/tetratelabs/wazero/api"
)

// CoreState is the lifecycle state exported by easytier-core's WASI ABI.
type CoreState int32

const (
	CoreStateCreated  CoreState = 0
	CoreStateStarting CoreState = 1
	CoreStateRunning  CoreState = 2
	CoreStateStopping CoreState = 3
	CoreStateStopped  CoreState = 4
)

// CoreInstance serializes calls into one instantiated easytier-core module.
type CoreInstance struct {
	mu      sync.Mutex
	module  api.Module
	handle  uint64
	dropped bool
}

// CreateCoreInstance copies normalized JSON configuration into guest memory
// and creates one core instance using an already-instantiated module.
func CreateCoreInstance(
	ctx context.Context,
	module api.Module,
	config []byte,
	packetSink uint64,
) (*CoreInstance, error) {
	instance := &CoreInstance{module: module}
	pointer, err := instance.allocate(ctx, uint32(len(config)))
	if err != nil {
		return nil, err
	}
	defer func() { _ = instance.free(ctx, pointer) }()
	if !module.Memory().Write(pointer, config) {
		return nil, fmt.Errorf("write core config to guest memory")
	}
	result, err := callOne(
		ctx,
		module,
		"easytier_instance_create",
		uint64(pointer),
		uint64(len(config)),
		packetSink,
	)
	if err != nil {
		return nil, err
	}
	if result == 0 {
		message, readErr := instance.errorMessage(ctx, 0)
		if readErr != nil {
			return nil, fmt.Errorf("create core instance: %w", readErr)
		}
		return nil, fmt.Errorf("create core instance: %s", message)
	}
	instance.handle = result
	return instance, nil
}

func (instance *CoreInstance) Handle() uint64 {
	return instance.handle
}

func (instance *CoreInstance) Start(ctx context.Context) error {
	return instance.callStatus(ctx, "easytier_instance_start")
}

func (instance *CoreInstance) Stop(ctx context.Context) error {
	return instance.callStatus(ctx, "easytier_instance_stop")
}

func (instance *CoreInstance) Drive(ctx context.Context) (CoreState, error) {
	instance.mu.Lock()
	defer instance.mu.Unlock()
	if instance.dropped {
		return 0, fmt.Errorf("drive dropped core instance")
	}
	result, err := callOne(ctx, instance.module, "easytier_instance_drive", instance.handle)
	if err != nil {
		return 0, err
	}
	state := CoreState(int32(result))
	if state < 0 {
		return 0, instance.statusError(ctx, "drive core instance", int32(state))
	}
	return state, nil
}

func (instance *CoreInstance) NextDeadline(ctx context.Context) (int64, error) {
	instance.mu.Lock()
	defer instance.mu.Unlock()
	if instance.dropped {
		return 0, fmt.Errorf("query deadline for dropped core instance")
	}
	result, err := callOne(
		ctx,
		instance.module,
		"easytier_instance_next_deadline_millis",
		instance.handle,
	)
	if err != nil {
		return 0, err
	}
	deadline := int64(result)
	if deadline < 0 {
		return 0, instance.statusError(ctx, "query core deadline", int32(deadline))
	}
	return deadline, nil
}

// DriveUntil runs bounded guest turns and waits only for host completion or
// the exact next deadline exported by core.
func (instance *CoreInstance) DriveUntil(
	ctx context.Context,
	completion <-chan struct{},
	wanted CoreState,
) error {
	for {
		state, err := instance.Drive(ctx)
		if err != nil {
			return err
		}
		if state == wanted {
			return nil
		}
		if state == CoreStateStarting || state == CoreStateStopping {
			continue
		}
		deadline, err := instance.NextDeadline(ctx)
		if err != nil {
			return err
		}
		if deadline == math.MaxInt64 {
			select {
			case <-completion:
			case <-ctx.Done():
				return ctx.Err()
			}
			continue
		}
		timer := time.NewTimer(time.Duration(deadline) * time.Millisecond)
		select {
		case <-completion:
			stopTimer(timer)
		case <-timer.C:
		case <-ctx.Done():
			stopTimer(timer)
			return ctx.Err()
		}
	}
}

func (instance *CoreInstance) SendPacket(ctx context.Context, packet []byte) error {
	instance.mu.Lock()
	defer instance.mu.Unlock()
	if instance.dropped {
		return fmt.Errorf("send packet to dropped core instance")
	}
	pointer, err := instance.allocate(ctx, uint32(len(packet)))
	if err != nil {
		return err
	}
	defer func() { _ = instance.free(ctx, pointer) }()
	if !instance.module.Memory().Write(pointer, packet) {
		return fmt.Errorf("write packet to guest memory")
	}
	result, err := callOne(
		ctx,
		instance.module,
		"easytier_instance_send_packet",
		instance.handle,
		uint64(pointer),
		uint64(len(packet)),
	)
	if err != nil {
		return err
	}
	if status := int32(result); status != 0 {
		return instance.statusError(ctx, "send core packet", status)
	}
	return nil
}

func (instance *CoreInstance) Drop(ctx context.Context) error {
	instance.mu.Lock()
	defer instance.mu.Unlock()
	if instance.dropped {
		return nil
	}
	if err := instance.callStatusLocked(ctx, "easytier_instance_drop"); err != nil {
		return err
	}
	instance.dropped = true
	return nil
}

func (instance *CoreInstance) callStatus(ctx context.Context, name string) error {
	instance.mu.Lock()
	defer instance.mu.Unlock()
	return instance.callStatusLocked(ctx, name)
}

func (instance *CoreInstance) callStatusLocked(ctx context.Context, name string) error {
	if instance.dropped {
		return fmt.Errorf("%s on dropped core instance", name)
	}
	result, err := callOne(ctx, instance.module, name, instance.handle)
	if err != nil {
		return err
	}
	if status := int32(result); status != 0 {
		return instance.statusError(ctx, name, status)
	}
	return nil
}

func (instance *CoreInstance) statusError(ctx context.Context, operation string, status int32) error {
	message, err := instance.errorMessage(ctx, instance.handle)
	if err != nil {
		return fmt.Errorf("%s: status=%d: %w", operation, status, err)
	}
	return fmt.Errorf("%s: status=%d: %s", operation, status, message)
}

func (instance *CoreInstance) errorMessage(ctx context.Context, handle uint64) (string, error) {
	length, err := callOne(ctx, instance.module, "easytier_instance_error_len", handle)
	if err != nil {
		return "", err
	}
	if length == 0 {
		return "<no core error>", nil
	}
	pointer, err := instance.allocate(ctx, uint32(length))
	if err != nil {
		return "", err
	}
	defer func() { _ = instance.free(ctx, pointer) }()
	result, err := callOne(
		ctx,
		instance.module,
		"easytier_instance_error_copy",
		handle,
		uint64(pointer),
		length,
	)
	if err != nil {
		return "", err
	}
	if status := int32(result); status < 0 {
		return "", fmt.Errorf("copy core error: status=%d", status)
	}
	encoded, ok := instance.module.Memory().Read(pointer, uint32(length))
	if !ok {
		return "", fmt.Errorf("read core error from guest memory")
	}
	return string(encoded), nil
}

func (instance *CoreInstance) allocate(ctx context.Context, length uint32) (uint32, error) {
	result, err := callOne(ctx, instance.module, "easytier_buffer_alloc", uint64(length))
	if err != nil {
		return 0, err
	}
	if result == 0 {
		return 0, fmt.Errorf("allocate %d guest bytes", length)
	}
	return uint32(result), nil
}

func (instance *CoreInstance) free(ctx context.Context, pointer uint32) error {
	result, err := callOne(ctx, instance.module, "easytier_buffer_free", uint64(pointer))
	if err != nil {
		return err
	}
	if status := int32(result); status != 0 {
		return fmt.Errorf("free guest buffer: status=%d", status)
	}
	return nil
}

func callOne(ctx context.Context, module api.Module, name string, params ...uint64) (uint64, error) {
	results, err := module.ExportedFunction(name).Call(ctx, params...)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if len(results) != 1 {
		return 0, fmt.Errorf("%s returned %d values", name, len(results))
	}
	return results[0], nil
}

func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}
