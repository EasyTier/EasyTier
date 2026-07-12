package host

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
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

// CoreModule serializes every call into one instantiated easytier-core module.
// A module owns at most one live CoreInstance because host completion readiness
// is module-scoped.
type CoreModule struct {
	mu             sync.Mutex
	module         api.Module
	activeInstance uint64
}

// CoreInstance is one core handle owned by a CoreModule.
type CoreInstance struct {
	coreModule *CoreModule
	handle     uint64
	dropped    bool
}

// InstantiateCoreModule instantiates one compiled easytier-core module and
// creates its unique call-serialization and completion ownership domain.
func InstantiateCoreModule(
	ctx context.Context,
	runtime wazero.Runtime,
	compiled wazero.CompiledModule,
	moduleConfig wazero.ModuleConfig,
) (*CoreModule, error) {
	module, err := runtime.InstantiateModule(ctx, compiled, moduleConfig)
	if err != nil {
		return nil, err
	}
	return &CoreModule{module: module}, nil
}

// CreateInstance copies normalized JSON configuration into guest memory and
// creates one core instance in the module.
func (module *CoreModule) CreateInstance(
	ctx context.Context,
	config []byte,
	packetSink uint64,
) (*CoreInstance, error) {
	module.mu.Lock()
	defer module.mu.Unlock()
	if module.activeInstance != 0 {
		return nil, fmt.Errorf("core module already owns a live instance")
	}

	pointer, err := module.allocate(ctx, uint32(len(config)))
	if err != nil {
		return nil, err
	}
	if !module.module.Memory().Write(pointer, config) {
		_ = module.free(context.WithoutCancel(ctx), pointer)
		return nil, fmt.Errorf("write core config to guest memory")
	}
	result, err := callOne(
		ctx,
		module.module,
		"easytier_instance_create",
		uint64(pointer),
		uint64(len(config)),
		packetSink,
	)
	if err != nil {
		_ = module.free(context.WithoutCancel(ctx), pointer)
		return nil, err
	}
	if result == 0 {
		message, readErr := module.errorMessage(ctx, 0)
		_ = module.free(context.WithoutCancel(ctx), pointer)
		if readErr != nil {
			return nil, fmt.Errorf("create core instance: %w", readErr)
		}
		return nil, fmt.Errorf("create core instance: %s", message)
	}
	module.activeInstance = result
	if err := module.free(context.WithoutCancel(ctx), pointer); err != nil {
		dropResult, dropErr := callOne(
			context.WithoutCancel(ctx),
			module.module,
			"easytier_instance_drop",
			result,
		)
		if dropErr == nil && int32(dropResult) == 0 {
			module.activeInstance = 0
			return nil, err
		}
		if dropErr != nil {
			return nil, fmt.Errorf("%w; drop failed core instance: %v", err, dropErr)
		}
		return nil, fmt.Errorf(
			"%w; drop failed core instance: status=%d",
			err,
			int32(dropResult),
		)
	}
	return &CoreInstance{coreModule: module, handle: result}, nil
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
	instance.coreModule.mu.Lock()
	defer instance.coreModule.mu.Unlock()
	if instance.dropped {
		return 0, fmt.Errorf("drive dropped core instance")
	}
	result, err := callOne(
		ctx,
		instance.coreModule.module,
		"easytier_instance_drive",
		instance.handle,
	)
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
	instance.coreModule.mu.Lock()
	defer instance.coreModule.mu.Unlock()
	if instance.dropped {
		return 0, fmt.Errorf("query deadline for dropped core instance")
	}
	result, err := callOne(
		ctx,
		instance.coreModule.module,
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
	return driveUntil(ctx, completion, wanted, instance.Drive, instance.NextDeadline)
}

func driveUntil(
	ctx context.Context,
	completion <-chan struct{},
	wanted CoreState,
	drive func(context.Context) (CoreState, error),
	nextDeadline func(context.Context) (int64, error),
) error {
	for {
		state, err := drive(ctx)
		if err != nil {
			return err
		}
		if state == wanted {
			return nil
		}
		deadline, err := nextDeadline(ctx)
		if err != nil {
			return err
		}
		if deadline == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
			continue
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

func (instance *CoreInstance) SendPacket(ctx context.Context, packet []byte) (err error) {
	instance.coreModule.mu.Lock()
	defer instance.coreModule.mu.Unlock()
	if instance.dropped {
		return fmt.Errorf("send packet to dropped core instance")
	}
	pointer, err := instance.coreModule.allocate(ctx, uint32(len(packet)))
	if err != nil {
		return err
	}
	defer instance.coreModule.cleanupBuffer(ctx, pointer, &err)
	if !instance.coreModule.module.Memory().Write(pointer, packet) {
		return fmt.Errorf("write packet to guest memory")
	}
	result, err := callOne(
		ctx,
		instance.coreModule.module,
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
	instance.coreModule.mu.Lock()
	defer instance.coreModule.mu.Unlock()
	if instance.dropped {
		return nil
	}
	if err := instance.callStatusLocked(ctx, "easytier_instance_drop"); err != nil {
		return err
	}
	instance.dropped = true
	instance.coreModule.activeInstance = 0
	return nil
}

func (instance *CoreInstance) callStatus(ctx context.Context, name string) error {
	instance.coreModule.mu.Lock()
	defer instance.coreModule.mu.Unlock()
	return instance.callStatusLocked(ctx, name)
}

func (instance *CoreInstance) callStatusLocked(ctx context.Context, name string) error {
	if instance.dropped {
		return fmt.Errorf("%s on dropped core instance", name)
	}
	result, err := callOne(ctx, instance.coreModule.module, name, instance.handle)
	if err != nil {
		return err
	}
	if status := int32(result); status != 0 {
		return instance.statusError(ctx, name, status)
	}
	return nil
}

func (instance *CoreInstance) statusError(ctx context.Context, operation string, status int32) error {
	message, err := instance.coreModule.errorMessage(ctx, instance.handle)
	if err != nil {
		return fmt.Errorf("%s: status=%d: %w", operation, status, err)
	}
	return fmt.Errorf("%s: status=%d: %s", operation, status, message)
}

func (module *CoreModule) errorMessage(ctx context.Context, handle uint64) (message string, err error) {
	length, err := callOne(ctx, module.module, "easytier_instance_error_len", handle)
	if err != nil {
		return "", err
	}
	if length == 0 {
		return "<no core error>", nil
	}
	pointer, err := module.allocate(ctx, uint32(length))
	if err != nil {
		return "", err
	}
	defer module.cleanupBuffer(ctx, pointer, &err)
	result, err := callOne(
		ctx,
		module.module,
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
	encoded, ok := module.module.Memory().Read(pointer, uint32(length))
	if !ok {
		return "", fmt.Errorf("read core error from guest memory")
	}
	return string(encoded), nil
}

func (module *CoreModule) allocate(ctx context.Context, length uint32) (uint32, error) {
	result, err := callOne(ctx, module.module, "easytier_buffer_alloc", uint64(length))
	if err != nil {
		return 0, err
	}
	if result == 0 {
		return 0, fmt.Errorf("allocate %d guest bytes", length)
	}
	return uint32(result), nil
}

func (module *CoreModule) free(ctx context.Context, pointer uint32) error {
	result, err := callOne(ctx, module.module, "easytier_buffer_free", uint64(pointer))
	if err != nil {
		return err
	}
	if status := int32(result); status != 0 {
		return fmt.Errorf("free guest buffer: status=%d", status)
	}
	return nil
}

func (module *CoreModule) cleanupBuffer(
	ctx context.Context,
	pointer uint32,
	operationErr *error,
) {
	cleanupErr := module.free(context.WithoutCancel(ctx), pointer)
	if *operationErr == nil && cleanupErr != nil {
		*operationErr = cleanupErr
	}
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
