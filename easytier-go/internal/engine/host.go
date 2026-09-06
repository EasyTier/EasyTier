package engine

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/easytier-go/internal/artifact"
	"github.com/EasyTier/EasyTier/easytier-go/internal/contextutil"
	"github.com/EasyTier/EasyTier/easytier-go/internal/coreabi"
	"github.com/EasyTier/EasyTier/easytier-go/internal/hostabi"
	"github.com/EasyTier/EasyTier/easytier-go/internal/reactor"
	"github.com/EasyTier/EasyTier/easytier-go/platform"
	"github.com/metacubex/wazero"
	"github.com/metacubex/wazero/api"
	"github.com/metacubex/wazero/imports/wasi_snapshot_preview1"
)

const defaultPacketQueueCapacity = 64
const maximumPacketIngressBatch = 32

type Options struct {
	Services            platform.Services
	PacketQueueCapacity int
	Management          reactor.ManagementHandler
}

type Host struct {
	ctx    context.Context
	cancel context.CancelFunc

	runtime wazero.Runtime
	module  api.Module
	reactor *reactor.Reactor
	options Options

	guestMu sync.Mutex

	mu        sync.Mutex
	closed    bool
	instances map[*Instance]struct{}
	webClient *WebClient
	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

func NewHost(ctx context.Context, options Options) (_ *Host, err error) {
	if ctx == nil {
		return nil, fmt.Errorf("create EasyTier engine host with nil context")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if options.PacketQueueCapacity == 0 {
		options.PacketQueueCapacity = defaultPacketQueueCapacity
	}
	if options.PacketQueueCapacity < 0 {
		return nil, fmt.Errorf("packet queue capacity must be positive")
	}

	lifetime, cancel := context.WithCancel(contextutil.WithoutCancel(ctx))
	runtime := wazero.NewRuntime(lifetime)
	var module api.Module
	var hostReactor *reactor.Reactor
	defer func() {
		if err == nil {
			return
		}
		cancel()
		if module != nil {
			_ = module.Close(contextutil.WithoutCancel(ctx))
		}
		if hostReactor != nil {
			hostReactor.Close()
		}
		_ = runtime.Close(contextutil.WithoutCancel(ctx))
	}()

	if _, err = wasi_snapshot_preview1.Instantiate(ctx, runtime); err != nil {
		return nil, fmt.Errorf("instantiate WASI preview1: %w", err)
	}
	hostReactor = reactor.New(lifetime, reactor.Options{
		Services:   options.Services,
		Management: options.Management,
	})
	adapter, err := hostabi.New(hostReactor)
	if err != nil {
		return nil, err
	}
	if err = adapter.Instantiate(ctx, runtime); err != nil {
		return nil, fmt.Errorf("instantiate EasyTier host ABI: %w", err)
	}
	compiled, err := runtime.CompileModule(ctx, artifact.Core())
	if err != nil {
		return nil, fmt.Errorf("compile embedded EasyTier core: %w", err)
	}
	defer compiled.Close(contextutil.WithoutCancel(ctx))
	module, err = runtime.InstantiateModule(ctx, compiled, newModuleConfig())
	if err != nil {
		return nil, fmt.Errorf("instantiate embedded EasyTier core: %w", err)
	}

	host := &Host{
		ctx:       lifetime,
		cancel:    cancel,
		runtime:   runtime,
		module:    module,
		reactor:   hostReactor,
		options:   options,
		instances: make(map[*Instance]struct{}),
		closeDone: make(chan struct{}),
	}
	go host.broadcastCompletions()
	return host, nil
}

func newModuleConfig() wazero.ModuleConfig {
	return wazero.NewModuleConfig().
		WithRandSource(rand.Reader).
		WithSysWalltime().
		WithSysNanotime().
		WithSysNanosleep()
}

func (host *Host) CreateInstance(
	ctx context.Context,
	configTOML string,
) (*Instance, error) {
	if host == nil {
		return nil, fmt.Errorf("create instance with nil EasyTier engine host")
	}
	if ctx == nil {
		return nil, fmt.Errorf("create EasyTier instance with nil context")
	}
	envelope, err := encodeCreateEnvelope(configTOML, host.options.Services.Snapshot)
	if err != nil {
		return nil, err
	}

	host.mu.Lock()
	defer host.mu.Unlock()
	if host.closed {
		return nil, fmt.Errorf("create instance with closed EasyTier engine host")
	}
	packetSink, err := host.reactor.RegisterPacketSink(host.options.PacketQueueCapacity)
	if err != nil {
		return nil, fmt.Errorf("register EasyTier packet sink: %w", err)
	}
	events := make(chan Event, instanceEventQueueCapacity)
	journal := newEventJournal()
	eventSink, err := host.reactor.RegisterEventSink(func(kind, message string) bool {
		journal.add(kind, message)
		select {
		case events <- Event{Kind: kind, Message: message}:
			return true
		default:
			return false
		}
	})
	if err != nil {
		host.reactor.UnregisterPacketSink(packetSink)
		close(events)
		return nil, fmt.Errorf("register EasyTier event sink: %w", err)
	}
	host.guestMu.Lock()
	core, err := coreabi.New(host.module)
	if err == nil {
		err = core.Create(ctx, envelope, packetSink, eventSink)
	}
	host.guestMu.Unlock()
	if err != nil {
		host.reactor.UnregisterPacketSink(packetSink)
		host.reactor.UnregisterEventSink(eventSink)
		close(events)
		return nil, err
	}

	lifetime, cancel := context.WithCancel(host.ctx)
	instance := &Instance{
		host:              host,
		ctx:               lifetime,
		cancel:            cancel,
		core:              core,
		dataPlane:         core,
		rpc:               core,
		reactor:           host.reactor,
		packetSink:        packetSink,
		eventSink:         eventSink,
		events:            events,
		journal:           journal,
		commands:          make(chan command, maximumPacketIngressBatch),
		dataPlaneCommands: make(chan dataPlaneCommand),
		rpcCommands:       make(chan rpcCommand),
		pendingOperations: make(
			map[coreabi.OperationID]*pendingOperation,
		),
		pendingRPCs: make(
			map[coreabi.RPCOperationID]*pendingRPC,
		),
		completions:    make(chan struct{}, 1),
		closeRequested: make(chan struct{}),
		done:           make(chan struct{}),
		running:        make(chan struct{}),
		stopped:        make(chan struct{}),
	}
	instance.state.Store(int32(coreabi.StateCreated))
	host.instances[instance] = struct{}{}
	go instance.run()
	return instance, nil
}

func (host *Host) Close(ctx context.Context) error {
	if host == nil {
		return nil
	}
	if ctx == nil {
		return fmt.Errorf("close EasyTier engine host with nil context")
	}
	host.closeOnce.Do(func() {
		host.mu.Lock()
		host.closed = true
		webClient := host.webClient
		instances := make([]*Instance, 0, len(host.instances))
		for instance := range host.instances {
			instances = append(instances, instance)
		}
		host.mu.Unlock()
		go host.shutdown(webClient, instances)
	})
	select {
	case <-host.closeDone:
		host.mu.Lock()
		err := host.closeErr
		host.mu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (host *Host) shutdown(webClient *WebClient, instances []*Instance) {
	var closeErrors []error
	if webClient != nil {
		if err := webClient.Close(host.ctx); err != nil {
			closeErrors = append(closeErrors, err)
		}
	}
	for _, instance := range instances {
		if err := instance.Close(host.ctx); err != nil {
			closeErrors = append(closeErrors, err)
		}
	}

	host.cancel()
	host.reactor.Close()
	cleanupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	moduleErr := host.module.Close(cleanupContext)
	runtimeErr := host.runtime.Close(cleanupContext)

	host.mu.Lock()
	host.closeErr = errors.Join(
		append(closeErrors, moduleErr, runtimeErr)...,
	)
	host.mu.Unlock()
	close(host.closeDone)
}

func (host *Host) broadcastCompletions() {
	for {
		select {
		case <-host.reactor.Completions():
			host.mu.Lock()
			if host.webClient != nil {
				select {
				case host.webClient.completions <- struct{}{}:
				default:
				}
			}
			for instance := range host.instances {
				select {
				case instance.completions <- struct{}{}:
				default:
				}
			}
			host.mu.Unlock()
		case <-host.ctx.Done():
			return
		}
	}
}

func (host *Host) removeWebClient(client *WebClient) {
	host.mu.Lock()
	if host.webClient == client {
		host.webClient = nil
	}
	host.mu.Unlock()
}

func (host *Host) removeInstance(instance *Instance) {
	host.mu.Lock()
	delete(host.instances, instance)
	host.mu.Unlock()
}
