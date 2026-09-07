package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/EasyTier/EasyTier/easytier-go/internal/contextutil"
	"github.com/EasyTier/EasyTier/easytier-go/internal/coreabi"
)

type WebClientOptions struct {
	Endpoint   string
	MachineID  string
	Hostname   string
	SecureMode bool
	OSType     string
}

type WebClient struct {
	host   *Host
	ctx    context.Context
	cancel context.CancelFunc
	core   *coreabi.WebClient

	completions    chan struct{}
	closeRequested chan struct{}
	closeOnce      sync.Once
	done           chan struct{}
	connected      atomic.Bool

	errMu       sync.Mutex
	terminalErr error
}

func (host *Host) CreateWebClient(
	ctx context.Context,
	options WebClientOptions,
) (*WebClient, error) {
	if host == nil {
		return nil, fmt.Errorf("create WebClient with nil EasyTier engine host")
	}
	if ctx == nil {
		return nil, fmt.Errorf("create EasyTier WebClient with nil context")
	}
	envelope, err := encodeWebClientEnvelope(options, host.options.Services.Snapshot)
	if err != nil {
		return nil, err
	}

	host.mu.Lock()
	defer host.mu.Unlock()
	if host.closed {
		return nil, fmt.Errorf("create WebClient with closed EasyTier engine host")
	}
	if host.webClient != nil {
		return nil, fmt.Errorf("EasyTier WebClient is already running")
	}
	host.guestMu.Lock()
	core, err := coreabi.NewWebClient(host.module)
	if err == nil {
		err = core.Create(ctx, envelope)
	}
	host.guestMu.Unlock()
	if err != nil {
		return nil, err
	}

	lifetime, cancel := context.WithCancel(host.ctx)
	client := &WebClient{
		host:           host,
		ctx:            lifetime,
		cancel:         cancel,
		core:           core,
		completions:    make(chan struct{}, 1),
		closeRequested: make(chan struct{}),
		done:           make(chan struct{}),
	}
	host.webClient = client
	go client.run()
	return client, nil
}

func (client *WebClient) Connected() bool {
	return client != nil && client.connected.Load()
}

func (client *WebClient) Close(ctx context.Context) error {
	if client == nil {
		return nil
	}
	if ctx == nil {
		return fmt.Errorf("close EasyTier WebClient with nil context")
	}
	client.closeOnce.Do(func() { close(client.closeRequested) })
	select {
	case <-client.done:
		return client.terminalError()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (client *WebClient) run() {
	runErr := client.driveLoop()
	cleanupErr := client.shutdown()
	client.errMu.Lock()
	client.terminalErr = errors.Join(runErr, cleanupErr)
	client.errMu.Unlock()
	close(client.done)
}

func (client *WebClient) driveLoop() error {
	deadline := int64(0)
	timer := time.NewTimer(0)
	stopTimer(timer)
	defer stopTimer(timer)
	for {
		select {
		case <-client.completions:
			stopTimer(timer)
			next, err := client.drive(true)
			if err != nil {
				return err
			}
			deadline = next
		case <-deadlineTimer(timer, deadline):
			next, err := client.drive(false)
			if err != nil {
				return err
			}
			deadline = next
		case <-client.closeRequested:
			return nil
		case <-client.ctx.Done():
			return client.ctx.Err()
		}
	}
}

func (client *WebClient) drive(notify bool) (int64, error) {
	client.host.guestMu.Lock()
	defer client.host.guestMu.Unlock()
	if notify {
		if err := client.core.NotifyCompletions(client.ctx); err != nil {
			return 0, err
		}
	}
	if err := client.core.Drive(client.ctx); err != nil {
		return 0, err
	}
	connected, err := client.core.IsConnected(client.ctx)
	if err != nil {
		return 0, err
	}
	client.connected.Store(connected)
	return client.core.NextDeadline(client.ctx)
}

func (client *WebClient) shutdown() error {
	cleanupContext, cancel := context.WithTimeout(
		contextutil.WithoutCancel(client.ctx),
		5*time.Second,
	)
	defer cancel()
	client.host.guestMu.Lock()
	err := client.core.Drop(cleanupContext)
	client.host.guestMu.Unlock()
	client.connected.Store(false)
	client.cancel()
	client.host.removeWebClient(client)
	return err
}

func (client *WebClient) terminalError() error {
	client.errMu.Lock()
	defer client.errMu.Unlock()
	return client.terminalErr
}
