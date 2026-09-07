package coreabi

import (
	"context"
	"fmt"

	"github.com/metacubex/wazero/api"
)

type WebClient struct {
	core               *Core
	driveFunction      guestFunction
	deadlineFunction   guestFunction
	completionFunction guestFunction
	created            bool
	dropped            bool
}

func NewWebClient(module api.Module) (*WebClient, error) {
	core, err := New(module)
	if err != nil {
		return nil, err
	}
	return &WebClient{core: core}, nil
}

func (client *WebClient) Create(ctx context.Context, envelope []byte) (err error) {
	if client.created || client.dropped {
		return fmt.Errorf("create used EasyTier WebClient")
	}
	pointer, err := client.core.allocate(ctx, uint32(len(envelope)))
	if err != nil {
		return err
	}
	defer client.core.cleanupBuffer(ctx, pointer, &err)
	if !client.core.module.Memory().Write(pointer, envelope) {
		return fmt.Errorf("write EasyTier WebClient config to guest memory")
	}
	result, err := client.core.callOne(
		ctx,
		"easytier_web_client_create",
		uint64(pointer),
		uint64(len(envelope)),
	)
	if err != nil {
		return err
	}
	if status := int32(result); status != 0 {
		return client.statusError(ctx, "create EasyTier WebClient", status)
	}
	client.created = true
	return nil
}

func (client *WebClient) Drive(ctx context.Context) error {
	result, err := client.core.callCached(
		ctx,
		"easytier_web_client_drive",
		&client.driveFunction,
	)
	if err != nil {
		return err
	}
	if status := int32(result); status != 0 {
		return client.statusError(ctx, "drive EasyTier WebClient", status)
	}
	return nil
}

func (client *WebClient) NotifyCompletions(ctx context.Context) error {
	result, err := client.core.callCached(
		ctx,
		"easytier_web_client_notify_completions",
		&client.completionFunction,
	)
	if err != nil {
		return err
	}
	if status := int32(result); status != 0 {
		return client.statusError(ctx, "notify EasyTier WebClient", status)
	}
	return nil
}

func (client *WebClient) NextDeadline(ctx context.Context) (int64, error) {
	result, err := client.core.callCached(
		ctx,
		"easytier_web_client_next_deadline_millis",
		&client.deadlineFunction,
	)
	if err != nil {
		return 0, err
	}
	deadline := int64(result)
	if deadline < 0 {
		return 0, client.statusError(
			ctx,
			"query EasyTier WebClient deadline",
			int32(deadline),
		)
	}
	return deadline, nil
}

func (client *WebClient) IsConnected(ctx context.Context) (bool, error) {
	result, err := client.core.callOne(ctx, "easytier_web_client_is_connected")
	if err != nil {
		return false, err
	}
	status := int32(result)
	if status < 0 {
		return false, client.statusError(
			ctx,
			"query EasyTier WebClient connection",
			status,
		)
	}
	return status != 0, nil
}

func (client *WebClient) Drop(ctx context.Context) error {
	if !client.created || client.dropped {
		return nil
	}
	result, err := client.core.callOne(ctx, "easytier_web_client_drop")
	if err != nil {
		return err
	}
	if status := int32(result); status != 0 {
		return client.statusError(ctx, "drop EasyTier WebClient", status)
	}
	client.dropped = true
	return nil
}

func (client *WebClient) statusError(
	ctx context.Context,
	operation string,
	status int32,
) error {
	message, err := client.core.errorMessage(ctx, 0)
	if err != nil {
		return fmt.Errorf("%s: status=%d: %w", operation, status, err)
	}
	return fmt.Errorf("%s: status=%d: %s", operation, status, message)
}
