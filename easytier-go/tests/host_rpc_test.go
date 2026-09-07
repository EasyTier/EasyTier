package host_test

import (
	"context"
	"errors"
	"testing"
	"time"

	corehost "github.com/EasyTier/EasyTier/easytier-go"
)

func TestPublicManagementRPCMethods(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	host, err := corehost.New(ctx, corehost.Options{})
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	defer host.Close(ctx)
	instance, err := host.CreateInstance(
		ctx,
		instanceConfig(t, 201, "10.144.0.201", 0, false, false),
	)
	if err != nil {
		t.Fatalf("create instance: %v", err)
	}
	defer instance.Close(ctx)
	if err := instance.Start(ctx); err != nil {
		t.Fatalf("start instance: %v", err)
	}
	if _, err := instance.ListPeer(nil); err == nil {
		t.Fatal("ListPeer accepted a nil context")
	}
	if _, err := instance.ListRoute(nil); err == nil {
		t.Fatal("ListRoute accepted a nil context")
	}

	cancelled, cancelQuery := context.WithCancel(ctx)
	cancelQuery()
	if _, err := instance.ListPeer(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("ListPeer with cancelled context error = %v", err)
	}

	if _, err := instance.ListPeer(context.Background()); err != nil {
		t.Fatalf("list peers: %v", err)
	}
	if _, err := instance.ListRoute(ctx); err != nil {
		t.Fatalf("list routes: %v", err)
	}
}
