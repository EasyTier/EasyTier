package engine

import (
	"context"
	"testing"
	"time"

	"github.com/easytier/easytier/easytier-go/platform/netstd"
)

func TestHostsSharingCompiledCoreOutliveEachOther(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	startInstance := func(host *Host) *Instance {
		t.Helper()
		instance, err := host.CreateInstance(ctx, minimalConfig)
		if err != nil {
			t.Fatalf("create instance: %v", err)
		}
		if err := instance.Start(ctx); err != nil {
			t.Fatalf("start instance: %v", err)
		}
		return instance
	}

	first, err := NewHost(ctx, Options{Services: netstd.Services()})
	if err != nil {
		t.Fatalf("create first host: %v", err)
	}
	second, err := NewHost(ctx, Options{Services: netstd.Services()})
	if err != nil {
		t.Fatalf("create second host: %v", err)
	}
	startInstance(first)
	running := startInstance(second)

	if err := first.Close(ctx); err != nil {
		t.Fatalf("close first host: %v", err)
	}
	// The second host runs code compiled by the first one; it must keep
	// working after the first runtime is gone.
	if state := running.State(); state != 2 {
		t.Fatalf("second instance state = %d, want 2", state)
	}
	if err := running.Stop(ctx); err != nil {
		t.Fatalf("stop second instance: %v", err)
	}
	if err := running.Wait(ctx); err != nil {
		t.Fatalf("wait for second instance: %v", err)
	}
	if err := second.Close(ctx); err != nil {
		t.Fatalf("close second host: %v", err)
	}

	third, err := NewHost(ctx, Options{Services: netstd.Services()})
	if err != nil {
		t.Fatalf("create host after all hosts closed: %v", err)
	}
	defer third.Close(ctx)
	startInstance(third)
}
