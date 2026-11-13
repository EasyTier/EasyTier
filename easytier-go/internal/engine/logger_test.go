package engine

import (
	"context"
	"testing"
	"time"

	"github.com/easytier/easytier/easytier-go/internal/coreabi"
	"github.com/easytier/easytier/easytier-go/platform/netstd"
)

func TestLoggerInitializationDoesNotResetLevel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	host, err := NewHost(ctx, Options{Services: netstd.Services()})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close(ctx)
	if err := host.SetLogLevel(ctx, coreabi.LogLevelTrace); err != nil {
		t.Fatal(err)
	}
	host.guestMu.Lock()
	_, err = host.module.ExportedFunction("_start").Call(ctx)
	host.guestMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if level, err := host.LogLevel(ctx); err != nil || level != coreabi.LogLevelTrace {
		t.Fatalf("repeated initialization changed level: %d, %v", level, err)
	}
}
