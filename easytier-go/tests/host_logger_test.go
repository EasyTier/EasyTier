package host_test

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	corehost "github.com/easytier/easytier/easytier-go"
)

type logOutput struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	fail   bool
	writes int
}

func (output *logOutput) Write(data []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	output.writes++
	if output.fail {
		return 0, io.ErrClosedPipe
	}
	return output.buffer.Write(data)
}

func (output *logOutput) take() string {
	output.mu.Lock()
	defer output.mu.Unlock()
	text := output.buffer.String()
	output.buffer.Reset()
	return text
}

func TestHostLoggingIsIndependentOfInstances(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	output := &logOutput{}
	host, err := corehost.New(ctx, corehost.Options{LogWriter: output})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close(ctx)
	assertLevel := func(want corehost.LogLevel) {
		t.Helper()
		got, err := host.LogLevel(ctx)
		if err != nil || got != want {
			t.Fatalf("log level = %d, %v; want %d", got, err, want)
		}
	}
	assertLevel(corehost.LogLevelInfo)
	if err := host.SetLogLevel(ctx, corehost.LogLevelOff); err != nil {
		t.Fatal(err)
	}
	create := func(id int) *corehost.Instance {
		t.Helper()
		instance, err := host.CreateInstance(ctx, instanceConfig(t, id, "10.144.0.1", 0, false, false))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = instance.Close(context.Background()) })
		if err := instance.Start(ctx); err != nil {
			t.Fatal(err)
		}
		return instance
	}
	first := create(1)
	assertLevel(corehost.LogLevelOff)
	if text := output.take(); text != "" {
		t.Fatalf("logging is off but received %q", text)
	}
	if err := host.SetLogLevel(ctx, corehost.LogLevelTrace); err != nil {
		t.Fatal(err)
	}
	second := create(2)
	assertLevel(corehost.LogLevelTrace)
	if text := output.take(); !strings.Contains(text, "[INFO]") {
		t.Fatalf("guest did not write info logs: %q", text)
	}
	if err := first.Close(ctx); err != nil {
		t.Fatal(err)
	}
	assertLevel(corehost.LogLevelTrace)
	if err := host.SetLogLevel(ctx, corehost.LogLevelOff); err != nil {
		t.Fatal(err)
	}
	output.take()
	if err := second.Close(ctx); err != nil {
		t.Fatal(err)
	}
	third := create(3)
	if err := third.Close(ctx); err != nil {
		t.Fatal(err)
	}
	assertLevel(corehost.LogLevelOff)
	if text := output.take(); text != "" {
		t.Fatalf("logging resumed during instance lifecycle: %q", text)
	}
	if err := host.SetLogLevel(ctx, corehost.LogLevel(6)); err == nil {
		t.Fatal("invalid log level was accepted")
	}
	assertLevel(corehost.LogLevelOff)

	other, err := corehost.New(ctx, corehost.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(ctx)
	if level, err := other.LogLevel(ctx); err != nil || level != corehost.LogLevelInfo {
		t.Fatalf("another Host inherited log level: %d, %v", level, err)
	}
	if err := other.SetLogLevel(ctx, corehost.LogLevelDebug); err != nil {
		t.Fatal(err)
	}
	assertLevel(corehost.LogLevelOff)
	if err := host.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := host.SetLogLevel(ctx, corehost.LogLevelInfo); err == nil {
		t.Fatal("changed log level after Host shutdown")
	}
}

func TestHostLoggingWriterFailureDoesNotStopInstance(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	output := &logOutput{fail: true}
	host, err := corehost.New(ctx, corehost.Options{LogWriter: output})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close(ctx)
	instance, err := host.CreateInstance(ctx, instanceConfig(t, 1, "10.144.0.1", 0, false, false))
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close(ctx)
	if err := instance.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if state := instance.State(); state != corehost.StateRunning {
		t.Fatalf("instance state = %d, want running", state)
	}
	if err := instance.Close(ctx); err != nil {
		t.Fatal(err)
	}
	output.mu.Lock()
	defer output.mu.Unlock()
	if output.writes == 0 {
		t.Fatal("test did not exercise the failing writer")
	}
}
