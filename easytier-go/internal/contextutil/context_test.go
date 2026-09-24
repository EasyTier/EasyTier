package contextutil

import (
	"context"
	"testing"
	"time"
)

type contextKey struct{}

func TestWithoutCancelPreservesValuesOnly(t *testing.T) {
	deadline := time.Now().Add(time.Minute)
	parent, cancel := context.WithDeadline(
		context.WithValue(context.Background(), contextKey{}, "value"),
		deadline,
	)
	cancel()

	ctx := WithoutCancel(parent)
	if got := ctx.Value(contextKey{}); got != "value" {
		t.Fatalf("value = %v, want value", got)
	}
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("deadline was preserved")
	}
	if ctx.Done() != nil {
		t.Fatal("Done channel is non-nil")
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("Err = %v, want nil", err)
	}
}

func TestAfterFuncRunsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	called := make(chan struct{})
	stop := AfterFunc(ctx, func() { close(called) })
	cancel()
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("function was not called")
	}
	if stop() {
		t.Fatal("stop prevented an already started function")
	}
}

func TestAfterFuncCanBeStopped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	called := make(chan struct{})
	stop := AfterFunc(ctx, func() { close(called) })
	if !stop() {
		t.Fatal("stop did not prevent function")
	}
	cancel()
	select {
	case <-called:
		t.Fatal("stopped function was called")
	case <-time.After(10 * time.Millisecond):
	}
}
