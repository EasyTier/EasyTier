package contextutil

import (
	"context"
	"sync"
	"time"
)

type withoutCancelContext struct {
	context.Context
}

func (withoutCancelContext) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

func (withoutCancelContext) Done() <-chan struct{} {
	return nil
}

func (withoutCancelContext) Err() error {
	return nil
}

// WithoutCancel returns a copy of parent that is not canceled when parent is.
//
// This is the Go 1.20-compatible equivalent of context.WithoutCancel.
func WithoutCancel(parent context.Context) context.Context {
	if parent == nil {
		panic("cannot create context from nil parent")
	}
	return withoutCancelContext{Context: parent}
}

// AfterFunc arranges to call function in its own goroutine after context is
// canceled. The returned stop function reports whether it prevented the call.
//
// This is the Go 1.20-compatible equivalent of context.AfterFunc.
func AfterFunc(ctx context.Context, function func()) func() bool {
	var once sync.Once
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			once.Do(func() { go function() })
		case <-stopped:
		}
	}()
	return func() bool {
		prevented := false
		once.Do(func() {
			prevented = true
			close(stopped)
		})
		return prevented
	}
}
