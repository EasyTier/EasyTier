package host

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"
)

func TestDriveUntilWaitsForCompletionWhileStarting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	completion := make(chan struct{})
	deadlineQueried := make(chan struct{})
	var queryOnce sync.Once
	var driveCalls int

	drive := func(context.Context) (CoreState, error) {
		driveCalls++
		if driveCalls == 1 {
			return CoreStateStarting, nil
		}
		return CoreStateRunning, nil
	}
	nextDeadline := func(context.Context) (int64, error) {
		queryOnce.Do(func() { close(deadlineQueried) })
		return math.MaxInt64, nil
	}

	done := make(chan error, 1)
	go func() {
		done <- driveUntil(ctx, completion, CoreStateRunning, drive, nextDeadline)
	}()

	select {
	case <-deadlineQueried:
	case <-ctx.Done():
		t.Fatalf("starting state did not query its wake requirement: %v", ctx.Err())
	}
	select {
	case err := <-done:
		t.Fatalf("drive returned before host completion: %v", err)
	default:
	}
	completion <- struct{}{}
	if err := <-done; err != nil {
		t.Fatalf("drive until running: %v", err)
	}
	if driveCalls != 2 {
		t.Fatalf("unexpected drive call count: %d", driveCalls)
	}
}
