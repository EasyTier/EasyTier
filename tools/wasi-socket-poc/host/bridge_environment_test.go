package host

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestOpaqueEnvironmentCancellationRemovesOwnedResult(t *testing.T) {
	bridge := newOpaqueBridge(nil, nil)
	defer bridge.close()
	cancelled := make(chan struct{})
	if status := bridge.startEnvironmentOperation(99, func(ctx context.Context) (net.Addr, error) {
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	}); status != 0 {
		t.Fatalf("start environment operation: %d", status)
	}
	if status := bridge.cancelOperation(context.Background(), nil, 99); status != 0 {
		t.Fatalf("cancel environment operation: %d", status)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("environment worker did not observe cancellation")
	}
	bridge.mu.Lock()
	_, exists := bridge.environment[99]
	bridge.mu.Unlock()
	if exists {
		t.Fatal("cancelled environment operation remained owned by bridge")
	}
	select {
	case <-bridge.completion:
	default:
		t.Fatal("environment cancellation did not signal completion")
	}
}
