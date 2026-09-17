package reactor

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestManagementOperationCopiesAndConsumesResult(t *testing.T) {
	release := make(chan struct{})
	runtime := New(context.Background(), Options{
		Management: func(_ context.Context, request []byte) []byte {
			<-release
			return append([]byte("response:"), request...)
		},
	})
	defer runtime.Close()

	if err := runtime.StartManagement(7, []byte("request")); err != nil {
		t.Fatalf("start management operation: %v", err)
	}
	if _, err := runtime.ManagementResult(7); !errors.Is(err, ErrPending) {
		t.Fatalf("initial result error = %v, want pending", err)
	}
	close(release)
	select {
	case <-runtime.Completions():
	case <-time.After(time.Second):
		t.Fatal("management operation did not complete")
	}
	result, err := runtime.ManagementResult(7)
	if err != nil {
		t.Fatalf("take management result: %v", err)
	}
	if string(result) != "response:request" {
		t.Fatalf("management result = %q", result)
	}
	if err := runtime.FinishManagement(7); err != nil {
		t.Fatalf("finish management operation: %v", err)
	}
	if _, err := runtime.ManagementResult(7); !errors.Is(err, ErrInvalid) {
		t.Fatalf("consumed result error = %v, want invalid", err)
	}
}
