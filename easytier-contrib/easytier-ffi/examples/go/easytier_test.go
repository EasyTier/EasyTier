package easytierffi

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSSHIntegration(t *testing.T) {
	config := os.Getenv("EASYTIER_FFI_CONFIG")
	instance := os.Getenv("EASYTIER_FFI_INSTANCE")
	target := os.Getenv("EASYTIER_FFI_TARGET")
	if config == "" || instance == "" || target == "" {
		t.Skip("set EASYTIER_FFI_CONFIG, EASYTIER_FFI_INSTANCE and EASYTIER_FFI_TARGET to run integration test")
	}

	n, err := Open(defaultLibraryPath())
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	if err := n.RunNetworkInstance(config); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	var lastErr error
	for attempt := 1; ctx.Err() == nil; attempt++ {
		conn, err := n.DialContext(ctx, instance, "tcp", target)
		if err != nil {
			lastErr = err
			t.Logf("attempt %d: dial failed: %v", attempt, err)
			time.Sleep(3 * time.Second)
			continue
		}

		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 128)
		nn, err := conn.Read(buf)
		_ = conn.Close()
		if err != nil {
			lastErr = err
			t.Logf("attempt %d: read failed: %v", attempt, err)
			time.Sleep(3 * time.Second)
			continue
		}
		banner := string(buf[:nn])
		if !strings.HasPrefix(banner, "SSH-") {
			t.Fatalf("attempt %d: expected SSH banner, got %q", attempt, banner)
		}
		t.Logf("attempt %d: got banner %q", attempt, strings.TrimRight(banner, "\r\n"))
		return
	}
	t.Fatalf("never got SSH banner, last err: %v", lastErr)
}
