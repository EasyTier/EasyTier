package easytierffi

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestInterfaces(t *testing.T) {
	var _ net.Conn = (*Conn)(nil)
	var _ net.PacketConn = (*PacketConn)(nil)
}

func TestParseIPPortRejectsNames(t *testing.T) {
	_, _, err := parseIPPort("example.com:22")
	if err == nil || !strings.Contains(err.Error(), "requires an IP address") {
		t.Fatalf("expected IP-only error, got %v", err)
	}
}

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
		conn, err := (&Dialer{Native: n, Instance: instance, Timeout: 10 * time.Second}).DialContext(ctx, "tcp", target)
		if err != nil {
			lastErr = err
			t.Logf("attempt %d: dial failed: %v", attempt, err)
			time.Sleep(3 * time.Second)
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 128)
		nn, err := conn.Read(buf)
		if err != nil {
			lastErr = err
			t.Logf("attempt %d: read failed: %v", attempt, err)
			conn.Close()
			time.Sleep(3 * time.Second)
			continue
		}
		conn.Close()
		if !strings.HasPrefix(string(buf[:nn]), "SSH-") {
			t.Fatalf("attempt %d: expected SSH banner, got %q", attempt, string(buf[:nn]))
		}
		t.Logf("attempt %d: got banner %q", attempt, strings.TrimRight(string(buf[:nn]), "\r\n"))
		return
	}
	t.Fatalf("never got SSH banner, last err: %v", lastErr)
}
