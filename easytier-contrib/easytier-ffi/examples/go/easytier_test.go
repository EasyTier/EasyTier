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

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var conn net.Conn
	for ctx.Err() == nil {
		conn, err = (&Dialer{Native: n, Instance: instance, Timeout: 5 * time.Second}).DialContext(ctx, "tcp", target)
		if err == nil {
			break
		}
		t.Logf("dial failed, retrying: %v", err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	buf := make([]byte, 128)
	nn, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(buf[:nn]), "SSH-") {
		t.Fatalf("expected SSH banner, got %q", string(buf[:nn]))
	}
}
