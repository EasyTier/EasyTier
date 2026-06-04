package easytierffi

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
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

func TestTCPListenIntegration(t *testing.T) {
	config := os.Getenv("EASYTIER_FFI_LISTEN_CONFIG")
	instance := os.Getenv("EASYTIER_FFI_LISTEN_INSTANCE")
	listenPort := os.Getenv("EASYTIER_FFI_LISTEN_PORT")
	if config == "" || instance == "" || listenPort == "" {
		t.Skip("set EASYTIER_FFI_LISTEN_CONFIG, EASYTIER_FFI_LISTEN_INSTANCE and EASYTIER_FFI_LISTEN_PORT to run integration test")
	}
	port, err := strconv.ParseUint(listenPort, 10, 16)
	if err != nil {
		t.Fatal(err)
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

	// Data-plane readiness is asynchronous: the instance must finish starting
	// before the data plane accepts binds. Retry until ready or ctx expires.
	var listener net.Listener
	for attempt := 1; ; attempt++ {
		listener, err = n.ListenContext(ctx, instance, "tcp", net.JoinHostPort("0.0.0.0", strconv.Itoa(int(port))))
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("bind never succeeded, last err: %v", err)
		}
		t.Logf("attempt %d: bind failed: %v", attempt, err)
		time.Sleep(3 * time.Second)
	}
	t.Logf("listening on %s; connect from another EasyTier peer and send ping", listener.Addr())

	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer conn.Close()

		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			accepted <- err
			return
		}
		if string(buf) != "ping" {
			accepted <- fmt.Errorf("expected %q, got %q", "ping", string(buf))
			return
		}
		_, err = conn.Write([]byte("pong"))
		accepted <- err
	}()

	select {
	case err := <-accepted:
		_ = listener.Close()
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		_ = listener.Close()
		t.Fatal(ctx.Err())
	}
}
