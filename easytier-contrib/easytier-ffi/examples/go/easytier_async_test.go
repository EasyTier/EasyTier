package easytierffi

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"
)

const asyncLocalTestTimeout = 120 * time.Second

func TestAsyncSymbolBinding(t *testing.T) {
	n := openAsyncForTest(t)

	status, err := n.opWaitStatus(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if status != dataPlaneOpInvalid {
		t.Fatalf("expected invalid status for op 0, got %d", status)
	}
}

func TestAsyncLocalTwoNodeTCPAndUDP(t *testing.T) {
	n := openAsyncForTest(t)
	topology := startLocalAsyncTopology(t, n)

	ctx, cancel := context.WithTimeout(context.Background(), asyncLocalTestTimeout)
	defer cancel()

	runAsyncTCPPingPong(t, ctx, n, topology)
	runAsyncUDPPingPong(t, ctx, n, topology)
}

type localAsyncTopology struct {
	dialerInstance   string
	listenerInstance string
	listenerIP       string
}

func openAsyncForTest(t *testing.T) *AsyncNative {
	t.Helper()

	libraryPath := defaultLibraryPath()
	if _, err := os.Stat(libraryPath); err != nil {
		if os.IsNotExist(err) {
			t.Skipf("build easytier-ffi with ffi-dataplane before running async tests: %v", err)
		}
		t.Fatalf("stat async ffi library: %v", err)
	}

	n, err := OpenAsync(libraryPath)
	if err != nil {
		t.Fatalf("open async ffi library: %v", err)
	}
	t.Cleanup(func() {
		if err := n.Close(); err != nil {
			t.Errorf("close async native: %v", err)
		}
	})
	return n
}

func startLocalAsyncTopology(t *testing.T, n *AsyncNative) localAsyncTopology {
	t.Helper()

	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	networkName := "ffi-async-" + suffix
	networkSecret := "ffi-async-secret-" + suffix
	listenerInstance := "ffi-async-listener-" + suffix
	dialerInstance := "ffi-async-dialer-" + suffix
	listenerIP := "10.251.1.2"
	dialerIP := "10.251.1.1"
	listenerPort := freeLocalTCPPort(t)
	listenerEndpoint := fmt.Sprintf("tcp://127.0.0.1:%d", listenerPort)
	t.Cleanup(func() {
		if err := n.deleteNetworkInstances([]string{dialerInstance, listenerInstance}); err != nil {
			t.Errorf("cleanup async test EasyTier instances: %v", err)
		}
	})

	listenerConfig := localAsyncConfig(
		listenerInstance,
		listenerIP,
		networkName,
		networkSecret,
		[]string{listenerEndpoint},
		nil,
	)
	dialerConfig := localAsyncConfig(
		dialerInstance,
		dialerIP,
		networkName,
		networkSecret,
		nil,
		[]string{listenerEndpoint},
	)

	if err := n.RunNetworkInstance(listenerConfig); err != nil {
		t.Fatalf("start listener instance: %v", err)
	}
	if err := n.RunNetworkInstance(dialerConfig); err != nil {
		t.Fatalf("start dialer instance: %v", err)
	}

	return localAsyncTopology{
		dialerInstance:   dialerInstance,
		listenerInstance: listenerInstance,
		listenerIP:       listenerIP,
	}
}

func localAsyncConfig(instance, ipv4, networkName, networkSecret string, listeners, peers []string) string {
	config := fmt.Sprintf(`instance_name = %s
ipv4 = %s
listeners = %s

[network_identity]
network_name = %s
network_secret = %s

[flags]
no_tun = true
bind_device = false
`,
		strconv.Quote(instance),
		strconv.Quote(ipv4),
		tomlStringList(listeners),
		strconv.Quote(networkName),
		strconv.Quote(networkSecret),
	)
	for _, peer := range peers {
		config += fmt.Sprintf("\n[[peer]]\nuri = %s\n", strconv.Quote(peer))
	}
	return config
}

func tomlStringList(values []string) string {
	if len(values) == 0 {
		return "[]"
	}

	out := "["
	for i, value := range values {
		if i > 0 {
			out += ", "
		}
		out += strconv.Quote(value)
	}
	return out + "]"
}

func freeLocalTCPPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate local tcp port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func runAsyncTCPPingPong(t *testing.T, ctx context.Context, n *AsyncNative, topology localAsyncTopology) {
	t.Helper()

	listener, listenerAddr := eventuallyTCPListen(t, ctx, n, topology.listenerInstance)

	tcpCtx, cancel := context.WithCancel(ctx)
	accepted := make(chan error, 1)
	defer waitForAsyncHelper(t, accepted, "tcp accept helper")
	defer cancel()
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- fmt.Errorf("accept tcp stream: %w", err)
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

		payload := make([]byte, len("ping"))
		if _, err := io.ReadFull(conn, payload); err != nil {
			accepted <- fmt.Errorf("read tcp ping: %w", err)
			return
		}
		if string(payload) != "ping" {
			accepted <- fmt.Errorf("expected tcp ping, got %q", string(payload))
			return
		}
		if _, err := conn.Write([]byte("pong")); err != nil {
			accepted <- fmt.Errorf("write tcp pong: %w", err)
			return
		}
		accepted <- nil
	}()

	conn, err := eventuallyTCPDial(t, tcpCtx, n, topology.dialerInstance, topology.listenerIP, listenerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write tcp ping: %v", err)
	}
	payload := make([]byte, len("pong"))
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("read tcp pong: %v", err)
	}
	if string(payload) != "pong" {
		t.Fatalf("expected tcp pong, got %q", string(payload))
	}
}

func eventuallyTCPListen(t *testing.T, ctx context.Context, n *AsyncNative, instance string) (net.Listener, *net.TCPAddr) {
	t.Helper()

	var lastErr error
	for attempt := 1; ctx.Err() == nil; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		listener, err := n.ListenContext(attemptCtx, instance, "tcp", "0.0.0.0:0")
		cancel()
		if err == nil {
			addr := listener.Addr().(*net.TCPAddr)
			t.Logf("async tcp bind succeeded on attempt %d at %s", attempt, addr)
			return listener, addr
		}

		lastErr = err
		t.Logf("attempt %d: async tcp bind failed: %v", attempt, err)
		waitForRetry(ctx, 500*time.Millisecond)
	}
	t.Fatalf("async tcp bind never succeeded: %v", lastErr)
	panic("unreachable")
}

func eventuallyTCPDial(t *testing.T, ctx context.Context, n *AsyncNative, instance, ip string, port int) (net.Conn, error) {
	t.Helper()

	address := net.JoinHostPort(ip, strconv.Itoa(port))
	var lastErr error
	for attempt := 1; ctx.Err() == nil; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		conn, err := n.DialContext(attemptCtx, instance, "tcp", address)
		cancel()
		if err == nil {
			t.Logf("async tcp connect succeeded on attempt %d to %s", attempt, address)
			return conn, nil
		}

		lastErr = err
		t.Logf("attempt %d: async tcp connect failed: %v", attempt, err)
		waitForRetry(ctx, 500*time.Millisecond)
	}
	return nil, fmt.Errorf("async tcp connect never succeeded: %w", lastErr)
}

func runAsyncUDPPingPong(t *testing.T, ctx context.Context, n *AsyncNative, topology localAsyncTopology) {
	t.Helper()

	dialerSocket, err := n.UDPBindContext(ctx, topology.dialerInstance, 0)
	if err != nil {
		t.Fatalf("bind dialer udp socket: %v", err)
	}

	listenerSocket, err := n.UDPBindContext(ctx, topology.listenerInstance, 0)
	if err != nil {
		t.Fatalf("bind listener udp socket: %v", err)
	}

	udpCtx, cancel := context.WithCancel(ctx)
	warmupDone := make(chan error, 1)
	received := make(chan error, 1)
	defer waitForAsyncHelper(t, received, "udp receive helper")
	defer cancel()
	defer listenerSocket.Close()
	defer dialerSocket.Close()

	go func() {
		if _, err := listenerSocket.SendTo(udpCtx, []byte("warmup"), dialerSocket.LocalAddr()); err != nil {
			err = fmt.Errorf("send udp warmup: %w", err)
			warmupDone <- err
			received <- err
			return
		}
		warmupDone <- nil

		payload, from, err := listenerSocket.RecvFrom(udpCtx, 512)
		if err != nil {
			received <- fmt.Errorf("recv udp ping: %w", err)
			return
		}
		if string(payload) != "ping" {
			received <- fmt.Errorf("expected udp ping, got %q", string(payload))
			return
		}
		if _, err := listenerSocket.SendTo(udpCtx, []byte("pong"), from); err != nil {
			received <- fmt.Errorf("send udp pong: %w", err)
			return
		}
		received <- nil
	}()

	select {
	case err := <-warmupDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-udpCtx.Done():
		t.Fatal(udpCtx.Err())
	}

	target := &net.UDPAddr{IP: net.ParseIP(topology.listenerIP), Port: listenerSocket.LocalAddr().Port}
	if _, err := dialerSocket.SendTo(udpCtx, []byte("ping"), target); err != nil {
		t.Fatalf("send udp ping: %v", err)
	}
	for {
		payload, from, err := dialerSocket.RecvFrom(udpCtx, 512)
		if err != nil {
			t.Fatalf("recv udp pong: %v", err)
		}
		if string(payload) == "pong" {
			if !from.IP.Equal(target.IP) || from.Port != target.Port {
				t.Fatalf("expected udp pong from %s, got %s", target, from)
			}
			break
		}
		t.Logf("skipping udp datagram from %s: %q", from, string(payload))
	}
}

func waitForAsyncHelper(t *testing.T, done <-chan error, name string) {
	t.Helper()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	case <-time.After(10 * time.Second):
		t.Errorf("%s did not stop", name)
	}
}

func waitForRetry(ctx context.Context, delay time.Duration) {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}
