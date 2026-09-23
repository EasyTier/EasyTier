package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParseOptions(t *testing.T) {
	options, err := parseOptions([]string{
		"-p", "tcp://198.51.100.10:11010",
		"--network-name", "office",
		"--network-secret", "secret",
		"--ipv4", "10.144.0.10/24",
		"--port-forward", "tcp://127.0.0.1:5202/10.144.0.20:5201",
		"--port-forward", "udp://127.0.0.1:5202/10.144.0.20:5201",
	})
	if err != nil {
		t.Fatalf("parse options: %v", err)
	}
	if len(options.portForwards) != 2 {
		t.Fatalf("port-forward count = %d", len(options.portForwards))
	}
}

func TestPortForwardList(t *testing.T) {
	var rules portForwardList
	for _, value := range []string{
		"tcp://127.0.0.1:5202/10.144.0.20:5201",
		"udp://0.0.0.0:5203/10.144.0.21:5201",
	} {
		if err := rules.Set(value); err != nil {
			t.Fatalf("set %q: %v", value, err)
		}
	}
	if got := rules.String(); got !=
		"tcp://127.0.0.1:5202/10.144.0.20:5201,"+
			"udp://0.0.0.0:5203/10.144.0.21:5201" {
		t.Fatalf("rules string = %q", got)
	}
	if err := rules.Set("sctp://127.0.0.1:1/10.0.0.1:2"); err == nil {
		t.Fatal("unsupported protocol was accepted")
	}
}

func TestTCPPortForward(t *testing.T) {
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer echo.Close()
	go func() {
		connection, acceptErr := echo.Accept()
		if acceptErr == nil {
			defer connection.Close()
			_, _ = io.Copy(connection, connection)
		}
	}()

	rule, err := parsePortForwardRule(
		"tcp://127.0.0.1:0/" + echo.Addr().String(),
	)
	if err != nil {
		t.Fatalf("parse forward: %v", err)
	}
	forwards, err := startPortForwards(
		context.Background(),
		standardDial,
		[]portForwardRule{rule},
	)
	if err != nil {
		t.Fatalf("start forward: %v", err)
	}
	defer forwards.Close()

	connection, err := net.Dial("tcp4", forwards.addresses[0].String())
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	sent := bytes.Repeat([]byte("easytier"), 1024)
	if _, err := connection.Write(sent); err != nil {
		t.Fatalf("write forward: %v", err)
	}
	received := make([]byte, len(sent))
	if _, err := io.ReadFull(connection, received); err != nil {
		t.Fatalf("read forward: %v", err)
	}
	if !bytes.Equal(received, sent) {
		t.Fatal("forwarded TCP data differs")
	}
}

func TestUDPPortForward(t *testing.T) {
	echo, err := net.ListenUDP(
		"udp4",
		net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")),
	)
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer echo.Close()
	_ = echo.SetDeadline(time.Now().Add(5 * time.Second))
	firstReceived := make(chan struct{})
	go func() {
		packet := make([]byte, 65535)
		if _, _, readErr := echo.ReadFromUDPAddrPort(packet); readErr != nil {
			close(firstReceived)
			return
		}
		close(firstReceived)
		length, client, readErr := echo.ReadFromUDPAddrPort(packet)
		if readErr != nil {
			return
		}
		_, _ = echo.WriteToUDPAddrPort(packet[:length], client)
	}()

	rule, err := parsePortForwardRule(
		"udp://127.0.0.1:0/" + echo.LocalAddr().String(),
	)
	if err != nil {
		t.Fatalf("parse forward: %v", err)
	}
	forwards, err := startPortForwards(
		context.Background(),
		standardDial,
		[]portForwardRule{rule},
	)
	if err != nil {
		t.Fatalf("start forward: %v", err)
	}
	defer forwards.Close()

	firstClient, err := net.Dial("udp4", forwards.addresses[0].String())
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	defer firstClient.Close()
	if _, err := firstClient.Write([]byte("first")); err != nil {
		t.Fatalf("write from first client: %v", err)
	}
	<-firstReceived

	lastClient, err := net.Dial("udp4", forwards.addresses[0].String())
	if err != nil {
		t.Fatalf("dial forward from last client: %v", err)
	}
	defer lastClient.Close()
	_ = lastClient.SetDeadline(time.Now().Add(5 * time.Second))
	sent := []byte("last")
	if _, err := lastClient.Write(sent); err != nil {
		t.Fatalf("write from last client: %v", err)
	}
	received := make([]byte, len(sent))
	if _, err := io.ReadFull(lastClient, received); err != nil {
		t.Fatalf("read forward: %v", err)
	}
	if !bytes.Equal(received, sent) {
		t.Fatal("forwarded UDP data differs")
	}
}

func standardDial(
	ctx context.Context,
	network string,
	address string,
) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func TestParseOptionsRequiresForward(t *testing.T) {
	_, err := parseOptions([]string{
		"-p", "tcp://198.51.100.10:11010",
		"--network-name", "office",
		"--network-secret", "secret",
		"--ipv4", "10.144.0.10/24",
	})
	if err == nil || !strings.Contains(err.Error(), "--port-forward") {
		t.Fatalf("parse error = %v, want missing port-forward", err)
	}
}
