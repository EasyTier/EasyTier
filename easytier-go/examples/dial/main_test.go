package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	corehost "github.com/EasyTier/EasyTier/easytier-go"
	"github.com/EasyTier/EasyTier/easytier-go/proto/common"
)

func TestParseOptions(t *testing.T) {
	options, err := parseOptions([]string{
		"-p", "tcp://198.51.100.10:11010",
		"--network-name", "office",
		"--network-secret", "secret",
		"--ipv4", "10.144.0.10/24",
		"--network", "udp4",
		"--address", "10.144.0.20:7000",
		"--connect-timeout", "3s",
	})
	if err != nil {
		t.Fatalf("parse options: %v", err)
	}
	if options.network != "udp4" ||
		options.address != "10.144.0.20:7000" ||
		options.connectTimeout != 3*time.Second ||
		len(options.peers) != 1 {
		t.Fatalf("parsed options = %+v", options)
	}
}

func TestParseOptionsRejectsInvalidArguments(t *testing.T) {
	valid := []string{
		"-p", "tcp://198.51.100.10:11010",
		"--network-name", "office",
		"--network-secret", "secret",
		"--ipv4", "10.144.0.10/24",
		"--address", "10.144.0.20:7000",
	}
	tests := []struct {
		name      string
		arguments []string
		want      string
	}{
		{
			name:      "network",
			arguments: append(append([]string(nil), valid...), "--network", "sctp"),
			want:      "--network",
		},
		{
			name: "destination",
			arguments: []string{
				"-p", "tcp://198.51.100.10:11010",
				"--network-name", "office",
				"--network-secret", "secret",
				"--ipv4", "10.144.0.10/24",
				"--address", "[2001:db8::1]:7000",
			},
			want: "--address",
		},
		{
			name:      "connect timeout",
			arguments: append(append([]string(nil), valid...), "--connect-timeout", "0s"),
			want:      "--connect-timeout",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseOptions(test.arguments)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("parse error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestRoutesReachOverlayOrProxyDestination(t *testing.T) {
	overlay := netip.MustParseAddr("10.144.0.20")
	overlayOctets := overlay.As4()
	routes := []*corehost.Route{
		{
			Ipv4Addr: &common.Ipv4Inet{
				Address: &common.Ipv4Addr{
					Addr: binary.BigEndian.Uint32(overlayOctets[:]),
				},
			},
		},
		{ProxyCidrs: []string{"10.200.0.0/24"}},
	}
	if !routesReach(routes, overlay) {
		t.Fatal("overlay destination was not reachable")
	}
	if !routesReach(routes, netip.MustParseAddr("10.200.0.8")) {
		t.Fatal("proxy destination was not reachable")
	}
	if routesReach(routes, netip.MustParseAddr("10.201.0.8")) {
		t.Fatal("unknown destination was reachable")
	}
}

func TestRelayTCP(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	serverDone := make(chan error, 1)
	go func() {
		request := make([]byte, len("request"))
		if _, err := io.ReadFull(server, request); err != nil {
			serverDone <- err
			return
		}
		if string(request) != "request" {
			serverDone <- io.ErrUnexpectedEOF
			return
		}
		if _, err := server.Write([]byte("response")); err != nil {
			serverDone <- err
			return
		}
		serverDone <- server.Close()
	}()

	var output bytes.Buffer
	if err := relayTCP(client, strings.NewReader("request"), &output); err != nil {
		t.Fatalf("relay TCP: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("serve TCP exchange: %v", err)
	}
	if output.String() != "response" {
		t.Fatalf("TCP output = %q", output.String())
	}
}

func TestExchangeUDP(t *testing.T) {
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP echo: %v", err)
	}
	defer echo.Close()
	echoDone := make(chan error, 1)
	go func() {
		packet := make([]byte, maxUDPPayload)
		length, client, err := echo.ReadFromUDP(packet)
		if err == nil {
			_, err = echo.WriteToUDP(packet[:length], client)
		}
		echoDone <- err
	}()

	connection, err := net.DialUDP("udp4", nil, echo.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial UDP echo: %v", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))

	var output bytes.Buffer
	if err := exchangeUDP(
		context.Background(),
		connection,
		strings.NewReader("datagram"),
		&output,
	); err != nil {
		t.Fatalf("exchange UDP: %v", err)
	}
	if err := <-echoDone; err != nil {
		t.Fatalf("serve UDP exchange: %v", err)
	}
	if output.String() != "datagram" {
		t.Fatalf("UDP output = %q", output.String())
	}
}

func TestExchangeUDPRejectsOversizedInput(t *testing.T) {
	connection, peer := net.Pipe()
	defer connection.Close()
	defer peer.Close()
	err := exchangeUDP(
		context.Background(),
		connection,
		strings.NewReader(strings.Repeat("x", maxUDPPayload+1)),
		io.Discard,
	)
	if err == nil || !strings.Contains(err.Error(), "maximum payload") {
		t.Fatalf("oversized UDP error = %v", err)
	}
}

func TestExchangeUDPCanCancelInputRead(t *testing.T) {
	connection, peer := net.Pipe()
	defer connection.Close()
	defer peer.Close()
	input, inputWriter := io.Pipe()
	defer input.Close()
	defer inputWriter.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := exchangeUDP(ctx, connection, input, io.Discard); err != context.Canceled {
		t.Fatalf("cancelled UDP exchange error = %v", err)
	}
}
