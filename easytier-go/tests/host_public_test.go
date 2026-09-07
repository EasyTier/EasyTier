package host_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	corehost "github.com/EasyTier/EasyTier/easytier-go"
	"github.com/EasyTier/EasyTier/easytier-go/platform"
	"github.com/EasyTier/EasyTier/easytier-go/platform/netstd"
	hostproto "github.com/EasyTier/EasyTier/easytier-go/proto"
)

func TestPublicLifecycleDoesNotExposeWazero(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	host, err := corehost.New(ctx, corehost.Options{})
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	defer host.Close(ctx)
	instance, err := host.CreateInstance(
		ctx,
		instanceConfig(t, 1, "10.144.0.1", 0, false, false),
	)
	if err != nil {
		t.Fatalf("create instance: %v", err)
	}
	defer instance.Close(ctx)
	if err := instance.Start(ctx); err != nil {
		t.Fatalf("start instance: %v", err)
	}
	if state := instance.State(); state != corehost.StateRunning {
		t.Fatalf("state = %d, want running", state)
	}
	if err := instance.Start(ctx); err == nil {
		t.Fatal("started running instance twice")
	}
	if state := instance.State(); state != corehost.StateRunning {
		t.Fatalf("duplicate start terminated instance: state=%d", state)
	}
	if err := instance.Stop(ctx); err != nil {
		t.Fatalf("stop instance: %v", err)
	}
	if err := instance.Wait(ctx); err != nil {
		t.Fatalf("wait for instance: %v", err)
	}
}

func TestPublicFacadeConnectsTwoCoresAndExchangesPacket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sockets := &recordingSocketFactory{}
	host, err := corehost.New(ctx, corehost.Options{
		Platform: platform.Services{Sockets: sockets},
	})
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	defer host.Close(ctx)
	server, err := host.CreateInstance(
		ctx,
		instanceConfig(t, 1, "10.144.0.1", 0, false, true),
	)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer server.Close(ctx)
	if err := server.Start(ctx); err != nil {
		t.Fatalf("start server: %v", err)
	}
	port := sockets.listenerPort(t)
	client, err := host.CreateInstance(
		ctx,
		instanceConfig(t, 2, "10.144.0.2", port, true, false),
	)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close(ctx)
	if err := client.Start(ctx); err != nil {
		t.Fatalf("start client: %v", err)
	}

	packet := ipv4Packet(
		net.IPv4(10, 144, 0, 2),
		net.IPv4(10, 144, 0, 1),
		[]byte("public-go-host"),
	)
	var received []byte
	exchangeDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(exchangeDeadline) {
		if err := client.SendPacket(ctx, packet); err != nil {
			t.Fatalf("send packet: %v", err)
		}
		receiveContext, stopReceive := context.WithTimeout(ctx, 100*time.Millisecond)
		received, err = server.ReceivePacket(receiveContext)
		timedOut := errors.Is(err, context.DeadlineExceeded)
		stopReceive()
		if err == nil {
			break
		}
		if !timedOut {
			t.Fatalf("receive packet: %v", err)
		}
	}
	if string(received) != string(packet) {
		t.Fatalf("received packet = %x, want %x", received, packet)
	}
	event := waitForEvent(t, ctx, client.Events(), "peer_added")
	if !strings.Contains(event.Message, "PeerAdded") {
		t.Fatalf("peer event message = %q", event.Message)
	}
	peers, err := client.ListPeer(ctx)
	if err != nil {
		t.Fatalf("list connected peers: %v", err)
	}
	if len(peers) == 0 {
		t.Fatal("connected peer list is empty")
	}

	if err := client.Stop(ctx); err != nil {
		t.Fatalf("stop client: %v", err)
	}
	if err := server.Stop(ctx); err != nil {
		t.Fatalf("stop server: %v", err)
	}
}

func TestPublicConfigUsesCoreTCPPortForward(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sockets := &recordingSocketFactory{}
	host, err := corehost.New(ctx, corehost.Options{
		Platform: platform.Services{Sockets: sockets},
	})
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	defer host.Close(ctx)

	server, err := host.CreateInstance(
		ctx,
		instanceConfig(t, 201, "10.144.0.201", 0, false, true),
	)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer server.Close(ctx)
	if err := server.Start(ctx); err != nil {
		t.Fatalf("start server: %v", err)
	}
	underlayPort := sockets.listenerPort(t)
	overlayListener := listenTCPEventually(t, ctx, server)
	defer overlayListener.Close()
	go func() {
		for {
			connection, acceptErr := overlayListener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()

	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port-forward address: %v", err)
	}
	forwardAddress := netip.MustParseAddrPort(probe.Addr().String())
	if err := probe.Close(); err != nil {
		t.Fatalf("release port-forward address: %v", err)
	}
	destination := netip.AddrPortFrom(
		netip.MustParseAddr("10.144.0.201"),
		uint16(overlayListener.Addr().(*net.TCPAddr).Port),
	)
	clientConfig, err := corehost.NewInstanceConfigBuilder("default").
		NetworkSecret("test").
		Hostname("go-host-202").
		IPv4(netip.MustParsePrefix("10.144.0.202/24")).
		AddPeers(fmt.Sprintf("tcp://127.0.0.1:%d", underlayPort)).
		AddPortForwards(corehost.PortForwardConfig{
			Protocol:    corehost.PortForwardTCP,
			Bind:        forwardAddress,
			Destination: destination,
		}).
		P2P(corehost.P2PPolicy{Disable: true}).
		Encryption(false).
		Build()
	if err != nil {
		t.Fatalf("build client config: %v", err)
	}
	client, err := host.CreateInstance(ctx, clientConfig)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close(ctx)
	if err := client.Start(ctx); err != nil {
		t.Fatalf("start client: %v", err)
	}

	payload := []byte("core-owned-port-forward")
	var lastErr error
	forwardDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(forwardDeadline) {
		connection, dialErr := net.DialTimeout(
			"tcp4",
			forwardAddress.String(),
			200*time.Millisecond,
		)
		if dialErr == nil {
			_ = connection.SetDeadline(time.Now().Add(time.Second))
			_, writeErr := connection.Write(payload)
			response := make([]byte, len(payload))
			_, readErr := io.ReadFull(connection, response)
			_ = connection.Close()
			if writeErr == nil && readErr == nil &&
				string(response) == string(payload) {
				return
			}
			if writeErr == nil && readErr == nil {
				lastErr = fmt.Errorf("forwarded response = %q", response)
			} else {
				lastErr = errors.Join(writeErr, readErr)
			}
		} else {
			lastErr = dialErr
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			t.Fatalf("wait for core port forward: %v", ctx.Err())
		}
	}
	t.Fatalf("core TCP port forward did not carry traffic: %v", lastErr)
}

func TestPublicConfigUsesCoreUDPPortForwardForMaximumPayload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sockets := &recordingSocketFactory{}
	host, err := corehost.New(ctx, corehost.Options{
		Platform: platform.Services{Sockets: sockets},
	})
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	defer host.Close(ctx)

	server, err := host.CreateInstance(
		ctx,
		instanceConfig(t, 203, "10.144.0.203", 0, false, true),
	)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer server.Close(ctx)
	if err := server.Start(ctx); err != nil {
		t.Fatalf("start server: %v", err)
	}
	underlayPort := sockets.listenerPort(t)
	reflectorDone := make(chan error, 1)
	go func() {
		for {
			packet, receiveErr := server.ReceivePacket(ctx)
			if receiveErr != nil {
				reflectorDone <- receiveErr
				return
			}
			response, ok := reflectIPv4UDPFragment(packet)
			if !ok {
				continue
			}
			if sendErr := server.SendPacket(ctx, response); sendErr != nil {
				reflectorDone <- sendErr
				return
			}
		}
	}()

	probe, err := net.ListenUDP(
		"udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
	)
	if err != nil {
		t.Fatalf("reserve UDP port-forward address: %v", err)
	}
	forwardAddress := netip.MustParseAddrPort(probe.LocalAddr().String())
	if err := probe.Close(); err != nil {
		t.Fatalf("release UDP port-forward address: %v", err)
	}
	destination := netip.AddrPortFrom(
		netip.MustParseAddr("10.144.0.203"),
		41000,
	)
	clientConfig, err := corehost.NewInstanceConfigBuilder("default").
		NetworkSecret("test").
		Hostname("go-host-204").
		IPv4(netip.MustParsePrefix("10.144.0.204/24")).
		AddPeers(fmt.Sprintf("tcp://127.0.0.1:%d", underlayPort)).
		AddPortForwards(corehost.PortForwardConfig{
			Protocol:    corehost.PortForwardUDP,
			Bind:        forwardAddress,
			Destination: destination,
		}).
		P2P(corehost.P2PPolicy{Disable: true}).
		Encryption(false).
		Build()
	if err != nil {
		t.Fatalf("build client config: %v", err)
	}
	client, err := host.CreateInstance(ctx, clientConfig)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close(ctx)
	if err := client.Start(ctx); err != nil {
		t.Fatalf("start client: %v", err)
	}
	eventContext, stopEvent := context.WithTimeout(ctx, 5*time.Second)
	_ = waitForEvent(
		t,
		eventContext,
		client.Events(),
		"gateway_port_forward_added",
	)
	stopEvent()
	waitForOverlayRoute(
		t,
		ctx,
		client,
		netip.MustParseAddr("10.144.0.203"),
	)
	waitForOverlayRoute(
		t,
		ctx,
		server,
		netip.MustParseAddr("10.144.0.204"),
	)

	connection, err := net.DialUDP(
		"udp4",
		nil,
		net.UDPAddrFromAddrPort(forwardAddress),
	)
	if err != nil {
		t.Fatalf("dial UDP port forward: %v", err)
	}
	defer connection.Close()
	var lastErr error
	forwardDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(forwardDeadline) {
		if err := connection.SetDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("set UDP port-forward deadline: %v", err)
		}
		if _, err := connection.Write([]byte("warmup")); err != nil {
			lastErr = err
			continue
		}
		warmup := make([]byte, len("warmup"))
		length, err := connection.Read(warmup)
		if err != nil {
			lastErr = err
			select {
			case reflectorErr := <-reflectorDone:
				t.Fatalf("reflect UDP port-forward packet: %v", reflectorErr)
			default:
			}
			continue
		}
		if string(warmup[:length]) == "warmup" {
			lastErr = nil
			break
		}
		lastErr = fmt.Errorf("UDP port-forward warmup response = %q", warmup[:length])
	}
	if lastErr != nil {
		t.Fatalf("core UDP port forward did not become ready: %v", lastErr)
	}

	payload := make([]byte, 65_507)
	for index := range payload {
		payload[index] = byte(index)
	}
	response := make([]byte, len(payload))
	forwardDeadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(forwardDeadline) {
		if err := connection.SetDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("set UDP port-forward deadline: %v", err)
		}
		if _, err := connection.Write(payload); err != nil {
			lastErr = err
			continue
		}
		length, err := connection.Read(response)
		if err != nil {
			lastErr = err
			select {
			case reflectorErr := <-reflectorDone:
				t.Fatalf("reflect maximum UDP port-forward payload: %v", reflectorErr)
			default:
			}
			continue
		}
		if string(response[:length]) == "warmup" {
			continue
		}
		if length != len(payload) {
			t.Fatalf(
				"forwarded UDP payload length = %d, want %d",
				length,
				len(payload),
			)
		}
		if !bytes.Equal(response[:length], payload) {
			t.Fatal("forwarded UDP payload contents changed")
		}
		return
	}
	t.Fatalf("core UDP port forward did not carry maximum payload: %v", lastErr)
}

func reflectIPv4UDPFragment(packet []byte) ([]byte, bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 || packet[9] != 17 {
		return nil, false
	}
	headerLength := int(packet[0]&0x0f) * 4
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if headerLength < 20 || totalLength < headerLength ||
		totalLength > len(packet) {
		return nil, false
	}
	response := append([]byte(nil), packet[:totalLength]...)
	source := append([]byte(nil), response[12:16]...)
	copy(response[12:16], response[16:20])
	copy(response[16:20], source)
	fragmentOffset := binary.BigEndian.Uint16(response[6:8]) & 0x1fff
	if fragmentOffset == 0 {
		if totalLength < headerLength+8 {
			return nil, false
		}
		// Swapping both endpoints preserves the UDP checksum sum, including
		// its pseudo-header, so only the IPv4 header checksum must change.
		sourcePort := append([]byte(nil), response[headerLength:headerLength+2]...)
		copy(
			response[headerLength:headerLength+2],
			response[headerLength+2:headerLength+4],
		)
		copy(response[headerLength+2:headerLength+4], sourcePort)
	}
	response[10], response[11] = 0, 0
	binary.BigEndian.PutUint16(
		response[10:12],
		ipv4Checksum(response[:headerLength]),
	)
	return response, true
}

func waitForOverlayRoute(
	t *testing.T,
	ctx context.Context,
	instance *corehost.Instance,
	target netip.Addr,
) {
	t.Helper()
	octets := target.As4()
	targetValue := binary.BigEndian.Uint32(octets[:])
	for {
		routes, err := instance.ListRoute(ctx)
		if err != nil {
			t.Fatalf("list routes: %v", err)
		}
		for _, route := range routes {
			if route.GetIpv4Addr().GetAddress().GetAddr() == targetValue {
				return
			}
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			t.Fatalf("wait for overlay route to %s: %v", target, ctx.Err())
		}
	}
}

func TestPublicEventStreamClosesWithInstance(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	host, err := corehost.New(ctx, corehost.Options{})
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	defer host.Close(ctx)
	instance, err := host.CreateInstance(
		ctx,
		instanceConfig(t, 3, "10.144.0.3", 0, false, false),
	)
	if err != nil {
		t.Fatalf("create instance: %v", err)
	}
	events := instance.Events()
	if err := instance.Close(ctx); err != nil {
		t.Fatalf("close instance: %v", err)
	}
	select {
	case _, open := <-events:
		if open {
			t.Fatal("event stream remained open after instance close")
		}
	case <-ctx.Done():
		t.Fatal("event stream did not close with instance")
	}
}

func TestEmbeddedCoreInfoIsPublicWithoutArtifactBytes(t *testing.T) {
	info := corehost.CoreInfo()
	if len(info.EasyTierCommit) != 40 {
		t.Fatalf("EasyTier commit = %q", info.EasyTierCommit)
	}
	if len(info.SHA256) != 64 {
		t.Fatalf("EasyTier SHA-256 = %q", info.SHA256)
	}
	if info.EasyTierCommit != hostproto.EasyTierCommit {
		t.Fatalf(
			"EasyTier artifact commit %q != protobuf commit %q",
			info.EasyTierCommit,
			hostproto.EasyTierCommit,
		)
	}
	if len(hostproto.SchemaSHA256) != 64 {
		t.Fatalf("protobuf schema SHA-256 = %q", hostproto.SchemaSHA256)
	}
}

func TestPublicCreateInstanceAcceptsSecureModeConfig(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	host, err := corehost.New(ctx, corehost.Options{})
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	defer host.Close(ctx)

	privateKey := make([]byte, 32)
	for index := range privateKey {
		privateKey[index] = byte(index + 1)
	}
	config, err := corehost.NewInstanceConfigBuilder("secure-test").
		NetworkSecret("test").
		P2P(corehost.P2PPolicy{Disable: true}).
		Encryption(false).
		SecureModeWithPrivateKey(privateKey).
		Build()
	if err != nil {
		t.Fatalf("build secure-mode config: %v", err)
	}
	instance, err := host.CreateInstance(ctx, config)
	if err != nil {
		t.Fatalf("create secure-mode instance: %v", err)
	}
	defer instance.Close(ctx)
}

func instanceConfig(
	t *testing.T,
	id int,
	ipv4 string,
	port int,
	connect bool,
	listen bool,
) corehost.InstanceConfig {
	t.Helper()
	builder := corehost.NewInstanceConfigBuilder("default").
		NetworkSecret("test").
		Hostname(fmt.Sprintf("go-host-%d", id)).
		IPv4(netip.MustParsePrefix(ipv4 + "/24")).
		P2P(corehost.P2PPolicy{Disable: true}).
		Encryption(false)
	if connect {
		builder.AddPeers(fmt.Sprintf("tcp://127.0.0.1:%d", port))
	} else if listen {
		builder.AddListeners(fmt.Sprintf("tcp://127.0.0.1:%d", port))
	}
	config, err := builder.Build()
	if err != nil {
		t.Fatalf("build instance config: %v", err)
	}
	return config
}

func waitForEvent(
	t *testing.T,
	ctx context.Context,
	events <-chan corehost.Event,
	kind string,
) corehost.Event {
	t.Helper()
	for {
		select {
		case event, open := <-events:
			if !open {
				t.Fatalf("event stream closed before %q", kind)
			}
			if event.Kind == kind {
				return event
			}
		case <-ctx.Done():
			t.Fatalf("wait for event %q: %v", kind, ctx.Err())
		}
	}
}

type recordingSocketFactory struct {
	inner netstd.SocketFactory
	mu    sync.Mutex
	port  int
}

func (factory *recordingSocketFactory) ConnectTCP(
	ctx context.Context,
	options platform.TCPConnectOptions,
) (net.Conn, error) {
	return factory.inner.ConnectTCP(ctx, options)
}

func (factory *recordingSocketFactory) BindUDP(
	ctx context.Context,
	options platform.UDPBindOptions,
) (net.PacketConn, error) {
	return factory.inner.BindUDP(ctx, options)
}

func (factory *recordingSocketFactory) ListenTCP(
	ctx context.Context,
	options platform.TCPListenOptions,
) (net.Listener, error) {
	listener, err := factory.inner.ListenTCP(ctx, options)
	if err != nil {
		return nil, err
	}
	factory.mu.Lock()
	factory.port = listener.Addr().(*net.TCPAddr).Port
	factory.mu.Unlock()
	return listener, nil
}

func (factory *recordingSocketFactory) listenerPort(t *testing.T) int {
	t.Helper()
	factory.mu.Lock()
	defer factory.mu.Unlock()
	if factory.port == 0 {
		t.Fatal("EasyTier did not create a TCP listener")
	}
	return factory.port
}

func ipv4Packet(source, destination net.IP, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 1
	copy(packet[12:16], source.To4())
	copy(packet[16:20], destination.To4())
	copy(packet[20:], payload)
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:20]))
	return packet
}

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for index := 0; index < len(header); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[index : index+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
