package host_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	corehost "github.com/EasyTier/EasyTier/easytier-go"
	"github.com/EasyTier/EasyTier/easytier-go/platform"
)

func TestPublicDataPlaneTCPAndUDP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	host, server, client := startDataPlanePair(t, ctx)
	defer host.Close(ctx)
	defer server.Close(ctx)
	defer client.Close(ctx)

	testTCPDataPlane(t, ctx, server, client)
	testUDPDataPlane(t, ctx, server, client)
}

func startDataPlanePair(
	t *testing.T,
	ctx context.Context,
) (*corehost.Host, *corehost.Instance, *corehost.Instance) {
	t.Helper()
	sockets := &recordingSocketFactory{}
	host, err := corehost.New(ctx, corehost.Options{
		Platform: platform.Services{Sockets: sockets},
	})
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	server, err := host.CreateInstance(
		ctx,
		instanceConfig(t, 101, "10.144.0.101", 0, false, true),
	)
	if err != nil {
		host.Close(ctx)
		t.Fatalf("create server: %v", err)
	}
	if err := server.Start(ctx); err != nil {
		server.Close(ctx)
		host.Close(ctx)
		t.Fatalf("start server: %v", err)
	}
	client, err := host.CreateInstance(
		ctx,
		instanceConfig(
			t,
			102,
			"10.144.0.102",
			sockets.listenerPort(t),
			true,
			false,
		),
	)
	if err != nil {
		server.Close(ctx)
		host.Close(ctx)
		t.Fatalf("create client: %v", err)
	}
	if err := client.Start(ctx); err != nil {
		client.Close(ctx)
		server.Close(ctx)
		host.Close(ctx)
		t.Fatalf("start client: %v", err)
	}
	return host, server, client
}

func testTCPDataPlane(
	t *testing.T,
	ctx context.Context,
	server *corehost.Instance,
	client *corehost.Instance,
) {
	t.Helper()
	listener := listenTCPEventually(t, ctx, server)
	defer listener.Close()
	serverPort := listener.Addr().(*net.TCPAddr).Port
	accepted := make(chan connectionResult, 1)
	go func() {
		connection, err := listener.Accept()
		accepted <- connectionResult{connection: connection, err: err}
	}()

	clientConnection := dialEventually(
		t,
		ctx,
		client,
		fmt.Sprintf("10.144.0.101:%d", serverPort),
	)
	defer clientConnection.Close()
	var serverConnection net.Conn
	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatalf("accept EasyTier TCP: %v", result.err)
		}
		serverConnection = result.connection
	case <-ctx.Done():
		t.Fatalf("accept EasyTier TCP: %v", ctx.Err())
	}
	defer serverConnection.Close()

	if err := clientConnection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set client TCP deadline: %v", err)
	}
	if err := serverConnection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set server TCP deadline: %v", err)
	}
	assertStreamExchange(t, clientConnection, serverConnection, []byte("client-to-server"))
	assertStreamExchange(t, serverConnection, clientConnection, []byte("server-to-client"))

	if err := clientConnection.SetReadDeadline(
		time.Now().Add(100 * time.Millisecond),
	); err != nil {
		t.Fatalf("set expiring TCP read deadline: %v", err)
	}
	if _, err := clientConnection.Read(make([]byte, 1)); !errors.Is(
		err,
		os.ErrDeadlineExceeded,
	) {
		t.Fatalf("TCP read deadline error = %v, want deadline exceeded", err)
	}

	if err := clientConnection.SetReadDeadline(
		time.Now().Add(100 * time.Millisecond),
	); err != nil {
		t.Fatalf("set initial TCP read deadline: %v", err)
	}
	read := make(chan readResult, 1)
	go func() {
		buffer := make([]byte, 16)
		n, err := clientConnection.Read(buffer)
		read <- readResult{data: buffer[:n], err: err}
	}()
	time.Sleep(40 * time.Millisecond)
	if err := clientConnection.SetReadDeadline(
		time.Now().Add(2 * time.Second),
	); err != nil {
		t.Fatalf("extend active TCP read deadline: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := serverConnection.Write([]byte("extended")); err != nil {
		t.Fatalf("write after extending TCP deadline: %v", err)
	}
	select {
	case result := <-read:
		if result.err != nil {
			t.Fatalf("read after extending TCP deadline: %v", result.err)
		}
		if string(result.data) != "extended" {
			t.Fatalf("extended deadline read = %q", result.data)
		}
	case <-ctx.Done():
		t.Fatalf("read after extending TCP deadline: %v", ctx.Err())
	}

	if err := clientConnection.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear TCP read deadline: %v", err)
	}
	blockedRead := make(chan error, 1)
	go func() {
		_, err := clientConnection.Read(make([]byte, 1))
		blockedRead <- err
	}()
	time.Sleep(40 * time.Millisecond)
	if err := clientConnection.Close(); err != nil {
		t.Fatalf("close TCP connection with blocked read: %v", err)
	}
	select {
	case err := <-blockedRead:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked TCP read error = %v, want net.ErrClosed", err)
		}
	case <-ctx.Done():
		t.Fatalf("blocked TCP read did not wake: %v", ctx.Err())
	}
}

func testUDPDataPlane(
	t *testing.T,
	ctx context.Context,
	server *corehost.Instance,
	client *corehost.Instance,
) {
	t.Helper()
	serverPacket := listenUDPEventually(t, ctx, server)
	defer serverPacket.Close()
	clientPacket := listenUDPEventually(t, ctx, client)
	defer clientPacket.Close()
	if err := serverPacket.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set server UDP deadline: %v", err)
	}
	if err := clientPacket.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set client UDP deadline: %v", err)
	}

	serverPort := serverPacket.LocalAddr().(*net.UDPAddr).Port
	serverOverlay := &net.UDPAddr{
		IP:   net.IPv4(10, 144, 0, 101),
		Port: serverPort,
	}
	clientOverlay := &net.UDPAddr{
		IP:   net.IPv4(10, 144, 0, 102),
		Port: clientPacket.LocalAddr().(*net.UDPAddr).Port,
	}
	writePacketEventually(t, ctx, serverPacket, []byte("warmup"), clientOverlay)
	writePacketEventually(t, ctx, clientPacket, []byte("datagram"), serverOverlay)
	buffer := make([]byte, 64)
	n, peer, err := serverPacket.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("read EasyTier UDP: %v", err)
	}
	if string(buffer[:n]) != "datagram" {
		t.Fatalf("UDP payload = %q", buffer[:n])
	}
	if peer.(*net.UDPAddr).IP.String() != "10.144.0.102" {
		t.Fatalf("UDP source = %v", peer)
	}

	if _, err := serverPacket.WriteTo([]byte("reply"), clientOverlay); err != nil {
		t.Fatalf("reply over EasyTier UDP: %v", err)
	}
	for {
		n, _, err = clientPacket.ReadFrom(buffer)
		if err != nil {
			t.Fatalf("read EasyTier UDP reply: %v", err)
		}
		if string(buffer[:n]) == "reply" {
			break
		}
	}

	if _, err := clientPacket.WriteTo([]byte("truncate"), serverOverlay); err != nil {
		t.Fatalf("write truncation UDP packet: %v", err)
	}
	n, _, err = serverPacket.ReadFrom(make([]byte, 2))
	if n != 2 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("truncated UDP read = (%d, %v), want (2, io.ErrShortBuffer)", n, err)
	}

	testConnectedUDPDataPlane(t, ctx, server, client)
}

func testConnectedUDPDataPlane(
	t *testing.T,
	ctx context.Context,
	server *corehost.Instance,
	client *corehost.Instance,
) {
	t.Helper()
	serverPacket := listenUDPEventually(t, ctx, server)
	defer serverPacket.Close()
	wrongPeer := listenUDPEventually(t, ctx, server)
	defer wrongPeer.Close()
	serverOverlay := &net.UDPAddr{
		IP:   net.IPv4(10, 144, 0, 101),
		Port: serverPacket.LocalAddr().(*net.UDPAddr).Port,
	}
	clientConnection, err := client.Dial(ctx, "udp4", serverOverlay.String())
	if err != nil {
		t.Fatalf("dial through EasyTier UDP: %v", err)
	}
	defer clientConnection.Close()
	if err := clientConnection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set connected UDP deadline: %v", err)
	}
	if err := serverPacket.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set connected UDP server deadline: %v", err)
	}

	clientOverlay := &net.UDPAddr{
		IP:   net.IPv4(10, 144, 0, 102),
		Port: clientConnection.LocalAddr().(*net.UDPAddr).Port,
	}
	if _, err := serverPacket.WriteTo([]byte("warmup"), clientOverlay); err != nil {
		t.Fatalf("warm connected EasyTier UDP path: %v", err)
	}
	if _, err := clientConnection.Write([]byte("connected")); err != nil {
		t.Fatalf("write connected EasyTier UDP: %v", err)
	}
	buffer := make([]byte, 64)
	n, peer, err := serverPacket.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("read connected EasyTier UDP: %v", err)
	}
	if string(buffer[:n]) != "connected" {
		t.Fatalf("connected UDP payload = %q", buffer[:n])
	}
	if peer.(*net.UDPAddr).IP.String() != "10.144.0.102" {
		t.Fatalf("connected UDP source = %v", peer)
	}

	if _, err := wrongPeer.WriteTo([]byte("wrong-peer"), clientOverlay); err != nil {
		t.Fatalf("write wrong-peer EasyTier UDP: %v", err)
	}
	if _, err := serverPacket.WriteTo([]byte("right-peer"), clientOverlay); err != nil {
		t.Fatalf("write fixed-peer EasyTier UDP: %v", err)
	}
	for {
		n, err = clientConnection.Read(buffer)
		if err != nil {
			t.Fatalf("read connected EasyTier UDP reply: %v", err)
		}
		if string(buffer[:n]) == "right-peer" {
			break
		}
		if string(buffer[:n]) != "warmup" {
			t.Fatalf(
				"connected UDP reply = %q, want fixed-peer datagram",
				buffer[:n],
			)
		}
	}
	if clientConnection.RemoteAddr().String() != serverOverlay.String() {
		t.Fatalf(
			"connected UDP remote = %v, want %v",
			clientConnection.RemoteAddr(),
			serverOverlay,
		)
	}
}

func listenTCPEventually(
	t *testing.T,
	ctx context.Context,
	instance *corehost.Instance,
) net.Listener {
	t.Helper()
	for {
		listener, err := instance.Listen("tcp4", ":0")
		if err == nil {
			return listener
		}
		if !errors.Is(err, syscall.ENETUNREACH) {
			t.Fatalf("listen through EasyTier TCP: %v", err)
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			t.Fatalf("wait for EasyTier TCP data plane: %v", ctx.Err())
		}
	}
}

func listenUDPEventually(
	t *testing.T,
	ctx context.Context,
	instance *corehost.Instance,
) net.PacketConn {
	t.Helper()
	for {
		connection, err := instance.ListenPacket("udp4", ":0")
		if err == nil {
			return connection
		}
		if !errors.Is(err, syscall.ENETUNREACH) {
			t.Fatalf("listen through EasyTier UDP: %v", err)
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			t.Fatalf("wait for EasyTier UDP data plane: %v", ctx.Err())
		}
	}
}

func dialEventually(
	t *testing.T,
	ctx context.Context,
	instance *corehost.Instance,
	address string,
) net.Conn {
	t.Helper()
	for {
		attempt, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		connection, err := instance.Dial(attempt, "tcp4", address)
		cancel()
		if err == nil {
			return connection
		}
		if !errors.Is(err, syscall.ENETUNREACH) &&
			!errors.Is(err, syscall.ECONNREFUSED) &&
			!errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("dial through EasyTier TCP: %v", err)
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			t.Fatalf("wait for EasyTier TCP route: %v", ctx.Err())
		}
	}
}

func writePacketEventually(
	t *testing.T,
	ctx context.Context,
	connection net.PacketConn,
	data []byte,
	peer net.Addr,
) {
	t.Helper()
	for {
		if _, err := connection.WriteTo(data, peer); err == nil {
			return
		} else if !errors.Is(err, syscall.ENETUNREACH) {
			t.Fatalf("write through EasyTier UDP: %v", err)
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			t.Fatalf("wait for EasyTier UDP route: %v", ctx.Err())
		}
	}
}

func assertStreamExchange(
	t *testing.T,
	writer net.Conn,
	reader net.Conn,
	payload []byte,
) {
	t.Helper()
	if _, err := writer.Write(payload); err != nil {
		t.Fatalf("write EasyTier TCP: %v", err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, received); err != nil {
		t.Fatalf("read EasyTier TCP: %v", err)
	}
	if string(received) != string(payload) {
		t.Fatalf("TCP payload = %q, want %q", received, payload)
	}
}

type connectionResult struct {
	connection net.Conn
	err        error
}

type readResult struct {
	data []byte
	err  error
}
