package reactor

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/easytier-go/platform"
)

func TestOperationIDsAreUniqueAcrossOperationKinds(t *testing.T) {
	host, peer := net.Pipe()
	defer peer.Close()
	runtime := New(context.Background(), Options{
		InitialStreams: map[uint64]net.Conn{1: host},
	})
	defer runtime.Close()
	if err := runtime.StartRead(1, 99, 1); err != nil {
		t.Fatalf("start read: %v", err)
	}
	if err := runtime.StartWrite(1, 99, []byte("x")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate cross-kind operation error = %v, want invalid", err)
	}
	if err := runtime.CancelOperation(99); err != nil {
		t.Fatalf("cancel read: %v", err)
	}
	if err := runtime.StartWrite(1, 99, []byte("x")); err != nil {
		t.Fatalf("reuse released operation ID: %v", err)
	}
}

type blockingSocketFactory struct {
	started chan struct{}
	once    sync.Once
}

func (factory *blockingSocketFactory) ConnectTCP(
	ctx context.Context,
	_ platform.TCPConnectOptions,
) (net.Conn, error) {
	factory.once.Do(func() { close(factory.started) })
	<-ctx.Done()
	return nil, ctx.Err()
}

func (*blockingSocketFactory) BindUDP(
	context.Context,
	platform.UDPBindOptions,
) (net.PacketConn, error) {
	return nil, errors.New("not used")
}

func (*blockingSocketFactory) ListenTCP(
	context.Context,
	platform.TCPListenOptions,
) (net.Listener, error) {
	return nil, errors.New("not used")
}

func TestCloseCancelsInstanceScopedOperations(t *testing.T) {
	factory := &blockingSocketFactory{started: make(chan struct{})}
	runtime := New(context.Background(), Options{
		Services: platform.Services{Sockets: factory},
	})
	if err := runtime.StartTCPConnect(1, platform.TCPConnectOptions{}); err != nil {
		t.Fatalf("start TCP connect: %v", err)
	}
	select {
	case <-factory.started:
	case <-time.After(time.Second):
		t.Fatal("socket factory did not start")
	}
	closed := make(chan struct{})
	go func() {
		runtime.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("reactor close did not cancel socket factory")
	}
}

func TestCreateTakeMustMatchStartKind(t *testing.T) {
	factory := &blockingSocketFactory{started: make(chan struct{})}
	runtime := New(context.Background(), Options{
		Services: platform.Services{Sockets: factory},
	})
	defer runtime.Close()
	if err := runtime.StartTCPConnect(1, platform.TCPConnectOptions{}); err != nil {
		t.Fatalf("start TCP connect: %v", err)
	}
	if _, err := runtime.TakeUDPBind(1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("take TCP connect as UDP bind error = %v, want invalid", err)
	}
	if err := runtime.CancelOperation(1); err != nil {
		t.Fatalf("cancel TCP connect: %v", err)
	}
}

func TestReceivePacketUnblocksWhenReactorCloses(t *testing.T) {
	runtime := New(context.Background(), Options{})
	handle, err := runtime.RegisterPacketSink(1)
	if err != nil {
		t.Fatalf("register packet sink: %v", err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := runtime.ReceivePacket(context.Background(), handle)
		result <- err
	}()
	runtime.Close()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("packet receive succeeded after close")
		}
	case <-time.After(time.Second):
		t.Fatal("packet receive remained blocked after close")
	}
}

func TestEventSinkRejectsFullAndUnregisteredWrites(t *testing.T) {
	runtime := New(context.Background(), Options{})
	defer runtime.Close()
	events := make(chan string, 1)
	handle, err := runtime.RegisterEventSink(func(kind, message string) bool {
		select {
		case events <- kind + ":" + message:
			return true
		default:
			return false
		}
	})
	if err != nil {
		t.Fatalf("register event sink: %v", err)
	}
	if err := runtime.TryEventWrite(handle, "peer_added", "PeerAdded(7)"); err != nil {
		t.Fatalf("write event: %v", err)
	}
	if err := runtime.TryEventWrite(handle, "peer_removed", "PeerRemoved(7)"); !errors.Is(
		err,
		ErrWouldBlock,
	) {
		t.Fatalf("full event sink error = %v, want would block", err)
	}
	if event := <-events; event != "peer_added:PeerAdded(7)" {
		t.Fatalf("event = %q", event)
	}
	runtime.UnregisterEventSink(handle)
	if err := runtime.TryEventWrite(handle, "peer_removed", "PeerRemoved(7)"); !errors.Is(
		err,
		ErrInvalid,
	) {
		t.Fatalf("unregistered event sink error = %v, want invalid", err)
	}
}

func TestReceivePacketUnblocksWhenSinkIsUnregistered(t *testing.T) {
	runtime := New(context.Background(), Options{})
	defer runtime.Close()
	handle, err := runtime.RegisterPacketSink(1)
	if err != nil {
		t.Fatalf("register packet sink: %v", err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := runtime.ReceivePacket(context.Background(), handle)
		result <- err
	}()
	runtime.UnregisterPacketSink(handle)
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("packet receive error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("packet receive remained blocked after sink unregister")
	}
}

func TestConcurrentCloseWaitsForOneCleanup(t *testing.T) {
	runtime := New(context.Background(), Options{})
	var workers sync.WaitGroup
	workers.Add(2)
	for worker := 0; worker < 2; worker++ {
		go func() {
			defer workers.Done()
			runtime.Close()
		}()
	}
	done := make(chan struct{})
	go func() {
		workers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("concurrent close did not converge")
	}
}

func TestUDPSendWorkerWritesQueuedDatagram(t *testing.T) {
	hostPacket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen host UDP: %v", err)
	}
	peerPacket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		hostPacket.Close()
		t.Fatalf("listen peer UDP: %v", err)
	}
	defer peerPacket.Close()
	const handle uint64 = 17
	runtime := New(context.Background(), Options{
		InitialDatagrams: map[uint64]net.PacketConn{handle: hostPacket},
	})
	defer runtime.Close()
	peer := peerPacket.LocalAddr().(*net.UDPAddr)
	if err := runtime.TryUDPSend(handle, []byte("udp"), peer); err != nil {
		t.Fatalf("queue UDP send: %v", err)
	}
	if err := peerPacket.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 16)
	n, _, err := peerPacket.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("read queued UDP send: %v", err)
	}
	if string(buffer[:n]) != "udp" {
		t.Fatalf("queued UDP payload = %q", buffer[:n])
	}
}

type blockingWritePacketConn struct {
	writeStarted chan struct{}
	closed       chan struct{}
	startOnce    sync.Once
	closeOnce    sync.Once
}

func newBlockingWritePacketConn() *blockingWritePacketConn {
	return &blockingWritePacketConn{
		writeStarted: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (connection *blockingWritePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-connection.closed
	return 0, nil, net.ErrClosed
}

func (connection *blockingWritePacketConn) WriteTo(
	[]byte,
	net.Addr,
) (int, error) {
	connection.startOnce.Do(func() { close(connection.writeStarted) })
	<-connection.closed
	return 0, net.ErrClosed
}

func (connection *blockingWritePacketConn) Close() error {
	connection.closeOnce.Do(func() { close(connection.closed) })
	return nil
}

func (*blockingWritePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (*blockingWritePacketConn) SetDeadline(time.Time) error      { return nil }
func (*blockingWritePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*blockingWritePacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestCloseForcesClosedHandleWithBlockedUDPSend(t *testing.T) {
	const handle uint64 = 23
	connection := newBlockingWritePacketConn()
	runtime := New(context.Background(), Options{
		InitialDatagrams: map[uint64]net.PacketConn{handle: connection},
	})
	if err := runtime.TryUDPSend(
		handle,
		[]byte("blocked"),
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
	); err != nil {
		t.Fatalf("queue UDP send: %v", err)
	}
	select {
	case <-connection.writeStarted:
	case <-time.After(time.Second):
		connection.Close()
		runtime.Close()
		t.Fatal("UDP write did not start")
	}
	if err := runtime.CloseHandle(handle); err != nil {
		connection.Close()
		runtime.Close()
		t.Fatalf("close UDP handle: %v", err)
	}

	closed := make(chan struct{})
	go func() {
		runtime.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		connection.Close()
		<-closed
		t.Fatal("reactor close did not force-close draining UDP socket")
	}
}

var errTransientUDPRead = errors.New("transient UDP read error")

type retryReadPacketConn struct {
	firstReadStarted  chan struct{}
	releaseFirstRead  chan struct{}
	secondReadStarted chan struct{}
	secondPayload     chan []byte
	closed            chan struct{}
	closeOnce         sync.Once
	mu                sync.Mutex
	readCount         int
}

func newRetryReadPacketConn() *retryReadPacketConn {
	return &retryReadPacketConn{
		firstReadStarted:  make(chan struct{}),
		releaseFirstRead:  make(chan struct{}),
		secondReadStarted: make(chan struct{}),
		secondPayload:     make(chan []byte),
		closed:            make(chan struct{}),
	}
}

func (connection *retryReadPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	connection.mu.Lock()
	connection.readCount++
	readCount := connection.readCount
	connection.mu.Unlock()

	switch readCount {
	case 1:
		close(connection.firstReadStarted)
		select {
		case <-connection.releaseFirstRead:
			return 0, nil, errTransientUDPRead
		case <-connection.closed:
			return 0, nil, net.ErrClosed
		}
	case 2:
		close(connection.secondReadStarted)
		select {
		case payload := <-connection.secondPayload:
			return copy(buffer, payload), &net.UDPAddr{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: 2,
			}, nil
		case <-connection.closed:
			return 0, nil, net.ErrClosed
		}
	default:
		<-connection.closed
		return 0, nil, net.ErrClosed
	}
}

func (*retryReadPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return len(payload), nil
}

func (connection *retryReadPacketConn) Close() error {
	connection.closeOnce.Do(func() { close(connection.closed) })
	return nil
}

func (*retryReadPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (*retryReadPacketConn) SetDeadline(time.Time) error      { return nil }
func (*retryReadPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*retryReadPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestUDPReceiveErrorRestartsWorkerForRemainingWaiter(t *testing.T) {
	const handle uint64 = 29
	connection := newRetryReadPacketConn()
	runtime := New(context.Background(), Options{
		InitialDatagrams: map[uint64]net.PacketConn{handle: connection},
	})
	defer runtime.Close()

	if err := runtime.StartUDPReceive(handle, 1); err != nil {
		t.Fatalf("start first UDP receive: %v", err)
	}
	select {
	case <-connection.firstReadStarted:
	case <-time.After(time.Second):
		t.Fatal("first UDP read did not start")
	}
	if err := runtime.StartUDPReceive(handle, 2); err != nil {
		t.Fatalf("start second UDP receive: %v", err)
	}
	close(connection.releaseFirstRead)
	select {
	case <-runtime.Completions():
	case <-time.After(time.Second):
		t.Fatal("transient UDP read error did not signal completion")
	}
	if _, err := runtime.TakeUDPReceive(1, 64); !errors.Is(err, errTransientUDPRead) {
		t.Fatalf("first UDP receive error = %v, want transient error", err)
	}

	select {
	case <-connection.secondReadStarted:
	case <-time.After(time.Second):
		t.Fatal("remaining UDP waiter did not restart receive worker")
	}
	connection.secondPayload <- []byte("retry")
	select {
	case <-runtime.Completions():
	case <-time.After(time.Second):
		t.Fatal("retried UDP read did not signal completion")
	}
	datagram, err := runtime.TakeUDPReceive(2, 64)
	if err != nil {
		t.Fatalf("take retried UDP receive: %v", err)
	}
	if string(datagram.Data) != "retry" {
		t.Fatalf("retried UDP payload = %q, want retry", datagram.Data)
	}
}

type prefetchPacketConn struct {
	readStarted chan struct{}
	payloads    chan []byte
	closed      chan struct{}
	closeOnce   sync.Once
}

func newPrefetchPacketConn() *prefetchPacketConn {
	return &prefetchPacketConn{
		readStarted: make(chan struct{}, 3),
		payloads:    make(chan []byte, 2),
		closed:      make(chan struct{}),
	}
}

func (connection *prefetchPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	connection.readStarted <- struct{}{}
	select {
	case payload := <-connection.payloads:
		return copy(buffer, payload), &net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 3,
		}, nil
	case <-connection.closed:
		return 0, nil, net.ErrClosed
	}
}

func (*prefetchPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return len(payload), nil
}

func (connection *prefetchPacketConn) Close() error {
	connection.closeOnce.Do(func() { close(connection.closed) })
	return nil
}

func (*prefetchPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (*prefetchPacketConn) SetDeadline(time.Time) error      { return nil }
func (*prefetchPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*prefetchPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestUDPReceivePrefetchesWhileWaiterIsPending(t *testing.T) {
	const handle uint64 = 31
	connection := newPrefetchPacketConn()
	runtime := New(context.Background(), Options{
		InitialDatagrams: map[uint64]net.PacketConn{handle: connection},
	})
	defer runtime.Close()

	if err := runtime.StartUDPReceive(handle, 1); err != nil {
		t.Fatalf("start first UDP receive: %v", err)
	}
	waitForUDPReadStart(t, connection)
	connection.payloads <- []byte("first")
	waitForUDPReadStart(t, connection)
	connection.payloads <- []byte("second")
	waitForUDPReadStart(t, connection)

	first, err := runtime.TakeUDPReceive(1, 64)
	if err != nil {
		t.Fatalf("take first prefetched UDP receive: %v", err)
	}
	if string(first.Data) != "first" {
		t.Fatalf("first prefetched UDP payload = %q, want first", first.Data)
	}
	if err := runtime.StartUDPReceive(handle, 2); err != nil {
		t.Fatalf("start second UDP receive: %v", err)
	}
	second, err := runtime.TakeUDPReceive(2, 64)
	if err != nil {
		t.Fatalf("take second prefetched UDP receive: %v", err)
	}
	if string(second.Data) != "second" {
		t.Fatalf("second prefetched UDP payload = %q, want second", second.Data)
	}
}

func waitForUDPReadStart(t *testing.T, connection *prefetchPacketConn) {
	t.Helper()
	select {
	case <-connection.readStarted:
	case <-time.After(time.Second):
		t.Fatal("UDP read did not start")
	}
}
