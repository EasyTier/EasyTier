package reactor

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type controlledReadResult struct {
	data []byte
	err  error
}

type controlledReadRequest struct {
	result chan controlledReadResult
}

type controlledReadConn struct {
	reads     chan controlledReadRequest
	closed    chan struct{}
	closeOnce sync.Once
}

func newControlledReadConn() *controlledReadConn {
	return &controlledReadConn{
		reads:  make(chan controlledReadRequest, 2),
		closed: make(chan struct{}),
	}
}

func (connection *controlledReadConn) Read(buffer []byte) (int, error) {
	request := controlledReadRequest{result: make(chan controlledReadResult, 1)}
	select {
	case connection.reads <- request:
	case <-connection.closed:
		return 0, net.ErrClosed
	}
	select {
	case result := <-request.result:
		return copy(buffer, result.data), result.err
	case <-connection.closed:
		return 0, net.ErrClosed
	}
}

func (connection *controlledReadConn) Write(payload []byte) (int, error) {
	select {
	case <-connection.closed:
		return 0, net.ErrClosed
	default:
		return len(payload), nil
	}
}

func (connection *controlledReadConn) Close() error {
	connection.closeOnce.Do(func() { close(connection.closed) })
	return nil
}

func (*controlledReadConn) LocalAddr() net.Addr  { return streamTestAddr("local") }
func (*controlledReadConn) RemoteAddr() net.Addr { return streamTestAddr("remote") }

func (*controlledReadConn) SetDeadline(time.Time) error      { return nil }
func (*controlledReadConn) SetReadDeadline(time.Time) error  { return nil }
func (*controlledReadConn) SetWriteDeadline(time.Time) error { return nil }

type streamTestAddr string

func (streamTestAddr) Network() string        { return "test" }
func (address streamTestAddr) String() string { return string(address) }

func waitForReadRequest(t *testing.T, connection *controlledReadConn) controlledReadRequest {
	t.Helper()
	select {
	case request := <-connection.reads:
		return request
	case <-time.After(time.Second):
		t.Fatal("stream read did not start")
		return controlledReadRequest{}
	}
}

func waitForCompletion(t *testing.T, runtime *Reactor) {
	t.Helper()
	select {
	case <-runtime.Completions():
	case <-time.After(time.Second):
		t.Fatal("stream operation did not signal completion")
	}
}

func TestCanceledPendingReadPreservesDataForNextOperation(t *testing.T) {
	const handle uint64 = 1
	connection := newControlledReadConn()
	runtime := New(context.Background(), Options{
		InitialStreams: map[uint64]net.Conn{handle: connection},
	})
	defer runtime.Close()

	if err := runtime.StartRead(handle, 1, 4); err != nil {
		t.Fatalf("start first read: %v", err)
	}
	request := waitForReadRequest(t, connection)
	if err := runtime.CancelOperation(1); err != nil {
		t.Fatalf("cancel first read: %v", err)
	}
	if err := runtime.StartRead(handle, 2, 2); err != nil {
		t.Fatalf("start second read: %v", err)
	}
	request.result <- controlledReadResult{data: []byte("data")}

	waitForCompletion(t, runtime)
	data, err := runtime.TakeRead(2)
	if err != nil {
		t.Fatalf("take second read: %v", err)
	}
	if string(data) != "da" {
		t.Fatalf("second read data = %q, want da", data)
	}
	if err := runtime.StartRead(handle, 3, 2); err != nil {
		t.Fatalf("start third read: %v", err)
	}
	waitForCompletion(t, runtime)
	data, err = runtime.TakeRead(3)
	if err != nil {
		t.Fatalf("take third read: %v", err)
	}
	if string(data) != "ta" {
		t.Fatalf("third read data = %q, want ta", data)
	}
}

func TestCanceledCompletedReadPreservesDataForNextOperation(t *testing.T) {
	const handle uint64 = 1
	connection := newControlledReadConn()
	runtime := New(context.Background(), Options{
		InitialStreams: map[uint64]net.Conn{handle: connection},
	})
	defer runtime.Close()

	if err := runtime.StartRead(handle, 1, 4); err != nil {
		t.Fatalf("start first read: %v", err)
	}
	request := waitForReadRequest(t, connection)
	request.result <- controlledReadResult{data: []byte("data")}
	waitForCompletion(t, runtime)
	if err := runtime.CancelOperation(1); err != nil {
		t.Fatalf("cancel completed read: %v", err)
	}
	if err := runtime.StartRead(handle, 2, 4); err != nil {
		t.Fatalf("start second read: %v", err)
	}

	waitForCompletion(t, runtime)
	data, err := runtime.TakeRead(2)
	if err != nil {
		t.Fatalf("take second read: %v", err)
	}
	if string(data) != "data" {
		t.Fatalf("second read data = %q, want data", data)
	}
}

type blockingFirstWriteConn struct {
	firstStarted  chan struct{}
	secondStarted chan struct{}
	releaseFirst  chan struct{}
	closed        chan struct{}
	closeOnce     sync.Once
	mu            sync.Mutex
	writes        int
}

func newBlockingFirstWriteConn() *blockingFirstWriteConn {
	return &blockingFirstWriteConn{
		firstStarted:  make(chan struct{}),
		secondStarted: make(chan struct{}),
		releaseFirst:  make(chan struct{}),
		closed:        make(chan struct{}),
	}
}

func (connection *blockingFirstWriteConn) Read([]byte) (int, error) {
	<-connection.closed
	return 0, net.ErrClosed
}

func (connection *blockingFirstWriteConn) Write(payload []byte) (int, error) {
	connection.mu.Lock()
	connection.writes++
	write := connection.writes
	connection.mu.Unlock()

	switch write {
	case 1:
		close(connection.firstStarted)
		select {
		case <-connection.releaseFirst:
		case <-connection.closed:
			return 0, net.ErrClosed
		}
	case 2:
		close(connection.secondStarted)
	}
	return len(payload), nil
}

func (connection *blockingFirstWriteConn) Close() error {
	connection.closeOnce.Do(func() { close(connection.closed) })
	return nil
}

func (*blockingFirstWriteConn) LocalAddr() net.Addr  { return streamTestAddr("local") }
func (*blockingFirstWriteConn) RemoteAddr() net.Addr { return streamTestAddr("remote") }

func (*blockingFirstWriteConn) SetDeadline(time.Time) error      { return nil }
func (*blockingFirstWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (*blockingFirstWriteConn) SetWriteDeadline(time.Time) error { return nil }

func TestCanceledWriteKeepsFollowingWriteSerialized(t *testing.T) {
	const handle uint64 = 1
	connection := newBlockingFirstWriteConn()
	runtime := New(context.Background(), Options{
		InitialStreams: map[uint64]net.Conn{handle: connection},
	})
	defer runtime.Close()

	if err := runtime.StartWrite(handle, 1, []byte("first")); err != nil {
		t.Fatalf("start first write: %v", err)
	}
	select {
	case <-connection.firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first stream write did not start")
	}
	if err := runtime.CancelOperation(1); err != nil {
		t.Fatalf("cancel first write: %v", err)
	}
	if err := runtime.StartWrite(handle, 2, []byte("second")); err != nil {
		t.Fatalf("start second write: %v", err)
	}

	select {
	case <-connection.secondStarted:
		t.Fatal("second stream write started before canceled write completed")
	case <-time.After(100 * time.Millisecond):
	}
	close(connection.releaseFirst)
	select {
	case <-connection.secondStarted:
	case <-time.After(time.Second):
		t.Fatal("second stream write did not start after first completed")
	}
	waitForCompletion(t, runtime)
	if err := runtime.TakeWrite(2); err != nil {
		t.Fatalf("take second write: %v", err)
	}
}

func TestClosedHandleCompletesQueuedStreamWrite(t *testing.T) {
	const handle uint64 = 1
	connection := newBlockingFirstWriteConn()
	runtime := New(context.Background(), Options{
		InitialStreams: map[uint64]net.Conn{handle: connection},
	})
	defer runtime.Close()

	if err := runtime.StartWrite(handle, 1, []byte("first")); err != nil {
		t.Fatalf("start first write: %v", err)
	}
	select {
	case <-connection.firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first stream write did not start")
	}
	if err := runtime.StartWrite(handle, 2, []byte("second")); err != nil {
		t.Fatalf("start second write: %v", err)
	}
	if err := runtime.CloseHandle(handle); err != nil {
		t.Fatalf("close stream handle: %v", err)
	}

	waitForCompletion(t, runtime)
	if err := runtime.TakeWrite(2); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("queued write error = %v, want net.ErrClosed", err)
	}
}
