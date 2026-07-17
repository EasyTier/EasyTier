// Package easytierffi contains a small Go wrapper around the EasyTier FFI
// examples. This file documents the async data-plane surface; the synchronous
// wrapper lives in easytier.go.
//
// Public async entry points:
//
//   - OpenAsync(path) loads the EasyTier FFI dynamic library and binds the
//     async dataplane symbols. Close releases only the dynamic library handle;
//     network instances started through RunNetworkInstance are process-global
//     EasyTier state.
//
//   - (*AsyncNative).RunNetworkInstance(config) starts one EasyTier instance
//     from TOML. The instance name in the config is used by all dataplane calls.
//
//   - (*AsyncNative).DialContext(ctx, instance, "tcp", "ip:port") starts an
//     async TCP connect and returns an AsyncConn implementing net.Conn.
//
//   - (*AsyncNative).ListenContext(ctx, instance, "tcp", "0.0.0.0:port") starts
//     an async TCP bind and returns an AsyncListener implementing net.Listener.
//
//   - AsyncConn implements net.Conn. Read and Write each start one native async
//     read/write op and wait for completion. Deadlines are mapped to operation
//     timeouts. Close closes the underlying dataplane stream handle.
//
//   - AsyncListener implements net.Listener. Accept starts one native async
//     accept op and waits for a stream. Close closes the listener handle.
//
//   - (*AsyncNative).UDPBindContext(ctx, instance, port) returns an
//     AsyncUDPSocket. AsyncUDPSocket.SendTo and RecvFrom start one native async
//     UDP send/receive op and wait for completion. Close closes the socket
//     handle.
//
//   - TCPConnectContext/TCPBindContext/TCPAcceptContext/TCPReadContext/
//     TCPWriteContext and UDPSendToContext/UDPRecvFromContext are lower-level
//     handle helpers used by the examples and tests. External callers should
//     prefer DialContext, ListenContext, AsyncConn, AsyncListener, and
//     AsyncUDPSocket because raw handle close helpers are intentionally internal
//     to this example package.
//
// Async operation semantics:
//
//   - Each Context method starts a native async op, polls data_plane_async_op_wait
//     in short intervals, then calls the matching finish function. Finish is
//     single-consume on the native side.
//
//   - If the context is canceled or its deadline expires before completion, the
//     wrapper cancels and frees the native op and returns the context error.
//
//   - Read and RecvFrom copy Rust-owned output buffers into Go slices and free
//     the native allocation before returning.
//
//   - Write and SendTo keep the Go input buffer alive for the start call. The
//     native async API copies the input buffer during start, so callers do not
//     need to keep it alive after the Go method returns.
//
//   - FFI calls that read the Rust thread-local error string pin the goroutine
//     to one OS thread from the failing call through get_error_msg.
package easytierffi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/go-webgpu/goffi/ffi"
	"github.com/go-webgpu/goffi/types"
)

const (
	dataPlaneOpPending = int32(0)
	dataPlaneOpReady   = int32(1)
	dataPlaneOpFailed  = int32(-1)
	dataPlaneOpInvalid = int32(-2)

	asyncPollInterval = 50 * time.Millisecond
)

type AsyncNative struct {
	lib unsafe.Pointer

	runNetworkInstance symCall
	deleteNetworkInst  symCall
	getErrorMsg        symCall
	freeString         symCall
	freeBytes          symCall

	asyncOpStatus symCall
	asyncOpWait   symCall
	asyncOpCancel symCall
	asyncOpFree   symCall

	tcpConnectStart  symCall
	tcpConnectFinish symCall
	tcpBindStart     symCall
	tcpBindFinish    symCall
	tcpAcceptStart   symCall
	tcpAcceptFinish  symCall
	tcpReadStart     symCall
	tcpReadFinish    symCall
	tcpWriteStart    symCall
	tcpWriteFinish   symCall
	tcpClose         symCall
	tcpListenerClose symCall

	udpBindStart      symCall
	udpBindFinish     symCall
	udpSendToStart    symCall
	udpSendToFinish   symCall
	udpRecvFromStart  symCall
	udpRecvFromFinish symCall
	udpClose          symCall
}

type AsyncConn struct {
	native *AsyncNative
	handle uint64
	local  net.Addr
	remote net.Addr
	closed atomicBool
	rd     atomicDeadline
	wd     atomicDeadline
}

type AsyncListener struct {
	native *AsyncNative
	handle uint64
	addr   net.Addr
	closed atomicBool
}

type AsyncUDPSocket struct {
	native *AsyncNative
	handle uint64
	addr   *net.UDPAddr
	closed atomicBool
}

type atomicBool struct{ v atomic.Bool }

func OpenAsync(path string) (*AsyncNative, error) {
	lib, err := ffi.LoadLibrary(path)
	if err != nil {
		return nil, err
	}
	n := &AsyncNative{lib: lib}
	if err := n.bind(); err != nil {
		ffi.FreeLibrary(lib)
		return nil, err
	}
	return n, nil
}

func (n *AsyncNative) Close() error {
	if n.lib == nil {
		return nil
	}
	ffi.FreeLibrary(n.lib)
	n.lib = nil
	return nil
}

func (n *AsyncNative) RunNetworkInstance(config string) error {
	defer pinErrorThread()()
	cfg := cString(config)
	cfgPtr := unsafe.Pointer(&cfg[0])
	var ret int32
	err := n.runNetworkInstance.call(unsafe.Pointer(&ret), unsafe.Pointer(&cfgPtr))
	runtime.KeepAlive(cfg)
	if err != nil {
		return err
	}
	if ret != 0 {
		return n.lastError()
	}
	return nil
}

func (n *AsyncNative) deleteNetworkInstances(names []string) error {
	defer pinErrorThread()()

	cNames := make([][]byte, len(names))
	namePtrs := make([]unsafe.Pointer, len(names))
	for i, name := range names {
		cNames[i] = cString(name)
		namePtrs[i] = unsafe.Pointer(&cNames[i][0])
	}

	var namesPtr unsafe.Pointer
	if len(namePtrs) > 0 {
		namesPtr = unsafe.Pointer(&namePtrs[0])
	}
	length := uint64(len(names))
	var ret int32
	err := n.deleteNetworkInst.call(unsafe.Pointer(&ret), unsafe.Pointer(&namesPtr), unsafe.Pointer(&length))
	runtime.KeepAlive(cNames)
	runtime.KeepAlive(namePtrs)
	if err != nil {
		return err
	}
	if ret != 0 {
		return n.lastError()
	}
	return nil
}

func (n *AsyncNative) DialContext(ctx context.Context, instance, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, net.UnknownNetworkError(network)
	}
	ip, port, err := parseIPPort(address)
	if err != nil {
		return nil, err
	}
	handle, local, err := n.TCPConnectContext(ctx, instance, ip.String(), uint16(port))
	if err != nil {
		return nil, err
	}
	return &AsyncConn{
		native: n,
		handle: handle,
		local:  local,
		remote: &net.TCPAddr{IP: ip, Port: port},
	}, nil
}

func (n *AsyncNative) ListenContext(ctx context.Context, instance, network, address string) (net.Listener, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, net.UnknownNetworkError(network)
	}
	port, err := parseListenPort(address)
	if err != nil {
		return nil, err
	}
	handle, local, err := n.TCPBindContext(ctx, instance, uint16(port))
	if err != nil {
		return nil, err
	}
	return &AsyncListener{native: n, handle: handle, addr: local}, nil
}

func (n *AsyncNative) TCPConnectContext(ctx context.Context, instance, ip string, port uint16) (uint64, *net.TCPAddr, error) {
	timeout, err := contextTimeout(ctx)
	if err != nil {
		return 0, nil, err
	}
	op, err := n.tcpConnectStartCall(instance, ip, port, timeout)
	if err != nil {
		return 0, nil, err
	}
	if err := n.waitOp(ctx, op); err != nil {
		return 0, nil, err
	}
	return n.tcpConnectFinishCall(op)
}

func (n *AsyncNative) TCPBindContext(ctx context.Context, instance string, port uint16) (uint64, *net.TCPAddr, error) {
	timeout, err := contextTimeout(ctx)
	if err != nil {
		return 0, nil, err
	}
	op, err := n.tcpBindStartCall(instance, port, timeout)
	if err != nil {
		return 0, nil, err
	}
	if err := n.waitOp(ctx, op); err != nil {
		return 0, nil, err
	}
	return n.tcpBindFinishCall(op)
}

func (n *AsyncNative) TCPAcceptContext(ctx context.Context, listener uint64) (uint64, *net.TCPAddr, *net.TCPAddr, error) {
	timeout, err := contextTimeout(ctx)
	if err != nil {
		return 0, nil, nil, err
	}
	op, err := n.tcpAcceptStartCall(listener, timeout)
	if err != nil {
		return 0, nil, nil, err
	}
	if err := n.waitOp(ctx, op); err != nil {
		return 0, nil, nil, err
	}
	return n.tcpAcceptFinishCall(op)
}

func (n *AsyncNative) TCPReadContext(ctx context.Context, stream uint64, maxLen uint32) ([]byte, error) {
	timeout, err := contextTimeout(ctx)
	if err != nil {
		return nil, err
	}
	op, err := n.tcpReadStartCall(stream, maxLen, timeout)
	if err != nil {
		return nil, err
	}
	if err := n.waitOp(ctx, op); err != nil {
		return nil, err
	}
	return n.tcpReadFinishCall(op)
}

func (n *AsyncNative) TCPWriteContext(ctx context.Context, stream uint64, data []byte) (int, error) {
	timeout, err := contextTimeout(ctx)
	if err != nil {
		return 0, err
	}
	op, err := n.tcpWriteStartCall(stream, data, timeout)
	if err != nil {
		return 0, err
	}
	if err := n.waitOp(ctx, op); err != nil {
		return 0, err
	}
	return n.tcpWriteFinishCall(op)
}

func (n *AsyncNative) UDPBindContext(ctx context.Context, instance string, port uint16) (*AsyncUDPSocket, error) {
	timeout, err := contextTimeout(ctx)
	if err != nil {
		return nil, err
	}
	op, err := n.udpBindStartCall(instance, port, timeout)
	if err != nil {
		return nil, err
	}
	if err := n.waitOp(ctx, op); err != nil {
		return nil, err
	}
	handle, local, err := n.udpBindFinishCall(op)
	if err != nil {
		return nil, err
	}
	return &AsyncUDPSocket{native: n, handle: handle, addr: local}, nil
}

func (n *AsyncNative) UDPSendToContext(ctx context.Context, socket uint64, addr *net.UDPAddr, data []byte) (int, error) {
	timeout, err := contextTimeout(ctx)
	if err != nil {
		return 0, err
	}
	op, err := n.udpSendToStartCall(socket, addr, data, timeout)
	if err != nil {
		return 0, err
	}
	if err := n.waitOp(ctx, op); err != nil {
		return 0, err
	}
	return n.udpSendToFinishCall(op)
}

func (n *AsyncNative) UDPRecvFromContext(ctx context.Context, socket uint64, maxLen uint32) ([]byte, *net.UDPAddr, error) {
	timeout, err := contextTimeout(ctx)
	if err != nil {
		return nil, nil, err
	}
	op, err := n.udpRecvFromStartCall(socket, maxLen, timeout)
	if err != nil {
		return nil, nil, err
	}
	if err := n.waitOp(ctx, op); err != nil {
		return nil, nil, err
	}
	return n.udpRecvFromFinishCall(op)
}

func (c *AsyncConn) Read(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(b) == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.rd.timeout(defaultTimeout))
	defer cancel()
	data, err := c.native.TCPReadContext(ctx, c.handle, uint32(len(b)))
	if err != nil {
		return 0, opError("read", c.remote, err)
	}
	if len(data) == 0 {
		return 0, io.EOF
	}
	return copy(b, data), nil
}

func (c *AsyncConn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.wd.timeout(defaultTimeout))
	defer cancel()
	n, err := c.native.TCPWriteContext(ctx, c.handle, b)
	if err != nil {
		return 0, opError("write", c.remote, err)
	}
	return n, nil
}

func (c *AsyncConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return net.ErrClosed
	}
	return c.native.tcpCloseHandle(c.handle)
}

func (c *AsyncConn) LocalAddr() net.Addr                { return c.local }
func (c *AsyncConn) RemoteAddr() net.Addr               { return c.remote }
func (c *AsyncConn) SetDeadline(t time.Time) error      { c.rd.set(t); c.wd.set(t); return nil }
func (c *AsyncConn) SetReadDeadline(t time.Time) error  { c.rd.set(t); return nil }
func (c *AsyncConn) SetWriteDeadline(t time.Time) error { c.wd.set(t); return nil }

func (l *AsyncListener) Accept() (net.Conn, error) {
	if l.closed.Load() {
		return nil, net.ErrClosed
	}
	for {
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		handle, local, peer, err := l.native.TCPAcceptContext(ctx, l.handle)
		cancel()
		if err == nil {
			return &AsyncConn{native: l.native, handle: handle, local: local, remote: peer}, nil
		}
		if l.closed.Load() {
			return nil, net.ErrClosed
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			continue
		}
		return nil, opError("accept", l.addr, err)
	}
}

func (l *AsyncListener) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return net.ErrClosed
	}
	return l.native.tcpListenerCloseHandle(l.handle)
}

func (l *AsyncListener) Addr() net.Addr { return l.addr }

func (s *AsyncUDPSocket) SendTo(ctx context.Context, data []byte, addr *net.UDPAddr) (int, error) {
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	return s.native.UDPSendToContext(ctx, s.handle, addr, data)
}

func (s *AsyncUDPSocket) RecvFrom(ctx context.Context, maxLen uint32) ([]byte, *net.UDPAddr, error) {
	if s.closed.Load() {
		return nil, nil, net.ErrClosed
	}
	return s.native.UDPRecvFromContext(ctx, s.handle, maxLen)
}

func (s *AsyncUDPSocket) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return net.ErrClosed
	}
	return s.native.udpCloseHandle(s.handle)
}

func (s *AsyncUDPSocket) LocalAddr() *net.UDPAddr { return s.addr }

func (n *AsyncNative) bind() error {
	return errors.Join(
		n.bindSym(&n.runNetworkInstance, "run_network_instance", types.SInt32TypeDescriptor, types.PointerTypeDescriptor),
		n.bindSym(&n.deleteNetworkInst, "delete_network_instance", types.SInt32TypeDescriptor, types.PointerTypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.getErrorMsg, "get_error_msg", types.VoidTypeDescriptor, types.PointerTypeDescriptor),
		n.bindSym(&n.freeString, "free_string", types.VoidTypeDescriptor, types.PointerTypeDescriptor),
		n.bindSym(&n.freeBytes, "data_plane_free_bytes", types.VoidTypeDescriptor, types.PointerTypeDescriptor, types.UInt32TypeDescriptor),
		n.bindSym(&n.asyncOpStatus, "data_plane_async_op_status", types.SInt32TypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.asyncOpWait, "data_plane_async_op_wait", types.SInt32TypeDescriptor, types.UInt64TypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.asyncOpCancel, "data_plane_async_op_cancel", types.SInt32TypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.asyncOpFree, "data_plane_async_op_free", types.SInt32TypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.tcpConnectStart, "data_plane_tcp_connect_start", types.UInt64TypeDescriptor, types.PointerTypeDescriptor, types.PointerTypeDescriptor, types.UInt16TypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.tcpConnectFinish, "data_plane_tcp_connect_finish", types.UInt64TypeDescriptor, types.UInt64TypeDescriptor, types.PointerTypeDescriptor, types.PointerTypeDescriptor),
		n.bindSym(&n.tcpBindStart, "data_plane_tcp_bind_start", types.UInt64TypeDescriptor, types.PointerTypeDescriptor, types.UInt16TypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.tcpBindFinish, "data_plane_tcp_bind_finish", types.UInt64TypeDescriptor, types.UInt64TypeDescriptor, types.PointerTypeDescriptor, types.PointerTypeDescriptor),
		n.bindSym(&n.tcpAcceptStart, "data_plane_tcp_accept_start", types.UInt64TypeDescriptor, types.UInt64TypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.tcpAcceptFinish, "data_plane_tcp_accept_finish", types.UInt64TypeDescriptor, types.UInt64TypeDescriptor, types.PointerTypeDescriptor, types.PointerTypeDescriptor, types.PointerTypeDescriptor, types.PointerTypeDescriptor),
		n.bindSym(&n.tcpReadStart, "data_plane_tcp_read_start", types.UInt64TypeDescriptor, types.UInt64TypeDescriptor, types.UInt32TypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.tcpReadFinish, "data_plane_tcp_read_finish", types.SInt32TypeDescriptor, types.UInt64TypeDescriptor, types.PointerTypeDescriptor, types.PointerTypeDescriptor),
		n.bindSym(&n.tcpWriteStart, "data_plane_tcp_write_start", types.UInt64TypeDescriptor, types.UInt64TypeDescriptor, types.PointerTypeDescriptor, types.UInt32TypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.tcpWriteFinish, "data_plane_tcp_write_finish", types.SInt32TypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.tcpClose, "data_plane_tcp_close", types.SInt32TypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.tcpListenerClose, "data_plane_tcp_listener_close", types.SInt32TypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.udpBindStart, "data_plane_udp_bind_start", types.UInt64TypeDescriptor, types.PointerTypeDescriptor, types.UInt16TypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.udpBindFinish, "data_plane_udp_bind_finish", types.UInt64TypeDescriptor, types.UInt64TypeDescriptor, types.PointerTypeDescriptor, types.PointerTypeDescriptor),
		n.bindSym(&n.udpSendToStart, "data_plane_udp_send_to_start", types.UInt64TypeDescriptor, types.UInt64TypeDescriptor, types.PointerTypeDescriptor, types.UInt16TypeDescriptor, types.PointerTypeDescriptor, types.UInt32TypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.udpSendToFinish, "data_plane_udp_send_to_finish", types.SInt32TypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.udpRecvFromStart, "data_plane_udp_recv_from_start", types.UInt64TypeDescriptor, types.UInt64TypeDescriptor, types.UInt32TypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.udpRecvFromFinish, "data_plane_udp_recv_from_finish", types.SInt32TypeDescriptor, types.UInt64TypeDescriptor, types.PointerTypeDescriptor, types.PointerTypeDescriptor, types.PointerTypeDescriptor, types.PointerTypeDescriptor),
		n.bindSym(&n.udpClose, "data_plane_udp_close", types.SInt32TypeDescriptor, types.UInt64TypeDescriptor),
	)
}

func (n *AsyncNative) bindSym(dst *symCall, name string, ret *types.TypeDescriptor, args ...*types.TypeDescriptor) error {
	sym, err := ffi.GetSymbol(n.lib, name)
	if err != nil {
		return err
	}
	if err := ffi.PrepareCallInterface(&dst.cif, types.DefaultCall, ret, args); err != nil {
		return err
	}
	dst.fn = sym
	return nil
}

func (n *AsyncNative) tcpConnectStartCall(instance, ip string, port uint16, timeout time.Duration) (uint64, error) {
	defer pinErrorThread()()
	inst := cString(instance)
	dst := cString(ip)
	instPtr := unsafe.Pointer(&inst[0])
	dstPtr := unsafe.Pointer(&dst[0])
	timeoutMS := durationMillis(timeout)
	var op uint64
	err := n.tcpConnectStart.call(
		unsafe.Pointer(&op),
		unsafe.Pointer(&instPtr),
		unsafe.Pointer(&dstPtr),
		unsafe.Pointer(&port),
		unsafe.Pointer(&timeoutMS),
	)
	runtime.KeepAlive(inst)
	runtime.KeepAlive(dst)
	return n.startResult(op, err)
}

func (n *AsyncNative) tcpConnectFinishCall(op uint64) (uint64, *net.TCPAddr, error) {
	defer pinErrorThread()()
	var handle uint64
	var outIP unsafe.Pointer
	outIPArg := unsafe.Pointer(&outIP)
	var outPort uint16
	outPortArg := unsafe.Pointer(&outPort)
	err := n.tcpConnectFinish.call(
		unsafe.Pointer(&handle),
		unsafe.Pointer(&op),
		unsafe.Pointer(&outIPArg),
		unsafe.Pointer(&outPortArg),
	)
	if err != nil {
		return 0, nil, err
	}
	if handle == 0 {
		return 0, nil, n.lastError()
	}
	return handle, n.takeTCPAddr(outIP, outPort), nil
}

func (n *AsyncNative) tcpBindStartCall(instance string, port uint16, timeout time.Duration) (uint64, error) {
	defer pinErrorThread()()
	inst := cString(instance)
	instPtr := unsafe.Pointer(&inst[0])
	timeoutMS := durationMillis(timeout)
	var op uint64
	err := n.tcpBindStart.call(
		unsafe.Pointer(&op),
		unsafe.Pointer(&instPtr),
		unsafe.Pointer(&port),
		unsafe.Pointer(&timeoutMS),
	)
	runtime.KeepAlive(inst)
	return n.startResult(op, err)
}

func (n *AsyncNative) tcpBindFinishCall(op uint64) (uint64, *net.TCPAddr, error) {
	defer pinErrorThread()()
	var handle uint64
	var outIP unsafe.Pointer
	outIPArg := unsafe.Pointer(&outIP)
	var outPort uint16
	outPortArg := unsafe.Pointer(&outPort)
	err := n.tcpBindFinish.call(
		unsafe.Pointer(&handle),
		unsafe.Pointer(&op),
		unsafe.Pointer(&outIPArg),
		unsafe.Pointer(&outPortArg),
	)
	if err != nil {
		return 0, nil, err
	}
	if handle == 0 {
		return 0, nil, n.lastError()
	}
	return handle, n.takeTCPAddr(outIP, outPort), nil
}

func (n *AsyncNative) tcpAcceptStartCall(listener uint64, timeout time.Duration) (uint64, error) {
	defer pinErrorThread()()
	timeoutMS := durationMillis(timeout)
	var op uint64
	err := n.tcpAcceptStart.call(
		unsafe.Pointer(&op),
		unsafe.Pointer(&listener),
		unsafe.Pointer(&timeoutMS),
	)
	return n.startResult(op, err)
}

func (n *AsyncNative) tcpAcceptFinishCall(op uint64) (uint64, *net.TCPAddr, *net.TCPAddr, error) {
	defer pinErrorThread()()
	var handle uint64
	var localIP unsafe.Pointer
	localIPArg := unsafe.Pointer(&localIP)
	var localPort uint16
	localPortArg := unsafe.Pointer(&localPort)
	var peerIP unsafe.Pointer
	peerIPArg := unsafe.Pointer(&peerIP)
	var peerPort uint16
	peerPortArg := unsafe.Pointer(&peerPort)
	err := n.tcpAcceptFinish.call(
		unsafe.Pointer(&handle),
		unsafe.Pointer(&op),
		unsafe.Pointer(&localIPArg),
		unsafe.Pointer(&localPortArg),
		unsafe.Pointer(&peerIPArg),
		unsafe.Pointer(&peerPortArg),
	)
	if err != nil {
		return 0, nil, nil, err
	}
	if handle == 0 {
		return 0, nil, nil, n.lastError()
	}
	return handle, n.takeTCPAddr(localIP, localPort), n.takeTCPAddr(peerIP, peerPort), nil
}

func (n *AsyncNative) tcpReadStartCall(stream uint64, maxLen uint32, timeout time.Duration) (uint64, error) {
	defer pinErrorThread()()
	timeoutMS := durationMillis(timeout)
	var op uint64
	err := n.tcpReadStart.call(
		unsafe.Pointer(&op),
		unsafe.Pointer(&stream),
		unsafe.Pointer(&maxLen),
		unsafe.Pointer(&timeoutMS),
	)
	return n.startResult(op, err)
}

func (n *AsyncNative) tcpReadFinishCall(op uint64) ([]byte, error) {
	defer pinErrorThread()()
	var ret int32
	var ptr unsafe.Pointer
	ptrArg := unsafe.Pointer(&ptr)
	var len uint32
	lenArg := unsafe.Pointer(&len)
	err := n.tcpReadFinish.call(
		unsafe.Pointer(&ret),
		unsafe.Pointer(&op),
		unsafe.Pointer(&ptrArg),
		unsafe.Pointer(&lenArg),
	)
	if err != nil {
		return nil, err
	}
	if ret < 0 {
		return nil, n.lastError()
	}
	return n.takeBytes(ptr, len), nil
}

func (n *AsyncNative) tcpWriteStartCall(stream uint64, data []byte, timeout time.Duration) (uint64, error) {
	defer pinErrorThread()()
	ptr := unsafe.Pointer(nil)
	if len(data) > 0 {
		ptr = unsafe.Pointer(&data[0])
	}
	timeoutMS := durationMillis(timeout)
	length := uint32(len(data))
	var op uint64
	err := n.tcpWriteStart.call(
		unsafe.Pointer(&op),
		unsafe.Pointer(&stream),
		unsafe.Pointer(&ptr),
		unsafe.Pointer(&length),
		unsafe.Pointer(&timeoutMS),
	)
	runtime.KeepAlive(data)
	return n.startResult(op, err)
}

func (n *AsyncNative) tcpWriteFinishCall(op uint64) (int, error) {
	defer pinErrorThread()()
	var ret int32
	err := n.tcpWriteFinish.call(unsafe.Pointer(&ret), unsafe.Pointer(&op))
	if err != nil {
		return 0, err
	}
	if ret < 0 {
		return 0, n.lastError()
	}
	return int(ret), nil
}

func (n *AsyncNative) udpBindStartCall(instance string, port uint16, timeout time.Duration) (uint64, error) {
	defer pinErrorThread()()
	inst := cString(instance)
	instPtr := unsafe.Pointer(&inst[0])
	timeoutMS := durationMillis(timeout)
	var op uint64
	err := n.udpBindStart.call(
		unsafe.Pointer(&op),
		unsafe.Pointer(&instPtr),
		unsafe.Pointer(&port),
		unsafe.Pointer(&timeoutMS),
	)
	runtime.KeepAlive(inst)
	return n.startResult(op, err)
}

func (n *AsyncNative) udpBindFinishCall(op uint64) (uint64, *net.UDPAddr, error) {
	defer pinErrorThread()()
	var handle uint64
	var outIP unsafe.Pointer
	outIPArg := unsafe.Pointer(&outIP)
	var outPort uint16
	outPortArg := unsafe.Pointer(&outPort)
	err := n.udpBindFinish.call(
		unsafe.Pointer(&handle),
		unsafe.Pointer(&op),
		unsafe.Pointer(&outIPArg),
		unsafe.Pointer(&outPortArg),
	)
	if err != nil {
		return 0, nil, err
	}
	if handle == 0 {
		return 0, nil, n.lastError()
	}
	return handle, n.takeUDPAddr(outIP, outPort), nil
}

func (n *AsyncNative) udpSendToStartCall(socket uint64, addr *net.UDPAddr, data []byte, timeout time.Duration) (uint64, error) {
	defer pinErrorThread()()
	if addr == nil || addr.IP == nil {
		return 0, errors.New("udp destination address is nil")
	}
	dst := cString(addr.IP.String())
	dstPtr := unsafe.Pointer(&dst[0])
	ptr := unsafe.Pointer(nil)
	if len(data) > 0 {
		ptr = unsafe.Pointer(&data[0])
	}
	port := uint16(addr.Port)
	length := uint32(len(data))
	timeoutMS := durationMillis(timeout)
	var op uint64
	err := n.udpSendToStart.call(
		unsafe.Pointer(&op),
		unsafe.Pointer(&socket),
		unsafe.Pointer(&dstPtr),
		unsafe.Pointer(&port),
		unsafe.Pointer(&ptr),
		unsafe.Pointer(&length),
		unsafe.Pointer(&timeoutMS),
	)
	runtime.KeepAlive(dst)
	runtime.KeepAlive(data)
	return n.startResult(op, err)
}

func (n *AsyncNative) udpSendToFinishCall(op uint64) (int, error) {
	defer pinErrorThread()()
	var ret int32
	err := n.udpSendToFinish.call(unsafe.Pointer(&ret), unsafe.Pointer(&op))
	if err != nil {
		return 0, err
	}
	if ret < 0 {
		return 0, n.lastError()
	}
	return int(ret), nil
}

func (n *AsyncNative) udpRecvFromStartCall(socket uint64, maxLen uint32, timeout time.Duration) (uint64, error) {
	defer pinErrorThread()()
	timeoutMS := durationMillis(timeout)
	var op uint64
	err := n.udpRecvFromStart.call(
		unsafe.Pointer(&op),
		unsafe.Pointer(&socket),
		unsafe.Pointer(&maxLen),
		unsafe.Pointer(&timeoutMS),
	)
	return n.startResult(op, err)
}

func (n *AsyncNative) udpRecvFromFinishCall(op uint64) ([]byte, *net.UDPAddr, error) {
	defer pinErrorThread()()
	var ret int32
	var ptr unsafe.Pointer
	ptrArg := unsafe.Pointer(&ptr)
	var len uint32
	lenArg := unsafe.Pointer(&len)
	var peerIP unsafe.Pointer
	peerIPArg := unsafe.Pointer(&peerIP)
	var peerPort uint16
	peerPortArg := unsafe.Pointer(&peerPort)
	err := n.udpRecvFromFinish.call(
		unsafe.Pointer(&ret),
		unsafe.Pointer(&op),
		unsafe.Pointer(&ptrArg),
		unsafe.Pointer(&lenArg),
		unsafe.Pointer(&peerIPArg),
		unsafe.Pointer(&peerPortArg),
	)
	if err != nil {
		return nil, nil, err
	}
	if ret < 0 {
		return nil, nil, n.lastError()
	}
	return n.takeBytes(ptr, len), n.takeUDPAddr(peerIP, peerPort), nil
}

func (n *AsyncNative) waitOp(ctx context.Context, op uint64) error {
	for {
		if err := ctx.Err(); err != nil {
			n.cancelAndFreeOp(op)
			return err
		}

		wait := asyncPollInterval
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				n.cancelAndFreeOp(op)
				return context.DeadlineExceeded
			}
			if remaining < wait {
				wait = remaining
			}
		}

		status, err := n.opWaitStatus(op, wait)
		if err != nil {
			n.cancelAndFreeOp(op)
			return err
		}
		switch status {
		case dataPlaneOpPending:
			continue
		case dataPlaneOpReady, dataPlaneOpFailed:
			return nil
		case dataPlaneOpInvalid:
			return errors.New("data plane async op is invalid")
		default:
			return fmt.Errorf("unexpected data plane async op status %d", status)
		}
	}
}

func (n *AsyncNative) opWaitStatus(op uint64, timeout time.Duration) (int32, error) {
	timeoutMS := durationMillis(timeout)
	var status int32
	err := n.asyncOpWait.call(
		unsafe.Pointer(&status),
		unsafe.Pointer(&op),
		unsafe.Pointer(&timeoutMS),
	)
	return status, err
}

func (n *AsyncNative) cancelAndFreeOp(op uint64) {
	var ret int32
	_ = n.asyncOpCancel.call(unsafe.Pointer(&ret), unsafe.Pointer(&op))
	_ = n.asyncOpFree.call(unsafe.Pointer(&ret), unsafe.Pointer(&op))
}

func (n *AsyncNative) startResult(op uint64, err error) (uint64, error) {
	if err != nil {
		return 0, err
	}
	if op == 0 {
		return 0, n.lastError()
	}
	return op, nil
}

func (n *AsyncNative) lastError() error {
	var out unsafe.Pointer
	outArg := unsafe.Pointer(&out)
	if err := n.getErrorMsg.call(nil, unsafe.Pointer(&outArg)); err != nil {
		return err
	}
	if out == nil {
		return errors.New("easytier ffi call failed")
	}
	msg := readCString(out)
	_ = n.freeCString(out)
	if msg == "" {
		return errors.New("easytier ffi call failed")
	}
	if containsTimeout(msg) {
		return timeoutError(msg)
	}
	return errors.New(msg)
}

func (n *AsyncNative) freeCString(ptr unsafe.Pointer) error {
	if ptr == nil {
		return nil
	}
	return n.freeString.call(nil, unsafe.Pointer(&ptr))
}

func (n *AsyncNative) takeTCPAddr(ipPtr unsafe.Pointer, port uint16) *net.TCPAddr {
	if ipPtr == nil {
		return nil
	}
	ip := net.ParseIP(readCString(ipPtr))
	_ = n.freeCString(ipPtr)
	return &net.TCPAddr{IP: ip, Port: int(port)}
}

func (n *AsyncNative) takeUDPAddr(ipPtr unsafe.Pointer, port uint16) *net.UDPAddr {
	if ipPtr == nil {
		return nil
	}
	ip := net.ParseIP(readCString(ipPtr))
	_ = n.freeCString(ipPtr)
	return &net.UDPAddr{IP: ip, Port: int(port)}
}

func (n *AsyncNative) takeBytes(ptr unsafe.Pointer, len uint32) []byte {
	if ptr == nil || len == 0 {
		return nil
	}
	bytes := make([]byte, int(len))
	copy(bytes, unsafe.Slice((*byte)(ptr), int(len)))
	_ = n.freeBytes.call(nil, unsafe.Pointer(&ptr), unsafe.Pointer(&len))
	return bytes
}

func (n *AsyncNative) tcpCloseHandle(handle uint64) error {
	defer pinErrorThread()()
	var ret int32
	if err := n.tcpClose.call(unsafe.Pointer(&ret), unsafe.Pointer(&handle)); err != nil {
		return err
	}
	if ret != 0 {
		return n.lastError()
	}
	return nil
}

func (n *AsyncNative) tcpListenerCloseHandle(handle uint64) error {
	defer pinErrorThread()()
	var ret int32
	if err := n.tcpListenerClose.call(unsafe.Pointer(&ret), unsafe.Pointer(&handle)); err != nil {
		return err
	}
	if ret != 0 {
		return n.lastError()
	}
	return nil
}

func (n *AsyncNative) udpCloseHandle(handle uint64) error {
	defer pinErrorThread()()
	var ret int32
	if err := n.udpClose.call(unsafe.Pointer(&ret), unsafe.Pointer(&handle)); err != nil {
		return err
	}
	if ret != 0 {
		return n.lastError()
	}
	return nil
}

func contextTimeout(ctx context.Context) (time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	timeout := defaultTimeout
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	if timeout <= 0 {
		return 0, context.DeadlineExceeded
	}
	return timeout, nil
}

func durationMillis(d time.Duration) uint64 {
	if d <= 0 {
		return 0
	}
	ms := d / time.Millisecond
	if ms <= 0 {
		return 1
	}
	return uint64(ms)
}

func containsTimeout(msg string) bool {
	return strings.Contains(msg, "timed out") || strings.Contains(msg, "timeout")
}

func (b *atomicBool) Load() bool {
	return b.v.Load()
}

func (b *atomicBool) CompareAndSwap(old, new bool) bool {
	return b.v.CompareAndSwap(old, new)
}

var _ net.Conn = (*AsyncConn)(nil)
var _ net.Listener = (*AsyncListener)(nil)
