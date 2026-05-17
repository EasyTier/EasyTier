package easytierffi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/go-webgpu/goffi/ffi"
	"github.com/go-webgpu/goffi/types"
)

const defaultTimeout = 30 * time.Second

type Native struct {
	lib unsafe.Pointer

	runNetworkInstance symCall
	getErrorMsg        symCall
	freeString         symCall
	tcpConnect         symCall
	tcpRead            symCall
	tcpWrite           symCall
	tcpClose           symCall
	udpBind            symCall
	udpSendTo          symCall
	udpRecvFrom        symCall
	udpClose           symCall
}

type symCall struct {
	fn  unsafe.Pointer
	cif types.CallInterface
	mu  sync.Mutex
}

type Dialer struct {
	Native   *Native
	Instance string
	Timeout  time.Duration
}

type Conn struct {
	native *Native
	handle uint64
	remote net.Addr
	closed atomic.Bool
	rd     atomicDeadline
	wd     atomicDeadline
}

type PacketConn struct {
	native *Native
	handle uint64
	local  net.Addr
	closed atomic.Bool
	rd     atomicDeadline
	wd     atomicDeadline
}

type atomicDeadline struct{ v atomic.Int64 }

type timeoutError string

func Open(path string) (*Native, error) {
	lib, err := ffi.LoadLibrary(path)
	if err != nil {
		return nil, err
	}
	n := &Native{lib: lib}
	if err := n.bind(); err != nil {
		ffi.FreeLibrary(lib)
		return nil, err
	}
	return n, nil
}

func (n *Native) Close() error {
	if n.lib == nil {
		return nil
	}
	ffi.FreeLibrary(n.lib)
	n.lib = nil
	return nil
}

func (n *Native) RunNetworkInstance(config string) error {
	cfg := cString(config)
	cfgPtr := unsafe.Pointer(&cfg[0])
	var ret int32
	err := n.runNetworkInstance.call(unsafe.Pointer(&ret), unsafe.Pointer(&cfgPtr))
	runtime.KeepAlive(cfg)
	if err != nil {
		return err
	}
	if ret != 0 {
		return n.LastError()
	}
	return nil
}

func (n *Native) DialContext(ctx context.Context, instance, network, address string) (net.Conn, error) {
	return (&Dialer{Native: n, Instance: instance}).DialContext(ctx, network, address)
}

func (n *Native) ListenPacket(instance string, localPort uint16) (net.PacketConn, error) {
	return n.ListenPacketTimeout(instance, localPort, defaultTimeout)
}

func (n *Native) ListenPacketTimeout(instance string, localPort uint16, timeout time.Duration) (net.PacketConn, error) {
	inst := cString(instance)
	instPtr := unsafe.Pointer(&inst[0])
	timeoutMS := uint64(timeout / time.Millisecond)
	var handle uint64
	err := n.udpBind.call(
		unsafe.Pointer(&handle),
		unsafe.Pointer(&instPtr),
		unsafe.Pointer(&localPort),
		unsafe.Pointer(&timeoutMS),
	)
	runtime.KeepAlive(inst)
	if err != nil {
		return nil, err
	}
	if handle == 0 {
		return nil, n.LastError()
	}
	return &PacketConn{
		native: n,
		handle: handle,
		local:  newEasyTierAddr("udp", fmt.Sprintf("0.0.0.0:%d", localPort)),
	}, nil
}

func (n *Native) TCPConnect(instance, ip string, port uint16, timeout time.Duration) (uint64, error) {
	inst := cString(instance)
	dst := cString(ip)
	instPtr := unsafe.Pointer(&inst[0])
	dstPtr := unsafe.Pointer(&dst[0])
	timeoutMS := uint64(timeout / time.Millisecond)
	var handle uint64
	err := n.tcpConnect.call(
		unsafe.Pointer(&handle),
		unsafe.Pointer(&instPtr),
		unsafe.Pointer(&dstPtr),
		unsafe.Pointer(&port),
		unsafe.Pointer(&timeoutMS),
	)
	runtime.KeepAlive(inst)
	runtime.KeepAlive(dst)
	if err != nil {
		return 0, err
	}
	if handle == 0 {
		return 0, n.LastError()
	}
	return handle, nil
}

func (n *Native) TCPRead(handle uint64, buf []byte, timeout time.Duration) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	var ret int32
	bufPtr := unsafe.Pointer(&buf[0])
	timeoutMS := uint64(timeout / time.Millisecond)
	err := n.callWithBufferLen(&n.tcpRead, unsafe.Pointer(&ret), handle, bufPtr, len(buf), timeoutMS)
	runtime.KeepAlive(buf)
	if err != nil {
		return 0, err
	}
	if ret < 0 {
		return 0, n.LastError()
	}
	return int(ret), nil
}

func (n *Native) TCPWrite(handle uint64, buf []byte, timeout time.Duration) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	var ret int32
	bufPtr := unsafe.Pointer(&buf[0])
	timeoutMS := uint64(timeout / time.Millisecond)
	err := n.callWithBufferLen(&n.tcpWrite, unsafe.Pointer(&ret), handle, bufPtr, len(buf), timeoutMS)
	runtime.KeepAlive(buf)
	if err != nil {
		return 0, err
	}
	if ret < 0 {
		return 0, n.LastError()
	}
	return int(ret), nil
}

func (n *Native) TCPClose(handle uint64) error {
	var ret int32
	if err := n.tcpClose.call(unsafe.Pointer(&ret), unsafe.Pointer(&handle)); err != nil {
		return err
	}
	if ret != 0 {
		return n.LastError()
	}
	return nil
}

func (n *Native) UDPSendTo(handle uint64, ip string, port uint16, buf []byte, timeout time.Duration) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	dst := cString(ip)
	dstPtr := unsafe.Pointer(&dst[0])
	bufPtr := unsafe.Pointer(&buf[0])
	timeoutMS := uint64(timeout / time.Millisecond)
	var ret int32
	err := n.callWithBufferLenAndAddr(&n.udpSendTo, unsafe.Pointer(&ret), handle, dstPtr, port, bufPtr, len(buf), timeoutMS)
	runtime.KeepAlive(dst)
	runtime.KeepAlive(buf)
	if err != nil {
		return 0, err
	}
	if ret < 0 {
		return 0, n.LastError()
	}
	return int(ret), nil
}

func (n *Native) UDPRecvFrom(handle uint64, buf []byte, timeout time.Duration) (int, *net.UDPAddr, error) {
	if len(buf) == 0 {
		return 0, nil, nil
	}
	bufPtr := unsafe.Pointer(&buf[0])
	timeoutMS := uint64(timeout / time.Millisecond)
	var outIP unsafe.Pointer
	outIPPtr := unsafe.Pointer(&outIP)
	var outPort uint16
	var ret int32
	err := n.callRecvFrom(unsafe.Pointer(&ret), handle, bufPtr, len(buf), outIPPtr, &outPort, timeoutMS)
	runtime.KeepAlive(buf)
	if err != nil {
		return 0, nil, err
	}
	if ret < 0 {
		return 0, nil, n.LastError()
	}
	addr := &net.UDPAddr{IP: net.ParseIP(readCString(outIP)), Port: int(outPort)}
	_ = n.freeCString(outIP)
	return int(ret), addr, nil
}

func (n *Native) UDPClose(handle uint64) error {
	var ret int32
	if err := n.udpClose.call(unsafe.Pointer(&ret), unsafe.Pointer(&handle)); err != nil {
		return err
	}
	if ret != 0 {
		return n.LastError()
	}
	return nil
}

func (n *Native) LastError() error {
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
	if strings.Contains(msg, "timed out") {
		return timeoutError(msg)
	}
	return errors.New(msg)
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.Native == nil {
		return nil, errors.New("nil EasyTier native binding")
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, net.UnknownNetworkError(network)
	}
	ip, port, err := parseIPPort(address)
	if err != nil {
		return nil, err
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	handle, err := d.Native.TCPConnect(d.Instance, ip.String(), uint16(port), timeout)
	if err != nil {
		return nil, err
	}
	return &Conn{native: d.Native, handle: handle, remote: &net.TCPAddr{IP: ip, Port: port}}, nil
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := c.native.TCPRead(c.handle, b, c.rd.timeout(defaultTimeout))
	if err != nil {
		return 0, opError("read", c.remote, err)
	}
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := c.native.TCPWrite(c.handle, b, c.wd.timeout(defaultTimeout))
	if err != nil {
		return 0, opError("write", c.remote, err)
	}
	return n, nil
}

func (c *Conn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return net.ErrClosed
	}
	return c.native.TCPClose(c.handle)
}

func (c *Conn) LocalAddr() net.Addr                { return newEasyTierAddr("tcp", "0.0.0.0:0") }
func (c *Conn) RemoteAddr() net.Addr               { return c.remote }
func (c *Conn) SetDeadline(t time.Time) error      { c.rd.set(t); c.wd.set(t); return nil }
func (c *Conn) SetReadDeadline(t time.Time) error  { c.rd.set(t); return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { c.wd.set(t); return nil }

func (p *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if p.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	n, addr, err := p.native.UDPRecvFrom(p.handle, b, p.rd.timeout(defaultTimeout))
	if err != nil {
		return 0, nil, opError("read", nil, err)
	}
	return n, addr, nil
}

func (p *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if p.closed.Load() {
		return 0, net.ErrClosed
	}
	ip, port, err := parseIPPort(addr.String())
	if err != nil {
		return 0, err
	}
	n, err := p.native.UDPSendTo(p.handle, ip.String(), uint16(port), b, p.wd.timeout(defaultTimeout))
	if err != nil {
		return 0, opError("write", addr, err)
	}
	return n, nil
}

func (p *PacketConn) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return net.ErrClosed
	}
	return p.native.UDPClose(p.handle)
}

func (p *PacketConn) LocalAddr() net.Addr                { return p.local }
func (p *PacketConn) SetDeadline(t time.Time) error      { p.rd.set(t); p.wd.set(t); return nil }
func (p *PacketConn) SetReadDeadline(t time.Time) error  { p.rd.set(t); return nil }
func (p *PacketConn) SetWriteDeadline(t time.Time) error { p.wd.set(t); return nil }

func (n *Native) bind() error {
	return errors.Join(
		n.bindSym(&n.runNetworkInstance, "run_network_instance", types.SInt32TypeDescriptor, types.PointerTypeDescriptor),
		n.bindSym(&n.getErrorMsg, "get_error_msg", types.VoidTypeDescriptor, types.PointerTypeDescriptor),
		n.bindSym(&n.freeString, "free_string", types.VoidTypeDescriptor, types.PointerTypeDescriptor),
		n.bindSym(&n.tcpConnect, "data_plane_tcp_connect", types.UInt64TypeDescriptor, types.PointerTypeDescriptor, types.PointerTypeDescriptor, types.UInt16TypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.tcpRead, "data_plane_tcp_read", types.SInt32TypeDescriptor, types.UInt64TypeDescriptor, types.PointerTypeDescriptor, cULongType(), types.UInt64TypeDescriptor),
		n.bindSym(&n.tcpWrite, "data_plane_tcp_write", types.SInt32TypeDescriptor, types.UInt64TypeDescriptor, types.PointerTypeDescriptor, cULongType(), types.UInt64TypeDescriptor),
		n.bindSym(&n.tcpClose, "data_plane_tcp_close", types.SInt32TypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.udpBind, "data_plane_udp_bind", types.UInt64TypeDescriptor, types.PointerTypeDescriptor, types.UInt16TypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.udpSendTo, "data_plane_udp_send_to", types.SInt32TypeDescriptor, types.UInt64TypeDescriptor, types.PointerTypeDescriptor, types.UInt16TypeDescriptor, types.PointerTypeDescriptor, cULongType(), types.UInt64TypeDescriptor),
		n.bindSym(&n.udpRecvFrom, "data_plane_udp_recv_from", types.SInt32TypeDescriptor, types.UInt64TypeDescriptor, types.PointerTypeDescriptor, cULongType(), types.PointerTypeDescriptor, types.PointerTypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.udpClose, "data_plane_udp_close", types.SInt32TypeDescriptor, types.UInt64TypeDescriptor),
	)
}

func (n *Native) bindSym(dst *symCall, name string, ret *types.TypeDescriptor, args ...*types.TypeDescriptor) error {
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

func (s *symCall) call(ret unsafe.Pointer, args ...unsafe.Pointer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ffi.CallFunction(&s.cif, s.fn, ret, args)
}

func (n *Native) callWithBufferLen(s *symCall, ret unsafe.Pointer, handle uint64, buf unsafe.Pointer, length int, timeoutMS uint64) error {
	if runtime.GOOS == "windows" {
		l := uint32(length)
		return s.call(ret, unsafe.Pointer(&handle), unsafe.Pointer(&buf), unsafe.Pointer(&l), unsafe.Pointer(&timeoutMS))
	}
	l := uint64(length)
	return s.call(ret, unsafe.Pointer(&handle), unsafe.Pointer(&buf), unsafe.Pointer(&l), unsafe.Pointer(&timeoutMS))
}

func (n *Native) callWithBufferLenAndAddr(s *symCall, ret unsafe.Pointer, handle uint64, ip unsafe.Pointer, port uint16, buf unsafe.Pointer, length int, timeoutMS uint64) error {
	if runtime.GOOS == "windows" {
		l := uint32(length)
		return s.call(ret, unsafe.Pointer(&handle), unsafe.Pointer(&ip), unsafe.Pointer(&port), unsafe.Pointer(&buf), unsafe.Pointer(&l), unsafe.Pointer(&timeoutMS))
	}
	l := uint64(length)
	return s.call(ret, unsafe.Pointer(&handle), unsafe.Pointer(&ip), unsafe.Pointer(&port), unsafe.Pointer(&buf), unsafe.Pointer(&l), unsafe.Pointer(&timeoutMS))
}

func (n *Native) callRecvFrom(ret unsafe.Pointer, handle uint64, buf unsafe.Pointer, length int, outIP unsafe.Pointer, outPort *uint16, timeoutMS uint64) error {
	if runtime.GOOS == "windows" {
		l := uint32(length)
		return n.udpRecvFrom.call(ret, unsafe.Pointer(&handle), unsafe.Pointer(&buf), unsafe.Pointer(&l), unsafe.Pointer(&outIP), unsafe.Pointer(&outPort), unsafe.Pointer(&timeoutMS))
	}
	l := uint64(length)
	return n.udpRecvFrom.call(ret, unsafe.Pointer(&handle), unsafe.Pointer(&buf), unsafe.Pointer(&l), unsafe.Pointer(&outIP), unsafe.Pointer(&outPort), unsafe.Pointer(&timeoutMS))
}

func (n *Native) freeCString(ptr unsafe.Pointer) error {
	if ptr == nil {
		return nil
	}
	return n.freeString.call(nil, unsafe.Pointer(&ptr))
}

func (d *atomicDeadline) set(t time.Time) {
	if t.IsZero() {
		d.v.Store(0)
		return
	}
	d.v.Store(t.UnixNano())
}

func (d *atomicDeadline) timeout(fallback time.Duration) time.Duration {
	ns := d.v.Load()
	if ns == 0 {
		return fallback
	}
	remaining := time.Until(time.Unix(0, ns))
	if remaining <= 0 {
		return time.Millisecond
	}
	return remaining
}

func (e timeoutError) Error() string   { return string(e) }
func (e timeoutError) Timeout() bool   { return true }
func (e timeoutError) Temporary() bool { return true }

type easyTierAddr string

func newEasyTierAddr(network, address string) easyTierAddr {
	return easyTierAddr(network + "|" + address)
}
func (a easyTierAddr) Network() string { return strings.SplitN(string(a), "|", 2)[0] }
func (a easyTierAddr) String() string  { parts := strings.SplitN(string(a), "|", 2); return parts[1] }

func opError(op string, addr net.Addr, err error) error {
	return &net.OpError{Op: op, Net: "easytier", Addr: addr, Err: err}
}

func parseIPPort(address string) (net.IP, int, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, 0, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("easytier ffi requires an IP address, got %q", host)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, 0, err
	}
	return ip, int(port), nil
}

func cString(s string) []byte {
	if strings.ContainsRune(s, 0) {
		panic("easytier ffi string contains NUL")
	}
	return append([]byte(s), 0)
}

func readCString(ptr unsafe.Pointer) string {
	if ptr == nil {
		return ""
	}
	var b []byte
	for p := uintptr(ptr); ; p++ {
		c := *(*byte)(unsafe.Pointer(p))
		if c == 0 {
			return string(b)
		}
		b = append(b, c)
	}
}

func cULongType() *types.TypeDescriptor {
	if runtime.GOOS == "windows" {
		return types.UInt32TypeDescriptor
	}
	return types.UInt64TypeDescriptor
}

func defaultLibraryPath() string {
	if p := os.Getenv("EASYTIER_FFI_LIB"); p != "" {
		return p
	}
	switch runtime.GOOS {
	case "darwin":
		return "../../../../target/debug/libeasytier_ffi.dylib"
	case "windows":
		return "..\\..\\..\\..\\target\\debug\\easytier_ffi.dll"
	default:
		return "../../../../target/debug/libeasytier_ffi.so"
	}
}

var _ net.Conn = (*Conn)(nil)
var _ net.PacketConn = (*PacketConn)(nil)
