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
}

type Conn struct {
	native *Native
	handle uint64
	local  net.Addr
	remote net.Addr
	closed atomic.Bool
	rd     atomicDeadline
	wd     atomicDeadline
}

type symCall struct {
	fn  unsafe.Pointer
	cif types.CallInterface
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
		return n.lastError()
	}
	return nil
}

func (n *Native) DialContext(ctx context.Context, instance, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, net.UnknownNetworkError(network)
	}
	ip, port, err := parseIPPort(address)
	if err != nil {
		return nil, err
	}
	timeout := defaultTimeout
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	handle, local, err := n.tcpConnectTo(instance, ip.String(), uint16(port), timeout)
	if err != nil {
		return nil, err
	}
	return &Conn{native: n, handle: handle, local: local, remote: &net.TCPAddr{IP: ip, Port: port}}, nil
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := c.native.tcpReadFrom(c.handle, b, c.rd.timeout(defaultTimeout))
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
	n, err := c.native.tcpWriteTo(c.handle, b, c.wd.timeout(defaultTimeout))
	if err != nil {
		return 0, opError("write", c.remote, err)
	}
	return n, nil
}

func (c *Conn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return net.ErrClosed
	}
	return c.native.tcpCloseHandle(c.handle)
}

func (c *Conn) LocalAddr() net.Addr                { return c.local }
func (c *Conn) RemoteAddr() net.Addr               { return c.remote }
func (c *Conn) SetDeadline(t time.Time) error      { c.rd.set(t); c.wd.set(t); return nil }
func (c *Conn) SetReadDeadline(t time.Time) error  { c.rd.set(t); return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { c.wd.set(t); return nil }

func (n *Native) bind() error {
	return errors.Join(
		n.bindSym(&n.runNetworkInstance, "run_network_instance", types.SInt32TypeDescriptor, types.PointerTypeDescriptor),
		n.bindSym(&n.getErrorMsg, "get_error_msg", types.VoidTypeDescriptor, types.PointerTypeDescriptor),
		n.bindSym(&n.freeString, "free_string", types.VoidTypeDescriptor, types.PointerTypeDescriptor),
		n.bindSym(&n.tcpConnect, "data_plane_tcp_connect", types.UInt64TypeDescriptor, types.PointerTypeDescriptor, types.PointerTypeDescriptor, types.UInt16TypeDescriptor, types.UInt64TypeDescriptor, types.PointerTypeDescriptor, types.PointerTypeDescriptor),
		n.bindSym(&n.tcpRead, "data_plane_tcp_read", types.SInt32TypeDescriptor, types.UInt64TypeDescriptor, types.PointerTypeDescriptor, types.UInt32TypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.tcpWrite, "data_plane_tcp_write", types.SInt32TypeDescriptor, types.UInt64TypeDescriptor, types.PointerTypeDescriptor, types.UInt32TypeDescriptor, types.UInt64TypeDescriptor),
		n.bindSym(&n.tcpClose, "data_plane_tcp_close", types.SInt32TypeDescriptor, types.UInt64TypeDescriptor),
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
	// `ffi.CallFunction` and libffi `ffi_call` are safe to invoke concurrently
	// because `cif` is prepared once during binding and only read afterwards.
	return ffi.CallFunction(&s.cif, s.fn, ret, args)
}

func (n *Native) tcpConnectTo(instance, ip string, port uint16, timeout time.Duration) (uint64, *net.TCPAddr, error) {
	inst := cString(instance)
	dst := cString(ip)
	instPtr := unsafe.Pointer(&inst[0])
	dstPtr := unsafe.Pointer(&dst[0])
	timeoutMS := uint64(timeout / time.Millisecond)
	var handle uint64
	var outIP unsafe.Pointer
	outIPArg := unsafe.Pointer(&outIP)
	var outPort uint16
	outPortArg := unsafe.Pointer(&outPort)
	err := n.tcpConnect.call(
		unsafe.Pointer(&handle),
		unsafe.Pointer(&instPtr),
		unsafe.Pointer(&dstPtr),
		unsafe.Pointer(&port),
		unsafe.Pointer(&timeoutMS),
		unsafe.Pointer(&outIPArg),
		unsafe.Pointer(&outPortArg),
	)
	runtime.KeepAlive(inst)
	runtime.KeepAlive(dst)
	if err != nil {
		return 0, nil, err
	}
	if handle == 0 {
		return 0, nil, n.lastError()
	}
	return handle, n.takeTCPAddr(outIP, outPort), nil
}

func (n *Native) tcpReadFrom(handle uint64, buf []byte, timeout time.Duration) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	var ret int32
	bufPtr := unsafe.Pointer(&buf[0])
	length := uint32(len(buf))
	timeoutMS := uint64(timeout / time.Millisecond)
	err := n.tcpRead.call(unsafe.Pointer(&ret), unsafe.Pointer(&handle), unsafe.Pointer(&bufPtr), unsafe.Pointer(&length), unsafe.Pointer(&timeoutMS))
	runtime.KeepAlive(buf)
	if err != nil {
		return 0, err
	}
	if ret < 0 {
		return 0, n.lastError()
	}
	return int(ret), nil
}

func (n *Native) tcpWriteTo(handle uint64, buf []byte, timeout time.Duration) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	var ret int32
	bufPtr := unsafe.Pointer(&buf[0])
	length := uint32(len(buf))
	timeoutMS := uint64(timeout / time.Millisecond)
	err := n.tcpWrite.call(unsafe.Pointer(&ret), unsafe.Pointer(&handle), unsafe.Pointer(&bufPtr), unsafe.Pointer(&length), unsafe.Pointer(&timeoutMS))
	runtime.KeepAlive(buf)
	if err != nil {
		return 0, err
	}
	if ret < 0 {
		return 0, n.lastError()
	}
	return int(ret), nil
}

func (n *Native) tcpCloseHandle(handle uint64) error {
	var ret int32
	if err := n.tcpClose.call(unsafe.Pointer(&ret), unsafe.Pointer(&handle)); err != nil {
		return err
	}
	if ret != 0 {
		return n.lastError()
	}
	return nil
}

func (n *Native) lastError() error {
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

func (n *Native) freeCString(ptr unsafe.Pointer) error {
	if ptr == nil {
		return nil
	}
	return n.freeString.call(nil, unsafe.Pointer(&ptr))
}

func (n *Native) takeTCPAddr(ipPtr unsafe.Pointer, port uint16) *net.TCPAddr {
	if ipPtr == nil {
		return nil
	}
	ip := net.ParseIP(readCString(ipPtr))
	_ = n.freeCString(ipPtr)
	return &net.TCPAddr{IP: ip, Port: int(port)}
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
