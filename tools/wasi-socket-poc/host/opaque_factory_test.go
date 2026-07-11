package host

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

const (
	socketAddressLen      = 27
	tcpSocketResultLen    = 62
	boundSocketResultLen  = 35
	factoryTCPProgress    = 1 << 5
	factoryUDPProgress    = 1 << 6
	maxFactoryOptionsSize = 4096
)

type opaqueCreateOperation struct {
	done       bool
	cancel     context.CancelFunc
	connection net.Conn
	packet     net.PacketConn
	localAddr  net.Addr
	peerAddr   net.Addr
	err        error
}

type decodedTCPConnectOptions struct {
	remoteAddr *net.TCPAddr
	localAddr  *net.TCPAddr
}

type decodedUDPBindOptions struct {
	localAddr *net.UDPAddr
}

func (b *opaqueBridge) startTCPConnect(
	_ context.Context,
	module api.Module,
	operation uint64,
	optionsPointer uint32,
	optionsLength uint32,
) int32 {
	options, ok := readOwnedOptions(module, optionsPointer, optionsLength)
	if !ok {
		return opaqueHostMemory
	}
	decoded, err := decodeTCPConnectOptions(options)
	if err != nil {
		return opaqueHostInvalid
	}

	dialContext, cancel := context.WithCancel(context.Background())
	create := &opaqueCreateOperation{cancel: cancel}
	b.mu.Lock()
	if _, duplicate := b.creates[operation]; duplicate {
		b.mu.Unlock()
		cancel()
		return opaqueHostInvalid
	}
	b.creates[operation] = create
	b.workers.Add(1)
	b.mu.Unlock()

	go func() {
		defer b.workers.Done()
		dialer := net.Dialer{LocalAddr: decoded.localAddr}
		connection, err := dialer.DialContext(dialContext, "tcp", decoded.remoteAddr.String())

		b.mu.Lock()
		if b.creates[operation] != create {
			b.mu.Unlock()
			if connection != nil {
				_ = connection.Close()
			}
			return
		}
		create.connection = connection
		create.err = err
		create.done = true
		if connection != nil {
			create.localAddr = connection.LocalAddr()
			create.peerAddr = connection.RemoteAddr()
		}
		b.mu.Unlock()
		b.signalCompletion()
	}()
	return 0
}

func (b *opaqueBridge) takeTCPConnect(
	_ context.Context,
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultLength uint32,
) int32 {
	if resultLength != tcpSocketResultLen {
		return opaqueHostMemory
	}
	if _, ok := module.Memory().Read(resultPointer, resultLength); !ok {
		return opaqueHostMemory
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	create, exists := b.creates[operation]
	if !exists {
		return opaqueHostInvalid
	}
	if !create.done {
		return opaqueHostPending
	}
	delete(b.creates, operation)
	if create.cancel != nil {
		create.cancel()
	}
	if create.err != nil || create.connection == nil {
		return opaqueHostIOError
	}
	handle := b.allocateHandleLocked()
	encoded, err := encodeTCPSocketResult(handle, create.localAddr, create.peerAddr)
	if err != nil || !module.Memory().Write(resultPointer, encoded[:]) {
		_ = create.connection.Close()
		return opaqueHostMemory
	}
	b.handles[handle] = create.connection
	return 0
}

func (b *opaqueBridge) startUDPBind(
	_ context.Context,
	module api.Module,
	operation uint64,
	optionsPointer uint32,
	optionsLength uint32,
) int32 {
	options, ok := readOwnedOptions(module, optionsPointer, optionsLength)
	if !ok {
		return opaqueHostMemory
	}
	decoded, err := decodeUDPBindOptions(options)
	if err != nil {
		return opaqueHostInvalid
	}
	create := &opaqueCreateOperation{}
	b.mu.Lock()
	if _, duplicate := b.creates[operation]; duplicate {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	b.creates[operation] = create
	b.workers.Add(1)
	b.mu.Unlock()

	go func() {
		defer b.workers.Done()
		localAddr := decoded.localAddr
		network := "udp4"
		if localAddr != nil && localAddr.IP.To4() == nil {
			network = "udp6"
		}
		packet, err := net.ListenUDP(network, localAddr)

		b.mu.Lock()
		if b.creates[operation] != create {
			b.mu.Unlock()
			if packet != nil {
				_ = packet.Close()
			}
			return
		}
		create.packet = packet
		create.err = err
		create.done = true
		if packet != nil {
			create.localAddr = packet.LocalAddr()
		}
		b.mu.Unlock()
		b.signalCompletion()
	}()
	return 0
}

func (b *opaqueBridge) takeUDPBind(
	_ context.Context,
	module api.Module,
	operation uint64,
	resultPointer uint32,
	resultLength uint32,
) int32 {
	if resultLength != boundSocketResultLen {
		return opaqueHostMemory
	}
	if _, ok := module.Memory().Read(resultPointer, resultLength); !ok {
		return opaqueHostMemory
	}

	b.mu.Lock()
	create, exists := b.creates[operation]
	if !exists {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	if !create.done {
		b.mu.Unlock()
		return opaqueHostPending
	}
	delete(b.creates, operation)
	if create.err != nil || create.packet == nil {
		b.mu.Unlock()
		return opaqueHostIOError
	}
	handle := b.allocateHandleLocked()
	encoded, err := encodeBoundSocketResult(handle, create.localAddr)
	if err != nil || !module.Memory().Write(resultPointer, encoded[:]) {
		b.mu.Unlock()
		_ = create.packet.Close()
		return opaqueHostMemory
	}
	state := newOpaquePacketState(create.packet)
	b.packets[handle] = state
	b.workers.Add(1)
	b.mu.Unlock()
	go b.runUDPSends(handle, state)
	return 0
}

func (b *opaqueBridge) allocateHandleLocked() uint64 {
	b.nextHandle++
	return b.nextHandle
}

func readOwnedOptions(module api.Module, pointer, length uint32) ([]byte, bool) {
	if length > maxFactoryOptionsSize {
		return nil, false
	}
	options, ok := module.Memory().Read(pointer, length)
	if !ok {
		return nil, false
	}
	return append([]byte(nil), options...), true
}

func decodeTCPConnectOptions(encoded []byte) (decodedTCPConnectOptions, error) {
	if len(encoded) < 69 || encoded[0] != 1 {
		return decodedTCPConnectOptions{}, fmt.Errorf("invalid TCP connect options")
	}
	remote, err := decodeSocketAddress(encoded[1:28], false)
	if err != nil || remote == nil {
		return decodedTCPConnectOptions{}, fmt.Errorf("invalid TCP remote address")
	}
	local, err := decodeSocketAddress(encoded[28:55], true)
	if err != nil {
		return decodedTCPConnectOptions{}, err
	}
	if err := validatePoCBindOptions(encoded[55], encoded[56:60], encoded[60], encoded[61], encoded[62]); err != nil {
		return decodedTCPConnectOptions{}, err
	}
	if encoded[63] > 3 {
		return decodedTCPConnectOptions{}, fmt.Errorf("invalid TCP purpose")
	}
	device, err := decodeBindDevice(encoded[64:])
	if err != nil {
		return decodedTCPConnectOptions{}, err
	}
	if device != nil {
		return decodedTCPConnectOptions{}, fmt.Errorf("bind device policy is outside this PoC")
	}
	return decodedTCPConnectOptions{
		remoteAddr: &net.TCPAddr{IP: remote.IP, Port: remote.Port, Zone: remote.Zone},
		localAddr:  udpToTCPAddr(local),
	}, nil
}

func decodeUDPBindOptions(encoded []byte) (decodedUDPBindOptions, error) {
	if len(encoded) < 42 || encoded[0] != 1 {
		return decodedUDPBindOptions{}, fmt.Errorf("invalid UDP bind options")
	}
	local, err := decodeSocketAddress(encoded[1:28], true)
	if err != nil {
		return decodedUDPBindOptions{}, err
	}
	if err := validatePoCBindOptions(encoded[28], encoded[29:33], encoded[33], encoded[34], encoded[35]); err != nil {
		return decodedUDPBindOptions{}, err
	}
	if encoded[36] > 3 {
		return decodedUDPBindOptions{}, fmt.Errorf("invalid UDP purpose")
	}
	device, err := decodeBindDevice(encoded[37:])
	if err != nil {
		return decodedUDPBindOptions{}, err
	}
	if device != nil {
		return decodedUDPBindOptions{}, fmt.Errorf("bind device policy is outside this PoC")
	}
	return decodedUDPBindOptions{localAddr: local}, nil
}

func validatePoCBindOptions(markPresent byte, mark []byte, reuseMode, reusePort, onlyV6 byte) error {
	if markPresent > 1 || len(mark) != 4 || (markPresent == 0 && binary.BigEndian.Uint32(mark) != 0) {
		return fmt.Errorf("invalid socket mark encoding")
	}
	if markPresent != 0 || reuseMode != 0 || reusePort != 0 || onlyV6 != 0 {
		return fmt.Errorf("non-default bind policy is outside this PoC")
	}
	return nil
}

func decodeBindDevice(encoded []byte) (*string, error) {
	if len(encoded) < 5 || encoded[0] > 1 {
		return nil, fmt.Errorf("invalid bind device encoding")
	}
	length := int(binary.BigEndian.Uint32(encoded[1:5]))
	if len(encoded) != 5+length || (encoded[0] == 0 && length != 0) {
		return nil, fmt.Errorf("invalid bind device length")
	}
	if encoded[0] == 0 {
		return nil, nil
	}
	device := string(encoded[5:])
	return &device, nil
}

func decodeSocketAddress(encoded []byte, optional bool) (*net.UDPAddr, error) {
	if len(encoded) != socketAddressLen {
		return nil, fmt.Errorf("invalid socket address length")
	}
	if optional && encoded[0] == 0 {
		for _, value := range encoded[1:] {
			if value != 0 {
				return nil, fmt.Errorf("noncanonical absent socket address")
			}
		}
		return nil, nil
	}
	metadata := make([]byte, udpMetadataLen)
	copy(metadata, encoded)
	address, _, _, err := decodeUDPMetadata(metadata)
	return address, err
}

func udpToTCPAddr(address *net.UDPAddr) *net.TCPAddr {
	if address == nil {
		return nil
	}
	return &net.TCPAddr{IP: address.IP, Port: address.Port, Zone: address.Zone}
}

func encodeTCPSocketResult(handle uint64, localAddr, peerAddr net.Addr) ([tcpSocketResultLen]byte, error) {
	var encoded [tcpSocketResultLen]byte
	binary.BigEndian.PutUint64(encoded[:8], handle)
	local, err := encodeNetAddr(localAddr)
	if err != nil {
		return encoded, err
	}
	peer, err := encodeNetAddr(peerAddr)
	if err != nil {
		return encoded, err
	}
	copy(encoded[8:35], local[:])
	copy(encoded[35:], peer[:])
	return encoded, nil
}

func encodeBoundSocketResult(handle uint64, localAddr net.Addr) ([boundSocketResultLen]byte, error) {
	var encoded [boundSocketResultLen]byte
	binary.BigEndian.PutUint64(encoded[:8], handle)
	local, err := encodeNetAddr(localAddr)
	if err != nil {
		return encoded, err
	}
	copy(encoded[8:], local[:])
	return encoded, nil
}

func encodeNetAddr(address net.Addr) ([socketAddressLen]byte, error) {
	var encoded [socketAddressLen]byte
	var udpAddr *net.UDPAddr
	switch address := address.(type) {
	case *net.TCPAddr:
		udpAddr = &net.UDPAddr{IP: address.IP, Port: address.Port, Zone: address.Zone}
	case *net.UDPAddr:
		udpAddr = address
	default:
		return encoded, fmt.Errorf("unsupported socket address %T", address)
	}
	metadata, err := encodeUDPMetadata(udpAddr, nil)
	if err != nil {
		return encoded, err
	}
	copy(encoded[:], metadata[:socketAddressLen])
	return encoded, nil
}

func (b *opaqueBridge) unsupportedTCPBind(
	context.Context,
	api.Module,
	uint64,
	uint32,
	uint32,
) int32 {
	return opaqueHostInvalid
}

func (b *opaqueBridge) unsupportedTakeBound(
	context.Context,
	api.Module,
	uint64,
	uint32,
	uint32,
) int32 {
	return opaqueHostInvalid
}

func (b *opaqueBridge) unsupportedTCPAccept(context.Context, api.Module, uint64, uint64) int32 {
	return opaqueHostInvalid
}

func (b *opaqueBridge) unsupportedTakeSocket(
	context.Context,
	api.Module,
	uint64,
	uint32,
	uint32,
) int32 {
	return opaqueHostInvalid
}

func TestOpaqueFactoryCreatesSocketsForCore(t *testing.T) {
	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen TCP echo: %v", err)
	}
	defer tcpListener.Close()
	udpEcho, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen UDP echo: %v", err)
	}
	defer udpEcho.Close()

	tcpDone := make(chan error, 1)
	go func() {
		connection, err := tcpListener.Accept()
		if err != nil {
			tcpDone <- err
			return
		}
		defer connection.Close()
		buffer := make([]byte, 11)
		if _, err := io.ReadFull(connection, buffer); err == nil {
			_, err = connection.Write(buffer)
		}
		tcpDone <- err
	}()
	udpDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 64)
		n, peer, err := udpEcho.ReadFrom(buffer)
		if err == nil {
			_, err = udpEcho.WriteTo(buffer[:n], peer)
		}
		udpDone <- err
	}()

	bridge := newOpaqueBridge(nil, nil)
	defer bridge.close()
	wasm := buildGuest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runtime := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
	defer runtime.Close(ctx)
	instantiateOpaqueHost(t, ctx, runtime, bridge)
	wasi_snapshot_preview1.MustInstantiate(ctx, runtime)
	compiled, err := runtime.CompileModule(ctx, wasm)
	if err != nil {
		t.Fatalf("compile guest: %v", err)
	}
	module, err := runtime.InstantiateModule(
		ctx,
		compiled,
		wazero.NewModuleConfig().WithStartFunctions("_initialize").WithSysWalltime().WithSysNanotime().WithSysNanosleep(),
	)
	if err != nil {
		t.Fatalf("instantiate guest: %v", err)
	}

	tcpPort := tcpListener.Addr().(*net.TCPAddr).Port
	udpPort := udpEcho.LocalAddr().(*net.UDPAddr).Port
	results, err := module.ExportedFunction("init_factory_probe").Call(ctx, uint64(tcpPort), uint64(udpPort))
	if err != nil || len(results) != 1 || int32(results[0]) != 0 {
		t.Fatalf("initialize factory probe: results=%v err=%v", results, err)
	}
	wantStatus := uint32(opaqueDone | factoryTCPProgress | factoryUDPProgress)
	status := uint32(0)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for status&opaqueDone == 0 {
		select {
		case <-bridge.completion:
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("wait for factory probe: %v", ctx.Err())
		}
		results, err := module.ExportedFunction("drive_factory_probe").Call(ctx)
		if err != nil || len(results) != 1 {
			t.Fatalf("drive factory probe: results=%v err=%v", results, err)
		}
		status = uint32(results[0])
		if status&opaqueError != 0 {
			t.Fatalf("factory probe failed with status 0x%x", status)
		}
	}
	if status != wantStatus {
		t.Fatalf("factory status 0x%x, want 0x%x", status, wantStatus)
	}
	for name, done := range map[string]<-chan error{"TCP": tcpDone, "UDP": udpDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s echo: %v", name, err)
			}
		case <-ctx.Done():
			t.Fatalf("wait for %s echo: %v", name, ctx.Err())
		}
	}
}
