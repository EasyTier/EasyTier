package main

import (
	"io"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tun "github.com/sagernet/sing-tun"
)

func TestOptionsValidate(t *testing.T) {
	valid := options{
		peers:         peerList{"tcp://198.51.100.10:11010"},
		networkName:   "office",
		networkSecret: "secret",
		ipv4:          "10.144.0.10/24",
	}

	tests := []struct {
		name    string
		mutate  func(*options)
		wantErr string
	}{
		{
			name:    "missing peer",
			mutate:  func(value *options) { value.peers = nil },
			wantErr: "at least one -p",
		},
		{
			name:    "missing network name",
			mutate:  func(value *options) { value.networkName = "" },
			wantErr: "--network-name",
		},
		{
			name:    "missing network secret",
			mutate:  func(value *options) { value.networkSecret = "" },
			wantErr: "--network-secret",
		},
		{
			name:    "invalid IPv4 prefix",
			mutate:  func(value *options) { value.ipv4 = "10.144.0.10" },
			wantErr: "--ipv4",
		},
		{
			name:    "IPv6 prefix",
			mutate:  func(value *options) { value.ipv4 = "fd00::10/64" },
			wantErr: "IPv4",
		},
	}

	prefix, err := valid.validate()
	if err != nil {
		t.Fatalf("validate valid options: %v", err)
	}
	if prefix != netip.MustParsePrefix("10.144.0.10/24") {
		t.Fatalf("validated prefix = %s", prefix)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			value.peers = append(peerList(nil), valid.peers...)
			test.mutate(&value)
			_, err := value.validate()
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validate error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestPeerListRejectsEmptyPeer(t *testing.T) {
	var peers peerList
	if err := peers.Set(" "); err == nil {
		t.Fatal("empty peer was accepted")
	}
	if err := peers.Set("tcp://198.51.100.10:11010"); err != nil {
		t.Fatalf("set peer: %v", err)
	}
	if got := peers.String(); got != "tcp://198.51.100.10:11010" {
		t.Fatalf("peer list string = %q", got)
	}
}

type blockingTun struct {
	readStarted chan struct{}
	closed      chan struct{}
	startOnce   sync.Once
	closeOnce   sync.Once
	closeCount  atomic.Int32
}

func (device *blockingTun) Read([]byte) (int, error) {
	device.startOnce.Do(func() { close(device.readStarted) })
	<-device.closed
	return 0, io.ErrClosedPipe
}

func (*blockingTun) Write(packet []byte) (int, error) {
	return len(packet), nil
}

func (*blockingTun) Name() (string, error) {
	return "test-tun", nil
}

func (*blockingTun) Start() error {
	return nil
}

func (device *blockingTun) Close() error {
	device.closeOnce.Do(func() {
		device.closeCount.Add(1)
		close(device.closed)
	})
	return nil
}

func (*blockingTun) UpdateRouteOptions(tun.Options) error {
	return nil
}

func TestPacketDeviceCloseUnblocksRead(t *testing.T) {
	nativeTun := &blockingTun{
		readStarted: make(chan struct{}),
		closed:      make(chan struct{}),
	}
	device := newPacketDevice(nativeTun)
	readDone := make(chan error, 1)
	go func() {
		_, err := device.Read(make([]byte, 1500))
		readDone <- err
	}()
	<-nativeTun.readStarted

	if err := device.Close(); err != nil {
		t.Fatalf("close device: %v", err)
	}
	if err := device.Close(); err != nil {
		t.Fatalf("close device again: %v", err)
	}
	select {
	case err := <-readDone:
		if err != io.ErrClosedPipe {
			t.Fatalf("read error = %v, want %v", err, io.ErrClosedPipe)
		}
	case <-time.After(time.Second):
		t.Fatal("read remained blocked after close")
	}
	if count := nativeTun.closeCount.Load(); count != 1 {
		t.Fatalf("native close count = %d, want 1", count)
	}
}

type memoryTun struct {
	readPacket  []byte
	wrotePacket []byte
}

func (device *memoryTun) Read(packet []byte) (int, error) {
	return copy(packet, device.readPacket), nil
}

func (device *memoryTun) Write(packet []byte) (int, error) {
	device.wrotePacket = append(device.wrotePacket[:0], packet...)
	return len(packet), nil
}

func (*memoryTun) Name() (string, error) {
	return "memory-tun", nil
}

func (*memoryTun) Start() error {
	return nil
}

func (*memoryTun) Close() error {
	return nil
}

func (*memoryTun) UpdateRouteOptions(tun.Options) error {
	return nil
}

func TestPacketDeviceNativeFraming(t *testing.T) {
	ipPacket := []byte{
		0x45, 0, 0, 20,
		0, 0, 0, 0,
		64, 1, 0, 0,
		10, 0, 0, 1,
		10, 0, 0, 2,
	}
	nativeTun := &memoryTun{}
	device := newPacketDevice(nativeTun)
	nativePacket := make([]byte, device.packetOffset+len(ipPacket))
	if err := encodeNativeTunPacketHeader(
		nativePacket[:device.packetOffset],
		ipPacket,
	); err != nil {
		t.Fatalf("encode native test packet: %v", err)
	}
	copy(nativePacket[device.packetOffset:], ipPacket)

	nativeTun.readPacket = nativePacket
	received := make([]byte, 1500)
	length, err := device.Read(received)
	if err != nil {
		t.Fatalf("read packet: %v", err)
	}
	if string(received[:length]) != string(ipPacket) {
		t.Fatalf("read packet = %x, want %x", received[:length], ipPacket)
	}
	written, err := device.Write(ipPacket)
	if err != nil {
		t.Fatalf("write packet: %v", err)
	}
	if written != len(ipPacket) {
		t.Fatalf("write length = %d, want %d", written, len(ipPacket))
	}
	if string(nativeTun.wrotePacket) != string(nativePacket) {
		t.Fatalf(
			"native write packet = %x, want %x",
			nativeTun.wrotePacket,
			nativePacket,
		)
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
	if rules[0].Protocol != "tcp" ||
		rules[0].Bind != netip.MustParseAddrPort("127.0.0.1:5202") ||
		rules[0].Destination != netip.MustParseAddrPort("10.144.0.20:5201") {
		t.Fatalf("first port-forward rule = %+v", rules[0])
	}
}
