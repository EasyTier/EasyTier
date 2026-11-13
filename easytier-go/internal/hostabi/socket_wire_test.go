package hostabi

import (
	"encoding/binary"
	"net"
	"testing"
)

// encodeSocketAddress encodes a 27-byte socket address in the wire format
// used by the wasm core (first 27 bytes of UDP metadata).
func encodeSocketAddress(addr *net.UDPAddr) []byte {
	if addr == nil {
		return make([]byte, socketAddressLen)
	}
	var buf [48]byte
	if ipv4 := addr.IP.To4(); ipv4 != nil {
		buf[0] = 4
		copy(buf[1:5], ipv4)
	} else if ipv6 := addr.IP.To16(); ipv6 != nil {
		buf[0] = 6
		copy(buf[1:17], ipv6)
	} else {
		panic("invalid IP")
	}
	binary.BigEndian.PutUint16(buf[17:19], uint16(addr.Port))
	return buf[:socketAddressLen]
}

// encodeSocketContext encodes the socket context portion of the wire format.
func encodeSocketContext(
	ipVersion byte,
	mark *uint32,
	netns *string,
) []byte {
	buf := make([]byte, 0, 64)
	buf = append(buf, ipVersion)
	if mark != nil {
		buf = append(buf, 1)
		var m [4]byte
		binary.BigEndian.PutUint32(m[:], *mark)
		buf = append(buf, m[:]...)
	} else {
		buf = append(buf, 0, 0, 0, 0, 0)
	}
	if netns != nil {
		buf = append(buf, 1)
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(*netns)))
		buf = append(buf, l[:]...)
		buf = append(buf, []byte(*netns)...)
	} else {
		buf = append(buf, 0, 0, 0, 0, 0)
	}
	return buf
}

// encodeBindDeviceField encodes the bind_device field (present byte +
// u32 length + bytes).
func encodeBindDeviceField(device *string) []byte {
	if device == nil {
		return []byte{0, 0, 0, 0, 0}
	}
	buf := make([]byte, 0, 5+len(*device))
	buf = append(buf, 1)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(*device)))
	buf = append(buf, l[:]...)
	buf = append(buf, []byte(*device)...)
	return buf
}

func TestDecodeTCPConnectOptionsV3(t *testing.T) {
	tests := []struct {
		name     string
		mark     *uint32
		netns    *string
		device   *string
		local    *net.UDPAddr
		wantMark *uint32
	}{
		{
			name:  "minimal no netns no device",
			mark:  nil,
			netns: nil,
			device: nil,
			local: nil,
		},
		{
			name:  "with netns",
			mark:  nil,
			netns: strPtr("test-ns"),
			device: nil,
			local: nil,
		},
		{
			name:  "with bind device",
			mark:  nil,
			netns: nil,
			device: strPtr("eth0"),
			local: nil,
		},
		{
			name:  "with netns and device",
			mark:  nil,
			netns: strPtr("netns1"),
			device: strPtr("wg0"),
			local: nil,
		},
		{
			name:  "with socket mark",
			mark:  uint32Ptr(42),
			netns: nil,
			device: nil,
			local: nil,
		},
		{
			name:  "with local address",
			mark:  nil,
			netns: nil,
			device: nil,
			local: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			remote := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 11010}
			encoded := make([]byte, 0, 128)
			encoded = append(encoded, optionsWireVersion) // wire v3
			encoded = append(encoded, encodeSocketAddress(remote)...)
			encoded = append(encoded, encodeSocketAddress(tt.local)...)
			encoded = append(encoded, encodeSocketContext(0, tt.mark, tt.netns)...)
			// bind policy: reuse_addr, reuse_port, only_v6
			encoded = append(encoded, 0, 0, 0)
			// purpose: TcpDial (0)
			encoded = append(encoded, 0)
			// need_protect (wire v3 addition)
			encoded = append(encoded, 0)
			// bind device
			encoded = append(encoded, encodeBindDeviceField(tt.device)...)

			opts, err := decodeTCPConnectOptions(encoded)
			if err != nil {
				t.Fatalf("decodeTCPConnectOptions failed: %v", err)
			}
			if opts.RemoteAddr == nil {
				t.Fatal("remote address is nil")
			}
			if !opts.RemoteAddr.IP.Equal(remote.IP) || opts.RemoteAddr.Port != remote.Port {
				t.Errorf("remote addr = %v, want %v", opts.RemoteAddr, remote)
			}
			if tt.mark != nil {
				if opts.Bind.Context.SocketMark == nil || *opts.Bind.Context.SocketMark != *tt.mark {
					t.Errorf("socket mark = %v, want %v", opts.Bind.Context.SocketMark, tt.mark)
				}
			}
			if tt.netns != nil {
				if opts.Bind.Context.NetNS == nil || *opts.Bind.Context.NetNS != *tt.netns {
					t.Errorf("netns = %v, want %v", opts.Bind.Context.NetNS, tt.netns)
				}
			}
			if tt.device != nil {
				if opts.Bind.BindDevice == nil || *opts.Bind.BindDevice != *tt.device {
					t.Errorf("bind device = %v, want %v", opts.Bind.BindDevice, tt.device)
				}
			}
			if tt.local != nil {
				if opts.Bind.LocalAddr == nil || opts.Bind.LocalAddr.Port != tt.local.Port {
					t.Errorf("local addr = %v, want port %d", opts.Bind.LocalAddr, tt.local.Port)
				}
			}
		})
	}
}

func TestDecodeUDPBindOptionsV3(t *testing.T) {
	device := strPtr("eth1")
	netns := strPtr("udp-ns")
	mark := uint32Ptr(100)

	bindAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 11011}
	encoded := make([]byte, 0, 128)
	encoded = append(encoded, optionsWireVersion)
	encoded = append(encoded, encodeSocketAddress(bindAddr)...)
	encoded = append(encoded, encodeSocketContext(0, mark, netns)...)
	// remainder: reuse_addr, reuse_port, only_v6, purpose, need_protect, bind_device
	encoded = append(encoded, 0, 0, 0) // reuse_addr, reuse_port, only_v6
	encoded = append(encoded, 1)       // purpose: Standalone
	encoded = append(encoded, 0)       // need_protect (wire v3)
	encoded = append(encoded, encodeBindDeviceField(device)...)

	opts, err := decodeUDPBindOptions(encoded)
	if err != nil {
		t.Fatalf("decodeUDPBindOptions failed: %v", err)
	}
	if opts.LocalAddr == nil || opts.LocalAddr.Port != 11011 {
		t.Errorf("local addr = %v, want port 11011", opts.LocalAddr)
	}
	if opts.Context.SocketMark == nil || *opts.Context.SocketMark != 100 {
		t.Errorf("socket mark = %v, want 100", opts.Context.SocketMark)
	}
	if opts.Context.NetNS == nil || *opts.Context.NetNS != "udp-ns" {
		t.Errorf("netns = %v, want udp-ns", opts.Context.NetNS)
	}
	if opts.BindDevice == nil || *opts.BindDevice != "eth1" {
		t.Errorf("bind device = %v, want eth1", opts.BindDevice)
	}
	if opts.Purpose != 1 {
		t.Errorf("purpose = %d, want 1 (Standalone)", opts.Purpose)
	}
}

func TestDecodeTCPListenOptionsV3(t *testing.T) {
	device := strPtr("wg0")
	netns := strPtr("listen-ns")

	bindAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 22020}
	encoded := make([]byte, 0, 128)
	encoded = append(encoded, optionsWireVersion)
	encoded = append(encoded, encodeSocketAddress(bindAddr)...)
	encoded = append(encoded, encodeSocketContext(2, nil, netns)...) // IPVersionBoth
	// bind policy: reuse_addr=0, reuse_port=0, only_v6=0
	encoded = append(encoded, 0, 0, 0)
	// purpose: Kcp (1)
	encoded = append(encoded, 1)
	// need_protect (wire v3)
	encoded = append(encoded, 0)
	encoded = append(encoded, encodeBindDeviceField(device)...)

	opts, err := decodeTCPListenOptions(encoded)
	if err != nil {
		t.Fatalf("decodeTCPListenOptions failed: %v", err)
	}
	if opts.Bind.LocalAddr == nil || opts.Bind.LocalAddr.Port != 22020 {
		t.Errorf("bind addr = %v, want port 22020", opts.Bind.LocalAddr)
	}
	if opts.Bind.Context.NetNS == nil || *opts.Bind.Context.NetNS != "listen-ns" {
		t.Errorf("netns = %v, want listen-ns", opts.Bind.Context.NetNS)
	}
	if opts.Bind.BindDevice == nil || *opts.Bind.BindDevice != "wg0" {
		t.Errorf("bind device = %v, want wg0", opts.Bind.BindDevice)
	}
	if opts.Purpose != 1 {
		t.Errorf("purpose = %d, want 1 (Kcp)", opts.Purpose)
	}
}

func TestDecodeTCPConnectOptionsV2Rejected(t *testing.T) {
	remote := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 11010}
	encoded := make([]byte, 0, 128)
	encoded = append(encoded, 2) // wire v2 — must be rejected
	encoded = append(encoded, encodeSocketAddress(remote)...)
	encoded = append(encoded, encodeSocketAddress(nil)...)
	encoded = append(encoded, encodeSocketContext(0, nil, nil)...)
	encoded = append(encoded, 0, 0, 0, 0) // no need_protect in v2
	encoded = append(encoded, encodeBindDeviceField(nil)...)

	_, err := decodeTCPConnectOptions(encoded)
	if err == nil {
		t.Fatal("wire v2 should be rejected")
	}
}

func strPtr(s string) *string    { return &s }
func uint32Ptr(v uint32) *uint32 { return &v }
