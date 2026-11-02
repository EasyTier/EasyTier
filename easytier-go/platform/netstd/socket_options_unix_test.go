//go:build aix || android || darwin || dragonfly || freebsd || linux || netbsd || openbsd

package netstd

import (
	"context"
	"net"
	"testing"

	"github.com/easytier/easytier/easytier-go/platform"
	"golang.org/x/sys/unix"
)

func TestUDPReuseAddrHonorsExplicitFalseAndTrue(t *testing.T) {
	for _, reuse := range []*bool{nil, boolPtr(false), boolPtr(true)} {
		socket, err := (SocketFactory{}).BindUDP(context.Background(), platform.BindConfig{
			LocalAddr: sourceAddr(0), ReuseAddr: reuse, BindDevice: strPtr(""),
		})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := socket.(*net.UDPConn).SyscallConn()
		if err != nil {
			socket.Close()
			t.Fatal(err)
		}
		actual := 0
		var optionErr error
		if err := raw.Control(func(fd uintptr) { actual, optionErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR) }); err != nil {
			socket.Close()
			t.Fatal(err)
		}
		socket.Close()
		if optionErr != nil {
			t.Fatal(optionErr)
		}
		expected := 0
		if reuse != nil && *reuse {
			expected = 1
		}
		if actual != expected {
			t.Fatalf("SO_REUSEADDR = %d, want %d", actual, expected)
		}
	}
}

func TestUDPDefaultReuseAddrRejectsDuplicateBind(t *testing.T) {
	factory := SocketFactory{}
	first, err := factory.BindUDP(context.Background(), platform.BindConfig{
		LocalAddr: sourceAddr(0), BindDevice: strPtr(""),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	port := first.LocalAddr().(*net.UDPAddr).Port
	second, err := factory.BindUDP(context.Background(), platform.BindConfig{
		LocalAddr: sourceAddr(port), BindDevice: strPtr(""),
	})
	if err == nil {
		second.Close()
		t.Fatal("default UDP bind must reject a duplicate endpoint")
	}
}

func boolPtr(value bool) *bool    { return &value }
func strPtr(value string) *string { return &value }

func TestSocketFactoryUsesNativeTCPReuseAddrDefault(t *testing.T) {
	firstServer := listenTCP4(t)
	defer firstServer.Close()
	secondServer := listenTCP4(t)
	defer secondServer.Close()
	sourcePort := unusedTCP4Port(t)

	reuse := true
	first := connectTCP(t, firstServer, platform.BindConfig{
		Context:   platform.SocketContext{IPVersion: platform.IPVersionV4},
		LocalAddr: sourceAddr(sourcePort),
		ReuseAddr: &reuse,
	}, platform.TCPConnectSTUNProbe)
	defer first.Close()

	second := connectTCP(t, secondServer, platform.BindConfig{
		Context:   platform.SocketContext{IPVersion: platform.IPVersionV4},
		LocalAddr: sourceAddr(sourcePort),
		OnlyV6:    true,
	}, platform.TCPConnectHolePunch)
	defer second.Close()
}
