//go:build aix || android || darwin || dragonfly || freebsd || linux || netbsd || openbsd

package netstd

import (
	"net"
	"testing"

	"github.com/EasyTier/EasyTier/easytier-go/platform"
)

func TestSocketFactoryUsesNativeTCPReuseAddrDefault(t *testing.T) {
	firstServer := listenTCP4(t)
	defer firstServer.Close()
	secondServer := listenTCP4(t)
	defer secondServer.Close()
	sourcePort := unusedTCP4Port(t)

	reuse := true
	first := connectTCP(t, firstServer, platform.TCPBindOptions{
		Context:   platform.SocketContext{IPVersion: platform.IPVersionV4},
		LocalAddr: &net.TCPAddr{IP: net.IPv4zero, Port: sourcePort},
		ReuseAddr: &reuse,
	}, platform.TCPConnectSTUNProbe)
	defer first.Close()

	second := connectTCP(t, secondServer, platform.TCPBindOptions{
		Context:   platform.SocketContext{IPVersion: platform.IPVersionV4},
		LocalAddr: &net.TCPAddr{IP: net.IPv4zero, Port: sourcePort},
		OnlyV6:    true,
	}, platform.TCPConnectHolePunch)
	defer second.Close()
}
