//go:build windows

package host

import (
	"net"
	"os"
	"testing"
)

func windowsConnectError(errno error) error {
	return &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: &os.SyscallError{Syscall: "connectex", Err: errno},
	}
}

func refusedTestError() error {
	return windowsConnectError(wsaConnectionRefused)
}

func TestTCPConnectErrorStatus(t *testing.T) {
	for errno, want := range map[error]int32{
		wsaConnectionRefused: opaqueHostConnectionRefused,
		wsaConnectionAborted: opaqueHostConnectionAborted,
		wsaConnectionReset:   opaqueHostConnectionReset,
		wsaNotConnected:      opaqueHostNotConnected,
	} {
		if got := tcpConnectErrorStatus(windowsConnectError(errno)); got != want {
			t.Fatalf("connect error %v status %d, want %d", errno, got, want)
		}
	}
}
