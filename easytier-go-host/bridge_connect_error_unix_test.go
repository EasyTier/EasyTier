//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package host

import (
	"fmt"
	"syscall"
	"testing"
)

func refusedTestError() error {
	return fmt.Errorf("wrapped connect: %w", syscall.ECONNREFUSED)
}

func TestTCPConnectErrorStatus(t *testing.T) {
	for err, want := range map[error]int32{
		syscall.ECONNREFUSED: opaqueHostConnectionRefused,
		syscall.ECONNABORTED: opaqueHostConnectionAborted,
		syscall.ECONNRESET:   opaqueHostConnectionReset,
		syscall.ENOTCONN:     opaqueHostNotConnected,
	} {
		if got := tcpConnectErrorStatus(fmt.Errorf("wrapped: %w", err)); got != want {
			t.Fatalf("connect error %v status %d, want %d", err, got, want)
		}
	}
}
