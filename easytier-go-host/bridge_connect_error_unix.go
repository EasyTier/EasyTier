//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package host

import (
	"errors"
	"syscall"
)

func isConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

func isConnectionAborted(err error) bool {
	return errors.Is(err, syscall.ECONNABORTED)
}

func isConnectionReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET)
}

func isNotConnected(err error) bool {
	return errors.Is(err, syscall.ENOTCONN)
}
