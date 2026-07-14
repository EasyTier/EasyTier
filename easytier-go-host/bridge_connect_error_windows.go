//go:build windows

package host

import (
	"errors"
	"syscall"
)

const (
	wsaNotConnected      = syscall.Errno(10057)
	wsaConnectionAborted = syscall.Errno(10053)
	wsaConnectionReset   = syscall.Errno(10054)
	wsaConnectionRefused = syscall.Errno(10061)
)

func isConnectionRefused(err error) bool {
	return errors.Is(err, wsaConnectionRefused)
}

func isConnectionAborted(err error) bool {
	return errors.Is(err, wsaConnectionAborted)
}

func isConnectionReset(err error) bool {
	return errors.Is(err, wsaConnectionReset)
}

func isNotConnected(err error) bool {
	return errors.Is(err, wsaNotConnected)
}
