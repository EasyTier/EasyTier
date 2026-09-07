//go:build aix || android || darwin || dragonfly || freebsd || linux || netbsd || openbsd

package netstd

import (
	"fmt"

	"github.com/EasyTier/EasyTier/easytier-go/platform"
	"golang.org/x/sys/unix"
)

func applyTCPSocketOptions(
	descriptor uintptr,
	network string,
	options platform.TCPBindOptions,
) error {
	fd := int(descriptor)
	reuseAddr := true
	if options.ReuseAddr != nil {
		reuseAddr = *options.ReuseAddr
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, boolInt(reuseAddr)); err != nil {
		return fmt.Errorf("set TCP SO_REUSEADDR: %w", err)
	}
	if options.ReusePort {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			return fmt.Errorf("set TCP SO_REUSEPORT: %w", err)
		}
	}
	if options.OnlyV6 && network == "tcp6" {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
			return fmt.Errorf("set TCP IPV6_V6ONLY: %w", err)
		}
	}
	return nil
}
