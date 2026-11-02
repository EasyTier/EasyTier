//go:build aix || android || darwin || dragonfly || freebsd || linux || netbsd || openbsd

package netstd

import (
	"fmt"
	"strings"

	"github.com/easytier/easytier/easytier-go/platform"
	"golang.org/x/sys/unix"
)

func applySocketOptions(
	descriptor uintptr,
	network string,
	options platform.BindConfig,
) error {
	fd := int(descriptor)
	// TCP keeps the local-address default. UDP must not default to
	// SO_REUSEADDR: on Unix that lets another socket bind the same endpoint
	// and divert incoming datagrams.
	reuseAddr := strings.HasPrefix(network, "tcp") && options.LocalAddr != nil
	if options.ReuseAddr != nil {
		reuseAddr = *options.ReuseAddr
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, boolInt(reuseAddr)); err != nil {
		return fmt.Errorf("set socket SO_REUSEADDR: %w", err)
	}
	if options.ReusePort {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			return fmt.Errorf("set socket SO_REUSEPORT: %w", err)
		}
	}
	if options.OnlyV6 && (network == "tcp6" || network == "udp6") {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
			return fmt.Errorf("set socket IPV6_V6ONLY: %w", err)
		}
	}
	return nil
}
