//go:build windows

package netstd

import (
	"fmt"

	"github.com/EasyTier/EasyTier/easytier-go/platform"
	"golang.org/x/sys/windows"
)

func applyTCPSocketOptions(
	descriptor uintptr,
	network string,
	options platform.TCPBindOptions,
) error {
	reuseAddr := options.ReuseAddr
	if options.ReusePort {
		if reuseAddr != nil && !*reuseAddr {
			return fmt.Errorf("TCP reuse_port requires reuse_addr on Windows")
		}
		enabled := true
		reuseAddr = &enabled
	}
	if reuseAddr != nil {
		if err := windows.SetsockoptInt(windows.Handle(descriptor),
			windows.SOL_SOCKET, windows.SO_REUSEADDR, boolInt(*reuseAddr)); err != nil {
			return fmt.Errorf("set TCP SO_REUSEADDR: %w", err)
		}
	}
	if options.OnlyV6 && network == "tcp6" {
		if err := windows.SetsockoptInt(windows.Handle(descriptor),
			windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, 1); err != nil {
			return fmt.Errorf("set TCP IPV6_V6ONLY: %w", err)
		}
	}
	return nil
}
