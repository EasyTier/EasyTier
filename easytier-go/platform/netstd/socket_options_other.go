//go:build !aix && !android && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !windows

package netstd

import (
	"fmt"
	"runtime"

	"github.com/EasyTier/EasyTier/easytier-go/platform"
)

func applyTCPSocketOptions(
	_ uintptr,
	_ string,
	options platform.TCPBindOptions,
) error {
	if options.ReuseAddr == nil && !options.ReusePort && !options.OnlyV6 {
		return nil
	}
	return fmt.Errorf("TCP socket options are not supported on %s", runtime.GOOS)
}
