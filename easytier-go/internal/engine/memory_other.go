//go:build !aix && !android && !darwin && !dragonfly && !freebsd && !illumos && !ios && !linux && !netbsd && !openbsd && !solaris && !windows

package engine

import "github.com/metacubex/wazero/experimental"

func reserveGuestMemory(uint64) experimental.LinearMemory {
	return nil
}
