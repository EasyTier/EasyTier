package hostabi

import (
	"errors"

	"github.com/EasyTier/EasyTier/easytier-go/internal/reactor"
)

const (
	statusPending           int32 = -1
	statusInvalid           int32 = -2
	statusIOError           int32 = -3
	statusMemory            int32 = -4
	statusWouldBlock        int32 = -5
	statusConnectionRefused int32 = -6
	statusConnectionAborted int32 = -7
	statusConnectionReset   int32 = -8
	statusNotConnected      int32 = -9
)

func operationStatus(err error) int32 {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, reactor.ErrPending):
		return statusPending
	case errors.Is(err, reactor.ErrInvalid):
		return statusInvalid
	case errors.Is(err, reactor.ErrWouldBlock):
		return statusWouldBlock
	default:
		return statusIOError
	}
}

func connectStatus(err error) int32 {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, reactor.ErrPending):
		return statusPending
	case errors.Is(err, reactor.ErrInvalid):
		return statusInvalid
	case isConnectionRefused(err):
		return statusConnectionRefused
	case isConnectionAborted(err):
		return statusConnectionAborted
	case isConnectionReset(err):
		return statusConnectionReset
	case isNotConnected(err):
		return statusNotConnected
	default:
		return statusIOError
	}
}
