package host

import (
	"context"
	"fmt"

	"github.com/easytier/easytier/easytier-go/internal/coreabi"
)

type LogLevel = coreabi.LogLevel

const (
	LogLevelOff   = coreabi.LogLevelOff
	LogLevelError = coreabi.LogLevelError
	LogLevelWarn  = coreabi.LogLevelWarn
	LogLevelInfo  = coreabi.LogLevelInfo
	LogLevelDebug = coreabi.LogLevelDebug
	LogLevelTrace = coreabi.LogLevelTrace
)

// SetLogLevel changes logging for this Host, including all its instances and
// its WebClient. It can be called before any instance is created.
func (host *Host) SetLogLevel(ctx context.Context, level LogLevel) error {
	if host == nil {
		return fmt.Errorf("set log level with nil EasyTier host")
	}
	return host.engine.SetLogLevel(ctx, level)
}

// LogLevel returns this Host's current log level, which defaults to Info.
func (host *Host) LogLevel(ctx context.Context) (LogLevel, error) {
	if host == nil {
		return 0, fmt.Errorf("get log level with nil EasyTier host")
	}
	return host.engine.LogLevel(ctx)
}
