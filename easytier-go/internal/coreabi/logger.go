package coreabi

import (
	"context"
	"fmt"

	"github.com/metacubex/wazero/api"
)

// LogLevel uses the module-wide logger ABI values, matching api.logger.LogLevel.
type LogLevel uint32

const (
	LogLevelOff LogLevel = iota
	LogLevelError
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
	LogLevelTrace
)

func SetLogLevel(ctx context.Context, module api.Module, level LogLevel) error {
	status, err := callLogger(ctx, module, "easytier_logger_set_level", uint64(level))
	if err != nil {
		return err
	}
	if int32(status) != 0 {
		return fmt.Errorf("set EasyTier log level %d: status=%d", level, int32(status))
	}
	return nil
}

func GetLogLevel(ctx context.Context, module api.Module) (LogLevel, error) {
	value, err := callLogger(ctx, module, "easytier_logger_level")
	if err != nil {
		return 0, err
	}
	if value > uint64(LogLevelTrace) {
		return 0, fmt.Errorf("EasyTier guest returned invalid log level %d", value)
	}
	return LogLevel(value), nil
}

func callLogger(ctx context.Context, module api.Module, name string, args ...uint64) (uint64, error) {
	function := module.ExportedFunction(name)
	if function == nil {
		return 0, fmt.Errorf("EasyTier guest does not export %s", name)
	}
	results, err := function.Call(ctx, args...)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if len(results) != 1 {
		return 0, fmt.Errorf("%s returned %d values, want 1", name, len(results))
	}
	return results[0], nil
}
