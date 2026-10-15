package host

import internalhost "github.com/easytier/easytier/easytier-go/internal/host"

// LogLevel controls logging for an entire Host, independently of its instances.
type LogLevel = internalhost.LogLevel

const (
	LogLevelOff   = internalhost.LogLevelOff
	LogLevelError = internalhost.LogLevelError
	LogLevelWarn  = internalhost.LogLevelWarn
	LogLevelInfo  = internalhost.LogLevelInfo
	LogLevelDebug = internalhost.LogLevelDebug
	LogLevelTrace = internalhost.LogLevelTrace
)
