package host

import (
	"context"

	internalhost "github.com/EasyTier/EasyTier/easytier-go/internal/host"
)

type State = internalhost.State

const (
	StateCreated  State = internalhost.StateCreated
	StateStarting State = internalhost.StateStarting
	StateRunning  State = internalhost.StateRunning
	StateStopping State = internalhost.StateStopping
	StateStopped  State = internalhost.StateStopped
)

type Options = internalhost.Options

type EmbeddedCoreInfo = internalhost.EmbeddedCoreInfo

// Event is one best-effort notification emitted by an EasyTier instance.
type Event = internalhost.Event

type Host = internalhost.Host

type Instance = internalhost.Instance

func New(ctx context.Context, options Options) (*Host, error) {
	return internalhost.New(ctx, options)
}

func CoreInfo() EmbeddedCoreInfo {
	return internalhost.CoreInfo()
}
