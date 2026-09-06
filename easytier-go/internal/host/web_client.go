package host

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/EasyTier/EasyTier/easytier-go/internal/engine"
)

type WebClientOptions struct {
	// Endpoint is a tcp:// or udp:// config-server URL, or a shorthand token.
	Endpoint string
	// MachineID is the stable UUID used to identify this host.
	MachineID  string
	Hostname   string
	SecureMode bool
}

type WebClient struct {
	engine *engine.WebClient
}

// ConnectWebClient connects this Host to an EasyTier configuration server.
func (host *Host) ConnectWebClient(
	ctx context.Context,
	options WebClientOptions,
) (*WebClient, error) {
	if host == nil || host.engine == nil {
		return nil, fmt.Errorf("connect WebClient with nil EasyTier host")
	}
	if ctx == nil {
		return nil, fmt.Errorf("connect EasyTier WebClient with nil context")
	}
	if options.Hostname == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("resolve WebClient hostname: %w", err)
		}
		options.Hostname = hostname
	}
	client, err := host.engine.CreateWebClient(ctx, engine.WebClientOptions{
		Endpoint:   options.Endpoint,
		MachineID:  options.MachineID,
		Hostname:   options.Hostname,
		SecureMode: options.SecureMode,
		OSType:     runtime.GOOS,
	})
	if err != nil {
		return nil, err
	}
	return &WebClient{engine: client}, nil
}

func (client *WebClient) Connected() bool {
	return client != nil && client.engine != nil && client.engine.Connected()
}

func (client *WebClient) Close(ctx context.Context) error {
	if client == nil || client.engine == nil {
		return nil
	}
	return client.engine.Close(ctx)
}
