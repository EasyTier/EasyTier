package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	corehost "github.com/EasyTier/EasyTier/easytier-go"
)

type options struct {
	endpoint  string
	machineID string
	hostname  string
	secure    bool
}

func main() {
	options, err := parseOptions(os.Args[1:])
	if err == flag.ErrHelp {
		return
	}
	if err != nil {
		log.Printf("invalid arguments: %v", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()
	if err := run(ctx, options); err != nil {
		log.Printf("EasyTier Web client failed: %v", err)
		os.Exit(1)
	}
}

func parseOptions(arguments []string) (options, error) {
	flags := flag.NewFlagSet("web-client", flag.ContinueOnError)
	var options options
	flags.StringVar(&options.endpoint, "web-endpoint", "", "Web config-server endpoint")
	flags.StringVar(&options.machineID, "web-machine-id", "", "stable machine UUID")
	flags.StringVar(&options.hostname, "web-hostname", "", "machine hostname")
	flags.BoolVar(&options.secure, "web-secure", false, "use a secure Web connection")
	if err := flags.Parse(arguments); err != nil {
		return options, err
	}
	if flags.NArg() != 0 {
		return options, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	options.endpoint = strings.TrimSpace(options.endpoint)
	options.machineID = strings.TrimSpace(options.machineID)
	options.hostname = strings.TrimSpace(options.hostname)
	if options.endpoint == "" {
		return options, fmt.Errorf("--web-endpoint is required")
	}
	if options.machineID == "" {
		return options, fmt.Errorf("--web-machine-id is required")
	}
	return options, nil
}

func run(ctx context.Context, options options) error {
	host, err := corehost.New(ctx, corehost.Options{})
	if err != nil {
		return fmt.Errorf("create EasyTier host: %w", err)
	}
	defer host.Close(context.Background())

	client, err := host.ConnectWebClient(ctx, corehost.WebClientOptions{
		Endpoint:   options.endpoint,
		MachineID:  options.machineID,
		Hostname:   options.hostname,
		SecureMode: options.secure,
	})
	if err != nil {
		return fmt.Errorf("connect EasyTier Web client: %w", err)
	}
	defer client.Close(context.Background())

	log.Printf("EasyTier Web client started for machine %s", options.machineID)
	<-ctx.Done()
	return nil
}
