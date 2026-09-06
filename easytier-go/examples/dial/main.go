package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	corehost "github.com/EasyTier/EasyTier/easytier-go"
	"github.com/EasyTier/EasyTier/easytier-go/internal/contextutil"
)

const maxUDPPayload = 65507

type peerList []string

func (peers *peerList) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("peer URI must not be empty")
	}
	*peers = append(*peers, value)
	return nil
}

func (peers *peerList) String() string {
	return strings.Join(*peers, ",")
}

type options struct {
	peers          peerList
	networkName    string
	networkSecret  string
	ipv4           string
	network        string
	address        string
	connectTimeout time.Duration
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
	if err := run(ctx, options, os.Stdin, os.Stdout); err != nil {
		log.Printf("EasyTier dial failed: %v", err)
		os.Exit(1)
	}
}

func parseOptions(arguments []string) (options, error) {
	flags := flag.NewFlagSet("dial", flag.ContinueOnError)
	var options options
	flags.Var(&options.peers, "p", "EasyTier peer URI; may be repeated")
	flags.StringVar(&options.networkName, "network-name", "", "EasyTier network name")
	flags.StringVar(&options.networkSecret, "network-secret", "", "EasyTier network secret")
	flags.StringVar(&options.ipv4, "ipv4", "", "fixed EasyTier IPv4 address and prefix")
	flags.StringVar(&options.network, "network", "tcp4", "overlay network: tcp4 or udp4")
	flags.StringVar(&options.address, "address", "", "overlay IPv4 destination")
	flags.DurationVar(
		&options.connectTimeout,
		"connect-timeout",
		10*time.Second,
		"time to wait for an overlay route and connection",
	)
	if err := flags.Parse(arguments); err != nil {
		return options, err
	}
	if flags.NArg() != 0 {
		return options, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if err := options.validate(); err != nil {
		return options, err
	}
	return options, nil
}

func (options options) validate() error {
	if len(options.peers) == 0 {
		return fmt.Errorf("at least one -p peer is required")
	}
	if strings.TrimSpace(options.networkName) == "" {
		return fmt.Errorf("--network-name is required")
	}
	if options.networkSecret == "" {
		return fmt.Errorf("--network-secret is required")
	}
	prefix, err := netip.ParsePrefix(options.ipv4)
	if err != nil {
		return fmt.Errorf("parse --ipv4: %w", err)
	}
	if !prefix.Addr().Is4() {
		return fmt.Errorf("--ipv4 must be an IPv4 prefix")
	}
	if options.network != "tcp4" && options.network != "udp4" {
		return fmt.Errorf("--network must be tcp4 or udp4")
	}
	if options.connectTimeout <= 0 {
		return fmt.Errorf("--connect-timeout must be positive")
	}
	address, err := netip.ParseAddrPort(options.address)
	if err != nil || !address.Addr().Is4() || address.Port() == 0 {
		return fmt.Errorf("--address must be an IPv4 socket address with a nonzero port")
	}
	return nil
}

func run(
	ctx context.Context,
	options options,
	input io.Reader,
	output io.Writer,
) error {
	prefix, err := netip.ParsePrefix(options.ipv4)
	if err != nil {
		return fmt.Errorf("parse instance IPv4 prefix: %w", err)
	}
	config, err := corehost.NewInstanceConfigBuilder(options.networkName).
		NetworkSecret(options.networkSecret).
		IPv4(prefix).
		AddPeers([]string(options.peers)...).
		Build()
	if err != nil {
		return fmt.Errorf("build EasyTier instance config: %w", err)
	}

	host, err := corehost.New(ctx, corehost.Options{})
	if err != nil {
		return fmt.Errorf("create EasyTier host: %w", err)
	}
	defer host.Close(context.Background())
	instance, err := host.CreateInstance(ctx, config)
	if err != nil {
		return fmt.Errorf("create EasyTier instance: %w", err)
	}
	defer instance.Close(context.Background())
	if err := instance.Start(ctx); err != nil {
		return fmt.Errorf("start EasyTier instance: %w", err)
	}

	target := netip.MustParseAddrPort(options.address)
	connectContext, cancelConnect := context.WithTimeout(ctx, options.connectTimeout)
	defer cancelConnect()
	if target.Addr() != prefix.Addr() {
		if err := waitForRoute(connectContext, instance, target.Addr()); err != nil {
			return fmt.Errorf("wait for overlay route to %s: %w", target.Addr(), err)
		}
	}
	connection, err := instance.Dial(
		connectContext,
		options.network,
		options.address,
	)
	if err != nil {
		return err
	}
	defer connection.Close()
	stopClose := contextutil.AfterFunc(ctx, func() {
		_ = connection.Close()
	})
	defer stopClose()

	log.Printf("connected %s to %s through EasyTier", options.network, options.address)
	switch options.network {
	case "tcp4":
		err = relayTCP(connection, input, output)
	case "udp4":
		err = exchangeUDP(ctx, connection, input, output)
	}
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func waitForRoute(
	ctx context.Context,
	instance *corehost.Instance,
	target netip.Addr,
) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		routes, err := instance.ListRoute(ctx)
		if err != nil {
			return err
		}
		if routesReach(routes, target) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func routesReach(routes []*corehost.Route, target netip.Addr) bool {
	octets := target.As4()
	targetValue := binary.BigEndian.Uint32(octets[:])
	for _, route := range routes {
		if route.GetIpv4Addr().GetAddress().GetAddr() == targetValue {
			return true
		}
		for _, cidr := range route.GetProxyCidrs() {
			prefix, err := netip.ParsePrefix(cidr)
			if err == nil && prefix.Contains(target) {
				return true
			}
		}
	}
	return false
}

func relayTCP(connection net.Conn, input io.Reader, output io.Writer) error {
	writeResult := make(chan error, 1)
	go func() {
		_, err := io.Copy(connection, input)
		writeResult <- err
	}()

	_, readErr := io.Copy(output, connection)
	select {
	case writeErr := <-writeResult:
		return errors.Join(writeErr, readErr)
	default:
		return readErr
	}
}

func exchangeUDP(
	ctx context.Context,
	connection net.Conn,
	input io.Reader,
	output io.Writer,
) error {
	type readResult struct {
		payload []byte
		err     error
	}
	result := make(chan readResult, 1)
	go func() {
		payload, err := io.ReadAll(io.LimitReader(input, maxUDPPayload+1))
		result <- readResult{payload: payload, err: err}
	}()

	var payload []byte
	select {
	case <-ctx.Done():
		return ctx.Err()
	case read := <-result:
		if read.err != nil {
			return fmt.Errorf("read UDP payload: %w", read.err)
		}
		payload = read.payload
	}
	if len(payload) == 0 {
		return fmt.Errorf("UDP input must contain one non-empty datagram")
	}
	if len(payload) > maxUDPPayload {
		return fmt.Errorf("UDP input exceeds the maximum payload of %d bytes", maxUDPPayload)
	}
	written, err := connection.Write(payload)
	if err != nil {
		return fmt.Errorf("write UDP datagram: %w", err)
	}
	if written != len(payload) {
		return io.ErrShortWrite
	}

	response := make([]byte, maxUDPPayload)
	length, err := connection.Read(response)
	if err != nil {
		return fmt.Errorf("read UDP datagram: %w", err)
	}
	written, err = output.Write(response[:length])
	if err != nil {
		return fmt.Errorf("write UDP response: %w", err)
	}
	if written != length {
		return io.ErrShortWrite
	}
	return nil
}
