// Command dial-forward-bench measures the public Instance.Dial data path.
//
// User-facing port forwarding belongs to the embedded EasyTier core. This
// command intentionally keeps the forwarding loop in Go so benchmarks include
// the public Go/WASM data-plane boundary.
package main

import (
	"context"
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
	"sync/atomic"
	"syscall"

	corehost "github.com/EasyTier/EasyTier/easytier-go"
	"github.com/EasyTier/EasyTier/easytier-go/internal/contextutil"
)

type options struct {
	peers         peerList
	portForwards  portForwardList
	networkName   string
	networkSecret string
	ipv4          string
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
		log.Printf("EasyTier Dial benchmark failed: %v", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, options options) error {
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

	forwarders, err := startPortForwards(
		ctx,
		instance.Dial,
		options.portForwards,
	)
	if err != nil {
		return err
	}
	defer forwarders.Close()
	<-ctx.Done()
	return nil
}

func parseOptions(arguments []string) (options, error) {
	flags := flag.NewFlagSet("dial-forward-bench", flag.ContinueOnError)
	var options options
	flags.Var(&options.peers, "p", "EasyTier peer URI; may be repeated")
	flags.Var(
		&options.portForwards,
		"port-forward",
		"tcp://bind/overlay-target or udp://bind/overlay-target; may be repeated",
	)
	flags.StringVar(&options.networkName, "network-name", "", "EasyTier network name")
	flags.StringVar(&options.networkSecret, "network-secret", "", "EasyTier network secret")
	flags.StringVar(&options.ipv4, "ipv4", "", "fixed EasyTier IPv4 address and prefix")
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
	if len(options.portForwards) == 0 {
		return fmt.Errorf("at least one --port-forward rule is required")
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
	return nil
}

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

type portForwardRule struct {
	protocol string
	bind     netip.AddrPort
	target   netip.AddrPort
}

func (rule portForwardRule) String() string {
	return fmt.Sprintf("%s://%s/%s", rule.protocol, rule.bind, rule.target)
}

type portForwardList []portForwardRule

func (rules *portForwardList) Set(value string) error {
	rule, err := parsePortForwardRule(value)
	if err == nil {
		*rules = append(*rules, rule)
	}
	return err
}

func (rules *portForwardList) String() string {
	values := make([]string, len(*rules))
	for index, rule := range *rules {
		values[index] = rule.String()
	}
	return strings.Join(values, ",")
}

func parsePortForwardRule(value string) (portForwardRule, error) {
	protocol, addresses, ok := strings.Cut(value, "://")
	if !ok || (protocol != "tcp" && protocol != "udp") {
		return portForwardRule{}, fmt.Errorf(
			"port forward %q must use tcp:// or udp://",
			value,
		)
	}
	bindText, targetText, ok := strings.Cut(addresses, "/")
	if !ok {
		return portForwardRule{}, fmt.Errorf(
			"port forward %q must contain bind/overlay-target",
			value,
		)
	}
	bind, err := netip.ParseAddrPort(bindText)
	if err != nil {
		return portForwardRule{}, fmt.Errorf("parse bind address: %w", err)
	}
	target, err := netip.ParseAddrPort(targetText)
	if err != nil {
		return portForwardRule{}, fmt.Errorf("parse target address: %w", err)
	}
	if !bind.Addr().Is4() || !target.Addr().Is4() {
		return portForwardRule{}, fmt.Errorf("port forward requires IPv4 addresses")
	}
	return portForwardRule{protocol: protocol, bind: bind, target: target}, nil
}

type overlayDialFunc func(context.Context, string, string) (net.Conn, error)

type portForwardSet struct {
	ctx       context.Context
	cancel    context.CancelFunc
	dial      overlayDialFunc
	addresses []net.Addr
	closers   []io.Closer
}

func startPortForwards(
	ctx context.Context,
	dial overlayDialFunc,
	rules []portForwardRule,
) (*portForwardSet, error) {
	if dial == nil {
		return nil, fmt.Errorf("port forward dial function is nil")
	}
	forwardContext, cancel := context.WithCancel(ctx)
	forwards := &portForwardSet{
		ctx:    forwardContext,
		cancel: cancel,
		dial:   dial,
	}
	for _, rule := range rules {
		var err error
		switch rule.protocol {
		case "tcp":
			err = forwards.startTCP(rule)
		case "udp":
			err = forwards.startUDP(rule)
		default:
			err = fmt.Errorf("unsupported protocol %q", rule.protocol)
		}
		if err != nil {
			_ = forwards.Close()
			return nil, fmt.Errorf("start port forward %s: %w", rule, err)
		}
	}
	return forwards, nil
}

func (forwards *portForwardSet) Close() error {
	forwards.cancel()
	var errs []error
	for _, closer := range forwards.closers {
		errs = append(errs, closer.Close())
	}
	return errors.Join(errs...)
}

func (forwards *portForwardSet) startTCP(rule portForwardRule) error {
	listener, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(rule.bind))
	if err != nil {
		return err
	}
	forwards.closers = append(forwards.closers, listener)
	forwards.addresses = append(forwards.addresses, listener.Addr())
	log.Printf("forwarding tcp://%s to %s through Instance.Dial", listener.Addr(), rule.target)
	go func() {
		for {
			local, err := listener.Accept()
			if err != nil {
				return
			}
			go forwards.forwardTCP(local, rule.target)
		}
	}()
	return nil
}

func (forwards *portForwardSet) forwardTCP(
	local net.Conn,
	target netip.AddrPort,
) {
	defer local.Close()
	overlay, err := forwards.dial(
		forwards.ctx,
		"tcp4",
		target.String(),
	)
	if err != nil {
		return
	}
	defer overlay.Close()
	stopClose := contextutil.AfterFunc(forwards.ctx, func() {
		_ = local.Close()
		_ = overlay.Close()
	})
	defer stopClose()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(overlay, local); done <- struct{}{} }()
	go func() { _, _ = io.Copy(local, overlay); done <- struct{}{} }()
	<-done
}

func (forwards *portForwardSet) startUDP(rule portForwardRule) error {
	overlay, err := forwards.dial(
		forwards.ctx,
		"udp4",
		rule.target.String(),
	)
	if err != nil {
		return err
	}
	listener, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(rule.bind))
	if err != nil {
		_ = overlay.Close()
		return err
	}
	forwards.closers = append(forwards.closers, listener, overlay)
	forwards.addresses = append(forwards.addresses, listener.LocalAddr())
	log.Printf(
		"forwarding udp://%s to %s through Instance.Dial",
		listener.LocalAddr(),
		rule.target,
	)

	var lastClient atomic.Value
	go func() {
		packet := make([]byte, 65535)
		for {
			length, client, err := listener.ReadFromUDPAddrPort(packet)
			if err != nil {
				return
			}
			lastClient.Store(client)
			if written, err := overlay.Write(packet[:length]); err != nil ||
				written != length {
				return
			}
		}
	}()
	go func() {
		packet := make([]byte, 65535)
		for {
			length, err := overlay.Read(packet)
			if err != nil {
				return
			}
			client, ok := lastClient.Load().(netip.AddrPort)
			if ok {
				_, _ = listener.WriteToUDPAddrPort(packet[:length], client)
			}
		}
	}()
	return nil
}
