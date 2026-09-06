package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	corehost "github.com/EasyTier/EasyTier/easytier-go"
	tun "github.com/sagernet/sing-tun"
)

const (
	tunMTU         = 1380
	tunNamePrefix  = "et-go"
	tunReadWorkers = 32
)

func main() {
	options := parseOptions()
	if _, err := options.validate(); err != nil {
		log.Printf("invalid arguments: %v", err)
		flag.Usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()
	if err := run(ctx, options); err != nil {
		log.Printf("EasyTier TUN failed: %v", err)
		os.Exit(1)
	}
}

// EasyTier lifecycle

func run(ctx context.Context, options options) error {
	prefix, err := options.validate()
	if err != nil {
		return err
	}

	host, err := corehost.New(ctx, corehost.Options{})
	if err != nil {
		return fmt.Errorf("create EasyTier host: %w", err)
	}
	defer host.Close(context.Background())

	config, err := corehost.NewInstanceConfigBuilder(options.networkName).
		NetworkSecret(options.networkSecret).
		IPv4(prefix).
		AddPeers([]string(options.peers)...).
		AddPortForwards([]corehost.PortForwardConfig(options.portForwards)...).
		Build()
	if err != nil {
		return fmt.Errorf("build EasyTier instance config: %w", err)
	}
	instance, err := host.CreateInstance(ctx, config)
	if err != nil {
		return fmt.Errorf("create EasyTier instance: %w", err)
	}
	defer instance.Close(context.Background())
	go logEvents(ctx, instance.Events())

	device, err := createTun(prefix)
	if err != nil {
		return err
	}
	defer device.Close()
	deviceName, err := device.Name()
	if err != nil {
		return fmt.Errorf("query TUN interface name: %w", err)
	}

	if err := instance.Start(ctx); err != nil {
		return fmt.Errorf("start EasyTier instance: %w", err)
	}
	startManagementSignals(ctx, instance)
	log.Printf(
		"connected %s to EasyTier network %q as %s",
		deviceName,
		options.networkName,
		prefix,
	)
	return bridgePackets(ctx, device, instance)
}

func logEvents(ctx context.Context, events <-chan corehost.Event) {
	for {
		select {
		case event, open := <-events:
			if !open {
				return
			}
			log.Printf("EasyTier event [%s]: %s", event.Kind, event.Message)
		case <-ctx.Done():
			return
		}
	}
}

func startManagementSignals(
	ctx context.Context,
	instance *corehost.Instance,
) {
	var peerSignal syscall.Signal
	var routeSignal syscall.Signal
	// SIGUSR1 and SIGUSR2 have different numbers on Linux and macOS.
	switch runtime.GOOS {
	case "linux":
		peerSignal, routeSignal = 10, 12
	case "darwin":
		peerSignal, routeSignal = 30, 31
	default:
		return
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, peerSignal, routeSignal)
	go func() {
		defer signal.Stop(signals)
		for {
			select {
			case received := <-signals:
				queryContext, cancel := context.WithTimeout(ctx, 5*time.Second)
				switch received {
				case peerSignal:
					response, err := instance.ListPeer(queryContext)
					if err != nil {
						log.Printf("query EasyTier peer list: %v", err)
					} else {
						log.Printf("EasyTier peer list: %v", response)
					}
				case routeSignal:
					response, err := instance.ListRoute(queryContext)
					if err != nil {
						log.Printf("query EasyTier route list: %v", err)
					} else {
						log.Printf("EasyTier route list: %v", response)
					}
				}
				cancel()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Native TUN adapter

func createTun(prefix netip.Prefix) (*packetDevice, error) {
	name := tun.CalculateInterfaceName(tunNamePrefix)
	nativeTun, err := tun.New(tun.Options{
		Name:             name,
		Inet4Address:     []netip.Prefix{prefix},
		MTU:              tunMTU,
		GSO:              false,
		AutoRoute:        false,
		StrictRoute:      false,
		InterfaceMonitor: noRouteInterfaceMonitor{},
	})
	if err != nil {
		return nil, fmt.Errorf(
			"create TUN %q (requires elevated privileges): %w",
			name,
			err,
		)
	}
	device := newPacketDevice(nativeTun)
	if err := nativeTun.Start(); err != nil {
		_ = device.Close()
		return nil, fmt.Errorf("start TUN %q: %w", name, err)
	}
	return device, nil
}

type packetDevice struct {
	tun.Tun
	packetOffset int
	readMutex    sync.Mutex
	writeMutex   sync.Mutex
	readBuffer   []byte
	writeBuffer  []byte
	closeOnce    sync.Once
	closeErr     error
}

func newPacketDevice(nativeTun tun.Tun) *packetDevice {
	device := &packetDevice{Tun: nativeTun}
	if runtime.GOOS == "darwin" {
		device.packetOffset = 4
		device.readBuffer = make([]byte, 65535+device.packetOffset)
		device.writeBuffer = make([]byte, 65535+device.packetOffset)
	}
	return device
}

func (device *packetDevice) Read(packet []byte) (int, error) {
	device.readMutex.Lock()
	defer device.readMutex.Unlock()

	if device.packetOffset == 0 {
		return device.Tun.Read(packet)
	}
	if len(packet)+device.packetOffset > len(device.readBuffer) {
		return 0, io.ErrShortBuffer
	}
	frame := device.readBuffer[:len(packet)+device.packetOffset]
	length, err := device.Tun.Read(frame)
	if err != nil {
		return 0, err
	}
	if length < device.packetOffset {
		return 0, io.ErrUnexpectedEOF
	}
	length -= device.packetOffset
	copy(packet, frame[device.packetOffset:device.packetOffset+length])
	return length, nil
}

func (device *packetDevice) Write(packet []byte) (int, error) {
	device.writeMutex.Lock()
	defer device.writeMutex.Unlock()

	if device.packetOffset == 0 {
		return device.Tun.Write(packet)
	}
	if len(packet)+device.packetOffset > len(device.writeBuffer) {
		return 0, io.ErrShortBuffer
	}
	frame := device.writeBuffer[:len(packet)+device.packetOffset]
	if err := encodeNativeTunPacketHeader(
		frame[:device.packetOffset],
		packet,
	); err != nil {
		return 0, err
	}
	copy(frame[device.packetOffset:], packet)
	written, err := device.Tun.Write(frame)
	if written <= device.packetOffset {
		return 0, err
	}
	return written - device.packetOffset, err
}

func (device *packetDevice) Close() error {
	device.closeOnce.Do(func() {
		device.closeErr = device.Tun.Close()
	})
	return device.closeErr
}

func encodeNativeTunPacketHeader(header, packet []byte) error {
	if len(header) == 0 {
		return nil
	}
	if len(packet) == 0 {
		return fmt.Errorf("encode utun header: empty packet")
	}
	family := uint32(syscall.AF_INET)
	switch packet[0] >> 4 {
	case 4:
	case 6:
		family = syscall.AF_INET6
	default:
		return fmt.Errorf("unsupported IP version %d", packet[0]>>4)
	}
	binary.BigEndian.PutUint32(header, family)
	return nil
}

// AutoRoute is disabled, so sing-tun v0.8.11 only calls this method.
type noRouteInterfaceMonitor struct {
	tun.DefaultInterfaceMonitor
}

func (noRouteInterfaceMonitor) RegisterMyInterface(string) {
}

// Packet bridge

func bridgePackets(
	ctx context.Context,
	device *packetDevice,
	instance *corehost.Instance,
) error {
	pumpContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, tunReadWorkers+1)
	for range tunReadWorkers {
		go func() { results <- copyTunToEasyTier(pumpContext, device, instance) }()
	}
	go func() { results <- copyEasyTierToTun(pumpContext, instance, device) }()

	errs := []error{<-results}
	cancel()
	errs = append(errs, device.Close())
	for range tunReadWorkers {
		errs = append(errs, <-results)
	}
	return errors.Join(errs...)
}

func copyTunToEasyTier(
	ctx context.Context,
	device io.Reader,
	instance *corehost.Instance,
) error {
	packet := make([]byte, 65535)
	for {
		length, err := device.Read(packet)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read TUN packet: %w", err)
		}
		if length == 0 || packet[0]>>4 != 4 {
			continue
		}
		if err := instance.SendPacket(ctx, packet[:length]); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("send TUN packet to EasyTier: %w", err)
		}
	}
}

func copyEasyTierToTun(
	ctx context.Context,
	instance *corehost.Instance,
	device io.Writer,
) error {
	for {
		packet, err := instance.ReceivePacket(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("receive EasyTier packet: %w", err)
		}
		written, err := device.Write(packet)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("write EasyTier packet to TUN: %w", err)
		}
		// Wintun reports a full send ring as (0, nil), meaning that it has
		// dropped this packet. Keep the bridge alive for subsequent packets.
		if written == 0 {
			continue
		}
		if written != len(packet) {
			return io.ErrShortWrite
		}
	}
}

// Optional port forwarding

type portForwardList []corehost.PortForwardConfig

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
		values[index] = fmt.Sprintf(
			"%s://%s/%s",
			rule.Protocol,
			rule.Bind,
			rule.Destination,
		)
	}
	return strings.Join(values, ",")
}

func parsePortForwardRule(value string) (corehost.PortForwardConfig, error) {
	protocolText, addresses, ok := strings.Cut(value, "://")
	if !ok || (protocolText != "tcp" && protocolText != "udp") {
		return corehost.PortForwardConfig{}, fmt.Errorf(
			"port forward %q must use tcp:// or udp://",
			value,
		)
	}
	bindText, targetText, ok := strings.Cut(addresses, "/")
	if !ok {
		return corehost.PortForwardConfig{}, fmt.Errorf(
			"port forward %q must contain bind/overlay-target",
			value,
		)
	}
	bind, err := netip.ParseAddrPort(bindText)
	if err != nil {
		return corehost.PortForwardConfig{}, fmt.Errorf("parse bind address: %w", err)
	}
	target, err := netip.ParseAddrPort(targetText)
	if err != nil {
		return corehost.PortForwardConfig{}, fmt.Errorf("parse target address: %w", err)
	}
	if !bind.Addr().Is4() || !target.Addr().Is4() {
		return corehost.PortForwardConfig{}, fmt.Errorf(
			"port forward requires IPv4 addresses",
		)
	}
	protocol := corehost.PortForwardTCP
	if protocolText == "udp" {
		protocol = corehost.PortForwardUDP
	}
	return corehost.PortForwardConfig{
		Protocol:    protocol,
		Bind:        bind,
		Destination: target,
	}, nil
}

// Command-line options

func parseOptions() options {
	var options options
	flag.Var(&options.peers, "p", "EasyTier peer URI; may be repeated")
	flag.Var(
		&options.portForwards,
		"port-forward",
		"tcp://bind/overlay-target or udp://bind/overlay-target; may be repeated",
	)
	flag.StringVar(&options.networkName, "network-name", "", "EasyTier network name")
	flag.StringVar(&options.networkSecret, "network-secret", "", "EasyTier network secret")
	flag.StringVar(&options.ipv4, "ipv4", "", "fixed EasyTier IPv4 address and prefix")
	flag.Parse()
	return options
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

type options struct {
	peers         peerList
	portForwards  portForwardList
	networkName   string
	networkSecret string
	ipv4          string
}

func (options options) validate() (netip.Prefix, error) {
	if len(options.peers) == 0 {
		return netip.Prefix{}, fmt.Errorf("at least one -p peer is required")
	}
	if strings.TrimSpace(options.networkName) == "" {
		return netip.Prefix{}, fmt.Errorf("--network-name is required")
	}
	if options.networkSecret == "" {
		return netip.Prefix{}, fmt.Errorf("--network-secret is required")
	}
	prefix, err := netip.ParsePrefix(options.ipv4)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse --ipv4: %w", err)
	}
	if !prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("--ipv4 must be an IPv4 prefix")
	}
	return prefix, nil
}
