package engine

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"

	"github.com/EasyTier/EasyTier/easytier-go/platform"
)

const createConfigVersion = 14
const webClientConfigVersion = 1

type createEnvelope struct {
	Version     uint32              `json:"version"`
	Config      string              `json:"config"`
	Environment environmentSnapshot `json:"environment"`
}

type webClientEnvelope struct {
	Version     uint32              `json:"version"`
	Endpoint    string              `json:"endpoint"`
	MachineID   string              `json:"machine_id"`
	Hostname    string              `json:"hostname"`
	SecureMode  bool                `json:"secure_mode"`
	OSType      string              `json:"os_type"`
	Environment environmentSnapshot `json:"environment"`
}

type environmentSnapshot struct {
	PublicIPv4           *string               `json:"public_ipv4"`
	InterfaceIPv4s       []string              `json:"interface_ipv4s"`
	PublicIPv6           *string               `json:"public_ipv6"`
	InterfaceIPv6s       []string              `json:"interface_ipv6s"`
	MappedListeners      []string              `json:"mapped_listeners"`
	LocalIPs             []string              `json:"local_ips"`
	ProtectedTCPPorts    []uint16              `json:"protected_tcp_ports"`
	PreferredIPv6Sources []preferredIPv6Source `json:"preferred_ipv6_sources"`
}

type preferredIPv6Source struct {
	IP      string `json:"ip"`
	IfIndex uint32 `json:"ifindex"`
}

func encodeCreateEnvelope(
	configTOML string,
	snapshot platform.EnvironmentSnapshot,
) ([]byte, error) {
	if configTOML == "" {
		return nil, fmt.Errorf("EasyTier TOML configuration is empty")
	}
	environment, err := encodeEnvironmentSnapshot(snapshot)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(createEnvelope{
		Version:     createConfigVersion,
		Config:      configTOML,
		Environment: environment,
	})
	if err != nil {
		return nil, fmt.Errorf("encode EasyTier create envelope: %w", err)
	}
	return encoded, nil
}

func encodeWebClientEnvelope(
	options WebClientOptions,
	snapshot platform.EnvironmentSnapshot,
) ([]byte, error) {
	if options.Endpoint == "" {
		return nil, fmt.Errorf("EasyTier WebClient endpoint is empty")
	}
	if options.MachineID == "" {
		return nil, fmt.Errorf("EasyTier WebClient machine ID is empty")
	}
	if options.Hostname == "" {
		return nil, fmt.Errorf("EasyTier WebClient hostname is empty")
	}
	environment, err := encodeEnvironmentSnapshot(snapshot)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(webClientEnvelope{
		Version:     webClientConfigVersion,
		Endpoint:    options.Endpoint,
		MachineID:   options.MachineID,
		Hostname:    options.Hostname,
		SecureMode:  options.SecureMode,
		OSType:      options.OSType,
		Environment: environment,
	})
	if err != nil {
		return nil, fmt.Errorf("encode EasyTier WebClient envelope: %w", err)
	}
	return encoded, nil
}

func encodeEnvironmentSnapshot(
	snapshot platform.EnvironmentSnapshot,
) (environmentSnapshot, error) {
	encoded := environmentSnapshot{
		InterfaceIPv4s:       make([]string, len(snapshot.InterfaceIPv4s)),
		InterfaceIPv6s:       make([]string, len(snapshot.InterfaceIPv6s)),
		MappedListeners:      append([]string{}, snapshot.MappedListeners...),
		LocalIPs:             make([]string, len(snapshot.LocalIPs)),
		ProtectedTCPPorts:    append([]uint16{}, snapshot.ProtectedTCPPorts...),
		PreferredIPv6Sources: make([]preferredIPv6Source, len(snapshot.PreferredIPv6Sources)),
	}
	var err error
	encoded.PublicIPv4, err = encodeOptionalIP("public IPv4", snapshot.PublicIPv4, true)
	if err != nil {
		return environmentSnapshot{}, err
	}
	encoded.PublicIPv6, err = encodeOptionalIP("public IPv6", snapshot.PublicIPv6, false)
	if err != nil {
		return environmentSnapshot{}, err
	}
	for index, address := range snapshot.InterfaceIPv4s {
		if !address.Is4() {
			return environmentSnapshot{}, fmt.Errorf(
				"interface IPv4 %d is not IPv4: %s",
				index,
				address,
			)
		}
		encoded.InterfaceIPv4s[index] = address.String()
	}
	for index, address := range snapshot.InterfaceIPv6s {
		if !isIPv6(address) {
			return environmentSnapshot{}, fmt.Errorf(
				"interface IPv6 %d is not IPv6: %s",
				index,
				address,
			)
		}
		encoded.InterfaceIPv6s[index] = address.String()
	}
	for index, listener := range encoded.MappedListeners {
		parsed, parseErr := url.ParseRequestURI(listener)
		if parseErr != nil || parsed.Scheme == "" {
			return environmentSnapshot{}, fmt.Errorf(
				"mapped listener %d is not an absolute URL: %q",
				index,
				listener,
			)
		}
	}
	for index, address := range snapshot.LocalIPs {
		if !address.IsValid() {
			return environmentSnapshot{}, fmt.Errorf("local IP %d is invalid", index)
		}
		encoded.LocalIPs[index] = address.String()
	}
	for index, source := range snapshot.PreferredIPv6Sources {
		if !isIPv6(source.IP) {
			return environmentSnapshot{}, fmt.Errorf(
				"preferred IPv6 source %d is not IPv6: %s",
				index,
				source.IP,
			)
		}
		encoded.PreferredIPv6Sources[index] = preferredIPv6Source{
			IP:      source.IP.String(),
			IfIndex: source.IfIndex,
		}
	}
	return encoded, nil
}

func encodeOptionalIP(
	name string,
	address *netip.Addr,
	ipv4 bool,
) (*string, error) {
	if address == nil {
		return nil, nil
	}
	valid := address.Is4()
	if !ipv4 {
		valid = isIPv6(*address)
	}
	if !valid {
		return nil, fmt.Errorf("%s has wrong address family: %s", name, address)
	}
	encoded := address.String()
	return &encoded, nil
}

func isIPv6(address netip.Addr) bool {
	return address.Is6() && !address.Is4In6()
}
