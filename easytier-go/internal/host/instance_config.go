package host

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// P2PPolicy controls when an instance attempts peer-to-peer connections.
//
// Disable normally suppresses P2P, but a peer advertising Need may still
// request it. Need advertises that this instance requires P2P and may override
// a peer's Disable setting. Lazy defers background P2P until traffic needs it,
// except for peers advertising Need.
type P2PPolicy struct {
	Disable bool
	Need    bool
	Lazy    bool
}

// HolePunchingPolicy selects the hole-punching methods available to an
// instance. SymmetricUDP requires UDP.
type HolePunchingPolicy struct {
	TCP          bool
	UDP          bool
	SymmetricUDP bool
}

// PortForwardProtocol identifies the transport used by a port-forward rule.
type PortForwardProtocol string

const (
	PortForwardTCP PortForwardProtocol = "tcp"
	PortForwardUDP PortForwardProtocol = "udp"
)

// PortForwardConfig exposes a host socket through the EasyTier data plane.
type PortForwardConfig struct {
	Protocol    PortForwardProtocol
	Bind        netip.AddrPort
	Destination netip.AddrPort
}

// InstanceConfig is an immutable EasyTier instance configuration.
//
// Its zero value is invalid. Construct one with InstanceConfigBuilder.
type InstanceConfig struct {
	document *instanceConfigDocument
}

// InstanceConfigBuilder builds a validated InstanceConfig.
//
// A builder is not safe for concurrent use.
type InstanceConfigBuilder struct {
	document         instanceConfigDocument
	networkSecretSet bool
}

type instanceConfigDocument struct {
	networkName      string
	networkSecret    string
	hostname         *string
	ipv4             *netip.Prefix
	peers            []string
	listeners        []string
	portForwards     []PortForwardConfig
	stunServers      []string
	stunServersSet   bool
	stunServersV6    []string
	stunServersV6Set bool
	p2p              *P2PPolicy
	holePunching     *HolePunchingPolicy
	encryption       *bool
	secureMode       secureMode
	securePrivateKey []byte
}

type secureMode uint8

const (
	secureModeDisabled secureMode = iota
	secureModeAutomatic
	secureModeManual
)

// NewInstanceConfigBuilder starts a configuration for networkName.
func NewInstanceConfigBuilder(networkName string) *InstanceConfigBuilder {
	return &InstanceConfigBuilder{
		document: instanceConfigDocument{networkName: networkName},
	}
}

// NetworkSecret selects shared-secret network authentication.
//
// An empty secret is valid unless secure mode is enabled.
func (builder *InstanceConfigBuilder) NetworkSecret(
	secret string,
) *InstanceConfigBuilder {
	builder.document.networkSecret = secret
	builder.networkSecretSet = true
	return builder
}

// Hostname sets the hostname advertised by this instance.
func (builder *InstanceConfigBuilder) Hostname(
	hostname string,
) *InstanceConfigBuilder {
	builder.document.hostname = &hostname
	return builder
}

// IPv4 sets the instance's virtual IPv4 address and network prefix.
func (builder *InstanceConfigBuilder) IPv4(
	prefix netip.Prefix,
) *InstanceConfigBuilder {
	builder.document.ipv4 = &prefix
	return builder
}

// AddPeers appends TCP or UDP peer endpoints.
func (builder *InstanceConfigBuilder) AddPeers(
	uris ...string,
) *InstanceConfigBuilder {
	builder.document.peers = append(builder.document.peers, uris...)
	return builder
}

// AddListeners appends TCP or UDP listener endpoints.
func (builder *InstanceConfigBuilder) AddListeners(
	uris ...string,
) *InstanceConfigBuilder {
	builder.document.listeners = append(builder.document.listeners, uris...)
	return builder
}

// AddPortForwards appends TCP or UDP host-to-overlay forwarding rules.
func (builder *InstanceConfigBuilder) AddPortForwards(
	forwards ...PortForwardConfig,
) *InstanceConfigBuilder {
	builder.document.portForwards = append(builder.document.portForwards, forwards...)
	return builder
}

// STUNServers replaces the IPv4 UDP STUN server list.
//
// Calling STUNServers with no arguments explicitly disables the list. Omitting
// the call uses the embedded core's defaults.
func (builder *InstanceConfigBuilder) STUNServers(
	servers ...string,
) *InstanceConfigBuilder {
	builder.document.stunServers = append([]string(nil), servers...)
	builder.document.stunServersSet = true
	return builder
}

// STUNServersV6 replaces the IPv6 UDP STUN server list.
//
// Calling STUNServersV6 with no arguments explicitly disables the list.
// Omitting the call uses the embedded core's defaults.
func (builder *InstanceConfigBuilder) STUNServersV6(
	servers ...string,
) *InstanceConfigBuilder {
	builder.document.stunServersV6 = append([]string(nil), servers...)
	builder.document.stunServersV6Set = true
	return builder
}

// P2P sets the instance's P2P connection policy.
func (builder *InstanceConfigBuilder) P2P(
	policy P2PPolicy,
) *InstanceConfigBuilder {
	builder.document.p2p = &policy
	return builder
}

// HolePunching sets the instance's TCP and UDP hole-punching policy.
func (builder *InstanceConfigBuilder) HolePunching(
	policy HolePunchingPolicy,
) *InstanceConfigBuilder {
	builder.document.holePunching = &policy
	return builder
}

// Encryption explicitly enables or disables EasyTier data encryption.
func (builder *InstanceConfigBuilder) Encryption(
	enabled bool,
) *InstanceConfigBuilder {
	builder.document.encryption = &enabled
	return builder
}

// SecureMode enables secure mode with an automatically generated X25519 key.
func (builder *InstanceConfigBuilder) SecureMode() *InstanceConfigBuilder {
	builder.document.secureMode = secureModeAutomatic
	builder.document.securePrivateKey = nil
	return builder
}

// SecureModeWithPrivateKey enables secure mode with a caller-provided raw
// 32-byte X25519 private key. The key is copied immediately.
func (builder *InstanceConfigBuilder) SecureModeWithPrivateKey(
	privateKey []byte,
) *InstanceConfigBuilder {
	builder.document.secureMode = secureModeManual
	builder.document.securePrivateKey = append([]byte(nil), privateKey...)
	return builder
}

// Build validates the builder and returns an immutable configuration.
func (builder *InstanceConfigBuilder) Build() (InstanceConfig, error) {
	if builder == nil {
		return InstanceConfig{}, invalidInstanceConfig("", "builder is nil")
	}
	if err := builder.validateIdentity(); err != nil {
		return InstanceConfig{}, err
	}

	document := builder.document.clone()
	if err := validateHostname(document.hostname); err != nil {
		return InstanceConfig{}, err
	}
	if err := validateIPv4(document.ipv4); err != nil {
		return InstanceConfig{}, err
	}
	if err := normalizeEndpoints(document.peers, false, "peers"); err != nil {
		return InstanceConfig{}, err
	}
	if err := normalizeEndpoints(document.listeners, true, "listeners"); err != nil {
		return InstanceConfig{}, err
	}
	if err := validatePortForwards(document.portForwards); err != nil {
		return InstanceConfig{}, err
	}
	if document.stunServersSet {
		if err := validateSTUNServers(document.stunServers, false, "stun_servers"); err != nil {
			return InstanceConfig{}, err
		}
	}
	if document.stunServersV6Set {
		if err := validateSTUNServers(
			document.stunServersV6,
			true,
			"stun_servers_v6",
		); err != nil {
			return InstanceConfig{}, err
		}
	}
	if document.holePunching != nil &&
		document.holePunching.SymmetricUDP &&
		!document.holePunching.UDP {
		return InstanceConfig{}, invalidInstanceConfig(
			"hole_punching.symmetric_udp",
			"requires UDP hole punching",
		)
	}
	if document.secureMode != secureModeDisabled {
		if document.networkSecret == "" {
			return InstanceConfig{}, invalidInstanceConfig(
				"secure_mode",
				"requires a non-empty network secret",
			)
		}
		privateKey, err := builder.secureModePrivateKey()
		if err != nil {
			return InstanceConfig{}, err
		}
		document.securePrivateKey = privateKey
	}

	return InstanceConfig{document: &document}, nil
}

func (builder *InstanceConfigBuilder) validateIdentity() error {
	if !utf8.ValidString(builder.document.networkName) {
		return invalidInstanceConfig("network.name", "must be valid UTF-8")
	}
	if builder.document.networkName == "" {
		return invalidInstanceConfig("network.name", "must not be empty")
	}
	if !builder.networkSecretSet {
		return invalidInstanceConfig("network.secret", "must be explicitly set")
	}
	if !utf8.ValidString(builder.document.networkSecret) {
		return invalidInstanceConfig("network.secret", "must be valid UTF-8")
	}
	return nil
}

func (builder *InstanceConfigBuilder) secureModePrivateKey() ([]byte, error) {
	switch builder.document.secureMode {
	case secureModeAutomatic:
		if len(builder.document.securePrivateKey) == 0 {
			privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("generate secure mode X25519 key: %w", err)
			}
			builder.document.securePrivateKey = privateKey.Bytes()
		}
	case secureModeManual:
		if len(builder.document.securePrivateKey) != 32 {
			return nil, invalidInstanceConfig(
				"secure_mode.private_key",
				"must contain exactly 32 bytes",
			)
		}
		if _, err := ecdh.X25519().NewPrivateKey(
			builder.document.securePrivateKey,
		); err != nil {
			return nil, invalidInstanceConfig(
				"secure_mode.private_key",
				"is not a valid X25519 private key",
			)
		}
	default:
		return nil, invalidInstanceConfig("secure_mode", "has an invalid mode")
	}
	return append([]byte(nil), builder.document.securePrivateKey...), nil
}

func validateHostname(hostname *string) error {
	if hostname == nil {
		return nil
	}
	if !utf8.ValidString(*hostname) {
		return invalidInstanceConfig("hostname", "must be valid UTF-8")
	}
	if *hostname == "" {
		return invalidInstanceConfig("hostname", "must not be empty")
	}
	if utf8.RuneCountInString(*hostname) > 32 {
		return invalidInstanceConfig("hostname", "must not exceed 32 characters")
	}
	for _, character := range *hostname {
		if unicode.IsControl(character) {
			return invalidInstanceConfig("hostname", "must not contain control characters")
		}
	}
	return nil
}

func validateIPv4(prefix *netip.Prefix) error {
	if prefix == nil {
		return nil
	}
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return invalidInstanceConfig("ipv4", "must be a valid IPv4 prefix")
	}
	if prefix.Bits() == 32 {
		return invalidInstanceConfig(
			"ipv4",
			"must include a network prefix shorter than /32",
		)
	}
	return nil
}

func validatePortForwards(forwards []PortForwardConfig) error {
	seen := make(map[PortForwardConfig]struct{}, len(forwards))
	for index, forward := range forwards {
		field := fmt.Sprintf("port_forwards[%d]", index)
		if forward.Protocol != PortForwardTCP &&
			forward.Protocol != PortForwardUDP {
			return invalidInstanceConfig(
				field+".protocol",
				"must be TCP or UDP",
			)
		}
		if !forward.Bind.IsValid() || !forward.Bind.Addr().Is4() {
			return invalidInstanceConfig(
				field+".bind",
				"must be a valid IPv4 socket address",
			)
		}
		if !forward.Destination.IsValid() ||
			!forward.Destination.Addr().Is4() {
			return invalidInstanceConfig(
				field+".destination",
				"must be a valid IPv4 socket address",
			)
		}
		if forward.Destination.Port() == 0 {
			return invalidInstanceConfig(
				field+".destination",
				"port must not be zero",
			)
		}
		if _, exists := seen[forward]; exists {
			return invalidInstanceConfig(field, "duplicates another port forward")
		}
		seen[forward] = struct{}{}
	}
	return nil
}

func normalizeEndpoints(values []string, listener bool, field string) error {
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		normalized, err := normalizeEndpoint(value, listener)
		if err != nil {
			return invalidInstanceConfig(
				fmt.Sprintf("%s[%d]", field, index),
				err.Error(),
			)
		}
		if _, exists := seen[normalized]; exists {
			return invalidInstanceConfig(
				fmt.Sprintf("%s[%d]", field, index),
				"duplicates another endpoint",
			)
		}
		seen[normalized] = struct{}{}
		values[index] = normalized
	}
	return nil
}

func normalizeEndpoint(value string, listener bool) (string, error) {
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("must be valid UTF-8")
	}
	if value == "" || strings.TrimSpace(value) != value {
		return "", fmt.Errorf("must be a non-empty URI without surrounding whitespace")
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("must be an absolute TCP or UDP URI")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "tcp" && parsed.Scheme != "udp" {
		return "", fmt.Errorf("must use the TCP or UDP scheme")
	}
	if parsed.User != nil ||
		parsed.Opaque != "" ||
		parsed.Path != "" ||
		parsed.RawPath != "" ||
		parsed.RawQuery != "" ||
		parsed.ForceQuery ||
		parsed.Fragment != "" {
		return "", fmt.Errorf("must not contain credentials, a path, query, or fragment")
	}
	host := parsed.Hostname()
	if host == "" {
		return "", fmt.Errorf("must include a host")
	}
	if port := parsed.Port(); port != "" {
		value, parseErr := strconv.ParseUint(port, 10, 16)
		if parseErr != nil || (!listener && value == 0) {
			return "", fmt.Errorf("has an invalid port")
		}
	}
	if listener {
		if _, err := netip.ParseAddr(host); err != nil {
			return "", fmt.Errorf("listener host must be an IP address")
		}
	}
	return parsed.String(), nil
}

func validateSTUNServers(values []string, ipv6 bool, field string) error {
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if err := validateSTUNServer(value, ipv6); err != nil {
			return invalidInstanceConfig(
				fmt.Sprintf("%s[%d]", field, index),
				err.Error(),
			)
		}
		if _, exists := seen[value]; exists {
			return invalidInstanceConfig(
				fmt.Sprintf("%s[%d]", field, index),
				"duplicates another STUN server",
			)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateSTUNServer(value string, ipv6 bool) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("must be valid UTF-8")
	}
	if value == "" || strings.TrimSpace(value) != value {
		return fmt.Errorf("must be non-empty without surrounding whitespace")
	}
	if domain, found := strings.CutPrefix(value, "txt:"); found {
		if !validSTUNHostname(domain) {
			return fmt.Errorf("has an invalid TXT lookup name")
		}
		return nil
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return validateSTUNAddressFamily(address, ipv6)
	}
	if address, err := netip.ParseAddrPort(value); err == nil {
		if address.Port() == 0 {
			return fmt.Errorf("port must not be zero")
		}
		return validateSTUNAddressFamily(address.Addr(), ipv6)
	}

	parsed, err := url.Parse("stun://" + value)
	if err != nil ||
		parsed.Host == "" ||
		parsed.User != nil ||
		parsed.Path != "" ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" {
		return fmt.Errorf("must be a host, IP address, socket address, or txt: name")
	}
	host := parsed.Hostname()
	if !validSTUNHostname(host) {
		return fmt.Errorf("has an invalid host")
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return fmt.Errorf("has an invalid port")
	}
	if port := parsed.Port(); port != "" {
		value, parseErr := strconv.ParseUint(port, 10, 16)
		if parseErr != nil || value == 0 {
			return fmt.Errorf("has an invalid port")
		}
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return validateSTUNAddressFamily(address, ipv6)
	}
	return nil
}

func validSTUNHostname(value string) bool {
	if value == "" || strings.ContainsAny(value, " \t\r\n/?#@[]:") {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validateSTUNAddressFamily(address netip.Addr, ipv6 bool) error {
	if ipv6 {
		if address.Is6() && !address.Is4In6() {
			return nil
		}
		return fmt.Errorf("literal address must be IPv6")
	}
	if address.Is4() {
		return nil
	}
	return fmt.Errorf("literal address must be IPv4")
}

func invalidInstanceConfig(field string, message string) error {
	if field == "" {
		return fmt.Errorf("invalid EasyTier instance config: %s", message)
	}
	return fmt.Errorf("invalid EasyTier instance config %s: %s", field, message)
}

func (document instanceConfigDocument) clone() instanceConfigDocument {
	cloned := document
	cloned.peers = append([]string(nil), document.peers...)
	cloned.listeners = append([]string(nil), document.listeners...)
	cloned.portForwards = append([]PortForwardConfig(nil), document.portForwards...)
	cloned.stunServers = append([]string(nil), document.stunServers...)
	cloned.stunServersV6 = append([]string(nil), document.stunServersV6...)
	cloned.securePrivateKey = append([]byte(nil), document.securePrivateKey...)
	if document.hostname != nil {
		value := *document.hostname
		cloned.hostname = &value
	}
	if document.ipv4 != nil {
		value := *document.ipv4
		cloned.ipv4 = &value
	}
	if document.p2p != nil {
		value := *document.p2p
		cloned.p2p = &value
	}
	if document.holePunching != nil {
		value := *document.holePunching
		cloned.holePunching = &value
	}
	if document.encryption != nil {
		value := *document.encryption
		cloned.encryption = &value
	}
	return cloned
}

// Format prevents configuration secrets and private keys from being printed.
func (config InstanceConfig) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("InstanceConfig{<redacted>}"))
}

// Format prevents configuration secrets and private keys from being printed.
func (builder InstanceConfigBuilder) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("InstanceConfigBuilder{<redacted>}"))
}
