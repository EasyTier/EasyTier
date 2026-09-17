package host

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestInstanceConfigEncodesSupportedSettings(t *testing.T) {
	privateKeyBytes := make([]byte, 32)
	for index := range privateKeyBytes {
		privateKeyBytes[index] = byte(index + 1)
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateKeyBytes)
	if err != nil {
		t.Fatalf("create expected private key: %v", err)
	}

	config, err := NewInstanceConfigBuilder(`office "blue"`).
		NetworkSecret("line1\nline2").
		Hostname(`node "blue"`).
		IPv4(netip.MustParsePrefix("10.144.0.10/24")).
		AddPeers(
			"TCP://peer.example.com:11010",
			"udp://203.0.113.20",
		).
		AddListeners(
			"tcp://0.0.0.0:11010",
			"udp://[::]:0",
		).
		AddPortForwards(
			PortForwardConfig{
				Protocol:    PortForwardTCP,
				Bind:        netip.MustParseAddrPort("127.0.0.1:5202"),
				Destination: netip.MustParseAddrPort("10.144.0.20:5201"),
			},
			PortForwardConfig{
				Protocol:    PortForwardUDP,
				Bind:        netip.MustParseAddrPort("0.0.0.0:5203"),
				Destination: netip.MustParseAddrPort("10.144.0.21:5201"),
			},
		).
		STUNServers(
			"stun.example.com",
			"192.0.2.1:3478",
			"txt:_stun.example.com",
		).
		STUNServersV6(
			"2001:db8::1",
			"[2001:db8::2]:3478",
		).
		P2P(P2PPolicy{Disable: true, Need: true, Lazy: true}).
		HolePunching(HolePunchingPolicy{
			TCP:          true,
			UDP:          true,
			SymmetricUDP: false,
		}).
		Encryption(false).
		SecureModeWithPrivateKey(privateKeyBytes).
		Build()
	if err != nil {
		t.Fatalf("build config: %v", err)
	}

	encoded, err := encodeInstanceConfig(config)
	if err != nil {
		t.Fatalf("encode config: %v", err)
	}
	want := fmt.Sprintf(`hostname = "node \"blue\""
ipv4 = "10.144.0.10/24"
listeners = ["tcp://0.0.0.0:11010", "udp://[::]:0"]
stun_servers = ["stun.example.com", "192.0.2.1:3478", "txt:_stun.example.com"]
stun_servers_v6 = ["2001:db8::1", "[2001:db8::2]:3478"]

[network_identity]
network_name = "office \"blue\""
network_secret = "line1\nline2"

[[peer]]
uri = "tcp://peer.example.com:11010"

[[peer]]
uri = "udp://203.0.113.20"

[[port_forward]]
bind_addr = "127.0.0.1:5202"
dst_addr = "10.144.0.20:5201"
proto = "tcp"

[[port_forward]]
bind_addr = "0.0.0.0:5203"
dst_addr = "10.144.0.21:5201"
proto = "udp"

[flags]
enable_encryption = false
disable_p2p = true
need_p2p = true
lazy_p2p = true
disable_tcp_hole_punching = false
disable_udp_hole_punching = false
disable_sym_hole_punching = true

[secure_mode]
enabled = true
local_private_key = %q
local_public_key = %q
`,
		base64.StdEncoding.EncodeToString(privateKey.Bytes()),
		base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
	)
	if encoded != want {
		t.Fatalf("encoded config:\n%s\nwant:\n%s", encoded, want)
	}
}

func TestInstanceConfigPreservesCoreDefaults(t *testing.T) {
	config, err := NewInstanceConfigBuilder("default").
		NetworkSecret("").
		Build()
	if err != nil {
		t.Fatalf("build config: %v", err)
	}

	encoded, err := encodeInstanceConfig(config)
	if err != nil {
		t.Fatalf("encode config: %v", err)
	}
	want := `[network_identity]
network_name = "default"
network_secret = ""
`
	if encoded != want {
		t.Fatalf("encoded config:\n%s\nwant:\n%s", encoded, want)
	}
}

func TestInstanceConfigCanExplicitlyDisableSTUNServers(t *testing.T) {
	config, err := NewInstanceConfigBuilder("default").
		NetworkSecret("").
		STUNServers().
		STUNServersV6().
		Build()
	if err != nil {
		t.Fatalf("build config: %v", err)
	}

	encoded, err := encodeInstanceConfig(config)
	if err != nil {
		t.Fatalf("encode config: %v", err)
	}
	want := `stun_servers = []
stun_servers_v6 = []

[network_identity]
network_name = "default"
network_secret = ""
`
	if encoded != want {
		t.Fatalf("encoded config:\n%s\nwant:\n%s", encoded, want)
	}
}

func TestInstanceConfigValidation(t *testing.T) {
	invalidUTF8 := string([]byte{0xff})
	tests := []struct {
		name      string
		build     func() error
		wantField string
	}{
		{
			name: "nil builder",
			build: func() error {
				var builder *InstanceConfigBuilder
				_, err := builder.Build()
				return err
			},
			wantField: "builder is nil",
		},
		{
			name: "missing network name",
			build: func() error {
				_, err := NewInstanceConfigBuilder("").
					NetworkSecret("").
					Build()
				return err
			},
			wantField: "network.name",
		},
		{
			name: "invalid network name encoding",
			build: func() error {
				_, err := NewInstanceConfigBuilder(invalidUTF8).
					NetworkSecret("").
					Build()
				return err
			},
			wantField: "network.name",
		},
		{
			name: "network secret not specified",
			build: func() error {
				_, err := NewInstanceConfigBuilder("default").Build()
				return err
			},
			wantField: "network.secret",
		},
		{
			name: "invalid network secret encoding",
			build: func() error {
				_, err := NewInstanceConfigBuilder("default").
					NetworkSecret(invalidUTF8).
					Build()
				return err
			},
			wantField: "network.secret",
		},
		{
			name: "empty hostname",
			build: func() error {
				_, err := validInstanceConfigBuilder().Hostname("").Build()
				return err
			},
			wantField: "hostname",
		},
		{
			name: "hostname exceeds core limit",
			build: func() error {
				_, err := validInstanceConfigBuilder().
					Hostname(strings.Repeat("a", 33)).
					Build()
				return err
			},
			wantField: "hostname",
		},
		{
			name: "invalid IPv4 prefix",
			build: func() error {
				_, err := validInstanceConfigBuilder().
					IPv4(netip.Prefix{}).
					Build()
				return err
			},
			wantField: "ipv4",
		},
		{
			name: "IPv6 prefix",
			build: func() error {
				_, err := validInstanceConfigBuilder().
					IPv4(netip.MustParsePrefix("fd00::1/64")).
					Build()
				return err
			},
			wantField: "ipv4",
		},
		{
			name: "IPv4 host prefix",
			build: func() error {
				_, err := validInstanceConfigBuilder().
					IPv4(netip.MustParsePrefix("10.0.0.1/32")).
					Build()
				return err
			},
			wantField: "ipv4",
		},
		{
			name: "unsupported peer scheme",
			build: func() error {
				_, err := validInstanceConfigBuilder().
					AddPeers("ws://peer.example.com:11010").
					Build()
				return err
			},
			wantField: "peers[0]",
		},
		{
			name: "peer port zero",
			build: func() error {
				_, err := validInstanceConfigBuilder().
					AddPeers("tcp://peer.example.com:0").
					Build()
				return err
			},
			wantField: "peers[0]",
		},
		{
			name: "duplicate peer",
			build: func() error {
				_, err := validInstanceConfigBuilder().
					AddPeers(
						"TCP://peer.example.com:11010",
						"tcp://peer.example.com:11010",
					).
					Build()
				return err
			},
			wantField: "peers[1]",
		},
		{
			name: "listener hostname",
			build: func() error {
				_, err := validInstanceConfigBuilder().
					AddListeners("tcp://listener.example.com:11010").
					Build()
				return err
			},
			wantField: "listeners[0]",
		},
		{
			name: "unsupported port forward protocol",
			build: func() error {
				_, err := validInstanceConfigBuilder().
					AddPortForwards(PortForwardConfig{
						Protocol:    "sctp",
						Bind:        netip.MustParseAddrPort("127.0.0.1:5202"),
						Destination: netip.MustParseAddrPort("10.144.0.20:5201"),
					}).
					Build()
				return err
			},
			wantField: "port_forwards[0].protocol",
		},
		{
			name: "IPv6 port forward bind",
			build: func() error {
				_, err := validInstanceConfigBuilder().
					AddPortForwards(PortForwardConfig{
						Protocol:    PortForwardTCP,
						Bind:        netip.MustParseAddrPort("[::1]:5202"),
						Destination: netip.MustParseAddrPort("10.144.0.20:5201"),
					}).
					Build()
				return err
			},
			wantField: "port_forwards[0].bind",
		},
		{
			name: "zero port forward destination port",
			build: func() error {
				_, err := validInstanceConfigBuilder().
					AddPortForwards(PortForwardConfig{
						Protocol:    PortForwardUDP,
						Bind:        netip.MustParseAddrPort("127.0.0.1:5202"),
						Destination: netip.MustParseAddrPort("10.144.0.20:0"),
					}).
					Build()
				return err
			},
			wantField: "port_forwards[0].destination",
		},
		{
			name: "duplicate port forward",
			build: func() error {
				forward := PortForwardConfig{
					Protocol:    PortForwardTCP,
					Bind:        netip.MustParseAddrPort("127.0.0.1:5202"),
					Destination: netip.MustParseAddrPort("10.144.0.20:5201"),
				}
				_, err := validInstanceConfigBuilder().
					AddPortForwards(forward, forward).
					Build()
				return err
			},
			wantField: "port_forwards[1]",
		},
		{
			name: "IPv6 literal in IPv4 STUN list",
			build: func() error {
				_, err := validInstanceConfigBuilder().
					STUNServers("2001:db8::1").
					Build()
				return err
			},
			wantField: "stun_servers[0]",
		},
		{
			name: "IPv4 literal in IPv6 STUN list",
			build: func() error {
				_, err := validInstanceConfigBuilder().
					STUNServersV6("192.0.2.1").
					Build()
				return err
			},
			wantField: "stun_servers_v6[0]",
		},
		{
			name: "duplicate STUN server",
			build: func() error {
				_, err := validInstanceConfigBuilder().
					STUNServers("stun.example.com", "stun.example.com").
					Build()
				return err
			},
			wantField: "stun_servers[1]",
		},
		{
			name: "symmetric UDP without UDP",
			build: func() error {
				_, err := validInstanceConfigBuilder().
					HolePunching(HolePunchingPolicy{SymmetricUDP: true}).
					Build()
				return err
			},
			wantField: "hole_punching.symmetric_udp",
		},
		{
			name: "secure mode without shared secret",
			build: func() error {
				_, err := NewInstanceConfigBuilder("default").
					NetworkSecret("").
					SecureMode().
					Build()
				return err
			},
			wantField: "secure_mode",
		},
		{
			name: "invalid manual private key",
			build: func() error {
				_, err := validInstanceConfigBuilder().
					SecureModeWithPrivateKey(make([]byte, 31)).
					Build()
				return err
			},
			wantField: "secure_mode.private_key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.build()
			if err == nil || !strings.Contains(err.Error(), test.wantField) {
				t.Fatalf("Build() error = %v, want containing %q", err, test.wantField)
			}
		})
	}
}

func TestInstanceConfigCopiesInputsAndRedactsSecrets(t *testing.T) {
	privateKey := bytes.Repeat([]byte{7}, 32)
	peers := []string{"tcp://peer.example.com:11010"}
	builder := NewInstanceConfigBuilder("private-network").
		NetworkSecret("very-secret-value").
		AddPeers(peers...).
		SecureModeWithPrivateKey(privateKey)

	config, err := builder.Build()
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	before, err := encodeInstanceConfig(config)
	if err != nil {
		t.Fatalf("encode config before input mutation: %v", err)
	}

	privateKey[0] = 9
	peers[0] = "udp://other.example.com:11010"
	builder.NetworkSecret("changed-secret").
		AddPeers("tcp://another.example.com:11010")
	after, err := encodeInstanceConfig(config)
	if err != nil {
		t.Fatalf("encode config after input mutation: %v", err)
	}
	if after != before {
		t.Fatalf("built config changed after mutating inputs:\nbefore:\n%s\nafter:\n%s", before, after)
	}

	formatted := []string{
		fmt.Sprintf("%v", config),
		fmt.Sprintf("%+v", config),
		fmt.Sprintf("%#v", config),
		fmt.Sprintf("%v", builder),
		fmt.Sprintf("%+v", *builder),
		fmt.Sprintf("%#v", *builder),
	}
	for _, value := range formatted {
		if strings.Contains(value, "very-secret-value") ||
			strings.Contains(value, "changed-secret") {
			t.Fatalf("formatted configuration exposed a secret: %s", value)
		}
		if !strings.Contains(value, "<redacted>") {
			t.Fatalf("formatted configuration was not redacted: %s", value)
		}
	}
}

func TestAutomaticSecureModeProducesStableKeyPair(t *testing.T) {
	builder := validInstanceConfigBuilder().SecureMode()
	first, err := builder.Build()
	if err != nil {
		t.Fatalf("build first config: %v", err)
	}
	second, err := builder.Build()
	if err != nil {
		t.Fatalf("build second config: %v", err)
	}
	if !bytes.Equal(
		first.document.securePrivateKey,
		second.document.securePrivateKey,
	) {
		t.Fatal("automatic secure-mode key changed between builds")
	}

	privateKey, err := ecdh.X25519().NewPrivateKey(first.document.securePrivateKey)
	if err != nil {
		t.Fatalf("parse generated private key: %v", err)
	}
	encoded, err := encodeInstanceConfig(first)
	if err != nil {
		t.Fatalf("encode config: %v", err)
	}
	privateKeyText := base64.StdEncoding.EncodeToString(privateKey.Bytes())
	publicKeyText := base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes())
	if !strings.Contains(encoded, `local_private_key = "`+privateKeyText+`"`) {
		t.Fatal("encoded config does not contain generated private key")
	}
	if !strings.Contains(encoded, `local_public_key = "`+publicKeyText+`"`) {
		t.Fatal("encoded config does not contain derived public key")
	}
}

func TestZeroInstanceConfigIsInvalid(t *testing.T) {
	if _, err := encodeInstanceConfig(InstanceConfig{}); err == nil {
		t.Fatal("zero InstanceConfig was accepted")
	}
}

func validInstanceConfigBuilder() *InstanceConfigBuilder {
	return NewInstanceConfigBuilder("default").NetworkSecret("secret")
}
