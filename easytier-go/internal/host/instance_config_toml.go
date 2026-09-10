package host

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

func encodeInstanceConfig(config InstanceConfig) (string, error) {
	if config.document == nil {
		return "", invalidInstanceConfig("", "configuration was not built")
	}
	document := config.document
	var encoded strings.Builder

	if document.hostname != nil {
		writeTOMLStringField(&encoded, "hostname", *document.hostname)
	}
	if document.ipv4 != nil {
		writeTOMLStringField(&encoded, "ipv4", document.ipv4.String())
	}
	if len(document.listeners) != 0 {
		writeTOMLStringArrayField(&encoded, "listeners", document.listeners)
	}
	if document.stunServersSet {
		writeTOMLStringArrayField(&encoded, "stun_servers", document.stunServers)
	}
	if document.stunServersV6Set {
		writeTOMLStringArrayField(&encoded, "stun_servers_v6", document.stunServersV6)
	}
	if encoded.Len() != 0 {
		encoded.WriteByte('\n')
	}

	encoded.WriteString("[network_identity]\n")
	writeTOMLStringField(&encoded, "network_name", document.networkName)
	writeTOMLStringField(&encoded, "network_secret", document.networkSecret)

	for _, peer := range document.peers {
		encoded.WriteString("\n[[peer]]\n")
		writeTOMLStringField(&encoded, "uri", peer)
	}

	for _, forward := range document.portForwards {
		encoded.WriteString("\n[[port_forward]]\n")
		writeTOMLStringField(&encoded, "bind_addr", forward.Bind.String())
		writeTOMLStringField(
			&encoded,
			"dst_addr",
			forward.Destination.String(),
		)
		writeTOMLStringField(&encoded, "proto", string(forward.Protocol))
	}

	if document.encryption != nil ||
		document.p2p != nil ||
		document.holePunching != nil {
		encoded.WriteString("\n[flags]\n")
		if document.encryption != nil {
			writeTOMLBoolField(&encoded, "enable_encryption", *document.encryption)
		}
		if document.p2p != nil {
			writeTOMLBoolField(&encoded, "disable_p2p", document.p2p.Disable)
			writeTOMLBoolField(&encoded, "need_p2p", document.p2p.Need)
			writeTOMLBoolField(&encoded, "lazy_p2p", document.p2p.Lazy)
		}
		if document.holePunching != nil {
			writeTOMLBoolField(
				&encoded,
				"disable_tcp_hole_punching",
				!document.holePunching.TCP,
			)
			writeTOMLBoolField(
				&encoded,
				"disable_udp_hole_punching",
				!document.holePunching.UDP,
			)
			writeTOMLBoolField(
				&encoded,
				"disable_sym_hole_punching",
				!document.holePunching.SymmetricUDP,
			)
		}
	}

	if document.secureMode != secureModeDisabled {
		privateKey, err := ecdh.X25519().NewPrivateKey(document.securePrivateKey)
		if err != nil {
			return "", invalidInstanceConfig(
				"secure_mode.private_key",
				"is not a valid X25519 private key",
			)
		}
		encoded.WriteString("\n[secure_mode]\n")
		writeTOMLBoolField(&encoded, "enabled", true)
		writeTOMLStringField(
			&encoded,
			"local_private_key",
			base64.StdEncoding.EncodeToString(privateKey.Bytes()),
		)
		writeTOMLStringField(
			&encoded,
			"local_public_key",
			base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
		)
	}

	return encoded.String(), nil
}

func writeTOMLStringField(encoded *strings.Builder, name string, value string) {
	fmt.Fprintf(encoded, "%s = %s\n", name, quoteTOMLString(value))
}

func writeTOMLBoolField(encoded *strings.Builder, name string, value bool) {
	fmt.Fprintf(encoded, "%s = %t\n", name, value)
}

func writeTOMLStringArrayField(
	encoded *strings.Builder,
	name string,
	values []string,
) {
	fmt.Fprintf(encoded, "%s = [", name)
	for index, value := range values {
		if index != 0 {
			encoded.WriteString(", ")
		}
		encoded.WriteString(quoteTOMLString(value))
	}
	encoded.WriteString("]\n")
}

func quoteTOMLString(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic("encoding a validated Go string as JSON cannot fail")
	}
	return string(encoded)
}

func stripInstanceIdentity(configTOML string) string {
	var kept []string
	for _, line := range strings.Split(configTOML, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "instance_id") || strings.HasPrefix(trimmed, "instance_name") {
			key := trimmed
			if idx := strings.IndexByte(trimmed, '='); idx >= 0 {
				key = strings.TrimSpace(trimmed[:idx])
			}
			if key == "instance_id" || key == "instance_name" {
				continue
			}
		}
		kept = append(kept, line)
	}
	return strings.TrimSpace(strings.Join(kept, "\n"))
}
