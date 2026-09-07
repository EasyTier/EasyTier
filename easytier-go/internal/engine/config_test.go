package engine

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/EasyTier/EasyTier/easytier-go/platform"
)

func TestEncodeCreateEnvelopeOwnsVersionAndEnvironmentSchema(t *testing.T) {
	ipv4 := netip.MustParseAddr("198.51.100.4")
	ipv6 := netip.MustParseAddr("2001:db8::4")
	encoded, err := encodeCreateEnvelope("instance_name = \"test\"\n", platform.EnvironmentSnapshot{
		PublicIPv4:      &ipv4,
		InterfaceIPv6s:  []netip.Addr{ipv6},
		MappedListeners: []string{"tcp://127.0.0.1:11010"},
		PreferredIPv6Sources: []platform.PreferredIPv6Source{{
			IP:      ipv6,
			IfIndex: 7,
		}},
	})
	if err != nil {
		t.Fatalf("encode create envelope: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("decode create envelope: %v", err)
	}
	if document["version"] != float64(createConfigVersion) {
		t.Fatalf("version = %v, want %d", document["version"], createConfigVersion)
	}
	environment := document["environment"].(map[string]any)
	if environment["public_ipv4"] != ipv4.String() {
		t.Fatalf("public_ipv4 = %v", environment["public_ipv4"])
	}
	if environment["public_ipv6"] != nil {
		t.Fatalf("public_ipv6 = %v, want nil", environment["public_ipv6"])
	}
	if got := environment["preferred_ipv6_sources"].([]any)[0].(map[string]any)["ifindex"]; got != float64(7) {
		t.Fatalf("preferred IPv6 ifindex = %v", got)
	}
	if environment["interface_ipv4s"] == nil || environment["local_ips"] == nil {
		t.Fatal("empty environment collections encoded as null")
	}
}

func TestEncodeCreateEnvelopeRejectsWrongAddressFamily(t *testing.T) {
	ipv6 := netip.MustParseAddr("2001:db8::1")
	_, err := encodeCreateEnvelope("instance_name = \"test\"\n", platform.EnvironmentSnapshot{
		PublicIPv4: &ipv6,
	})
	if err == nil {
		t.Fatal("accepted IPv6 public address as public IPv4")
	}
}
