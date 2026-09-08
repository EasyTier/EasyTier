package host

import (
	"strings"
	"testing"
)

func TestStripInstanceIdentityRemovesIdentityKeys(t *testing.T) {
	input := `instance_id = "87ede5a2-9c3d-492d-9bbe-989b9d07e742"
instance_name = "old-name"
hostname = "node-a"
instance_identity = "keep"

[network_identity]
network_name = "example"
`
	got := stripInstanceIdentity(input)
	if strings.Contains(got, "instance_id =") {
		t.Fatalf("instance_id was not stripped:\n%s", got)
	}
	if strings.Contains(got, "instance_name =") {
		t.Fatalf("instance_name was not stripped:\n%s", got)
	}
	if !strings.Contains(got, `hostname = "node-a"`) {
		t.Fatalf("hostname was stripped:\n%s", got)
	}
	if !strings.Contains(got, `instance_identity = "keep"`) {
		t.Fatalf("unrelated key was stripped:\n%s", got)
	}
	if !strings.Contains(got, "[network_identity]") {
		t.Fatalf("network identity section was stripped:\n%s", got)
	}
}

func TestStripInstanceIdentityIgnoresCommentedAndPrefixedKeys(t *testing.T) {
	input := `# instance_id = "commented"
instance_id_backup = "keep"
`
	got := stripInstanceIdentity(input)
	if !strings.Contains(got, `# instance_id = "commented"`) {
		t.Fatalf("comment was stripped:\n%s", got)
	}
	if !strings.Contains(got, `instance_id_backup = "keep"`) {
		t.Fatalf("prefixed key was stripped:\n%s", got)
	}
}

func TestBindInstanceIdentityPrependsCanonicalKeys(t *testing.T) {
	got := bindInstanceIdentity("hostname = \"node\"\n", "11111111-2222-4333-8444-555555555555", "mihomo")
	wantPrefix := `instance_id = "11111111-2222-4333-8444-555555555555"
instance_name = "mihomo"
`
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("bindInstanceIdentity() = %q, want prefix %q", got, wantPrefix)
	}
	if !strings.Contains(got, `hostname = "node"`) {
		t.Fatalf("original config was lost: %q", got)
	}
}
