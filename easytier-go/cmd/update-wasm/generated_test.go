package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/easytier/easytier/easytier-go/internal/artifact"
	"github.com/easytier/easytier/easytier-go/proto"
)

// The embedded core and the schema digest must match the checked-in
// provenance; otherwise the host reports a fingerprint that does not
// describe what it runs.
func TestGeneratedArtifactsMatchProvenance(t *testing.T) {
	moduleRoot := filepath.Join("..", "..")

	wasm, err := os.ReadFile(filepath.Join(moduleRoot, "internal", "artifact", "easytier_core.wasm"))
	if err != nil {
		t.Fatalf("read embedded core: %v", err)
	}
	sum := sha256.Sum256(wasm)
	if got := hex.EncodeToString(sum[:]); got != artifact.SHA256 {
		t.Fatalf("embedded core sha256 = %s, provenance says %s", got, artifact.SHA256)
	}

	digest, err := protoSchemaDigest(filepath.Join(moduleRoot, ".."))
	if err != nil {
		t.Fatalf("compute protobuf schema digest: %v", err)
	}
	if digest != proto.SchemaSHA256 {
		t.Fatalf("protobuf schema digest = %s, provenance says %s", digest, proto.SchemaSHA256)
	}

	if artifact.Commit != proto.EasyTierCommit {
		t.Fatalf("artifact commit = %s, protobuf provenance commit = %s; both must describe the same source tree", artifact.Commit, proto.EasyTierCommit)
	}
}
