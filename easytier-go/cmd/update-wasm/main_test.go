package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoreArtifactPathUsesCargoTargetDirectory(t *testing.T) {
	source := filepath.Join(string(filepath.Separator), "checkout")
	for _, test := range []struct {
		name           string
		cargoTargetDir string
		wantTargetDir  string
	}{
		{name: "default", wantTargetDir: filepath.Join(source, "target")},
		{
			name:           "relative",
			cargoTargetDir: "build",
			wantTargetDir:  filepath.Join(source, "build"),
		},
		{
			name:           "absolute",
			cargoTargetDir: filepath.Join(string(filepath.Separator), "cache"),
			wantTargetDir:  filepath.Join(string(filepath.Separator), "cache"),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := filepath.Join(test.wantTargetDir, coreArtifact)
			if got := coreArtifactPath(source, test.cargoTargetDir); got != want {
				t.Fatalf("core artifact path = %q, want %q", got, want)
			}
		})
	}
}

func TestReproducibleBuildEnvironmentControlsRustInputs(t *testing.T) {
	t.Setenv("RUSTFLAGS", "-C target-cpu=native")
	t.Setenv("CARGO_ENCODED_RUSTFLAGS", "-C\u001fopt-level=1")
	t.Setenv("SOURCE_DATE_EPOCH", "1")
	environment := reproducibleBuildEnvironment("/checkout", "1700000000")
	joined := strings.Join(environment, "\n")
	if strings.Contains(joined, "target-cpu=native") ||
		strings.Contains(joined, "opt-level=1") {
		t.Fatalf("uncontrolled Rust flags remained in environment:\n%s", joined)
	}
	for _, want := range []string{
		"CARGO_ENCODED_RUSTFLAGS=--remap-path-prefix=/checkout=/workspace/EasyTier",
		"SOURCE_DATE_EPOCH=1700000000",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("build environment does not contain %q", want)
		}
	}
}

func TestProtoSchemaDigestCoversEveryInput(t *testing.T) {
	source := t.TempDir()
	protoRoot := filepath.Join(source, "easytier-proto", "proto")
	if err := os.MkdirAll(protoRoot, 0o755); err != nil {
		t.Fatalf("create proto root: %v", err)
	}
	for _, name := range managementProtoFiles {
		if err := os.WriteFile(
			filepath.Join(protoRoot, name),
			[]byte(name),
			0o644,
		); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	before, err := protoSchemaDigest(source)
	if err != nil {
		t.Fatalf("digest proto schema: %v", err)
	}
	changed := managementProtoFiles[len(managementProtoFiles)-1]
	if err := os.WriteFile(
		filepath.Join(protoRoot, changed),
		[]byte("changed"),
		0o644,
	); err != nil {
		t.Fatalf("change %s: %v", changed, err)
	}
	after, err := protoSchemaDigest(source)
	if err != nil {
		t.Fatalf("digest changed proto schema: %v", err)
	}
	if before == after {
		t.Fatal("schema digest did not change with a protobuf input")
	}
}
