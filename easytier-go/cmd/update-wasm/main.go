package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	coreArtifact        = "wasm32-wasip1/release/easytier_core_go_host.wasm"
	coreBuildScript     = "script/build-wasi-core.sh"
	protoGenerateScript = "script/generate-proto.sh"
)

var managementProtoFiles = []string{
	"common.proto",
	"error.proto",
	"acl.proto",
	"peer_rpc.proto",
	"api_instance.proto",
	"api_config.proto",
	"api_manage.proto",
	"web.proto",
}

func main() {
	var source string
	flag.StringVar(&source, "easytier", os.Getenv("EASYTIER_SOURCE"), "path to a clean EasyTier checkout")
	flag.Parse()

	if err := update(source); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func update(source string) error {
	workingDirectory, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve generator directory: %w", err)
	}
	moduleFile, err := commandOutput(workingDirectory, "go", "env", "GOMOD")
	if err != nil {
		return err
	}
	if moduleFile == "" || moduleFile == os.DevNull {
		return fmt.Errorf("locate Go module from %s", workingDirectory)
	}
	repositoryRoot := filepath.Dir(moduleFile)
	if source == "" {
		source = filepath.Join(repositoryRoot, "..")
	}
	source, err = filepath.Abs(source)
	if err != nil {
		return fmt.Errorf("resolve EasyTier source: %w", err)
	}
	if _, err := os.Stat(filepath.Join(source, "Cargo.toml")); err != nil {
		return fmt.Errorf("validate EasyTier source %s: %w", source, err)
	}
	if err := requireCleanCheckout(source); err != nil {
		return err
	}
	commit, err := commandOutput(source, "git", "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	sourceDateEpoch, err := commandOutput(source, "git", "show", "-s", "--format=%ct", "HEAD")
	if err != nil {
		return err
	}

	if err := buildCore(source, sourceDateEpoch); err != nil {
		return err
	}
	if err := generateProto(repositoryRoot, source); err != nil {
		return err
	}
	protoDigest, err := protoSchemaDigest(source)
	if err != nil {
		return err
	}

	coreDigest, err := copyArtifact(
		coreArtifactPath(source, os.Getenv("CARGO_TARGET_DIR")),
		filepath.Join(repositoryRoot, "internal", "artifact", "easytier_core.wasm"),
	)
	if err != nil {
		return err
	}
	if err := writeProvenance(repositoryRoot, commit, coreDigest); err != nil {
		return err
	}
	if err := writeProtoProvenance(repositoryRoot, commit, protoDigest); err != nil {
		return err
	}
	fmt.Printf("embedded EasyTier %s (sha256 %s)\n", commit, coreDigest)
	return nil
}

func coreArtifactPath(source, cargoTargetDirectory string) string {
	if cargoTargetDirectory == "" {
		cargoTargetDirectory = "target"
	}
	if !filepath.IsAbs(cargoTargetDirectory) {
		cargoTargetDirectory = filepath.Join(source, cargoTargetDirectory)
	}
	return filepath.Join(cargoTargetDirectory, coreArtifact)
}

func requireCleanCheckout(source string) error {
	status, err := commandOutput(source, "git", "status", "--porcelain", "--untracked-files=no")
	if err != nil {
		return err
	}
	if status != "" {
		return fmt.Errorf("EasyTier checkout is dirty:\n%s", status)
	}
	return nil
}

func commandOutput(directory, name string, args ...string) (string, error) {
	command := exec.Command(name, args...)
	command.Dir = directory
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("run %s: %w\n%s", name, err, output)
	}
	return strings.TrimSpace(string(output)), nil
}

func buildCore(source, sourceDateEpoch string) error {
	command := exec.Command("bash", filepath.Join(source, coreBuildScript))
	command.Dir = source
	command.Env = reproducibleBuildEnvironment(source, sourceDateEpoch)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("run EasyTier WASI build script: %w", err)
	}
	return nil
}

func generateProto(repositoryRoot, source string) error {
	command := exec.Command(
		"bash",
		filepath.Join(repositoryRoot, protoGenerateScript),
		source,
	)
	command.Dir = repositoryRoot
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("generate EasyTier Go protobuf bindings: %w", err)
	}
	return nil
}

func protoSchemaDigest(source string) (string, error) {
	digest := sha256.New()
	protoRoot := filepath.Join(source, "easytier-proto", "proto")
	for _, name := range managementProtoFiles {
		contents, err := os.ReadFile(filepath.Join(protoRoot, name))
		if err != nil {
			return "", fmt.Errorf("read EasyTier protobuf source %s: %w", name, err)
		}
		digest.Write([]byte(name))
		digest.Write([]byte{0})
		digest.Write(contents)
		digest.Write([]byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func reproducibleBuildEnvironment(source, sourceDateEpoch string) []string {
	environment := make([]string, 0, len(os.Environ())+3)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "RUSTFLAGS=") ||
			strings.HasPrefix(entry, "CARGO_ENCODED_RUSTFLAGS=") ||
			strings.HasPrefix(entry, "SOURCE_DATE_EPOCH=") {
			continue
		}
		environment = append(environment, entry)
	}
	remap := "--remap-path-prefix=" + source + "=/workspace/EasyTier"
	return append(
		environment,
		"RUSTFLAGS=",
		"CARGO_ENCODED_RUSTFLAGS="+remap,
		"SOURCE_DATE_EPOCH="+sourceDateEpoch,
	)
}

func copyArtifact(source, destination string) (string, error) {
	contents, err := os.ReadFile(source)
	if err != nil {
		return "", fmt.Errorf("read artifact %s: %w", source, err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return "", fmt.Errorf("create artifact directory: %w", err)
	}
	if err := os.WriteFile(destination, contents, 0o644); err != nil {
		return "", fmt.Errorf("write artifact %s: %w", destination, err)
	}
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:]), nil
}

func writeProvenance(repositoryRoot, commit, digest string) error {
	source := fmt.Sprintf(`// Code generated by go generate; DO NOT EDIT.

package artifact

const (
	Commit = %q
	SHA256 = %q
)
`, commit, digest)
	formatted, err := format.Source([]byte(source))
	if err != nil {
		return fmt.Errorf("format provenance: %w", err)
	}
	path := filepath.Join(repositoryRoot, "internal", "artifact", "provenance.go")
	if err := os.WriteFile(path, formatted, 0o644); err != nil {
		return fmt.Errorf("write provenance: %w", err)
	}
	return nil
}

func writeProtoProvenance(repositoryRoot, commit, digest string) error {
	source := fmt.Sprintf(`// Code generated by go generate; DO NOT EDIT.

package proto

const (
	EasyTierCommit = %q
	SchemaSHA256 = %q
)
`, commit, digest)
	formatted, err := format.Source([]byte(source))
	if err != nil {
		return fmt.Errorf("format protobuf provenance: %w", err)
	}
	path := filepath.Join(repositoryRoot, "proto", "provenance.go")
	if err := os.WriteFile(path, formatted, 0o644); err != nil {
		return fmt.Errorf("write protobuf provenance: %w", err)
	}
	return nil
}
