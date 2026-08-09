package actuatord

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"testing"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

func TestProductionRuntimeInputsAreFreshStrictAndRootBound(t *testing.T) {
	registry, err := os.ReadFile("../../contracts/v1/ipv4-special-use.csv")
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	configRaw := []byte(`{
		"schema_version":"agmind.actuator-config.v1",
		"state_dir":"/var/lib/agmind-sais/actuator",
		"private_key_file":"/etc/agmind-sais/secrets/actuator-ed25519.key",
		"observer_socket":"/run/agmind-sais/observer-actuator/socket",
		"intent_socket":"/run/agmind-sais/actuator-intent/socket",
		"admin_socket":"/run/agmind-sais/actuator-admin/socket",
		"management_denylist_file":"/etc/agmind-sais/management-destinations.json",
		"special_use_registry_file":"/usr/share/agmind-sais/ipv4-special-use.csv",
		"approval_ttl_seconds":300,
		"default_action_ttl_seconds":120
	}`)
	inputs := map[string][]byte{
		DefaultConfigPath:             configRaw,
		defaultPrivateKeyPath:         privateKey,
		defaultSpecialUseRegistryPath: registry,
		defaultManagementDenylistPath: []byte(
			`{"denied_addresses":["10.0.0.2","192.0.2.9"],` +
				`"denied_networks":["10.0.0.0/8","192.0.2.0/24"]}`,
		),
	}
	type readCall struct {
		path     string
		maxBytes int64
		modes    []fs.FileMode
	}
	var calls []readCall
	reader := func(
		path string,
		maxBytes int64,
		allowedModes ...fs.FileMode,
	) ([]byte, error) {
		calls = append(calls, readCall{
			path:     path,
			maxBytes: maxBytes,
			modes:    slices.Clone(allowedModes),
		})
		raw, ok := inputs[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		if int64(len(raw)) > maxBytes {
			return nil, durablefile.ErrUnsafePath
		}
		return bytes.Clone(raw), nil
	}

	config, err := loadConfig(DefaultConfigPath, reader)
	if err != nil {
		t.Fatal(err)
	}
	if config.StateDir != defaultStateDir ||
		config.ApprovalTTLSeconds != 300 ||
		config.DefaultActionTTLSeconds != 120 {
		t.Fatalf("unexpected strict config: %+v", config)
	}
	if len(calls) != 1 || calls[0].path != DefaultConfigPath ||
		!slices.Equal(calls[0].modes, []fs.FileMode{0o444, 0o644}) {
		t.Fatalf("config read contract: %#v", calls)
	}
	inputs[DefaultConfigPath] = bytes.Replace(
		configRaw,
		[]byte(`"state_dir":"/var/lib/agmind-sais/actuator"`),
		[]byte(`"state_dir":"/tmp/actuator"`),
		1,
	)
	if _, err := loadConfig(DefaultConfigPath, reader); err == nil {
		t.Fatal("config-selected trust path was accepted")
	}
	inputs[DefaultConfigPath] = append(bytes.Clone(configRaw), []byte("{}")...)
	if _, err := loadConfig(DefaultConfigPath, reader); err == nil {
		t.Fatal("trailing config data was accepted")
	}
	inputs[DefaultConfigPath] = configRaw

	loadedKey, err := loadPrivateKey(defaultPrivateKeyPath, reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loadedKey, privateKey) {
		t.Fatal("private key bytes changed")
	}
	loadedKey[0] ^= 0xff
	if bytes.Equal(loadedKey, inputs[defaultPrivateKeyPath]) {
		t.Fatal("private key aliases reader storage")
	}
	inputs[defaultPrivateKeyPath] = privateKey[:ed25519.PrivateKeySize-1]
	if _, err := loadPrivateKey(defaultPrivateKeyPath, reader); err == nil {
		t.Fatal("non-64-byte private key was accepted")
	}
	inputs[defaultPrivateKeyPath] = append([]byte(nil), privateKey...)
	inputs[defaultPrivateKeyPath][ed25519.SeedSize] ^= 0xff
	if _, err := loadPrivateKey(defaultPrivateKeyPath, reader); err == nil {
		t.Fatal("seed/public mismatch was accepted")
	}
	inputs[defaultPrivateKeyPath] = privateKey

	provider, err := newFileSafetyProvider(
		defaultSpecialUseRegistryPath,
		defaultManagementDenylistPath,
		reader,
	)
	if err != nil {
		t.Fatal(err)
	}
	first, err := provider.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wantFirstHash, err := contracts.PCCManagementDenylistSHA256(
		[]string{"10.0.0.0/8", "192.0.2.0/24"},
		[]string{"10.0.0.2", "192.0.2.9"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if first.SpecialUseRegistrySHA256 != pinnedSpecialUseRegistrySHA256 ||
		first.ManagementDenylistSHA256 != wantFirstHash {
		t.Fatalf("unexpected safety binding: %+v", first)
	}
	first.SpecialUseRegistryRaw[0] ^= 0xff
	first.ManagementDeniedAddresses[0] = "8.8.8.8"
	inputs[defaultManagementDenylistPath] = []byte(
		`{"denied_addresses":["172.16.0.2"],` +
			`"denied_networks":["172.16.0.0/12"]}`,
	)
	second, err := provider.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second.SpecialUseRegistryRaw, registry) ||
		!reflect.DeepEqual(second.ManagementDeniedAddresses, []string{"172.16.0.2"}) {
		t.Fatalf("safety provider reused mutable/cached input: %+v", second)
	}
	if len(calls) < 2 ||
		calls[len(calls)-2].path != defaultSpecialUseRegistryPath ||
		calls[len(calls)-1].path != defaultManagementDenylistPath {
		t.Fatalf("fresh safety read order: %#v", calls)
	}
	inputs[defaultManagementDenylistPath] = []byte(
		`{"denied_addresses":["192.0.2.9","10.0.0.2"],` +
			`"denied_networks":[]}`,
	)
	if _, err := provider.Snapshot(context.Background()); err == nil {
		t.Fatal("non-sorted management denylist was accepted")
	}
	inputs[defaultManagementDenylistPath] = []byte(
		`{"denied_addresses":[],"denied_networks":[]}`,
	)
	inputs[defaultSpecialUseRegistryPath] = append(bytes.Clone(registry), '\n')
	if _, err := provider.Snapshot(context.Background()); err == nil {
		t.Fatal("unpinned IANA registry was accepted")
	}

	trustedSystemFile := "/etc/hosts"
	if runtime.GOOS == "darwin" {
		trustedSystemFile = "/private/etc/hosts"
	}
	trustedSystemRaw, err := durablefile.ReadTrustedRoot(
		trustedSystemFile,
		65_536,
		0o644,
	)
	if err != nil || len(trustedSystemRaw) == 0 {
		t.Fatalf("root-owned trusted read: bytes=%d, error=%v", len(trustedSystemRaw), err)
	}

	root := t.TempDir()
	regular := filepath.Join(root, "trusted")
	if err := os.WriteFile(regular, []byte("trusted"), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := durablefile.ReadTrustedRoot(regular, 16, 0o444); !errors.Is(
		err,
		durablefile.ErrUnsafePath,
	) {
		t.Fatalf("untrusted temporary path result: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if _, err := durablefile.ReadTrustedRoot(link, 16, 0o444); err == nil {
		t.Fatal("trusted reader followed a final symlink")
	}
	if err := os.Chmod(regular, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := durablefile.ReadTrustedRoot(regular, 16, 0o444); err == nil {
		t.Fatal("trusted reader accepted a mode outside its exact allowlist")
	}
}
