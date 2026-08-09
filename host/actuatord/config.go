package actuatord

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"fmt"
	"io/fs"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

const (
	DefaultConfigPath                   = "/etc/agmind-sais/actuator.json"
	defaultStateDir                     = "/var/lib/agmind-sais/actuator"
	defaultPrivateKeyPath               = "/etc/agmind-sais/secrets/actuator-ed25519.key"
	defaultObserverSocketPath           = "/run/agmind-sais/observer-actuator/socket"
	defaultIntentSocketPath             = "/run/agmind-sais/actuator-intent/socket"
	defaultAdminSocketPath              = "/run/agmind-sais/actuator-admin/socket"
	defaultManagementDenylistPath       = "/etc/agmind-sais/management-destinations.json"
	defaultSpecialUseRegistryPath       = "/usr/share/agmind-sais/ipv4-special-use.csv"
	runtimeInputMaxBytes          int64 = 65_536
)

type trustedRootReader func(
	string,
	int64,
	...fs.FileMode,
) ([]byte, error)

type Config struct {
	SchemaVersion           string `json:"schema_version"`
	StateDir                string `json:"state_dir"`
	PrivateKeyFile          string `json:"private_key_file"`
	ObserverSocket          string `json:"observer_socket"`
	IntentSocket            string `json:"intent_socket"`
	AdminSocket             string `json:"admin_socket"`
	ManagementDenylistFile  string `json:"management_denylist_file"`
	SpecialUseRegistryFile  string `json:"special_use_registry_file"`
	ApprovalTTLSeconds      uint64 `json:"approval_ttl_seconds"`
	DefaultActionTTLSeconds uint64 `json:"default_action_ttl_seconds"`
}

func (config Config) Validate() error {
	if config.SchemaVersion != "agmind.actuator-config.v1" ||
		config.StateDir != defaultStateDir ||
		config.PrivateKeyFile != defaultPrivateKeyPath ||
		config.ObserverSocket != defaultObserverSocketPath ||
		config.IntentSocket != defaultIntentSocketPath ||
		config.AdminSocket != defaultAdminSocketPath ||
		config.ManagementDenylistFile != defaultManagementDenylistPath ||
		config.SpecialUseRegistryFile != defaultSpecialUseRegistryPath ||
		config.ApprovalTTLSeconds != uint64(ApprovalTTL.Seconds()) ||
		config.DefaultActionTTLSeconds != DefaultTTLSeconds {
		return fmt.Errorf("actuator config must match the fixed production profile")
	}
	return nil
}

func loadConfig(path string, read trustedRootReader) (Config, error) {
	if path != DefaultConfigPath || read == nil {
		return Config{}, fmt.Errorf("actuator config path is not the fixed production path")
	}
	raw, err := read(path, runtimeInputMaxBytes, 0o444, 0o644)
	if err != nil {
		return Config{}, fmt.Errorf("read actuator config: %w", err)
	}
	config, err := contracts.DecodeStrict[Config](
		bytes.NewReader(raw),
		runtimeInputMaxBytes,
	)
	if err != nil {
		return Config{}, fmt.Errorf("decode actuator config: %w", err)
	}
	return config, nil
}

func LoadConfig(path string) (Config, error) {
	return loadConfig(path, durablefile.ReadTrustedRoot)
}

func loadPrivateKey(
	path string,
	read trustedRootReader,
) (ed25519.PrivateKey, error) {
	if path != defaultPrivateKeyPath || read == nil {
		return nil, fmt.Errorf("actuator private key path is not the fixed production path")
	}
	raw, err := read(path, ed25519.PrivateKeySize, 0o400)
	if err != nil {
		return nil, fmt.Errorf("read actuator private key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("actuator private key must be raw 64-byte Ed25519")
	}
	derived := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
	if subtle.ConstantTimeCompare(raw, derived) != 1 {
		return nil, fmt.Errorf("actuator private key seed/public mismatch")
	}
	return append(ed25519.PrivateKey(nil), raw...), nil
}

func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	return loadPrivateKey(path, durablefile.ReadTrustedRoot)
}
