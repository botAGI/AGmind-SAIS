package actuatord

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

type managementDenylistDocument struct {
	DeniedAddresses []string `json:"denied_addresses"`
	DeniedNetworks  []string `json:"denied_networks"`
}

func (document managementDenylistDocument) Validate() error {
	_, err := contracts.PCCManagementDenylistSHA256(
		document.DeniedNetworks,
		document.DeniedAddresses,
	)
	return err
}

type FileSafetyProvider struct {
	registryPath   string
	managementPath string
	read           trustedRootReader
}

func newFileSafetyProvider(
	registryPath string,
	managementPath string,
	read trustedRootReader,
) (*FileSafetyProvider, error) {
	if registryPath != defaultSpecialUseRegistryPath ||
		managementPath != defaultManagementDenylistPath ||
		read == nil {
		return nil, fmt.Errorf("actuator safety paths must match the fixed production profile")
	}
	return &FileSafetyProvider{
		registryPath:   registryPath,
		managementPath: managementPath,
		read:           read,
	}, nil
}

func NewFileSafetyProvider(
	registryPath string,
	managementPath string,
) (*FileSafetyProvider, error) {
	return newFileSafetyProvider(
		registryPath,
		managementPath,
		durablefile.ReadTrustedRoot,
	)
}

func (provider *FileSafetyProvider) Snapshot(
	ctx context.Context,
) (SafetySnapshot, error) {
	if provider == nil || provider.read == nil || ctx == nil {
		return SafetySnapshot{}, fmt.Errorf("invalid actuator file safety provider")
	}
	if err := ctx.Err(); err != nil {
		return SafetySnapshot{}, err
	}
	registryRaw, err := provider.read(
		provider.registryPath,
		runtimeInputMaxBytes,
		0o444,
	)
	if err != nil {
		return SafetySnapshot{}, fmt.Errorf("read special-use registry: %w", err)
	}
	registryRaw = slices.Clone(registryRaw)
	registrySum := sha256.Sum256(registryRaw)
	registrySHA256 := hex.EncodeToString(registrySum[:])
	if registrySHA256 != pinnedSpecialUseRegistrySHA256 {
		return SafetySnapshot{}, fmt.Errorf("special-use registry pin mismatch")
	}
	if err := ctx.Err(); err != nil {
		return SafetySnapshot{}, err
	}
	managementRaw, err := provider.read(
		provider.managementPath,
		runtimeInputMaxBytes,
		0o444,
		0o644,
	)
	if err != nil {
		return SafetySnapshot{}, fmt.Errorf("read management denylist: %w", err)
	}
	management, err := contracts.DecodeStrict[managementDenylistDocument](
		bytes.NewReader(managementRaw),
		runtimeInputMaxBytes,
	)
	if err != nil {
		return SafetySnapshot{}, fmt.Errorf("decode management denylist: %w", err)
	}
	managementSHA256, err := contracts.PCCManagementDenylistSHA256(
		management.DeniedNetworks,
		management.DeniedAddresses,
	)
	if err != nil {
		return SafetySnapshot{}, fmt.Errorf("bind management denylist: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return SafetySnapshot{}, err
	}
	snapshot := SafetySnapshot{
		SpecialUseRegistryRaw:     registryRaw,
		SpecialUseRegistrySHA256:  registrySHA256,
		ManagementDeniedNetworks:  slices.Clone(management.DeniedNetworks),
		ManagementDeniedAddresses: slices.Clone(management.DeniedAddresses),
		ManagementDenylistSHA256:  managementSHA256,
	}
	if _, err := snapshot.validatedRegistry(); err != nil {
		return SafetySnapshot{}, err
	}
	return snapshot, nil
}
