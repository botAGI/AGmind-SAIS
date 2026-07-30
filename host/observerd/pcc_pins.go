package observerd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"slices"

	"agmind.local/sais/internal/contracts"
)

const (
	pccDetectorRulesPath          = "/etc/falco/rules.d/agmind-pcc.yaml"
	pccSpecialUseRegistryPath     = "/usr/share/agmind-sais/ipv4-special-use.csv"
	pccOperatorDenylistPath       = "/etc/agmind-sais/operator-denylist.json"
	pccManagementDestinationsPath = "/etc/agmind-sais/management-destinations.json"

	pccSafetyPinMaxBytes        = int64(65_536)
	pccSpecialUseRegistrySHA256 = "e3e39e76d00b1677335db8e9a805c7b9480ea2f4dc9e33f0b93cd3a905128d73"
)

type PCCSafetyPinSnapshot struct {
	DetectorBundleSHA256      string
	SpecialUseRegistrySHA256  string
	OperatorDeniedNetworks    []string
	OperatorDeniedAddresses   []string
	OperatorDenylistSHA256    string
	ManagementDeniedNetworks  []string
	ManagementDeniedAddresses []string
	ManagementDenylistSHA256  string
}

type pccDenylistDocument struct {
	DeniedAddresses []string `json:"denied_addresses"`
	DeniedNetworks  []string `json:"denied_networks"`
}

func (document pccDenylistDocument) Validate() error {
	if document.DeniedAddresses == nil ||
		document.DeniedNetworks == nil ||
		len(document.DeniedAddresses) > 128 ||
		len(document.DeniedNetworks) > 128 {
		return fmt.Errorf("PCC denylist arrays must be present and bounded")
	}
	if err := validatePCCDeniedAddresses(document.DeniedAddresses); err != nil {
		return err
	}
	if err := validatePCCDeniedNetworks(document.DeniedNetworks); err != nil {
		return err
	}
	return nil
}

func validatePCCDeniedAddresses(addresses []string) error {
	seen := make(map[string]struct{}, len(addresses))
	for _, text := range addresses {
		address, err := netip.ParseAddr(text)
		if err != nil || !address.Is4() || address.String() != text {
			return fmt.Errorf("invalid canonical PCC denied address")
		}
		if _, exists := seen[text]; exists {
			return fmt.Errorf("duplicate PCC denied address")
		}
		seen[text] = struct{}{}
	}
	return nil
}

func validatePCCDeniedNetworks(networks []string) error {
	seen := make(map[string]struct{}, len(networks))
	for _, text := range networks {
		prefix, err := netip.ParsePrefix(text)
		if err != nil ||
			!prefix.Addr().Is4() ||
			prefix.Masked() != prefix ||
			prefix.String() != text {
			return fmt.Errorf("invalid canonical PCC denied network")
		}
		if _, exists := seen[text]; exists {
			return fmt.Errorf("duplicate PCC denied network")
		}
		seen[text] = struct{}{}
	}
	return nil
}

type pccSafetyPinReader func(string, int64) ([]byte, error)

func LoadPCCSafetyPinSnapshot() (PCCSafetyPinSnapshot, error) {
	return loadPCCSafetyPinSnapshot(readSingleLinkRegular, os.Geteuid())
}

func loadPCCSafetyPinSnapshot(
	read pccSafetyPinReader,
	effectiveUID int,
) (PCCSafetyPinSnapshot, error) {
	if effectiveUID != 0 {
		return PCCSafetyPinSnapshot{}, fmt.Errorf(
			"PCC safety pins require a root process",
		)
	}
	detectorRaw, err := readPCCSafetyPin(read, pccDetectorRulesPath)
	if err != nil {
		return PCCSafetyPinSnapshot{}, err
	}
	detectorHash, err := contracts.PCCDetectorBundleSHA256(detectorRaw)
	if err != nil {
		return PCCSafetyPinSnapshot{}, err
	}

	specialUseRaw, err := readPCCSafetyPin(read, pccSpecialUseRegistryPath)
	if err != nil {
		return PCCSafetyPinSnapshot{}, err
	}
	specialUseSum := sha256.Sum256(specialUseRaw)
	specialUseHash := hex.EncodeToString(specialUseSum[:])
	if specialUseHash != pccSpecialUseRegistrySHA256 {
		return PCCSafetyPinSnapshot{}, fmt.Errorf(
			"PCC special-use registry pin mismatch",
		)
	}

	operator, err := readPCCDenylist(read, pccOperatorDenylistPath)
	if err != nil {
		return PCCSafetyPinSnapshot{}, err
	}
	operatorHash, err := contracts.PCCOperatorDenylistSHA256(
		operator.DeniedNetworks,
		operator.DeniedAddresses,
	)
	if err != nil {
		return PCCSafetyPinSnapshot{}, err
	}

	management, err := readPCCDenylist(
		read,
		pccManagementDestinationsPath,
	)
	if err != nil {
		return PCCSafetyPinSnapshot{}, err
	}
	managementHash, err := contracts.PCCManagementDenylistSHA256(
		management.DeniedNetworks,
		management.DeniedAddresses,
	)
	if err != nil {
		return PCCSafetyPinSnapshot{}, err
	}

	return PCCSafetyPinSnapshot{
		DetectorBundleSHA256:      detectorHash,
		SpecialUseRegistrySHA256:  specialUseHash,
		OperatorDeniedNetworks:    slices.Clone(operator.DeniedNetworks),
		OperatorDeniedAddresses:   slices.Clone(operator.DeniedAddresses),
		OperatorDenylistSHA256:    operatorHash,
		ManagementDeniedNetworks:  slices.Clone(management.DeniedNetworks),
		ManagementDeniedAddresses: slices.Clone(management.DeniedAddresses),
		ManagementDenylistSHA256:  managementHash,
	}, nil
}

func readPCCSafetyPin(
	read pccSafetyPinReader,
	path string,
) ([]byte, error) {
	raw, err := read(path, pccSafetyPinMaxBytes)
	if err != nil {
		return nil, fmt.Errorf("read PCC safety pin %s: %w", path, err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("PCC safety pin %s is empty", path)
	}
	return bytes.Clone(raw), nil
}

func readPCCDenylist(
	read pccSafetyPinReader,
	path string,
) (pccDenylistDocument, error) {
	raw, err := readPCCSafetyPin(read, path)
	if err != nil {
		return pccDenylistDocument{}, err
	}
	document, err := contracts.DecodeStrict[pccDenylistDocument](
		bytes.NewReader(raw),
		pccSafetyPinMaxBytes,
	)
	if err != nil {
		return pccDenylistDocument{}, fmt.Errorf(
			"decode PCC denylist %s: %w",
			path,
			err,
		)
	}
	slices.Sort(document.DeniedAddresses)
	slices.Sort(document.DeniedNetworks)
	return document, nil
}
