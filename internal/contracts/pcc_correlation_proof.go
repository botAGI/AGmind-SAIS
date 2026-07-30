package contracts

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
)

const (
	pccCorrelationRequestSchema     = "agmind.pcc-correlation-snapshot-request.v1"
	pccFalcoTriggerProjectionSchema = "agmind.pcc-falco-trigger-projection.v1"
	pccCorrelationSnapshotSchema    = "agmind.pcc-correlation-snapshot.v1"
	pccAdapterSchemaVersion         = "agmind.falco-connect.v1"
	pccFalcoVersion                 = "0.44.1"
	pccDetectorRule                 = "AGmind PCC Suspicious Process Outbound Connect"
	pccDetectorRuleVersion          = "agmind-pcc-rules-v1"
	pccSpecialUseRegistrySHA256     = "e3e39e76d00b1677335db8e9a805c7b9480ea2f4dc9e33f0b93cd3a905128d73"
	pccDetectorBundleDomain         = "AGMIND_DETECTOR_BUNDLE_V1\x00"
	pccDockerNetworkSnapshotDomain  = "AGMIND_DOCKER_NETWORK_SNAPSHOT_V1\x00"
	pccOperatorDenylistDomain       = "AGMIND_OPERATOR_DENYLIST_V1\x00"
	pccManagementDenylistDomain     = "AGMIND_MANAGEMENT_DENYLIST_V1\x00"
	pccBootTransitionChainDomain    = "AGMIND_BOOT_TRANSITION_CHAIN_V1\x00"
)

// UnmarshalJSON preserves the security-relevant distinction between an absent
// optional evt_rawres and an explicitly null nested value. DecodeStrict's
// outer raw-object check cannot otherwise observe null inside snapshot.trigger.
func (trigger *PCCFalcoTriggerProjectionV1) UnmarshalJSON(raw []byte) error {
	type triggerWithoutMethods PCCFalcoTriggerProjectionV1
	var decoded triggerWithoutMethods
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for _, field := range requiredJSONFields(reflect.TypeOf(decoded)) {
		value, exists := fields[field]
		if !exists {
			return fmt.Errorf("missing required nested trigger property: %s", field)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf(
				"required nested trigger property must not be null: %s",
				field,
			)
		}
	}
	for field, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("nested trigger null is forbidden: %s", field)
		}
	}
	*trigger = PCCFalcoTriggerProjectionV1(decoded)
	return nil
}

// PCCCorrelationRequestSHA256 hashes the exact canonical narrow request. The
// frozen contract deliberately adds no domain prefix at this boundary.
func PCCCorrelationRequestSHA256(
	request PCCCorrelationSnapshotRequestV1,
) (string, error) {
	if err := request.Validate(); err != nil {
		return "", err
	}
	canonical, err := CanonicalJSON(request)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// PCCDetectorBundleSHA256 binds exact deployed rule bytes to fixed adapter and
// Falco version pins using uint64 big-endian length prefixes.
func PCCDetectorBundleSHA256(ruleFileBytes []byte) (string, error) {
	values := [][]byte{
		ruleFileBytes,
		[]byte(pccAdapterSchemaVersion),
		[]byte(pccFalcoVersion),
	}
	preimage := []byte(pccDetectorBundleDomain)
	var length [8]byte
	for _, value := range values {
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		preimage = append(preimage, length[:]...)
		preimage = append(preimage, value...)
	}
	sum := sha256.Sum256(preimage)
	return hex.EncodeToString(sum[:]), nil
}

type pccDenylistHashPayload struct {
	DeniedAddresses []string `json:"denied_addresses"`
	DeniedNetworks  []string `json:"denied_networks"`
}

func pccDenylistSHA256(
	domain string,
	deniedNetworks,
	deniedAddresses []string,
) (string, error) {
	if err := validatePCCDenylist(
		deniedNetworks,
		deniedAddresses,
	); err != nil {
		return "", err
	}
	canonical, err := CanonicalJSON(pccDenylistHashPayload{
		DeniedAddresses: deniedAddresses,
		DeniedNetworks:  deniedNetworks,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(domain), canonical...))
	return hex.EncodeToString(sum[:]), nil
}

func PCCOperatorDenylistSHA256(
	deniedNetworks,
	deniedAddresses []string,
) (string, error) {
	return pccDenylistSHA256(
		pccOperatorDenylistDomain,
		deniedNetworks,
		deniedAddresses,
	)
}

func PCCManagementDenylistSHA256(
	deniedNetworks,
	deniedAddresses []string,
) (string, error) {
	return pccDenylistSHA256(
		pccManagementDenylistDomain,
		deniedNetworks,
		deniedAddresses,
	)
}

func PCCDockerNetworkSnapshotSHA256(
	networks []PCCDockerNetworkV1,
) (string, error) {
	if err := validatePCCDockerNetworks(networks); err != nil {
		return "", err
	}
	canonical, err := CanonicalJSON(networks)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(
		append([]byte(pccDockerNetworkSnapshotDomain), canonical...),
	)
	return hex.EncodeToString(sum[:]), nil
}

func PCCBootTransitionChainSHA256(
	hops []PCCBootTransitionHopV1,
) (string, error) {
	if err := validatePCCBootTransitionChain(hops); err != nil {
		return "", err
	}
	canonical, err := CanonicalJSON(hops)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(
		append([]byte(pccBootTransitionChainDomain), canonical...),
	)
	return hex.EncodeToString(sum[:]), nil
}
