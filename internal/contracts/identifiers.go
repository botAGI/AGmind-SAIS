package contracts

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
)

func EventID(event EventEnvelopeV1) (string, error) {
	if err := event.Validate(); err != nil {
		return "", err
	}
	digest, err := hex.DecodeString(event.NormalizedFieldsSHA256)
	if err != nil || len(digest) != sha256.Size {
		return "", fmt.Errorf("invalid normalized_fields_sha256")
	}
	preimage := []byte("AGMIND_EVENT_ID_V1\x00" + event.HostID + "\x00" + event.BootID + "\x00")
	var numbers [16]byte
	binary.BigEndian.PutUint64(numbers[:8], event.KeyEpoch)
	binary.BigEndian.PutUint64(numbers[8:], event.SourceSequence)
	preimage = append(preimage, numbers[:]...)
	preimage = append(preimage, digest...)
	sum := sha256.Sum256(preimage)
	return "evt_" + hex.EncodeToString(sum[:]), nil
}

func ReleaseID(imageID, immutableSpecSHA256 string) (string, error) {
	if len(imageID) == 0 || len(immutableSpecSHA256) == 0 {
		return "", fmt.Errorf("release derivation fields must not be empty")
	}
	sum := sha256.Sum256([]byte(
		"AGMIND_RELEASE_ID_V1\x00" + imageID + "\x00" + immutableSpecSHA256,
	))
	return "rel_" + hex.EncodeToString(sum[:])[:32], nil
}

func CandidateID(
	eventID,
	dockerContainerID,
	dockerStartedAt,
	destinationIPv4,
	detectorBundleSHA256 string,
) (string, error) {
	fields := []string{
		eventID,
		dockerContainerID,
		dockerStartedAt,
		destinationIPv4,
		detectorBundleSHA256,
	}
	for _, field := range fields {
		if field == "" {
			return "", fmt.Errorf("candidate derivation fields must not be empty")
		}
	}
	preimage := []byte("AGMIND_CANDIDATE_ID_V1\x00" + fields[0])
	for _, field := range fields[1:] {
		preimage = append(preimage, 0)
		preimage = append(preimage, field...)
	}
	sum := sha256.Sum256(preimage)
	return "cand_" + hex.EncodeToString(sum[:]), nil
}

func IntentID(candidateID, policyBundleSHA256 string, ttlSeconds uint64) (string, error) {
	if candidateID == "" || policyBundleSHA256 == "" {
		return "", fmt.Errorf("intent derivation fields must not be empty")
	}
	preimage := []byte(
		"AGMIND_INTENT_ID_V1\x00" + candidateID + "\x00" +
			policyBundleSHA256 + "\x00" + strconv.FormatUint(ttlSeconds, 10),
	)
	sum := sha256.Sum256(preimage)
	return "int_" + hex.EncodeToString(sum[:])[:32], nil
}

func PlanID(intentID string, nonce []byte) (string, error) {
	if intentID == "" || len(nonce) == 0 {
		return "", fmt.Errorf("plan derivation fields must not be empty")
	}
	preimage := append([]byte("AGMIND_PLAN_ID_V1\x00"+intentID+"\x00"), nonce...)
	sum := sha256.Sum256(preimage)
	return "plan_" + hex.EncodeToString(sum[:])[:32], nil
}

func PlanHash(plan PreparedTemporaryEgressDenyPlanV1) (string, error) {
	raw, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return "", err
	}
	delete(document, "plan_hash")
	canonical, err := CanonicalJSON(document)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("AGMIND_PLAN_HASH_V1\x00"), canonical...))
	return hex.EncodeToString(sum[:]), nil
}

func ActionID(planHash string) (string, error) {
	digest, err := hex.DecodeString(planHash)
	if err != nil || len(digest) != sha256.Size {
		return "", fmt.Errorf("invalid plan_hash")
	}
	sum := sha256.Sum256(append([]byte("AGMIND_ACTION_ID_V1\x00"), digest...))
	return "act_" + hex.EncodeToString(sum[:])[:32], nil
}

func ActionRecordHash(record ActionRecordV1) (string, error) {
	raw, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return "", err
	}
	delete(document, "record_id")
	delete(document, "record_sha256")
	delete(document, "actuator_signature")
	canonical, err := CanonicalJSON(document)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(
		append([]byte("AGMIND_ACTION_RECORD_HASH_V1\x00"), canonical...),
	)
	return hex.EncodeToString(sum[:]), nil
}

func ActionRecordID(recordSHA256 string) string {
	if len(recordSHA256) < 32 {
		return ""
	}
	return "ar_" + recordSHA256[:32]
}

func KeyID(publicKey []byte) (string, error) {
	if len(publicKey) != 32 {
		return "", fmt.Errorf("Ed25519 public key must contain 32 bytes")
	}
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])[:32], nil
}
