package contracts

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"time"
)

func EventID(event EventEnvelopeV1) (string, error) {
	digest, err := hex.DecodeString(event.NormalizedFieldsSHA256)
	if err != nil || len(digest) != sha256.Size {
		return "", fmt.Errorf("invalid normalized_fields_sha256")
	}
	if err := validateEventEnvelope(event); err != nil {
		return "", err
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

var (
	hex64          = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex32          = regexp.MustCompile(`^[0-9a-f]{32}$`)
	uuid4          = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	utcRFC3339Nano = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$`)
)

func validUTC(value string) bool {
	if !utcRFC3339Nano.MatchString(value) {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, value)
	return err == nil
}

func validateEventEnvelope(event EventEnvelopeV1) error {
	if event.SchemaVersion != "agmind.event-envelope.v1" {
		return fmt.Errorf("unsupported event schema version")
	}
	if !regexp.MustCompile(`^evt_[0-9a-f]{64}$`).MatchString(event.EventID) {
		return fmt.Errorf("invalid event_id")
	}
	if !hex32.MatchString(event.KeyID) || !uuid4.MatchString(event.HostID) || !uuid4.MatchString(event.BootID) {
		return fmt.Errorf("invalid event identity")
	}
	if !validUTC(event.EventTime) || !validUTC(event.IngestTime) {
		return fmt.Errorf("timestamps must be UTC RFC3339Nano")
	}
	if event.ClockUncertaintyMS > 2000 || !hex64.MatchString(event.NormalizedFieldsSHA256) || !hex64.MatchString(event.SourcePayloadHash) {
		return fmt.Errorf("invalid event bounds or digest")
	}
	if !regexp.MustCompile(`^[0-9a-f]{128}$`).MatchString(event.SourceSignature) {
		return fmt.Errorf("invalid source signature")
	}
	canonical, err := CanonicalJSON(event.NormalizedFields)
	if err != nil {
		return err
	}
	if len(canonical) > 32*1024 {
		return fmt.Errorf("normalized fields exceed 32 KiB")
	}
	return nil
}

func validateIntent(intent TemporaryEgressDenyIntentV1) error {
	if intent.SchemaVersion != "agmind.temporary-egress-deny-intent.v1" || intent.Verb != "temporary_egress_deny" {
		return fmt.Errorf("unsupported intent")
	}
	if !regexp.MustCompile(`^int_[0-9a-f]{32}$`).MatchString(intent.IntentID) || !uuid4.MatchString(intent.HostID) || !hex64.MatchString(intent.DockerContainerID) || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(intent.ImageID) {
		return fmt.Errorf("invalid intent identity")
	}
	address, err := netip.ParseAddr(intent.DestinationIPv4)
	if err != nil || !address.Is4() || address.String() != intent.DestinationIPv4 {
		return fmt.Errorf("invalid canonical IPv4")
	}
	if intent.TTLSeconds < 30 || intent.TTLSeconds > 300 || len(intent.EvidenceIDs) < 1 || len(intent.EvidenceIDs) > 32 {
		return fmt.Errorf("invalid intent bounds")
	}
	if !validUTC(intent.DockerStartedAt) || !validUTC(intent.CreatedAt) {
		return fmt.Errorf("timestamps must be UTC RFC3339Nano")
	}
	for _, digest := range []string{intent.ImmutableSpecSHA256, intent.DetectorBundleSHA256, intent.PolicyBundleSHA256, intent.CoverageSnapshotSHA256} {
		if !hex64.MatchString(digest) {
			return fmt.Errorf("invalid sha256 digest")
		}
	}
	return nil
}
