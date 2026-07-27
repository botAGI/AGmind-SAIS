package contracts

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

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

func boundedUTF8(value string, minimum, maximum int) bool {
	return utf8.ValidString(value) && len([]byte(value)) >= minimum && len([]byte(value)) <= maximum
}

func boundedASCII(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, r := range value {
		if r > 0x7f {
			return false
		}
	}
	return true
}

func sortedUnique(values []string) bool {
	if len(values) == 0 {
		return true
	}
	for i, value := range values {
		if i > 0 && values[i-1] >= value {
			return false
		}
	}
	return true
}

func validRepoDigests(values []string) bool {
	if len(values) > 16 || !sortedUnique(values) {
		return false
	}
	for _, value := range values {
		if !boundedUTF8(value, 1, 256) {
			return false
		}
	}
	return true
}

func canonicalIPv4(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is4() && address.String() == value
}

func (event EventEnvelopeV1) Validate() error {
	if event.SchemaVersion != "agmind.event-envelope.v1" {
		return fmt.Errorf("unsupported event schema version")
	}
	if !regexp.MustCompile(`^evt_[0-9a-f]{64}$`).MatchString(event.EventID) ||
		!hex32.MatchString(event.KeyID) || !uuid4.MatchString(event.HostID) ||
		!uuid4.MatchString(event.BootID) {
		return fmt.Errorf("invalid event identity")
	}
	if !boundedASCII(event.EventType, 1, 64) ||
		!boundedUTF8(event.SourceID, 1, 512) ||
		!boundedASCII(event.SourceVersion, 1, 64) {
		return fmt.Errorf("invalid event source fields")
	}
	if event.KeyEpoch < 1 || !validUTC(event.EventTime) || !validUTC(event.IngestTime) {
		return fmt.Errorf("invalid event counters or timestamp")
	}
	if event.ContainerStartTime != nil && !validUTC(*event.ContainerStartTime) {
		return fmt.Errorf("invalid container_start_time")
	}
	if event.ContainerID != nil && !hex64.MatchString(*event.ContainerID) {
		return fmt.Errorf("invalid container_id")
	}
	if event.ReleaseID != nil &&
		!regexp.MustCompile(`^rel_[0-9a-f]{32}$`).MatchString(*event.ReleaseID) {
		return fmt.Errorf("invalid release_id")
	}
	if event.ClockUncertaintyMS > 2000 || !hex64.MatchString(event.NormalizedFieldsSHA256) ||
		!hex64.MatchString(event.SourcePayloadHash) {
		return fmt.Errorf("invalid event bounds or digest")
	}
	if !regexp.MustCompile(`^[0-9a-f]{128}$`).MatchString(event.SourceSignature) {
		return fmt.Errorf("invalid source signature")
	}
	for name, flags := range map[string][]string{
		"redaction_flags": event.RedactionFlags,
		"coverage_flags":  event.CoverageFlags,
	} {
		if len(flags) > 64 || !sortedUnique(flags) {
			return fmt.Errorf("%s must be bounded, unique, and sorted", name)
		}
		for _, flag := range flags {
			if !boundedASCII(flag, 1, 64) {
				return fmt.Errorf("invalid %s entry", name)
			}
		}
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

func (event FalcoConnectV1) Validate() error {
	if event.EvtType != "connect" ||
		!boundedUTF8(event.DetectorRule, 1, 512) ||
		!boundedASCII(event.DetectorRuleVersion, 1, 64) ||
		!boundedASCII(event.FalcoVersion, 1, 64) ||
		!boundedASCII(event.EvtRes, 1, 64) ||
		!boundedASCII(event.L4Protocol, 1, 64) {
		return fmt.Errorf("invalid Falco identity or enum")
	}
	if !regexp.MustCompile(`^[0-9a-f]{12,64}$`).MatchString(event.FalcoContainerIDPrefix) {
		return fmt.Errorf("invalid Falco container prefix")
	}
	for _, id := range []*string{event.FalcoContainerFullID, event.DockerContainerID} {
		if id != nil && !hex64.MatchString(*id) {
			return fmt.Errorf("invalid Docker full ID")
		}
	}
	switch value := event.FalcoContainerStartTS.(type) {
	case string:
		if !boundedASCII(value, 1, 64) {
			return fmt.Errorf("invalid falco_container_start_ts")
		}
	case json.Number:
		if !integerJSON.MatchString(value.String()) {
			return fmt.Errorf("invalid falco_container_start_ts")
		}
		if _, err := value.Int64(); err != nil {
			return fmt.Errorf("falco_container_start_ts exceeds int64")
		}
	default:
		return fmt.Errorf("invalid falco_container_start_ts type %T", value)
	}
	if event.DockerStartedAt != nil && !validUTC(*event.DockerStartedAt) {
		return fmt.Errorf("invalid docker_started_at")
	}
	if event.ImageID != nil &&
		!regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(*event.ImageID) {
		return fmt.Errorf("invalid image_id")
	}
	if event.ImmutableSpecSHA256 != nil && !hex64.MatchString(*event.ImmutableSpecSHA256) {
		return fmt.Errorf("invalid immutable_spec_sha256")
	}
	if !hex64.MatchString(event.RawEventSHA256) || !canonicalIPv4(event.DestinationIPv4) ||
		event.DestinationPort == 0 || !validRepoDigests(event.RepoDigests) {
		return fmt.Errorf("invalid Falco destination or digest")
	}
	for _, value := range []string{event.ProcName, event.ProcExePath, event.ProcParentName} {
		if !boundedUTF8(value, 1, 512) {
			return fmt.Errorf("invalid process identity")
		}
	}
	if len(event.MissingRequiredFields) > 32 || !sortedUnique(event.MissingRequiredFields) {
		return fmt.Errorf("missing_required_fields must be bounded, unique, and sorted")
	}
	for _, field := range event.MissingRequiredFields {
		if !boundedASCII(field, 1, 64) {
			return fmt.Errorf("invalid missing field")
		}
	}
	success := (event.EvtRawres != nil && *event.EvtRawres >= 0) ||
		strings.EqualFold(event.EvtRes, "EINPROGRESS") ||
		strings.EqualFold(event.EvtRes, "EINPROGRESS(115)")
	if event.SuccessfulConnect != success {
		return fmt.Errorf("successful_connect contradicts Falco result")
	}
	if !event.InvestigationOnly {
		if !event.SuccessfulConnect || event.DockerContainerID == nil ||
			event.DockerStartedAt == nil || event.ImageID == nil ||
			event.ImmutableSpecSHA256 == nil || event.InventoryRevision == nil ||
			len(event.MissingRequiredFields) != 0 {
			return fmt.Errorf("candidate-capable event lacks authoritative identity")
		}
	}
	if !event.SuccessfulConnect && !event.InvestigationOnly {
		return fmt.Errorf("hard errors must be investigation-only")
	}
	return nil
}

func (event CoverageEventV1) Validate() error {
	if !boundedASCII(event.Component, 1, 64) || !boundedASCII(event.Kind, 1, 64) ||
		!boundedASCII(event.ReasonCode, 1, 64) || !validUTC(event.OpenedAt) {
		return fmt.Errorf("invalid coverage fields")
	}
	if event.Severity != "INFO" && event.Severity != "WARNING" && event.Severity != "CRITICAL" {
		return fmt.Errorf("invalid coverage severity")
	}
	if event.ClosedAt != nil {
		if !validUTC(*event.ClosedAt) {
			return fmt.Errorf("invalid closed_at")
		}
		opened, _ := time.Parse(time.RFC3339Nano, event.OpenedAt)
		closed, _ := time.Parse(time.RFC3339Nano, *event.ClosedAt)
		if closed.Before(opened) {
			return fmt.Errorf("closed_at precedes opened_at")
		}
	}
	if event.AffectedSourceSequenceStart != nil && event.AffectedSourceSequenceEnd != nil &&
		*event.AffectedSourceSequenceEnd < *event.AffectedSourceSequenceStart {
		return fmt.Errorf("coverage sequence interval is reversed")
	}
	return nil
}

func validateEgress(fields EgressDenyFields, version string) error {
	if fields.SchemaVersion != version || fields.Verb != "temporary_egress_deny" {
		return fmt.Errorf("unsupported egress deny contract")
	}
	if !regexp.MustCompile(`^int_[0-9a-f]{32}$`).MatchString(fields.IntentID) ||
		!uuid4.MatchString(fields.HostID) || !hex64.MatchString(fields.DockerContainerID) ||
		!regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(fields.ImageID) {
		return fmt.Errorf("invalid egress deny identity")
	}
	if !validUTC(fields.DockerStartedAt) || !validUTC(fields.CreatedAt) ||
		!canonicalIPv4(fields.DestinationIPv4) {
		return fmt.Errorf("invalid egress deny timestamp or destination")
	}
	if fields.TTLSeconds < 30 || fields.TTLSeconds > 300 ||
		len(fields.EvidenceIDs) < 1 || len(fields.EvidenceIDs) > 32 ||
		!sortedUnique(fields.EvidenceIDs) || !validRepoDigests(fields.RepoDigests) {
		return fmt.Errorf("invalid egress deny collections or TTL")
	}
	for _, evidence := range fields.EvidenceIDs {
		if !regexp.MustCompile(`^evt_[0-9a-f]{64}$`).MatchString(evidence) {
			return fmt.Errorf("invalid evidence ID")
		}
	}
	for _, digest := range []string{
		fields.ImmutableSpecSHA256,
		fields.DetectorBundleSHA256,
		fields.PolicyBundleSHA256,
		fields.CoverageSnapshotSHA256,
	} {
		if !hex64.MatchString(digest) {
			return fmt.Errorf("invalid sha256 digest")
		}
	}
	if !boundedASCII(fields.PolicyBundleVersion, 1, 64) {
		return fmt.Errorf("invalid policy_bundle_version")
	}
	return nil
}

func (intent TemporaryEgressDenyIntentV1) Validate() error {
	return validateEgress(intent.EgressDenyFields, "agmind.temporary-egress-deny-intent.v1")
}

func (plan PreparedTemporaryEgressDenyPlanV1) Validate() error {
	if err := validateEgress(
		plan.EgressDenyFields,
		"agmind.prepared-temporary-egress-deny-plan.v1",
	); err != nil {
		return err
	}
	if !regexp.MustCompile(`^plan_[0-9a-f]{32}$`).MatchString(plan.PlanID) ||
		!uuid4.MatchString(plan.BootID) || plan.InitPID == 0 || plan.PIDStartTicks == 0 ||
		plan.NetworkNamespaceInode == 0 || plan.HardLimitsVersion != "pcc-hard-limits-v1" ||
		!regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(plan.Nonce) {
		return fmt.Errorf("invalid prepared plan identity or limits")
	}
	for _, digest := range []string{
		plan.CgroupPathSHA256,
		plan.DockerNetworkSnapshotSHA256,
		plan.SpecialUseRegistrySHA256,
		plan.ManagementDenylistSHA256,
		plan.PlanHashValue,
	} {
		if !hex64.MatchString(digest) {
			return fmt.Errorf("invalid prepared plan digest")
		}
	}
	if !validUTC(plan.PreparedAt) || !validUTC(plan.ApprovalExpiresAt) {
		return fmt.Errorf("invalid prepared plan timestamp")
	}
	prepared, _ := time.Parse(time.RFC3339Nano, plan.PreparedAt)
	expires, _ := time.Parse(time.RFC3339Nano, plan.ApprovalExpiresAt)
	if expires.Sub(prepared) != 5*time.Minute {
		return fmt.Errorf("approval expiry must be exactly five minutes")
	}
	nonce, _ := hex.DecodeString(plan.Nonce)
	expectedID, err := PlanID(plan.IntentID, nonce)
	if err != nil || expectedID != plan.PlanID {
		return fmt.Errorf("plan_id does not match locked derivation")
	}
	expectedHash, err := PlanHash(plan)
	if err != nil || expectedHash != plan.PlanHashValue {
		return fmt.Errorf("plan_hash does not match locked derivation")
	}
	return nil
}

func (output HunterOutputV1) Validate() error {
	if output.SchemaVersion != "agmind.hunter-output.v1" ||
		len(output.Hypotheses) > 8 || len(output.SupportingEvidenceIDs) > 8 ||
		len(output.RefutingQuestions) > 8 || len(output.Limitations) > 8 ||
		!boundedUTF8(output.Narrative, 0, 8192) {
		return fmt.Errorf("invalid hunter output bounds")
	}
	for _, values := range [][]string{
		output.Hypotheses,
		output.RefutingQuestions,
		output.Limitations,
	} {
		for _, value := range values {
			if !boundedUTF8(value, 1, 1024) {
				return fmt.Errorf("hunter entry exceeds 1,024 bytes")
			}
		}
	}
	if !sortedUnique(output.SupportingEvidenceIDs) {
		return fmt.Errorf("supporting evidence IDs must be unique and sorted")
	}
	for _, value := range output.SupportingEvidenceIDs {
		if !regexp.MustCompile(`^evt_[0-9a-f]{64}$`).MatchString(value) {
			return fmt.Errorf("invalid supporting evidence ID")
		}
	}
	return nil
}

func (record ActionRecordV1) Validate() error {
	if record.SchemaVersion != "agmind.action-record.v1" ||
		!regexp.MustCompile(`^ar_[0-9a-f]{32}$`).MatchString(record.RecordID) ||
		!regexp.MustCompile(`^plan_[0-9a-f]{32}$`).MatchString(record.PlanID) ||
		!hex64.MatchString(record.PlanHashValue) || !hex64.MatchString(record.PreviousRecordSHA256) ||
		!hex64.MatchString(record.RecordSHA256) || !hex32.MatchString(record.ActuatorKeyID) ||
		!regexp.MustCompile(`^[0-9a-f]{128}$`).MatchString(record.ActuatorSignature) {
		return fmt.Errorf("invalid action record identity")
	}
	if record.ActionID != nil &&
		!regexp.MustCompile(`^act_[0-9a-f]{32}$`).MatchString(*record.ActionID) {
		return fmt.Errorf("invalid action_id")
	}
	if record.ActionID != nil {
		expectedActionID, err := ActionID(record.PlanHashValue)
		if err != nil || expectedActionID != *record.ActionID {
			return fmt.Errorf("action_id does not match plan_hash")
		}
	}
	states := []string{
		"PROPOSED", "POLICY_ADMITTED", "PREPARED", "APPROVED", "APPLIED", "VERIFIED",
		"EXPIRED", "STALE_ABORT", "REJECTED", "FAILED_DIRTY", "EXPIRED_UNAPPLIED",
	}
	if !sort.StringsAreSorted(states) {
		sort.Strings(states)
	}
	if index := sort.SearchStrings(states, record.State); index == len(states) || states[index] != record.State {
		return fmt.Errorf("invalid action state")
	}
	if !boundedASCII(record.ReasonCode, 1, 64) || !validUTC(record.ObservedAt) {
		return fmt.Errorf("invalid action reason or timestamp")
	}
	details, err := CanonicalJSON(record.Details)
	if err != nil || len(details) > 32*1024 {
		return fmt.Errorf("action details exceed bound: %w", err)
	}
	expectedHash, err := ActionRecordHash(record)
	if err != nil || expectedHash != record.RecordSHA256 {
		return fmt.Errorf("record_sha256 does not match locked derivation")
	}
	if ActionRecordID(expectedHash) != record.RecordID {
		return fmt.Errorf("record_id does not match record_sha256")
	}
	return nil
}

func (transition KeyTransitionV1) Validate() error {
	if transition.SchemaVersion != "agmind.key-transition.v1" ||
		!hex32.MatchString(transition.OldKeyID) || !hex32.MatchString(transition.NewKeyID) ||
		!hex64.MatchString(transition.NewPublicKey) || !uuid4.MatchString(transition.HostID) ||
		!validUTC(transition.OccurredAt) ||
		!regexp.MustCompile(`^[0-9a-f]{128}$`).MatchString(transition.OldSignature) ||
		!regexp.MustCompile(`^[0-9a-f]{128}$`).MatchString(transition.NewSignature) {
		return fmt.Errorf("invalid key transition")
	}
	if transition.OldEpoch == 0 || transition.OldEpoch == ^uint64(0) ||
		transition.NewEpoch != transition.OldEpoch+1 {
		return fmt.Errorf("key epochs must be consecutive")
	}
	public, _ := hex.DecodeString(transition.NewPublicKey)
	derived, err := KeyID(public)
	if err != nil || derived != transition.NewKeyID || transition.OldKeyID == transition.NewKeyID {
		return fmt.Errorf("new_key_id does not bind new_public_key")
	}
	return nil
}
