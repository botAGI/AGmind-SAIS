package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	hex64          = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex32          = regexp.MustCompile(`^[0-9a-f]{32}$`)
	planID         = regexp.MustCompile(`^plan_[0-9a-f]{32}$`)
	uuid4          = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	utcRFC3339Nano = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$`)
)

func (summary PendingPlanSummaryV1) validate() error {
	prepared, preparedErr := time.Parse(time.RFC3339Nano, summary.PreparedAt)
	expires, expiresErr := time.Parse(time.RFC3339Nano, summary.ApprovalExpiresAt)
	if !planID.MatchString(summary.PlanID) ||
		!hex64.MatchString(summary.DockerContainerID) ||
		!canonicalIPv4(summary.DestinationIPv4) ||
		!validUTC(summary.PreparedAt) || !validUTC(summary.ApprovalExpiresAt) ||
		preparedErr != nil || expiresErr != nil || !prepared.Before(expires) {
		return fmt.Errorf("invalid pending plan summary")
	}
	return nil
}

func (listing PendingPlanListV1) Validate() error {
	if listing.SchemaVersion != "agmind.pending-plan-list.v1" ||
		listing.State != "PENDING_APPROVAL" || listing.Plans == nil ||
		len(listing.Plans) > 100 {
		return fmt.Errorf("invalid pending plan list")
	}
	for index, summary := range listing.Plans {
		if err := summary.validate(); err != nil {
			return err
		}
		if index > 0 && listing.Plans[index-1].PlanID >= summary.PlanID {
			return fmt.Errorf("pending plan summaries are not unique and sorted")
		}
	}
	return nil
}

func validUTC(value string) bool {
	if !utcRFC3339Nano.MatchString(value) || value[:4] == "0000" {
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
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}

type nestedBounds struct {
	maxStringCharacters       int
	maxArrayItems             int
	maxObjectProperties       int
	maxPropertyNameCharacters int
}

func validateBoundedNested(value any, bounds nestedBounds, containerDepth int) error {
	if value == nil {
		return nil
	}
	if number, ok := value.(json.Number); ok {
		return validateCanonicalInteger(number.String())
	}
	current := reflect.ValueOf(value)
	for current.Kind() == reflect.Interface {
		if current.IsNil() {
			return nil
		}
		current = current.Elem()
	}
	switch current.Kind() {
	case reflect.Bool:
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return nil
	case reflect.Float32, reflect.Float64:
		return fmt.Errorf("nested floating-point value is forbidden")
	case reflect.String:
		value := current.String()
		if !utf8.ValidString(value) ||
			utf8.RuneCountInString(value) > bounds.maxStringCharacters {
			return fmt.Errorf("nested string exceeds schema bound")
		}
		return nil
	case reflect.Array, reflect.Slice:
		if containerDepth > maxJSONNestingDepth {
			return fmt.Errorf("JSON nesting depth exceeds 64")
		}
		if current.Len() > bounds.maxArrayItems {
			return fmt.Errorf("nested array exceeds schema bound")
		}
		for i := 0; i < current.Len(); i++ {
			if err := validateBoundedNested(
				current.Index(i).Interface(),
				bounds,
				containerDepth+1,
			); err != nil {
				return err
			}
		}
		return nil
	case reflect.Map:
		if containerDepth > maxJSONNestingDepth {
			return fmt.Errorf("JSON nesting depth exceeds 64")
		}
		if current.Type().Key().Kind() != reflect.String {
			return fmt.Errorf("nested object keys must be strings")
		}
		if current.Len() > bounds.maxObjectProperties {
			return fmt.Errorf("nested object exceeds schema bound")
		}
		iterator := current.MapRange()
		for iterator.Next() {
			key := iterator.Key().String()
			if !utf8.ValidString(key) ||
				utf8.RuneCountInString(key) > bounds.maxPropertyNameCharacters {
				return fmt.Errorf("nested property name exceeds schema bound")
			}
			if err := validateBoundedNested(
				iterator.Value().Interface(),
				bounds,
				containerDepth+1,
			); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported nested JSON type %T", value)
	}
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
	if values == nil || len(values) > 16 || !sortedUnique(values) {
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
	if event.NormalizedFields == nil || event.RedactionFlags == nil ||
		event.CoverageFlags == nil {
		return fmt.Errorf("required event collections must not be nil")
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
	if event.KeyEpoch < 1 || event.SourceSequence == 0 ||
		!validUTC(event.EventTime) || !validUTC(event.IngestTime) {
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
	if err := validateBoundedNested(
		event.NormalizedFields,
		nestedBounds{8192, 128, 128, 512},
		1,
	); err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	if hex.EncodeToString(digest[:]) != event.NormalizedFieldsSHA256 {
		return fmt.Errorf("normalized_fields_sha256 does not match normalized_fields")
	}
	expectedID, err := eventIDUnchecked(event)
	if err != nil || expectedID != event.EventID {
		return fmt.Errorf("event_id does not match locked derivation")
	}
	return nil
}

func (event FalcoConnectV1) Validate() error {
	if event.RepoDigests == nil || event.MissingRequiredFields == nil {
		return fmt.Errorf("required Falco collections must not be nil")
	}
	if !validUTC(event.EventTime) ||
		event.EvtType != "connect" ||
		!boundedUTF8(event.DetectorRule, 1, 512) ||
		!boundedASCII(event.DetectorRuleVersion, 1, 64) ||
		!boundedASCII(event.FalcoVersion, 1, 64) ||
		!boundedASCII(event.EvtRes, 1, 64) {
		return fmt.Errorf("invalid Falco identity or enum")
	}
	if event.FalcoContainerIDPrefix != nil &&
		!regexp.MustCompile(`^[0-9a-f]{12,64}$`).MatchString(
			*event.FalcoContainerIDPrefix,
		) {
		return fmt.Errorf("invalid Falco container prefix")
	}
	for _, id := range []*string{event.FalcoContainerFullID, event.DockerContainerID} {
		if id != nil && !hex64.MatchString(*id) {
			return fmt.Errorf("invalid Docker full ID")
		}
	}
	switch value := event.FalcoContainerStartTS.(type) {
	case nil:
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
	if !hex64.MatchString(event.RawEventSHA256) ||
		event.DestinationIPv4 != nil && !canonicalIPv4(*event.DestinationIPv4) ||
		event.DestinationPort != nil && *event.DestinationPort == 0 ||
		!validRepoDigests(event.RepoDigests) {
		return fmt.Errorf("invalid Falco destination or digest")
	}
	for _, value := range []*string{
		event.ProcName,
		event.ProcExePath,
		event.ProcParentName,
	} {
		if value != nil && !boundedUTF8(*value, 1, 512) {
			return fmt.Errorf("invalid process identity")
		}
	}
	if event.L4Protocol != nil &&
		!boundedASCII(*event.L4Protocol, 1, 64) {
		return fmt.Errorf("invalid Falco protocol")
	}
	if len(event.MissingRequiredFields) > 32 || !sortedUnique(event.MissingRequiredFields) {
		return fmt.Errorf("missing_required_fields must be bounded, unique, and sorted")
	}
	for _, field := range event.MissingRequiredFields {
		if !boundedASCII(field, 1, 64) {
			return fmt.Errorf("invalid missing field")
		}
	}
	sensorFacts := map[string]bool{
		"falco_container_id_prefix": event.FalcoContainerIDPrefix != nil,
		"falco_container_start_ts":  event.FalcoContainerStartTS != nil,
		"proc_name":                 event.ProcName != nil,
		"proc_exe_path":             event.ProcExePath != nil,
		"proc_parent_name":          event.ProcParentName != nil,
		"destination_ipv4":          event.DestinationIPv4 != nil,
		"destination_port":          event.DestinationPort != nil,
		"l4_protocol":               event.L4Protocol != nil,
	}
	missing := make(map[string]struct{}, len(event.MissingRequiredFields))
	for _, field := range event.MissingRequiredFields {
		if _, known := sensorFacts[field]; !known {
			return fmt.Errorf("unknown missing_required_fields entry")
		}
		missing[field] = struct{}{}
	}
	sensorOmitted := false
	for field, present := range sensorFacts {
		_, reported := missing[field]
		if present == reported {
			return fmt.Errorf(
				"missing_required_fields does not match sensor omissions",
			)
		}
		sensorOmitted = sensorOmitted || !present
	}
	if sensorOmitted && !event.InvestigationOnly {
		return fmt.Errorf("sensor omissions must be investigation-only")
	}
	completedSuccess := event.EvtRes == "SUCCESS" &&
		event.EvtRawres != nil && *event.EvtRawres >= 0
	nonblockingSuccess := (event.EvtRes == "EINPROGRESS" ||
		event.EvtRes == "EINPROGRESS(115)") &&
		(event.EvtRawres == nil || *event.EvtRawres < 0)
	hardError := event.EvtRes != "SUCCESS" &&
		event.EvtRes != "EINPROGRESS" &&
		event.EvtRes != "EINPROGRESS(115)"
	if event.EvtRes == "SUCCESS" && !completedSuccess {
		return fmt.Errorf("invalid completed Falco result tuple")
	}
	if (event.EvtRes == "EINPROGRESS" || event.EvtRes == "EINPROGRESS(115)") &&
		!nonblockingSuccess {
		return fmt.Errorf("invalid nonblocking Falco result tuple")
	}
	if hardError && event.EvtRawres != nil && *event.EvtRawres >= 0 {
		return fmt.Errorf("invalid hard-error Falco result tuple")
	}
	success := completedSuccess || nonblockingSuccess
	if event.SuccessfulConnect != success {
		return fmt.Errorf("successful_connect contradicts Falco result")
	}
	if !event.InvestigationOnly {
		if !event.SuccessfulConnect || sensorOmitted ||
			event.DockerContainerID == nil ||
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

func (request PCCCorrelationSnapshotRequestV1) Validate() error {
	if request.SchemaVersion != pccCorrelationRequestSchema ||
		!regexp.MustCompile(`^evt_[0-9a-f]{64}$`).MatchString(
			request.TriggerEventID,
		) ||
		!hex64.MatchString(request.TriggerContentSHA256) ||
		request.TriggerSourceSequence == 0 ||
		request.RequestedTTLSeconds < 30 ||
		request.RequestedTTLSeconds > 300 {
		return fmt.Errorf("invalid PCC correlation snapshot request")
	}
	return nil
}

func (trigger PCCFalcoTriggerProjectionV1) Validate() error {
	if trigger.SchemaVersion != pccFalcoTriggerProjectionSchema ||
		!regexp.MustCompile(`^evt_[0-9a-f]{64}$`).MatchString(trigger.EventID) ||
		!hex64.MatchString(trigger.ContentSHA256) ||
		!hex64.MatchString(trigger.NormalizedFieldsSHA256) ||
		trigger.SourceSequence == 0 ||
		trigger.SourceID != "agmind-observerd" ||
		!boundedASCII(trigger.SourceVersion, 1, 64) ||
		!uuid4.MatchString(trigger.HostID) ||
		!uuid4.MatchString(trigger.BootID) {
		return fmt.Errorf("invalid retained PCC trigger identity")
	}
	if !validUTC(trigger.EventTime) ||
		!validUTC(trigger.IngestTime) ||
		trigger.ClockUncertaintyMS > 2_000 ||
		trigger.InventoryGeneration == 0 ||
		trigger.InventoryRevision == 0 ||
		!hex64.MatchString(trigger.ContainerID) ||
		!validUTC(trigger.ContainerStartTime) ||
		!regexp.MustCompile(`^rel_[0-9a-f]{32}$`).MatchString(
			trigger.ReleaseID,
		) {
		return fmt.Errorf("invalid retained PCC trigger authority")
	}
	if trigger.DetectorRule != pccDetectorRule ||
		trigger.DetectorRuleVersion != pccDetectorRuleVersion ||
		trigger.FalcoVersion != pccFalcoVersion ||
		!regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(
			trigger.ImageID,
		) ||
		!hex64.MatchString(trigger.ImmutableSpecSHA256) ||
		!validRepoDigests(trigger.RepoDigests) {
		return fmt.Errorf("invalid retained PCC trigger detector or release")
	}
	expectedRelease, err := ReleaseID(
		trigger.ImageID,
		trigger.ImmutableSpecSHA256,
	)
	if err != nil || expectedRelease != trigger.ReleaseID {
		return fmt.Errorf("retained PCC trigger release_id mismatch")
	}
	completedSuccess := trigger.EvtRes == "SUCCESS" &&
		trigger.EvtRawres != nil && *trigger.EvtRawres >= 0
	nonblockingSuccess := (trigger.EvtRes == "EINPROGRESS" ||
		trigger.EvtRes == "EINPROGRESS(115)") &&
		(trigger.EvtRawres == nil || *trigger.EvtRawres < 0)
	if !trigger.SuccessfulConnect ||
		trigger.InvestigationOnly ||
		!completedSuccess && !nonblockingSuccess {
		return fmt.Errorf("retained PCC trigger is not candidate-capable")
	}
	for _, value := range []*string{
		trigger.ProcName,
		trigger.ProcExePath,
		trigger.ProcParentName,
	} {
		if value == nil || !boundedUTF8(*value, 1, 512) {
			return fmt.Errorf("retained PCC trigger lacks process identity")
		}
	}
	if !canonicalIPv4(trigger.DestinationIPv4) ||
		trigger.DestinationPort == 0 ||
		!boundedASCII(trigger.L4Protocol, 1, 64) ||
		trigger.MissingRequiredFields == nil ||
		len(trigger.MissingRequiredFields) != 0 ||
		trigger.CoverageFlags == nil ||
		len(trigger.CoverageFlags) > 64 ||
		!sortedUnique(trigger.CoverageFlags) ||
		!hex64.MatchString(trigger.RawEventSHA256) {
		return fmt.Errorf("invalid retained PCC trigger observation")
	}
	for _, flag := range trigger.CoverageFlags {
		if !boundedASCII(flag, 1, 64) {
			return fmt.Errorf("invalid retained PCC trigger coverage flag")
		}
	}
	return nil
}

func validCanonicalIP(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil &&
		!address.Is4In6() &&
		address.String() == value
}

func validCanonicalNetwork(value string) bool {
	prefix, err := netip.ParsePrefix(value)
	return err == nil &&
		!prefix.Addr().Is4In6() &&
		prefix.String() == value &&
		prefix.Masked() == prefix
}

func (network PCCDockerNetworkV1) Validate() error {
	if !hex64.MatchString(network.NetworkID) ||
		!boundedASCII(network.Driver, 1, 64) ||
		network.SubnetCIDRs == nil ||
		network.GatewayAddresses == nil ||
		len(network.SubnetCIDRs) > 32 ||
		len(network.GatewayAddresses) > 32 ||
		!sortedUnique(network.SubnetCIDRs) ||
		!sortedUnique(network.GatewayAddresses) {
		return fmt.Errorf("invalid PCC Docker network")
	}
	for _, subnet := range network.SubnetCIDRs {
		if !validCanonicalNetwork(subnet) {
			return fmt.Errorf("invalid canonical PCC Docker subnet")
		}
	}
	for _, gateway := range network.GatewayAddresses {
		if !validCanonicalIP(gateway) {
			return fmt.Errorf("invalid canonical PCC Docker gateway")
		}
	}
	return nil
}

func validatePCCDockerNetworks(networks []PCCDockerNetworkV1) error {
	if networks == nil || len(networks) > 64 {
		return fmt.Errorf("PCC Docker network count exceeds bound")
	}
	totalSubnets := 0
	totalGateways := 0
	var previousID string
	for index, network := range networks {
		if err := network.Validate(); err != nil {
			return err
		}
		if index > 0 && network.NetworkID <= previousID {
			return fmt.Errorf("PCC Docker networks must be unique and sorted")
		}
		previousID = network.NetworkID
		totalSubnets += len(network.SubnetCIDRs)
		totalGateways += len(network.GatewayAddresses)
	}
	if totalSubnets > 128 || totalGateways > 128 {
		return fmt.Errorf("PCC Docker network address totals exceed bounds")
	}
	canonical, err := CanonicalJSON(networks)
	if err != nil {
		return err
	}
	if len(canonical) > 16*1024 {
		return fmt.Errorf("PCC Docker network snapshot exceeds 16 KiB")
	}
	return nil
}

func validatePCCDenylist(
	deniedNetworks,
	deniedAddresses []string,
) error {
	if deniedNetworks == nil ||
		deniedAddresses == nil ||
		len(deniedNetworks) > 128 ||
		len(deniedAddresses) > 128 ||
		!sortedUnique(deniedNetworks) ||
		!sortedUnique(deniedAddresses) {
		return fmt.Errorf("PCC denylist arrays must be present, unique, and sorted")
	}
	for _, network := range deniedNetworks {
		prefix, err := netip.ParsePrefix(network)
		if err != nil ||
			!prefix.Addr().Is4() ||
			prefix.String() != network ||
			prefix.Masked() != prefix {
			return fmt.Errorf("invalid canonical PCC deny network")
		}
	}
	for _, address := range deniedAddresses {
		if !canonicalIPv4(address) {
			return fmt.Errorf("invalid canonical PCC deny address")
		}
	}
	return nil
}

func (hop PCCBootTransitionHopV1) Validate() error {
	if !regexp.MustCompile(
		`^(observer_boot_boundary|observer_key_transition|observer_key_epoch_start)$`,
	).MatchString(hop.BoundaryEventType) ||
		!regexp.MustCompile(`^evt_[0-9a-f]{64}$`).MatchString(hop.EventID) ||
		!hex64.MatchString(hop.ContentSHA256) ||
		hop.SourceSequence <= hop.PreviousSourceSequence ||
		!uuid4.MatchString(hop.BootID) ||
		!uuid4.MatchString(hop.PreviousBootID) ||
		hop.BootID == hop.PreviousBootID {
		return fmt.Errorf("invalid PCC boot-transition hop")
	}
	companions := []any{
		hop.RotationCompanionEventType,
		hop.RotationCompanionEventID,
		hop.RotationCompanionContentSHA256,
		hop.RotationCompanionSourceSequence,
		hop.RotationCompanionBootID,
	}
	present := 0
	for _, companion := range companions {
		if !reflect.ValueOf(companion).IsNil() {
			present++
		}
	}
	if present != 0 && present != len(companions) {
		return fmt.Errorf("PCC rotation companion fields are all-or-none")
	}
	if hop.BoundaryEventType == "observer_boot_boundary" {
		if present != 0 {
			return fmt.Errorf("dedicated PCC boot boundary forbids companion")
		}
		return nil
	}
	if present != len(companions) ||
		!regexp.MustCompile(`^evt_[0-9a-f]{64}$`).MatchString(
			*hop.RotationCompanionEventID,
		) ||
		*hop.RotationCompanionEventID == hop.EventID ||
		!hex64.MatchString(*hop.RotationCompanionContentSHA256) ||
		!uuid4.MatchString(*hop.RotationCompanionBootID) {
		return fmt.Errorf("invalid PCC rotation companion identity")
	}
	switch hop.BoundaryEventType {
	case "observer_key_transition":
		if *hop.RotationCompanionEventType != "observer_key_epoch_start" ||
			hop.SourceSequence == ^uint64(0) ||
			*hop.RotationCompanionSourceSequence != hop.SourceSequence+1 ||
			*hop.RotationCompanionBootID != hop.BootID {
			return fmt.Errorf("invalid new-boot PCC rotation pair")
		}
	case "observer_key_epoch_start":
		if *hop.RotationCompanionEventType != "observer_key_transition" ||
			*hop.RotationCompanionSourceSequence == 0 ||
			*hop.RotationCompanionSourceSequence == ^uint64(0) ||
			*hop.RotationCompanionSourceSequence+1 != hop.SourceSequence ||
			*hop.RotationCompanionBootID != hop.PreviousBootID {
			return fmt.Errorf("invalid old-boot PCC rotation pair")
		}
	}
	return nil
}

func validatePCCBootTransitionChain(
	hops []PCCBootTransitionHopV1,
) error {
	if len(hops) < 1 || len(hops) > 1_024 {
		return fmt.Errorf("PCC boot-transition chain must contain 1..1024 hops")
	}
	eventIDs := make(map[string]bool, len(hops)*2)
	bootIDs := map[string]bool{hops[0].PreviousBootID: true}
	var previousBoot string
	var priorLastSequence uint64
	for index, hop := range hops {
		if err := hop.Validate(); err != nil {
			return err
		}
		hopEventIDs := []string{hop.EventID}
		if hop.RotationCompanionEventID != nil {
			hopEventIDs = append(
				hopEventIDs,
				*hop.RotationCompanionEventID,
			)
		}
		for _, eventID := range hopEventIDs {
			if eventIDs[eventID] {
				return fmt.Errorf(
					"PCC boot-transition chain contains duplicate event ID",
				)
			}
			eventIDs[eventID] = true
		}
		if bootIDs[hop.BootID] {
			return fmt.Errorf(
				"PCC boot-transition chain contains repeated boot ID",
			)
		}
		bootIDs[hop.BootID] = true
		if index > 0 &&
			(hop.PreviousBootID != previousBoot ||
				hop.PreviousSourceSequence < priorLastSequence) {
			return fmt.Errorf("disconnected PCC boot-transition chain")
		}
		previousBoot = hop.BootID
		priorLastSequence = hop.SourceSequence
		if hop.BoundaryEventType == "observer_key_transition" {
			priorLastSequence = *hop.RotationCompanionSourceSequence
		}
	}
	return nil
}

func validMicrosecondUTC(value string) bool {
	if !validUTC(value) {
		return false
	}
	withoutZulu := strings.TrimSuffix(value, "Z")
	point := strings.LastIndexByte(withoutZulu, '.')
	return point < 0 || len(withoutZulu)-point-1 <= 6
}

func validPCCCapabilities(values []string) bool {
	if values == nil || len(values) > 128 || !sortedUnique(values) {
		return false
	}
	for _, value := range values {
		if !boundedASCII(value, 1, 64) {
			return false
		}
	}
	return true
}

func (snapshot PCCCorrelationSnapshotV1) Validate() error {
	if snapshot.SchemaVersion != pccCorrelationSnapshotSchema ||
		!hex64.MatchString(snapshot.RequestSHA256) ||
		!validMicrosecondUTC(snapshot.DecisionTime) ||
		snapshot.RequestedTTLSeconds < 30 ||
		snapshot.RequestedTTLSeconds > 300 ||
		snapshot.CoverageThroughSequence < snapshot.Trigger.SourceSequence ||
		snapshot.HardLimitsVersion != "pcc-hard-limits-v1" {
		return fmt.Errorf("invalid PCC correlation snapshot header")
	}
	if err := snapshot.Trigger.Validate(); err != nil {
		return err
	}
	expectedRequestHash, err := PCCCorrelationRequestSHA256(
		PCCCorrelationSnapshotRequestV1{
			SchemaVersion:         pccCorrelationRequestSchema,
			TriggerEventID:        snapshot.Trigger.EventID,
			TriggerContentSHA256:  snapshot.Trigger.ContentSHA256,
			TriggerSourceSequence: snapshot.Trigger.SourceSequence,
			RequestedTTLSeconds:   snapshot.RequestedTTLSeconds,
		},
	)
	if err != nil || expectedRequestHash != snapshot.RequestSHA256 {
		return fmt.Errorf("PCC snapshot request hash mismatch")
	}
	switch snapshot.Outcome {
	case "complete":
		return snapshot.validateComplete()
	case "failed":
		return snapshot.validateFailed()
	default:
		return fmt.Errorf("invalid PCC correlation snapshot outcome")
	}
}

func (snapshot PCCCorrelationSnapshotV1) validateComplete() error {
	if snapshot.DetectorBundleSHA256 == nil ||
		snapshot.SpecialUseRegistrySHA256 == nil ||
		snapshot.OperatorDeniedNetworks == nil ||
		snapshot.OperatorDeniedAddresses == nil ||
		snapshot.OperatorDenylistSHA256 == nil ||
		snapshot.ManagementDeniedNetworks == nil ||
		snapshot.ManagementDeniedAddresses == nil ||
		snapshot.ManagementDenylistSHA256 == nil ||
		snapshot.DockerNetworks == nil ||
		snapshot.DockerNetworkSnapshotSHA256 == nil ||
		snapshot.DockerContainerID == nil ||
		snapshot.DockerStartedAt == nil ||
		snapshot.ImageID == nil ||
		snapshot.RepoDigests == nil ||
		snapshot.ImmutableSpecSHA256 == nil ||
		snapshot.InventoryGeneration == nil ||
		snapshot.InventoryRevision == nil ||
		snapshot.InventoryObservedAt == nil ||
		snapshot.NetworkMode == nil ||
		snapshot.NetworkDriver == nil ||
		snapshot.Privileged == nil ||
		snapshot.ConfiguredCapAdd == nil ||
		snapshot.ConfiguredCapDrop == nil ||
		snapshot.EffectiveCapNetAdmin == nil ||
		snapshot.Running == nil ||
		snapshot.FailureReasons != nil ||
		snapshot.BootTransitionHopCount != nil ||
		snapshot.BootTransitionChainSHA256 != nil {
		return fmt.Errorf("incomplete or mixed PCC complete snapshot form")
	}
	if *snapshot.OperatorDeniedNetworks == nil ||
		*snapshot.OperatorDeniedAddresses == nil ||
		*snapshot.ManagementDeniedNetworks == nil ||
		*snapshot.ManagementDeniedAddresses == nil ||
		*snapshot.DockerNetworks == nil ||
		*snapshot.RepoDigests == nil ||
		*snapshot.ConfiguredCapAdd == nil ||
		*snapshot.ConfiguredCapDrop == nil {
		return fmt.Errorf("PCC complete snapshot arrays must be present")
	}
	for _, digest := range []string{
		*snapshot.DetectorBundleSHA256,
		*snapshot.SpecialUseRegistrySHA256,
		*snapshot.OperatorDenylistSHA256,
		*snapshot.ManagementDenylistSHA256,
		*snapshot.DockerNetworkSnapshotSHA256,
		*snapshot.ImmutableSpecSHA256,
	} {
		if !hex64.MatchString(digest) {
			return fmt.Errorf("invalid PCC complete snapshot digest")
		}
	}
	if *snapshot.SpecialUseRegistrySHA256 != pccSpecialUseRegistrySHA256 {
		return fmt.Errorf("PCC special-use registry pin mismatch")
	}
	operatorHash, err := PCCOperatorDenylistSHA256(
		*snapshot.OperatorDeniedNetworks,
		*snapshot.OperatorDeniedAddresses,
	)
	if err != nil || operatorHash != *snapshot.OperatorDenylistSHA256 {
		return fmt.Errorf("PCC operator denylist hash mismatch")
	}
	managementHash, err := PCCManagementDenylistSHA256(
		*snapshot.ManagementDeniedNetworks,
		*snapshot.ManagementDeniedAddresses,
	)
	if err != nil || managementHash != *snapshot.ManagementDenylistSHA256 {
		return fmt.Errorf("PCC management denylist hash mismatch")
	}
	networkHash, err := PCCDockerNetworkSnapshotSHA256(
		*snapshot.DockerNetworks,
	)
	if err != nil || networkHash != *snapshot.DockerNetworkSnapshotSHA256 {
		return fmt.Errorf("PCC Docker network snapshot hash mismatch")
	}
	if !hex64.MatchString(*snapshot.DockerContainerID) ||
		!validUTC(*snapshot.DockerStartedAt) ||
		!regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(
			*snapshot.ImageID,
		) ||
		!validRepoDigests(*snapshot.RepoDigests) ||
		*snapshot.InventoryGeneration == 0 ||
		*snapshot.InventoryRevision == 0 ||
		!validUTC(*snapshot.InventoryObservedAt) ||
		!boundedASCII(*snapshot.NetworkMode, 1, 128) ||
		!boundedASCII(*snapshot.NetworkDriver, 1, 64) ||
		!validPCCCapabilities(*snapshot.ConfiguredCapAdd) ||
		!validPCCCapabilities(*snapshot.ConfiguredCapDrop) {
		return fmt.Errorf("invalid PCC complete inventory snapshot")
	}
	trigger := snapshot.Trigger
	if *snapshot.DockerContainerID != trigger.ContainerID ||
		*snapshot.DockerStartedAt != trigger.ContainerStartTime ||
		*snapshot.ImageID != trigger.ImageID ||
		!reflect.DeepEqual(*snapshot.RepoDigests, trigger.RepoDigests) ||
		*snapshot.ImmutableSpecSHA256 != trigger.ImmutableSpecSHA256 ||
		*snapshot.InventoryGeneration != trigger.InventoryGeneration ||
		*snapshot.InventoryRevision != trigger.InventoryRevision {
		return fmt.Errorf("PCC complete snapshot does not bind retained trigger")
	}
	canonical, err := CanonicalJSON(snapshot)
	if err != nil {
		return err
	}
	if len(canonical) > 24*1024 {
		return fmt.Errorf("PCC complete normalized snapshot exceeds 24 KiB")
	}
	return nil
}

func (snapshot PCCCorrelationSnapshotV1) validateFailed() error {
	if snapshot.DetectorBundleSHA256 != nil ||
		snapshot.SpecialUseRegistrySHA256 != nil ||
		snapshot.OperatorDeniedNetworks != nil ||
		snapshot.OperatorDeniedAddresses != nil ||
		snapshot.OperatorDenylistSHA256 != nil ||
		snapshot.ManagementDeniedNetworks != nil ||
		snapshot.ManagementDeniedAddresses != nil ||
		snapshot.ManagementDenylistSHA256 != nil ||
		snapshot.DockerNetworks != nil ||
		snapshot.DockerNetworkSnapshotSHA256 != nil ||
		snapshot.DockerContainerID != nil ||
		snapshot.DockerStartedAt != nil ||
		snapshot.ImageID != nil ||
		snapshot.RepoDigests != nil ||
		snapshot.ImmutableSpecSHA256 != nil ||
		snapshot.InventoryGeneration != nil ||
		snapshot.InventoryRevision != nil ||
		snapshot.InventoryObservedAt != nil ||
		snapshot.NetworkMode != nil ||
		snapshot.NetworkDriver != nil ||
		snapshot.Privileged != nil ||
		snapshot.ConfiguredCapAdd != nil ||
		snapshot.ConfiguredCapDrop != nil ||
		snapshot.EffectiveCapNetAdmin != nil ||
		snapshot.Running != nil ||
		snapshot.FailureReasons == nil ||
		*snapshot.FailureReasons == nil ||
		len(*snapshot.FailureReasons) == 0 ||
		!sortedUnique(*snapshot.FailureReasons) {
		return fmt.Errorf("incomplete or mixed PCC failed snapshot form")
	}
	allowed := map[string]bool{
		"mutation_read_only":                  true,
		"reconcile_required":                  true,
		"docker_reconcile_gap":                true,
		"routine_drop_pending":                true,
		"inventory_stale":                     true,
		"docker_network_snapshot_unavailable": true,
		"docker_network_snapshot_overflow":    true,
		"detector_bundle_unavailable":         true,
		"special_use_registry_unavailable":    true,
		"operator_denylist_unavailable":       true,
		"management_denylist_unavailable":     true,
		"container_not_running":               true,
		"container_identity_changed":          true,
		"observer_boot_changed":               true,
	}
	for _, reason := range *snapshot.FailureReasons {
		if !allowed[reason] {
			return fmt.Errorf("invalid PCC snapshot failure reason")
		}
	}
	crossBoot := len(*snapshot.FailureReasons) == 1 &&
		(*snapshot.FailureReasons)[0] == "observer_boot_changed"
	if crossBoot {
		if snapshot.BootTransitionHopCount == nil ||
			*snapshot.BootTransitionHopCount < 1 ||
			*snapshot.BootTransitionHopCount > 1_024 ||
			snapshot.BootTransitionChainSHA256 == nil ||
			!hex64.MatchString(*snapshot.BootTransitionChainSHA256) {
			return fmt.Errorf("invalid PCC cross-boot terminal proof")
		}
		return nil
	}
	for _, reason := range *snapshot.FailureReasons {
		if reason == "observer_boot_changed" {
			return fmt.Errorf("observer_boot_changed must be the only reason")
		}
	}
	if snapshot.BootTransitionHopCount != nil ||
		snapshot.BootTransitionChainSHA256 != nil {
		return fmt.Errorf("ordinary PCC failure forbids boot-transition proof")
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

func (boundary ObserverBootBoundaryV1) Validate() error {
	if boundary.SchemaVersion != "agmind.observer-boot-boundary.v1" ||
		boundary.Kind != "observer_boot_boundary" {
		return fmt.Errorf("invalid observer boot boundary identity")
	}
	switch boundary.ReasonCode {
	case "observer_genesis":
		if boundary.PreviousBootID != nil ||
			boundary.PreviousSourceSequence != 0 {
			return fmt.Errorf("observer genesis cannot name a predecessor")
		}
	case "kernel_boot_id_changed":
		if boundary.PreviousBootID == nil ||
			!uuid4.MatchString(*boundary.PreviousBootID) ||
			boundary.PreviousSourceSequence == 0 {
			return fmt.Errorf("changed boot requires a valid predecessor")
		}
	default:
		return fmt.Errorf("invalid observer boot boundary reason")
	}
	return nil
}

func (root ObserverTrustRootV1) Validate() error {
	if root.SchemaVersion != "agmind.observer-trust-root.v1" ||
		!uuid4.MatchString(root.HostID) ||
		!hex32.MatchString(root.KeyID) ||
		root.KeyEpoch != 1 ||
		!hex64.MatchString(root.PublicKey) {
		return fmt.Errorf("invalid observer trust root")
	}
	publicKey, err := hex.DecodeString(root.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid observer trust-root public key")
	}
	derived, err := KeyID(publicKey)
	if err != nil || derived != root.KeyID {
		return fmt.Errorf("observer trust-root key ID mismatch")
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
	if output.Hypotheses == nil || output.SupportingEvidenceIDs == nil ||
		output.RefutingQuestions == nil || output.Limitations == nil {
		return fmt.Errorf("required hunter collections must not be nil")
	}
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
	if record.Details == nil {
		return fmt.Errorf("required action details must not be nil")
	}
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
	if err := validateBoundedNested(
		record.Details,
		nestedBounds{1024, 64, 64, 64},
		1,
	); err != nil {
		return err
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
