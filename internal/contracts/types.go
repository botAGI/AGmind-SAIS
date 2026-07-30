package contracts

// Contract is deliberately mandatory for DecodeStrict. New wire types cannot
// silently bypass validation by falling through a type switch.
type Contract interface {
	Validate() error
}

// EventEnvelopeV1 is the signed observer-to-Core event contract.
type EventEnvelopeV1 struct {
	SchemaVersion          string         `json:"schema_version"`
	EventID                string         `json:"event_id"`
	EventType              string         `json:"event_type"`
	SourceID               string         `json:"source_id"`
	SourceVersion          string         `json:"source_version"`
	KeyID                  string         `json:"key_id"`
	KeyEpoch               uint64         `json:"key_epoch"`
	HostID                 string         `json:"host_id"`
	BootID                 string         `json:"boot_id"`
	SourceSequence         uint64         `json:"source_sequence"`
	EventTime              string         `json:"event_time"`
	IngestTime             string         `json:"ingest_time"`
	ClockUncertaintyMS     uint64         `json:"clock_uncertainty_ms"`
	ContainerID            *string        `json:"container_id,omitempty"`
	ContainerStartTime     *string        `json:"container_start_time,omitempty"`
	ReleaseID              *string        `json:"release_id,omitempty"`
	InventoryGeneration    uint64         `json:"inventory_generation"`
	InventoryRevision      *uint64        `json:"inventory_revision,omitempty"`
	NormalizedFields       map[string]any `json:"normalized_fields"`
	NormalizedFieldsSHA256 string         `json:"normalized_fields_sha256"`
	RedactionFlags         []string       `json:"redaction_flags"`
	CoverageFlags          []string       `json:"coverage_flags"`
	SourcePayloadHash      string         `json:"source_payload_hash"`
	SourceSignature        string         `json:"source_signature"`
}

// FalcoConnectV1 is the bounded, redacted normalized Falco connect event.
type FalcoConnectV1 struct {
	DetectorRule           string   `json:"detector_rule"`
	DetectorRuleVersion    string   `json:"detector_rule_version"`
	FalcoVersion           string   `json:"falco_version"`
	EventTime              string   `json:"event_time"`
	EvtType                string   `json:"evt_type"`
	EvtRawres              *int64   `json:"evt_rawres,omitempty"`
	EvtRes                 string   `json:"evt_res"`
	SuccessfulConnect      bool     `json:"successful_connect"`
	InvestigationOnly      bool     `json:"investigation_only"`
	FalcoContainerIDPrefix *string  `json:"falco_container_id_prefix,omitempty"`
	FalcoContainerFullID   *string  `json:"falco_container_full_id,omitempty"`
	FalcoContainerStartTS  any      `json:"falco_container_start_ts,omitempty"`
	DockerContainerID      *string  `json:"docker_container_id,omitempty"`
	DockerStartedAt        *string  `json:"docker_started_at,omitempty"`
	ImageID                *string  `json:"image_id,omitempty"`
	RepoDigests            []string `json:"repo_digests"`
	ImmutableSpecSHA256    *string  `json:"immutable_spec_sha256,omitempty"`
	InventoryRevision      *uint64  `json:"inventory_revision,omitempty"`
	ProcName               *string  `json:"proc_name,omitempty"`
	ProcExePath            *string  `json:"proc_exe_path,omitempty"`
	ProcParentName         *string  `json:"proc_parent_name,omitempty"`
	DestinationIPv4        *string  `json:"destination_ipv4,omitempty"`
	DestinationPort        *uint16  `json:"destination_port,omitempty"`
	L4Protocol             *string  `json:"l4_protocol,omitempty"`
	MissingRequiredFields  []string `json:"missing_required_fields"`
	RawEventSHA256         string   `json:"raw_event_sha256"`
}

// PCCCorrelationSnapshotRequestV1 is the narrow, non-authoritative Core
// request for one observer-generated correlation proof.
type PCCCorrelationSnapshotRequestV1 struct {
	SchemaVersion         string `json:"schema_version"`
	TriggerEventID        string `json:"trigger_event_id"`
	TriggerContentSHA256  string `json:"trigger_content_sha256"`
	TriggerSourceSequence uint64 `json:"trigger_source_sequence"`
	RequestedTTLSeconds   uint64 `json:"requested_ttl_seconds"`
}

// PCCFalcoTriggerProjectionV1 is the retained allowlist projection of the
// authenticated candidate-capable Falco trigger.
type PCCFalcoTriggerProjectionV1 struct {
	SchemaVersion          string   `json:"schema_version"`
	EventID                string   `json:"event_id"`
	ContentSHA256          string   `json:"content_sha256"`
	NormalizedFieldsSHA256 string   `json:"normalized_fields_sha256"`
	SourceSequence         uint64   `json:"source_sequence"`
	SourceID               string   `json:"source_id"`
	SourceVersion          string   `json:"source_version"`
	HostID                 string   `json:"host_id"`
	BootID                 string   `json:"boot_id"`
	EventTime              string   `json:"event_time"`
	IngestTime             string   `json:"ingest_time"`
	ClockUncertaintyMS     uint64   `json:"clock_uncertainty_ms"`
	InventoryGeneration    uint64   `json:"inventory_generation"`
	InventoryRevision      uint64   `json:"inventory_revision"`
	ContainerID            string   `json:"container_id"`
	ContainerStartTime     string   `json:"container_start_time"`
	ReleaseID              string   `json:"release_id"`
	DetectorRule           string   `json:"detector_rule"`
	DetectorRuleVersion    string   `json:"detector_rule_version"`
	FalcoVersion           string   `json:"falco_version"`
	EvtRawres              *int64   `json:"evt_rawres,omitempty"`
	EvtRes                 string   `json:"evt_res"`
	SuccessfulConnect      bool     `json:"successful_connect"`
	InvestigationOnly      bool     `json:"investigation_only"`
	ImageID                string   `json:"image_id"`
	RepoDigests            []string `json:"repo_digests"`
	ImmutableSpecSHA256    string   `json:"immutable_spec_sha256"`
	ProcName               *string  `json:"proc_name,omitempty"`
	ProcExePath            *string  `json:"proc_exe_path,omitempty"`
	ProcParentName         *string  `json:"proc_parent_name,omitempty"`
	DestinationIPv4        string   `json:"destination_ipv4"`
	DestinationPort        uint16   `json:"destination_port"`
	L4Protocol             string   `json:"l4_protocol"`
	MissingRequiredFields  []string `json:"missing_required_fields"`
	CoverageFlags          []string `json:"coverage_flags"`
	RawEventSHA256         string   `json:"raw_event_sha256"`
}

// PCCDockerNetworkV1 is one entry in the complete global Docker-network
// snapshot retained by a correlation proof.
type PCCDockerNetworkV1 struct {
	NetworkID        string   `json:"network_id"`
	Driver           string   `json:"driver"`
	SubnetCIDRs      []string `json:"subnet_cidrs"`
	GatewayAddresses []string `json:"gateway_addresses"`
}

// PCCBootTransitionHopV1 is one authenticated protected boot-boundary hop.
// Rotation companion fields are an all-or-none group.
type PCCBootTransitionHopV1 struct {
	BoundaryEventType               string  `json:"boundary_event_type"`
	EventID                         string  `json:"event_id"`
	ContentSHA256                   string  `json:"content_sha256"`
	SourceSequence                  uint64  `json:"source_sequence"`
	BootID                          string  `json:"boot_id"`
	PreviousBootID                  string  `json:"previous_boot_id"`
	PreviousSourceSequence          uint64  `json:"previous_source_sequence"`
	RotationCompanionEventType      *string `json:"rotation_companion_event_type,omitempty"`
	RotationCompanionEventID        *string `json:"rotation_companion_event_id,omitempty"`
	RotationCompanionContentSHA256  *string `json:"rotation_companion_content_sha256,omitempty"`
	RotationCompanionSourceSequence *uint64 `json:"rotation_companion_source_sequence,omitempty"`
	RotationCompanionBootID         *string `json:"rotation_companion_boot_id,omitempty"`
}

// PCCCorrelationSnapshotV1 is a discriminated complete-or-failed protected
// proof. Pointers preserve the wire distinction between an absent union field
// and a present false/zero/empty value.
type PCCCorrelationSnapshotV1 struct {
	SchemaVersion               string                      `json:"schema_version"`
	Outcome                     string                      `json:"outcome"`
	RequestSHA256               string                      `json:"request_sha256"`
	Trigger                     PCCFalcoTriggerProjectionV1 `json:"trigger"`
	DecisionTime                string                      `json:"decision_time"`
	DetectorBundleSHA256        *string                     `json:"detector_bundle_sha256,omitempty"`
	RequestedTTLSeconds         uint64                      `json:"requested_ttl_seconds"`
	SpecialUseRegistrySHA256    *string                     `json:"special_use_registry_sha256,omitempty"`
	OperatorDeniedNetworks      *[]string                   `json:"operator_denied_networks,omitempty"`
	OperatorDeniedAddresses     *[]string                   `json:"operator_denied_addresses,omitempty"`
	OperatorDenylistSHA256      *string                     `json:"operator_denylist_sha256,omitempty"`
	ManagementDeniedNetworks    *[]string                   `json:"management_denied_networks,omitempty"`
	ManagementDeniedAddresses   *[]string                   `json:"management_denied_addresses,omitempty"`
	ManagementDenylistSHA256    *string                     `json:"management_denylist_sha256,omitempty"`
	DockerNetworks              *[]PCCDockerNetworkV1       `json:"docker_networks,omitempty"`
	DockerNetworkSnapshotSHA256 *string                     `json:"docker_network_snapshot_sha256,omitempty"`
	DockerContainerID           *string                     `json:"docker_container_id,omitempty"`
	DockerStartedAt             *string                     `json:"docker_started_at,omitempty"`
	ImageID                     *string                     `json:"image_id,omitempty"`
	RepoDigests                 *[]string                   `json:"repo_digests,omitempty"`
	ImmutableSpecSHA256         *string                     `json:"immutable_spec_sha256,omitempty"`
	InventoryGeneration         *uint64                     `json:"inventory_generation,omitempty"`
	InventoryRevision           *uint64                     `json:"inventory_revision,omitempty"`
	InventoryObservedAt         *string                     `json:"inventory_observed_at,omitempty"`
	NetworkMode                 *string                     `json:"network_mode,omitempty"`
	NetworkDriver               *string                     `json:"network_driver,omitempty"`
	Privileged                  *bool                       `json:"privileged,omitempty"`
	ConfiguredCapAdd            *[]string                   `json:"configured_cap_add,omitempty"`
	ConfiguredCapDrop           *[]string                   `json:"configured_cap_drop,omitempty"`
	EffectiveCapNetAdmin        *bool                       `json:"effective_cap_net_admin,omitempty"`
	Running                     *bool                       `json:"running,omitempty"`
	FailureReasons              *[]string                   `json:"failure_reasons,omitempty"`
	CoverageThroughSequence     uint64                      `json:"coverage_through_sequence"`
	HardLimitsVersion           string                      `json:"hard_limits_version"`
	BootTransitionHopCount      *uint64                     `json:"boot_transition_hop_count,omitempty"`
	BootTransitionChainSHA256   *string                     `json:"boot_transition_chain_sha256,omitempty"`
}

// CoverageEventV1 is a bounded normalized coverage interval.
type CoverageEventV1 struct {
	Component                   string  `json:"component"`
	Kind                        string  `json:"kind"`
	Severity                    string  `json:"severity"`
	OpenedAt                    string  `json:"opened_at"`
	ClosedAt                    *string `json:"closed_at,omitempty"`
	AffectedSourceSequenceStart *uint64 `json:"affected_source_sequence_start,omitempty"`
	AffectedSourceSequenceEnd   *uint64 `json:"affected_source_sequence_end,omitempty"`
	DroppedCount                *uint64 `json:"dropped_count,omitempty"`
	ReasonCode                  string  `json:"reason_code"`
	ReconcileGeneration         *uint64 `json:"reconcile_generation,omitempty"`
}

// ObserverBootBoundaryV1 is the signed normalized payload that makes a new
// kernel boot observable to Core before ordinary observer events may publish.
type ObserverBootBoundaryV1 struct {
	SchemaVersion          string  `json:"schema_version"`
	Kind                   string  `json:"kind"`
	ReasonCode             string  `json:"reason_code"`
	PreviousBootID         *string `json:"previous_boot_id,omitempty"`
	PreviousSourceSequence uint64  `json:"previous_source_sequence"`
}

// ObserverTrustRootV1 is the immutable installation pin independently loaded
// by Core before observer key-transition metadata is considered.
type ObserverTrustRootV1 struct {
	SchemaVersion string `json:"schema_version"`
	HostID        string `json:"host_id"`
	KeyID         string `json:"key_id"`
	KeyEpoch      uint64 `json:"key_epoch"`
	PublicKey     string `json:"public_key"`
}

// EgressDenyFields are shared fields, not a standalone wire contract.
type EgressDenyFields struct {
	SchemaVersion          string   `json:"schema_version"`
	IntentID               string   `json:"intent_id"`
	Verb                   string   `json:"verb"`
	HostID                 string   `json:"host_id"`
	DockerContainerID      string   `json:"docker_container_id"`
	DockerStartedAt        string   `json:"docker_started_at"`
	ImageID                string   `json:"image_id"`
	RepoDigests            []string `json:"repo_digests"`
	ImmutableSpecSHA256    string   `json:"immutable_spec_sha256"`
	InventoryGeneration    uint64   `json:"inventory_generation"`
	InventoryRevision      uint64   `json:"inventory_revision"`
	DestinationIPv4        string   `json:"destination_ipv4"`
	TTLSeconds             uint64   `json:"ttl_seconds"`
	EvidenceIDs            []string `json:"evidence_ids"`
	DetectorBundleSHA256   string   `json:"detector_bundle_sha256"`
	PolicyBundleVersion    string   `json:"policy_bundle_version"`
	PolicyBundleSHA256     string   `json:"policy_bundle_sha256"`
	CoverageSnapshotSHA256 string   `json:"coverage_snapshot_sha256"`
	CreatedAt              string   `json:"created_at"`
}

type TemporaryEgressDenyIntentV1 struct {
	EgressDenyFields
}

type PreparedTemporaryEgressDenyPlanV1 struct {
	EgressDenyFields
	PlanID                      string `json:"plan_id"`
	BootID                      string `json:"boot_id"`
	InitPID                     uint64 `json:"init_pid"`
	PIDStartTicks               uint64 `json:"pid_start_ticks"`
	CgroupPathSHA256            string `json:"cgroup_path_sha256"`
	NetworkNamespaceInode       uint64 `json:"network_namespace_inode"`
	DockerNetworkSnapshotSHA256 string `json:"docker_network_snapshot_sha256"`
	SpecialUseRegistrySHA256    string `json:"special_use_registry_sha256"`
	ManagementDenylistSHA256    string `json:"management_denylist_sha256"`
	HardLimitsVersion           string `json:"hard_limits_version"`
	PreparedAt                  string `json:"prepared_at"`
	ApprovalExpiresAt           string `json:"approval_expires_at"`
	Nonce                       string `json:"nonce"`
	PlanHashValue               string `json:"plan_hash"`
}

type HunterOutputV1 struct {
	SchemaVersion         string   `json:"schema_version"`
	Hypotheses            []string `json:"hypotheses"`
	SupportingEvidenceIDs []string `json:"supporting_evidence_ids"`
	RefutingQuestions     []string `json:"refuting_questions"`
	Narrative             string   `json:"narrative"`
	Limitations           []string `json:"limitations"`
}

type ActionRecordV1 struct {
	SchemaVersion        string         `json:"schema_version"`
	RecordID             string         `json:"record_id"`
	ActionID             *string        `json:"action_id,omitempty"`
	PlanID               string         `json:"plan_id"`
	PlanHashValue        string         `json:"plan_hash"`
	State                string         `json:"state"`
	ReasonCode           string         `json:"reason_code"`
	ObservedAt           string         `json:"observed_at"`
	PreviousRecordSHA256 string         `json:"previous_record_sha256"`
	RecordSHA256         string         `json:"record_sha256"`
	Details              map[string]any `json:"details"`
	ActuatorKeyID        string         `json:"actuator_key_id"`
	ActuatorSignature    string         `json:"actuator_signature"`
}

type KeyTransitionV1 struct {
	SchemaVersion string `json:"schema_version"`
	OldKeyID      string `json:"old_key_id"`
	NewKeyID      string `json:"new_key_id"`
	OldEpoch      uint64 `json:"old_epoch"`
	NewEpoch      uint64 `json:"new_epoch"`
	NewPublicKey  string `json:"new_public_key"`
	HostID        string `json:"host_id"`
	OccurredAt    string `json:"occurred_at"`
	OldSignature  string `json:"old_signature"`
	NewSignature  string `json:"new_signature"`
}
