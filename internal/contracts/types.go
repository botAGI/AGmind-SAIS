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
