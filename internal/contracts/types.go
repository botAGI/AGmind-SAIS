package contracts

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

type TemporaryEgressDenyIntentV1 struct {
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

type PreparedTemporaryEgressDenyPlanV1 struct {
	TemporaryEgressDenyIntentV1
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
