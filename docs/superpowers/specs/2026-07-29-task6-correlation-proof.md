# Task 6 frozen correlation-proof contract

## Why Task 6 needs a proof event

The original Task 6 named live observer inventory and `CoverageState` as
correlation inputs while `incidents` and `candidates` are rebuildable SQLite
projection tables. A live response is not authenticated historical evidence,
and live `MutationReadiness` contains a monotonic lease that cannot be replayed.

Task 6 therefore admits no candidate directly from a live inventory response.
Candidate-capable correlation requires:

1. a primary authenticated routine `falco_connect`;
2. a later protected `pcc_correlation_snapshot`, bound to that exact trigger;
3. authenticated coverage records through the snapshot's exact prior prefix.

The snapshot contains both a fresh observer-owned inventory/network/safety
snapshot and a bounded observer-verified projection of the routine trigger.
Core can therefore reproduce the incident and candidate after retention removes
the original routine event. Core correlation performs no network call and has
no model input.

## Frozen slices

1. **6A — final proof contracts:** strict Python/Go request, retained-trigger,
   Docker-network, and snapshot mirrors; canonical hashes; verifier admission;
   protected evidence classification.
2. **6B — pure correlation:** immutable incident/candidate/result/context facts,
   ordered gates, identifiers, duplicate semantics, and cooldown query contract.
3. **6C — proof producer:** same-generation global Docker-network inventory,
   root-owned safety pins, one critical-section observer publication,
   specialized durable receipt, and Core transport-before-ACK orchestration.
4. **6D — historical coverage and projection V2:** replayable coverage
   assessment, append-only late invalidation, and rebuild-safe incident/candidate
   projection.

No slice introduces policy, AI, approval, actuator, or nftables authority.

## Narrow Core request

`PCCCorrelationSnapshotRequestV1` contains exactly:

```text
schema_version = "agmind.pcc-correlation-snapshot-request.v1"
trigger_event_id
trigger_content_sha256
trigger_source_sequence
requested_ttl_seconds
```

It is a request, not evidence or authority. TTL is constrained to `30..300`;
the Task 6C production path always sets `requested_ttl_seconds = 120`. That
value is Core-owned and is not caller, model, policy, operator, or
configuration input. The request has exactly its schema version and four
request facts above; it has no deadline, selection-time, or canonical-bytes
field. The operation key is
`pcc_correlation_snapshot:<trigger_event_id>`. An exact retry returns the
receipt-bound publication. Different canonical request bytes under the same key
are a security conflict and fence mutation readiness.

The request contains no detector, registry, management, Docker, health,
identity, policy, model, or action fact.

## Root-owned observer pins

The observer independently loads these inputs from root-owned, single-link
regular files beneath compile-time allowlisted paths:

```text
/etc/falco/rules.d/agmind-pcc.yaml
/usr/share/agmind-sais/ipv4-special-use.csv
/etc/agmind-sais/operator-denylist.json
/etc/agmind-sais/management-destinations.json
```

The detector hash preserves the parent-plan derivation exactly and makes the
concatenation unambiguous:

```text
hex(SHA256("AGMIND_DETECTOR_BUNDLE_V1\0" ||
           uint64_be(len(rule_file_bytes)) || rule_file_bytes ||
           uint64_be(len(adapter_schema_version_ascii)) ||
           adapter_schema_version_ascii ||
           uint64_be(len(falco_version_ascii)) || falco_version_ascii))
```

Python and Go share fixed parity vectors. The special-use registry hash must
equal the repository-pinned digest.

```text
adapter_schema_version_ascii = "agmind.falco-connect.v1"
falco_version_ascii = "0.44.1"
special_use_registry_sha256 =
  "e3e39e76d00b1677335db8e9a805c7b9480ea2f4dc9e33f0b93cd3a905128d73"
```

Both values are exact deployment pins, not caller input.

Core loads the special-use CSV through a bounded strict loader. It hashes the
raw bytes before parsing, requires the pinned digest and exact IANA header,
rejects malformed/duplicate/non-IPv4 prefixes or unrecognized reachability
values, and never skips a row. A permissive best-effort CSV parse is not
candidate authority.

Operator and management hashes use separate domains with the same canonical
payload:

```text
hex(SHA256(domain ||
           canonical_json({
             "denied_addresses": sorted_unique_addresses,
             "denied_networks": sorted_unique_networks
           })))

domain = "AGMIND_OPERATOR_DENYLIST_V1\0"
      or "AGMIND_MANAGEMENT_DENYLIST_V1\0"
```

Failure to safely load, parse, canonicalize, or bind any pin prevents a
candidate-capable snapshot.

## Retained trigger projection

`PCCFalcoTriggerProjectionV1` contains exactly:

```text
schema_version = "agmind.pcc-falco-trigger-projection.v1"
event_id
content_sha256
normalized_fields_sha256
source_sequence
source_id
source_version
host_id
boot_id
event_time
ingest_time
clock_uncertainty_ms
inventory_generation
inventory_revision
container_id
container_start_time
release_id
detector_rule
detector_rule_version
falco_version
evt_rawres?
evt_res
successful_connect
investigation_only
image_id
repo_digests[]
immutable_spec_sha256
proc_name?
proc_exe_path?
proc_parent_name?
destination_ipv4
destination_port
l4_protocol
missing_required_fields[]
coverage_flags[]
raw_event_sha256
```

The producer decodes the exact authenticated trigger from its still-unacknowledged
spool record and constructs this allowlisted projection itself. It accepts only
a candidate-capable `falco_connect`; caller-supplied trigger facts are forbidden.
The projection preserves every trigger fact needed for incident construction,
candidate gates, and cross-binding, but never raw Falco JSON.

Investigation-only events create ordinary incidents directly from their routine
evidence and may age out with that evidence. Active/rejected candidate decisions
use the protected snapshot authority.

## Docker network snapshot

Each `PCCDockerNetworkV1` contains exactly:

```text
network_id
driver
subnet_cidrs[]
gateway_addresses[]
```

All set-like arrays are canonical sorted unique arrays. Network entries are
sorted by `network_id`; conflicting duplicate IDs fail closed. IPv4-mapped
IPv6 spellings are rejected so Python and Go cannot canonicalize one Docker
fact to different bytes.

Task 6C extends the deliberately narrow read-only `DockerReader` boundary with
the exact Moby v1.55 method:

```go
NetworkList(
    context.Context,
    client.NetworkListOptions,
) (client.NetworkListResult, error)
```

The reconciler calls `NetworkList` without filters and then
`NetworkInspect` once for every returned exact network ID. It rejects empty or
duplicate IDs, list/inspect disagreement, a disappearing network, any parse
error, and any limit overflow. It sorts only after the full walk succeeds.
There is no Docker mutation, generic request, or client escape surface.

The inventory atomically commits that bounded complete global Docker-network
snapshot in the same generation as its container identities. A failed global
walk commits neither the new container identities nor a partial network list;
it leaves reconciliation required. Proof publication clones the target identity
and global networks under one inventory read lock. It never performs a partial
live network walk.

The limits are 64 networks, at most 128 subnet CIDRs total, at most 128 gateway
addresses total, at most 32 of either per network, and at most 16 KiB for the
canonical `docker_networks` array. A complete snapshot's entire canonical
normalized object is at most 24 KiB, leaving a fixed margin beneath the existing
32 KiB envelope limit. There is no truncation.

The network hash is:

```text
hex(SHA256("AGMIND_DOCKER_NETWORK_SNAPSHOT_V1\0" ||
           canonical_json(docker_networks)))
```

Docker deny networks and addresses are computed from the canonical network
snapshot at correlation time; they are not duplicated on the wire. If a
complete snapshot cannot be represented, the producer emits the strict failed
form below and never publishes a truncated network array.

## Protected observer snapshot

The complete `PCCCorrelationSnapshotV1` form contains exactly:

```text
schema_version = "agmind.pcc-correlation-snapshot.v1"
outcome = "complete"
request_sha256
trigger
decision_time
detector_bundle_sha256
requested_ttl_seconds
special_use_registry_sha256
operator_denied_networks[]
operator_denied_addresses[]
operator_denylist_sha256
management_denied_networks[]
management_denied_addresses[]
management_denylist_sha256
docker_networks[]
docker_network_snapshot_sha256
docker_container_id
docker_started_at
image_id
repo_digests[]
immutable_spec_sha256
inventory_generation
inventory_revision
inventory_observed_at
network_mode
network_driver
privileged
configured_cap_add[]
configured_cap_drop[]
effective_cap_net_admin
running
coverage_through_sequence
hard_limits_version = "pcc-hard-limits-v1"
```

The mutually exclusive failed form contains exactly:

```text
schema_version = "agmind.pcc-correlation-snapshot.v1"
outcome = "failed"
request_sha256
trigger
decision_time
requested_ttl_seconds
failure_reasons[]
coverage_through_sequence
hard_limits_version = "pcc-hard-limits-v1"
boot_transition_hop_count?
boot_transition_chain_sha256?
```

`failure_reasons` is nonempty, sorted, unique, and limited to:

```text
mutation_read_only
reconcile_required
docker_reconcile_gap
routine_drop_pending
inventory_stale
docker_network_snapshot_unavailable
docker_network_snapshot_overflow
detector_bundle_unavailable
special_use_registry_unavailable
operator_denylist_unavailable
management_denylist_unavailable
container_not_running
container_identity_changed
observer_boot_changed
```

Complete-only fields are absent, not null, in the failed form.
`failure_reasons` is absent in the complete form. A failed snapshot creates a
`Rejected` incident decision and can never create a candidate.

Ordinary failed snapshots have the same boot as the retained trigger, forbid
`observer_boot_changed`, and omit both boot-transition fields. If the observer
reboots after Core durably selects a trigger but before proof publication, the
producer emits the cross-boot terminal form with exactly:

```text
failure_reasons = ["observer_boot_changed"]
boot_transition_hop_count = number of boot-transition hops, in 1..1024
boot_transition_chain_sha256 =
  hex(SHA256("AGMIND_BOOT_TRANSITION_CHAIN_V1\0" ||
             canonical_json(boundary_chain)))
```

`boundary_chain` is the complete source-sequence-ordered list of authenticated
protected boot-transition hops from the trigger boot to the snapshot boot. It
uses the already-frozen closed boundary union: (A) a dedicated
`observer_boot_boundary`; (B) a new-boot `observer_key_transition` plus its
exact adjacent same-boot `observer_key_epoch_start`; or (C) an old-boot
`observer_key_transition` plus its exact adjacent new-boot
`observer_key_epoch_start`. A hop reference contains exactly:

```text
boundary_event_type = "observer_boot_boundary" |
                      "observer_key_transition" |
                      "observer_key_epoch_start"
event_id
content_sha256
source_sequence
boot_id
previous_boot_id
previous_source_sequence
rotation_companion_event_type?
rotation_companion_event_id?
rotation_companion_content_sha256?
rotation_companion_source_sequence?
rotation_companion_boot_id?
```

The five `rotation_companion_*` fields are all absent for A and all present for
B/C. For B the transition is the boundary event and the adjacent epoch start is
the companion; for C the epoch start is the boundary event and the immediately
preceding transition is the companion. Core requires the already-frozen
dual-signature, key-epoch, adjacency, boot, and exact coverage-flag rules for
the pair. It derives `previous_boot_id` and `previous_source_sequence` from its
accepted verifier FSM; rotation payloads do not invent predecessor fields.

The first hop names the trigger boot as `previous_boot_id`; every later hop
names the preceding hop's boot; the last boundary boot equals the snapshot
envelope boot. Core recomputes the chain from the complete protected boundary
union in the authenticated source prefix and requires the count and hash to
match. Missing, extra, reordered, disconnected, unavailable, or invalid
transition/start-pair evidence fails verification. The producer obtains the
retained trigger from its unacknowledged spool record and the boundary chain
from protected spool records plus persisted boot history; neither is caller
input.

This cross-boot form durably retains the trigger projection, deterministically
produces `Rejected(observer_boot_changed)`, and lets Core ACK the trigger and
proof in source order. It never attempts Docker, pin, freshness, coverage, or
candidate gates. If the authenticated chain cannot be reconstructed, observer
stays fail-closed and no ACK advances past the unresolved trigger.

The event envelope is exact:

- `event_type = "pcc_correlation_snapshot"`;
- `source_id = "agmind-observerd"` and protected evidence priority;
- one timestamp sample supplies `event_time = ingest_time = decision_time`;
- for `complete`, container/start/generation/revision equal the fresh normalized
  identity and release ID equals the locked image/spec derivation;
- for `failed`, container/start/release/revision are absent and inventory
  generation is zero;
- no redaction flags or coverage flags;
- `source_payload_hash = normalized_fields_sha256`;
- `coverage_through_sequence = source_sequence - 1`;
- trigger source sequence is lower than the snapshot source sequence;
- envelope host always equals the embedded trigger;
- for `complete` and ordinary `failed`, envelope boot equals the embedded
  trigger; for the exact cross-boot terminal form it differs and the locked
  transition-chain proof above is mandatory;
- request trigger triple equals the embedded trigger triple;
- embedded trigger identity/content/candidate facts match the exact spool record;
- `request_sha256` hashes the exact canonical request bytes.

At initial admission, while the trigger remains present, Core additionally
cross-checks the retained projection against that exact authenticated trigger.
On historical replay after retention, absence is legal only when authenticated
retired-range evidence covers the trigger sequence; Core then validates the
snapshot's internal bindings without fabricating a `VerifiedEnvelope` or
requiring a deleted trigger row. Cross-boot replay additionally requires every
protected dedicated boundary or rotation pair committed by
`boot_transition_chain_sha256`.

## Specialized publication receipt and ordering

The existing Core-control publisher cannot be reused because request bytes and
observer-derived normalized output differ. Snapshot publication uses a
specialized append-only receipt binding:

```text
operation_key
request_sha256
snapshot_normalized_sha256
snapshot_event_id
snapshot_content_sha256
```

Request and output hashes are never conflated. Exact retry verifies and returns
the receipt-bound event. A mismatched request or receipt is corruption/conflict.

Producer lock order is:

1. observer publication mutex;
2. exact unacknowledged trigger lookup/binding;
3. inventory read lock and same-generation target/global-network clone;
4. one root-owned safety-pin snapshot;
5. one UTC timestamp sample;
6. choose `S = last_sequence + 1`;
7. form fields with `coverage_through_sequence = S - 1`;
8. reserve, sign, atomically append event plus receipt, and publish state.

Persistent `mutation_read_only` is an absolute no-publication fence. The local
producer checks it before trigger lookup, sequence reservation, signing, spool
append, or receipt append and returns a typed unavailable result. Core keeps the
exact `selected` request and trigger unacknowledged and retries the same bytes
only after external recovery. `mutation_read_only` remains a decodable failed
snapshot reason for compatibility and replay, but the local producer never
synthesizes that failed proof from its own persistent hard fence.

Observer state advances once from V4 to V5 and adds these exact journal anchors:

```text
pcc_boundary_count
pcc_boundary_bytes
pcc_boundary_head_sha256
pcc_receipt_count
pcc_receipt_bytes
pcc_receipt_head_sha256
```

V4-to-V5 migration is legal only when both
`<state>/spool/pcc-boundaries.agf` and
`<state>/spool/pcc-receipts.agf` are absent. A pre-existing unanchored file
fails closed and is never adopted as migrated history.

`<state>/spool/pcc-boundaries.agf` contains at most 1,024
`agmind.pcc-boundary-archive-record.v1` records, at most 64 MiB of verified
framed bytes, and at most 128 KiB per frame payload. Each record contains one
exact authenticated `boundary_event` and an optional exact
`rotation_companion_event`; A/B/C is derived, never stored as caller data.
Recovery revalidates signatures, event/content IDs, flags, key epochs,
source-sequence adjacency, boot linkage, and the complete A/B/C grammar.
Existing public-key metadata remains capped at 16 epochs.

`<state>/spool/pcc-receipts.agf` contains at most 4,096
`agmind.pcc-publication-receipt-record.v1` records, at most 16 MiB of verified
framed bytes, and at most 128 KiB per frame payload. The nested receipt has
exactly the five fields frozen above, carries no source sequence, and rebinds
the spool event by event ID and content hash.

Core durably appends the trigger without ACK, requests the snapshot, fetches and
durably appends every intervening event plus the snapshot, then advances ACKs in
source order. A crash retries the exact persisted request bytes.

Before POST, Core appends and fsyncs the exact request to
`correlation-requests.agf`:

```text
schema_version = "agmind.correlation-request-state.v1"
operation_key
request_sha256
request
phase = "selected" | "proof_observed" | "completed"
snapshot_event_id?
snapshot_content_sha256?
```

The journal is capped at 4,096 records and 16 MiB. Trigger identity and TTL are
therefore byte-stable across restart or configuration changes. Each frame
payload is capped at 64 KiB. Recovery strictly decodes the nested four-field
request, re-derives its canonical bytes, and verifies `request_sha256`; the
record has no canonical-bytes, deadline, or selection-time field. The journal
is the exact evidence-root operational artifact `correlation-requests.agf` and
is operational authority, never a SQLite projection.

## Historical coverage proof

Correlation never reuses live `MutationReadiness`.

For snapshot source sequence `S`, Core evaluates authenticated coverage through
`coverage_through_sequence == S - 1` over:

```text
[trigger.event_time - trigger.clock_uncertainty_ms, snapshot.decision_time]
```

Negative trigger age, negative inventory age, decision before window start, an
incomplete structural prefix, or any intersecting critical interval fails
closed.

All age/window arithmetic parses canonical UTC strings into exact integer
nanoseconds; it never uses floating point. The observer deliberately truncates
the snapshot decision timestamp to microsecond precision so the required public
`datetime` wrapper can represent it exactly. Trigger, inventory, and coverage
timestamps may retain all nine fractional digits.

`coverage_snapshot_sha256` is:

```text
hex(SHA256("AGMIND_CORRELATION_COVERAGE_V1\0" ||
           canonical_json({
             "host_id": host_id,
             "boot_id": boot_id,
             "trigger_event_id": trigger.event_id,
             "trigger_source_sequence": trigger.source_sequence,
             "coverage_through_sequence": coverage_through_sequence,
             "window_start": canonical_window_start,
             "window_end": decision_time,
             "intersecting_intervals": [
               {
                 "component": component,
                 "kind": kind,
                 "opened_at": opened_at,
                 "closed_at": closed_at?,
                 "open_event_id": open_event_id,
                 "close_event_id": close_event_id?
               }
             ],
             "coverage_event_ids": sorted_unique_event_ids
           })))
```

Intervals are sorted by
`(opened_at,component,kind,open_event_id,close_event_id-or-empty)`.
`coverage_event_ids` contains every coverage event used to establish prefix and
interval state.

A later authenticated coverage record proving an earlier intersecting gap adds
an append-only `candidate_invalidations` row. Candidate bytes are never deleted
or rewritten; its admission view becomes invalid regardless of action state.
Later action admission also rechecks current mutation readiness.

## Immutable Core facts

`IncidentV1` fields, in order:

```text
schema_version = "agmind.incident.v1"
incident_id
primary_event_id
primary_source_sequence
host_id
boot_id
detector_rule
detector_rule_version
event_time
ingest_time
successful_connect
investigation_only
docker_container_id?
docker_started_at?
proc_name?
proc_exe_path?
proc_parent_name?
destination_ipv4?
destination_port?
l4_protocol?
missing_required_fields[]
coverage_flags[]
evidence_ids[]
reason_codes[]
authority_event_id
```

`ContainmentCandidateV1` fields, in order:

```text
schema_version = "agmind.containment-candidate.v1"
candidate_id
incident_id
host_id
boot_id
primary_event_id
primary_source_sequence
correlation_snapshot_event_id
docker_container_id
docker_started_at
image_id
repo_digests[]
immutable_spec_sha256
inventory_generation
inventory_revision
destination_ipv4
destination_port
l4_protocol
ttl_seconds
detector_rule
detector_rule_version
detector_bundle_sha256
coverage_snapshot_sha256
docker_network_snapshot_sha256
special_use_registry_sha256
operator_denylist_sha256
management_denylist_sha256
evidence_ids[]
created_at
```

Both models use strict, extra-forbid, deeply immutable validation. They contain
no raw Falco line, Docker inspect document, model output, policy decision,
command, PID, namespace handle, approval, or mutation authority.

Incident IDs are:

```text
"inc_" + hex(SHA256("AGMIND_INCIDENT_ID_V1\0" || primary_event_id))
```

Candidate IDs keep the existing locked derivation over primary Falco event ID,
container generation, destination, and detector bundle hash. `created_at`
equals the signed snapshot `decision_time`.

The candidate's immutable `evidence_ids` is exactly the sorted pair of trigger
ID and snapshot ID. Later duplicates live only in append-only
`candidate_evidence` rows. `authority_event_id` on the incident and every
candidate-evidence row identifies the protected snapshot carrying the retained
trigger projection. The retired routine trigger need not remain an `events`
foreign key.

A direct investigation incident has `evidence_ids = (trigger_event_id,)` and
`authority_event_id = trigger_event_id`. Every proof-backed result has the
sorted unique pair `(snapshot_event_id, trigger_event_id)` and names the
snapshot as `authority_event_id`. Coverage records are bound by
`coverage_snapshot_sha256` and later invalidation rows; they never enter the
candidate's immutable `evidence_ids`.

`VerifiedEnvelope` is only a staged presentation and is publicly constructible,
so it is not correlation authority. Production correlation accepts an opaque,
deeply immutable `AuthenticatedPCCInput` capability issued by the
verifier/store coordinator only after the exact PCC record is durably committed
or authenticated during recovery. The capability binds the canonical snapshot,
its retained trigger projection, exact request, and durable `EvidenceRef`.
There is no public facts-to-capability constructor. Tests use a separate
module-private factory that is absent from production call paths.

## Exact result and gate semantics

`CorrelationResult` is exactly one of:

```text
CandidateCreated(incident, candidate)
InvestigationOnly(incident, reason_codes)
Duplicate(incident, existing_candidate_id)
Rejected(incident, reason_codes)
```

The correlator is invoked only for an exact verified `falco_connect`; another
event type is a typed caller error before a result exists. Every valid Falco
input therefore returns its incident in every result variant.

`CorrelationReasonCode` is the closed union:

```text
detector_not_pinned
connect_not_successful
sensor_fields_incomplete
authoritative_identity_incomplete
investigation_only
detector_bundle_not_pinned
mutation_read_only
reconcile_required
docker_reconcile_gap
routine_drop_pending
inventory_stale
docker_network_snapshot_unavailable
docker_network_snapshot_overflow
detector_bundle_unavailable
special_use_registry_unavailable
operator_denylist_unavailable
management_denylist_unavailable
container_not_running
container_identity_changed
observer_boot_changed
event_stale
clock_uncertain
historical_coverage_incomplete
critical_coverage_gap
correlation_proof_mismatch
destination_not_public
docker_destination
operator_destination
management_destination
target_not_running
shared_network_namespace
unsupported_network_mode
unsupported_network_driver
privileged_target
target_cap_net_admin
ttl_out_of_bounds
candidate_cooldown
```

Failed-snapshot reasons are preserved in their contract-sorted order. Every
other ordered security gate emits exactly one reason. Unknown strings are
contract errors, never projection data.

Gate order is:

1. exact verified envelope/schema/source and pinned rule/bundle;
2. successful connect;
3. complete authoritative trigger and snapshot identity;
4. trigger freshness at snapshot decision time, maximum 30 seconds;
5. inventory freshness, maximum 10 seconds;
6. clock uncertainty, maximum 2,000 ms;
7. complete historical coverage with no intersecting critical interval;
8. exact host/boot/container/generation/revision trigger-snapshot match;
9. public IPv4 plus special-use, Docker, operator, and management denies;
10. running bridge target with no shared/host/none network namespace;
11. non-privileged and neither configured nor effective `CAP_NET_ADMIN`;
12. TTL in `30..300`;
13. deterministic active-duplicate lookup;
14. ten-minute terminal cooldown when no active duplicate exists.

The first failing security gate wins. Failed connect, sensor omissions,
investigation-only input, and unresolved identity produce `InvestigationOnly`.
Stale/conflicting proof, unsafe target, coverage failure, TTL failure, and
cooldown produce `Rejected`.

The production signature is:

```python
correlate_pcc(
    authenticated: AuthenticatedPCCInput,
    context: CorrelationContext,
) -> CorrelationResult
```

There is no `now` or model parameter. Signed `decision_time` is the only
correlation clock. The context is deeply immutable, has no model field, and
contains only the exact detector pin, strict pinned special-use registry,
authenticated historical-coverage assessment, and key-bound read-only
duplicate/cooldown observations. The function performs no I/O.

Rebuild never fabricates a `VerifiedEnvelope`. The live wrapper and projection
call one internal pure kernel:

```python
correlate_pcc_facts(
    trigger: AuthenticatedFalcoFacts,
    proof: AuthenticatedCorrelationProof,
    context: CorrelationContext,
) -> CorrelationResult
```

`incident_from_verified_falco` handles the live no-proof investigation path.
`incident_from_retained_trigger` handles the protected retained projection.

All timestamp subtraction uses canonical RFC3339Nano-to-integer-nanosecond
parsing. `datetime.fromisoformat()`, `timestamp()`, floating-point seconds, and
microsecond truncation are forbidden in gate arithmetic. Values with seven to
nine fractional digits retain every digit.

## Duplicate ordering and cooldown

The logical duplicate key is:

```text
(host_id, boot_id, docker_container_id, docker_started_at,
 detector_bundle_sha256, destination_ipv4)
```

Authenticated stream order is authoritative. The lower
`(source_sequence,event_id)` is primary; later matches add only
`candidate_evidence` and never change candidate bytes or ID.

The reducer is fed in authenticated source order and never retroactively
replaces a primary candidate. Encountering an existing primary with a greater
source-order tuple is projection corruption. The duplicate key deliberately
excludes destination port, L4 protocol, and TTL: a later otherwise-safe proof
with different values is supporting evidence for the existing candidate; the
first candidate's immutable values remain authoritative.

Cooldown uses the same key and covers
`[terminal_at, terminal_at + 10 minutes)`. Equality at the upper boundary is
expired. Task 6 accepts no arbitrary terminal setter: terminal observations
must later derive from verified actuator action records. Until then production
cooldown state is read-only/empty and unit tests use a repository test double.
The only terminal states are `VERIFIED`, `EXPIRED`, `STALE_ABORT`, `REJECTED`,
`FAILED_DIRTY`, and `EXPIRED_UNAPPLIED`. If an active duplicate and a terminal
observation are both presented, the active duplicate wins and cooldown is not
evaluated.

Configured capability names are normalized case-insensitively. `NET_ADMIN`,
`CAP_NET_ADMIN`, or `ALL` in `configured_cap_add` fails the capability gate;
`configured_cap_drop` never grants authority and cannot make an unsafe
`configured_cap_add` acceptable. `effective_cap_net_admin = true` always
fails.

## Projection V2 and retention

SQLite remains a projection. Every incident/candidate row is reconstructible
byte-for-byte from protected snapshot/coverage records plus pinned
hash-addressed inputs after the routine trigger is retired. No live response,
wall-clock sample, model output, or SQLite-only terminal transition can create
or preserve a candidate.

Task 6 introduces projection schema/reducer/snapshot V2 with:

```text
incidents
candidates
candidate_evidence
candidate_invalidations
```

`candidate_evidence` rows contain exactly:

```text
candidate_id
evidence_event_id
evidence_source_sequence
evidence_content_sha256
role = "primary_trigger" | "correlation_snapshot" |
       "supporting_trigger" | "supporting_snapshot"
authority_snapshot_event_id
```

The primary key is
`(candidate_id,evidence_event_id,role,authority_snapshot_event_id)`.
`candidate_id` references `candidates`; `authority_snapshot_event_id`
references the protected snapshot in `events`. `evidence_event_id` deliberately
has no `events` foreign key because routine evidence may be retired. A
duplicate snapshot adds its own supporting-trigger and supporting-snapshot rows.

`candidate_invalidations` rows contain exactly:

```text
candidate_id
coverage_event_id
coverage_source_sequence
coverage_content_sha256
reason_code = "late_critical_coverage_gap"
```

The primary key is `(candidate_id,coverage_event_id)`. Both IDs reference live
projection rows. Logical snapshot order is full primary-key order for both
tables.

Opening a V1 cache never migrates rows in place. After authenticated evidence
recovery, Core performs its existing held-directory atomic rebuild into exact
V2 schema and verifies the V2 logical snapshot before activation.
`_TABLE_LAYOUT`, schema metadata, snapshot domain, reopen verification,
retention rebuild, and late-gap invalidation tests change together.
