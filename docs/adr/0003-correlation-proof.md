# ADR 0003: Deterministic correlation proof

- Status: accepted
- Date: 2026-07-29 (recorded retroactively on 2026-08-11)

## Context

Under proof-carrying containment ([ADR 0001](0001-proof-carrying-containment.md)), Core turns an
authenticated Falco connect trigger into an incident and, when every safety gate passes, a
containment candidate. Incidents and candidates are rebuildable SQLite projection tables: every
row must be reconstructible, byte for byte, from durable signed evidence alone — including after
retention has removed the routine trigger event that started the correlation.

The original draft of this design named live observer inventory and live coverage state as
correlation inputs. That draft was rejected before implementation: a live response is not
authenticated historical evidence, and live `MutationReadiness` contains a monotonic lease that
cannot be replayed. Everything below follows from replacing live inputs with a protected,
observer-signed correlation snapshot.

This record covers the snapshot contract, the observer's production discipline, the deterministic
correlation function, and the projection schema. Related records:
[ADR 0004](0004-proof-production-and-transport.md) (proof production and transport),
[ADR 0005](0005-historical-projection-authority.md) (historical projection authority — the
coverage-hash lock and rebuild activation in detail), and
[ADR 0006](0006-trusted-linearization-boundary.md) (trusted linearization boundary).

## Decisions

### Candidates require a protected proof event, never live inventory

Core admits no containment candidate directly from a live observer inventory response.
Candidate-capable correlation requires three things: a primary authenticated routine
`falco_connect` trigger, a later protected `pcc_correlation_snapshot` event bound to that exact
trigger, and authenticated coverage records through the snapshot's exact prior prefix. The
snapshot embeds both a fresh observer-owned inventory/network/safety snapshot and a bounded
observer-verified projection of the routine trigger, so Core can reproduce the incident and
candidate after retention removes the original routine event. Core correlation performs no
network call and has no model input.

Consequence: every candidate is byte-for-byte reconstructible from protected snapshot and
coverage records plus pinned hash-addressed inputs; retention of the routine trigger cannot
destroy candidate provenance.

### A narrow snapshot request with a Core-owned TTL and a durable request journal

`PCCCorrelationSnapshotRequestV1` contains exactly `schema_version` plus four facts:
`trigger_event_id`, `trigger_content_sha256`, `trigger_source_sequence`, and
`requested_ttl_seconds`. It is a request, not evidence or authority. TTL is constrained to
30..300 and the production path always sets `requested_ttl_seconds=120`, a Core-owned constant
that is not caller, model, policy, operator, or configuration input. Deadline, selection-time,
and pre-computed canonical-bytes fields were explicitly excluded from the request and its journal
record. The operation key is `pcc_correlation_snapshot:<trigger_event_id>`; an exact retry
returns the receipt-bound publication, while different canonical request bytes under the same key
are a security conflict and fence mutation readiness. Minimizing the request surface keeps the
observer from receiving any detector, registry, management, Docker, health, identity, policy,
model, or action fact from Core.

Before POSTing the request, Core appends and fsyncs the exact request to the evidence-root
journal `correlation-requests.agf` (schema `agmind.correlation-request-state.v1`): operation key,
`request_sha256`, the nested four-field request, a phase in `{selected, proof_observed,
completed}`, and optional snapshot identity. Caps as originally frozen: 4,096 records, 16 MiB
verified bytes, 64 KiB per frame payload (the record cap was later raised — see Current state).
Recovery strictly decodes the nested request, re-derives its canonical bytes,
and verifies `request_sha256`; there is no stored canonical-bytes, deadline, or selection-time
field to diverge. The journal is operational authority, never a SQLite projection — storing
request state in SQLite was rejected because projections are rebuildable and this is authority.

Orchestration order is fixed: Core durably appends the trigger without acknowledging it, requests
the snapshot, fetches and durably appends every intervening event plus the snapshot, then
advances ACKs in source order. The asynchronous transport call (see
[ADR 0004](0004-proof-production-and-transport.md)) sits between the durable trigger append and
the trigger ACK; ACKing the trigger before the proof exists would let retention destroy the
trigger while the proof is pending, and source-order ACK preserves the stream prefix property the
coverage proof depends on. A crash retries the exact persisted request bytes; an unresolved
trigger blocks ACK advance past it, fail-closed, including in the cross-boot case below.

### Root-owned, fail-closed safety pins with domain-separated hashes

The observer independently loads four safety inputs, only from root-owned, single-link regular
files beneath compile-time allowlisted paths: `/etc/falco/rules.d/agmind-pcc.yaml`,
`/usr/share/agmind-sais/ipv4-special-use.csv`, `/etc/agmind-sais/operator-denylist.json`, and
`/etc/agmind-sais/management-destinations.json`. Pins must not be caller input; root ownership
and fixed paths keep the detector rules and denylists out of reach of non-root tampering. Failure
to safely load, parse, canonicalize, or bind any pin prevents a candidate-capable snapshot — the
strict failed form is emitted instead, with the corresponding closed failure reason
(`detector_bundle_unavailable`, `special_use_registry_unavailable`,
`operator_denylist_unavailable`, `management_denylist_unavailable`). Pin reading uses its own
single-link-regular-file path plus a root-process requirement
(`host/observerd/pcc_pins.go:122`), which interacts with the repo-wide file-mode regime: the
installer ships these artifacts read-only.

Each pin is bound by a domain-separated hash:

- `detector_bundle_sha256` = `hex(SHA256("AGMIND_DETECTOR_BUNDLE_V1\0" ||
  uint64_be(len(rule_file_bytes)) || rule_file_bytes || uint64_be(len(adapter_schema_version)) ||
  adapter_schema_version || uint64_be(len(falco_version)) || falco_version))`, with
  `adapter_schema_version="agmind.falco-connect.v1"` and `falco_version="0.44.1"` as exact
  deployment pins, not caller input. Length prefixes make the concatenation unambiguous, and the
  domain string separates this hash from every other SHA256 use. Any Falco version or adapter
  schema bump changes the bundle hash and therefore the candidate duplicate key.
- The IPv4 special-use registry is loaded through a bounded strict loader: it hashes the raw
  bytes before parsing, requires the repository-pinned digest
  (`e3e39e76d00b1677335db8e9a805c7b9480ea2f4dc9e33f0b93cd3a905128d73`) and the exact IANA header,
  rejects malformed, duplicate, or non-IPv4 prefixes and unrecognized reachability values, and
  never skips a row. Permissive skip-row parsing was rejected: a silently-degraded deny set is
  not candidate authority. Registry updates require updating the pinned digest in both language
  mirrors.
- Operator and management denylist hashes share one canonical payload shape —
  `hex(SHA256(domain || canonical_json({"denied_addresses": …, "denied_networks": …})))` with
  sorted unique arrays — but distinct domains `AGMIND_OPERATOR_DENYLIST_V1\0` and
  `AGMIND_MANAGEMENT_DENYLIST_V1\0`, so one denylist can never be replayed as the other even when
  contents coincide. The complete snapshot carries both hashes plus the arrays; either hash
  mismatch fails admission.

Python and Go share fixed parity vectors for every hash domain; both mirrors must change
together.

### The retained trigger projection is producer-constructed, never raw Falco JSON

`PCCFalcoTriggerProjectionV1` is an exact allowlisted projection of the triggering
`falco_connect`: identity, sequence, host/boot, times, inventory generation and revision,
container identity, detector rule facts, connect outcome, process names, destination triple,
omissions, coverage flags, and `raw_event_sha256`. The producer decodes the exact authenticated
trigger from its still-unacknowledged spool record and constructs the projection itself.
Caller-supplied trigger facts are forbidden, and raw Falco JSON is never embedded — the
projection preserves every trigger fact needed for incident construction, candidate gates, and
cross-binding after the routine event is retired, without letting Core or an attacker supply
trigger facts and without carrying unbounded raw sensor output. Replay after retention validates
the snapshot's internal bindings against this projection; the retired routine trigger need not
remain an events-table foreign key.

### A minimal, atomic Docker network view

The deliberately narrow read-only `DockerReader` boundary gains exactly one method: Moby v1.55's
`NetworkList(context.Context, client.NetworkListOptions)`. The reconciler calls `NetworkList`
without filters, then `NetworkInspect` once per returned exact network ID; it rejects empty or
duplicate IDs, list/inspect disagreement, disappearing networks, any parse error, and any limit
overflow, sorting only after the full walk succeeds. A generic Docker request surface or filtered
listing was rejected: the boundary stays minimal and read-only, and any future Docker need must
be argued as a new exact method.

The inventory atomically commits the bounded complete global Docker-network snapshot in the same
generation as its container identities; a failed global walk commits neither and leaves
reconciliation required. Proof publication clones target identity and global networks under one
inventory read lock and never performs a partial live network walk. Each `PCCDockerNetworkV1` has
exactly `network_id`, `driver`, `subnet_cidrs[]`, `gateway_addresses[]`; set-like arrays are
canonical sorted unique, entries are sorted by network ID, conflicting duplicate IDs fail closed,
and IPv4-mapped IPv6 spellings are rejected so Python and Go cannot canonicalize one Docker fact
to different bytes. Limits: 64 networks, at most 128 subnet CIDRs and 128 gateway addresses in
total, at most 32 of either per network, and a 16 KiB cap on the canonical `docker_networks`
array. The hash is `hex(SHA256("AGMIND_DOCKER_NETWORK_SNAPSHOT_V1\0" ||
canonical_json(docker_networks)))`. If a complete snapshot cannot be represented, the producer
emits the strict failed form; it never publishes a truncated network array, because truncation
would silently weaken the `docker_destination` deny gate. Docker deny networks and addresses are
computed from the canonical snapshot at correlation time, not duplicated on the wire.

### Exactly two mutually exclusive snapshot forms, exactly bound

`PCCCorrelationSnapshotV1` has exactly a complete form (full pin hashes, denylists, Docker
networks, container identity, capability flags, `coverage_through_sequence`,
`hard_limits_version="pcc-hard-limits-v1"`) and a failed form (request/trigger/decision-time/TTL,
a nonempty sorted-unique `failure_reasons` list drawn from a closed 14-value enum, and optional
boot-transition fields). The closed enum is exactly `mutation_read_only`, `reconcile_required`,
`docker_reconcile_gap`, `routine_drop_pending`, `inventory_stale`,
`docker_network_snapshot_unavailable`, `docker_network_snapshot_overflow`, the four
pin-unavailable reasons above, `container_not_running`, `container_identity_changed`, and
`observer_boot_changed`. Complete-only fields are absent — not null — in the failed form, and
`failure_reasons` is absent in the complete form; nullable complete-fields were rejected. A
failed snapshot creates a Rejected incident decision and can never create a candidate. Strict
mutually exclusive forms prevent a partially populated snapshot from being admitted as complete,
and the closed failure enum makes every degraded state an explicit, replayable decision instead
of silence. Verifier admission is exact-schema; unknown failure reasons are contract errors.

The envelope binding is exact: `event_type=pcc_correlation_snapshot`, `source_id=agmind-observerd`
with protected evidence priority; one timestamp sample supplies
`event_time = ingest_time = decision_time`; for the complete form, envelope
container/start/generation/revision equal the fresh normalized inventory identity and the release
ID equals the locked image/spec derivation, while in the failed form container, start, release,
and revision are absent and inventory generation is zero; no redaction or coverage flags;
`source_payload_hash = normalized_fields_sha256`; `coverage_through_sequence = source_sequence -
1`; the trigger source sequence strictly lower than the snapshot source sequence; envelope host
always equal to the embedded trigger's; envelope boot equal to the trigger's except in the
cross-boot terminal form; the request trigger triple equal to the embedded trigger triple;
embedded trigger identity, content, and candidate facts matching the exact spool record; and
`request_sha256` hashing the exact canonical request bytes. Every binding closes one substitution
avenue — same-stream trigger binding stops splicing a snapshot onto a different trigger, the
single timestamp sample makes `decision_time` the sole clock, and `coverage_through = S-1` pins
the coverage claim to the stream position. At initial admission Core additionally cross-checks
the retained projection against the still-present authenticated trigger. The verifier admits
only exact `pcc_correlation_snapshot` envelopes and classifies them protected.

### Cross-boot terminal form with a recomputable boot-transition chain proof

If the observer reboots after Core durably selects a trigger but before proof publication, the
producer emits a failed snapshot with exactly `failure_reasons=["observer_boot_changed"]`,
`boot_transition_hop_count` in 1..1024, and `boot_transition_chain_sha256 =
hex(SHA256("AGMIND_BOOT_TRANSITION_CHAIN_V1\0" || canonical_json(boundary_chain)))`. The chain is
the complete source-sequence-ordered list of authenticated protected boot-transition hops from
the trigger boot to the snapshot boot: the first hop names the trigger boot as its previous boot,
every later hop names the preceding hop's boot, and the last boundary boot equals the snapshot
envelope boot. Hops use the frozen closed boundary union: (A) a dedicated
`observer_boot_boundary`; (B) a new-boot
`observer_key_transition` plus its exact adjacent same-boot `observer_key_epoch_start`; (C) an
old-boot `observer_key_transition` plus its exact adjacent new-boot `observer_key_epoch_start`.
The five `rotation_companion_*` fields are all absent for A and all present for B and C.

Core recomputes the chain from the complete protected boundary union in the authenticated source
prefix and requires both count and hash to match; missing, extra, reordered, disconnected,
unavailable, or invalid pair evidence fails verification. Core derives `previous_boot_id` and
`previous_source_sequence` from its accepted verifier FSM — rotation payloads do not invent
predecessor fields. The producer obtains the chain from protected spool records plus persisted
boot history, never caller input. A boot change invalidates all live state behind the trigger;
the chain proof makes the rejection itself verifiable and replayable rather than trusting the
producer's claim.

This form deterministically produces `Rejected(observer_boot_changed)`, retains the trigger
projection durably, never attempts Docker, pin, freshness, coverage, or candidate gates, and lets
Core ACK trigger and proof in source order. If the chain cannot be reconstructed, the observer
stays fail-closed and no ACK advances past the unresolved trigger. Ordinary failed snapshots
forbid `observer_boot_changed` and omit both boot-transition fields — the cross-boot form is not
an optional extra on other failures. For this form only, envelope boot differs from the embedded
trigger boot, and cross-boot replay additionally requires every protected boundary or rotation
pair committed by `boot_transition_chain_sha256`.

### Producer publication discipline: frozen lock order, specialized receipt, mutation fence

The producer's lock order is frozen: (1) observer publication mutex; (2) exact unacknowledged
trigger lookup and binding; (3) inventory read lock and same-generation target/global-network
clone; (4) one root-owned safety-pin snapshot; (5) one UTC timestamp sample; (6) choose
`S = last_sequence + 1`; (7) form fields with `coverage_through_sequence = S - 1`; (8) reserve,
sign, atomically append event plus receipt, and publish state. A fixed order makes the critical
section deterministic and race-free — identity, networks, pins, and time are all captured before
the sequence is chosen — and any new input to the snapshot must be slotted into this order, not
sampled ad hoc.

Publication uses a specialized append-only receipt binding exactly five fields: `operation_key`,
`request_sha256`, `snapshot_normalized_sha256`, `snapshot_event_id`, `snapshot_content_sha256`.
Reusing the existing Core-control publisher was rejected: request bytes and observer-derived
normalized output differ, and separate request and output hashes prevent an idempotency check on
one from masquerading as integrity of the other. An exact retry verifies and returns the
receipt-bound event; a mismatched request or receipt is corruption or conflict. The nested
receipt carries no source sequence and rebinds the spool event by event ID and content hash.

Persistent `mutation_read_only` is an absolute typed-unavailable, no-publication fence: the local
producer checks it before trigger lookup, sequence reservation, signing, spool append, or receipt
append, and returns a typed unavailable result. Core keeps the exact selected request and trigger
unacknowledged and retries the same bytes only after external recovery. Emitting a
`mutation_read_only` failed snapshot locally was explicitly rejected — publishing a signed failed
proof while the observer's own durability is compromised would launder a hard-fence state into
evidence; the fence must stop all writes, including the write that would report the fence. The
enum value remains decodable for compatibility and replay only.

### Observer state V4→V5: six journal anchors, permanent append-only receipts

Observer state advances once from V4 to V5, adding exact count, byte, and head-hash anchors for
two new fixed journals: `pcc_boundary_count/bytes/head_sha256` and
`pcc_receipt_count/bytes/head_sha256`. Anchoring all three in signed state means a truncated,
extended, or substituted journal is detectable at startup. Migration is legal only when both
`<state>/spool/pcc-boundaries.agf` and `<state>/spool/pcc-receipts.agf` are absent; a
pre-existing unanchored file fails closed and is never adopted as migrated history, so an
attacker cannot pre-seed history before the migration. Journal caps: `pcc-boundaries.agf` at
1,024 records / 64 MiB verified framed bytes / 128 KiB per frame payload; `pcc-receipts.agf` at
4,096 records / 16 MiB / 128 KiB. Boundary records store one exact authenticated boundary event
plus an optional rotation companion event; the A/B/C classification is derived, never stored as
caller data, and recovery revalidates signatures, IDs, flags, key epochs, sequence adjacency,
boot linkage, and the complete A/B/C grammar.

Receipt records are permanent append-only audit history; ACK never deletes, compacts, or
checkpoints them (compaction on ACK was rejected). Startup accepts an exact anchored historical
receipt after its spool event has been acknowledged and removed, strictly revalidates every
receipt whose snapshot remains in the spool, and rejects every live snapshot without its exact
receipt. A new append, an exact retry lookup, and ACK authorization always require the exact live
unacknowledged spool frame and publication binding — historical receipt presence alone can never
republish or return an acknowledged snapshot. The receipt journal cap is therefore a lifetime
bound on snapshot publications per state instance.

### Correlation authority is a post-commit capability; the correlator is a pure function

`VerifiedEnvelope` is only a staged presentation and is publicly constructible, so it is not
correlation authority. Production correlation accepts an opaque, deeply immutable
`AuthenticatedPCCInput` capability issued by the verifier/store coordinator only after the exact
PCC record is durably committed, or authenticated during recovery. The capability binds the
canonical snapshot, its retained trigger projection, the exact request, and a durable
`EvidenceRef`. There is no public facts-to-capability constructor; tests use a separate
module-private factory absent from production call paths. Accepting a caller-constructed
`VerifiedEnvelope` or public facts object as authority was explicitly rejected: any publicly
constructible input type lets a caller forge correlation authority from unauthenticated facts.

The production signature is `correlate_pcc(authenticated: AuthenticatedPCCInput, context:
CorrelationContext) -> CorrelationResult`. There is no `now` and no model parameter; the signed
`decision_time` is the only correlation clock, and the deeply immutable context contains only the
exact detector pin, the strict pinned special-use registry, the authenticated historical-coverage
assessment, and key-bound read-only duplicate/cooldown observations. The function performs no
I/O. The live wrapper and the rebuild projection both call one internal pure kernel,
`correlate_pcc_facts(trigger, proof, context)`, so live evaluation and historical rebuild cannot
diverge. Any non-determinism — time, I/O, model output — must live outside correlation and
enter, if at all, as signed evidence.

### Fourteen ordered security gates, closed results, closed reasons

`CorrelationResult` is exactly one of `CandidateCreated(incident, candidate)`,
`InvestigationOnly(incident, reason_codes)`, `Duplicate(incident, existing_candidate_id)`, or
`Rejected(incident, reason_codes)`. The correlator is invoked only for an exact verified
`falco_connect` — another event type is a typed caller error before a result exists — so every
valid input returns its incident in every result variant and no signal is silently dropped.
`CorrelationReasonCode` is a closed union: the 14 failed-snapshot reasons in contract-sorted
order plus gate reasons such as `detector_not_pinned`, `event_stale`, `clock_uncertain`,
`historical_coverage_incomplete`, `critical_coverage_gap`, `correlation_proof_mismatch`,
`destination_not_public`, `docker/operator/management_destination`, `target_not_running`,
`shared_network_namespace`, `unsupported_network_mode/driver`, `privileged_target`,
`target_cap_net_admin`, `ttl_out_of_bounds`, and `candidate_cooldown`. Unknown strings are
contract errors, never projection data. Adding a reason code is a contract change requiring
both-language mirror updates.

Gate order is fixed, the first failing security gate wins, and each gate emits exactly one
reason: (1) exact verified envelope, schema, source, and pinned rule/bundle; (2) successful
connect; (3) complete authoritative trigger and snapshot identity; (4) trigger freshness at
snapshot decision time, max 30 s; (5) inventory freshness, max 10 s; (6) clock uncertainty, max
2,000 ms; (7) complete historical coverage with no intersecting critical interval; (8) exact
host/boot/container/generation/revision trigger-snapshot match; (9) public IPv4 plus
special-use, Docker, operator, and management denies; (10) running bridge target with no
shared/host/none network namespace; (11) non-privileged and neither configured nor effective
`CAP_NET_ADMIN`; (12) TTL in 30..300; (13) deterministic active-duplicate lookup; (14) a
ten-minute terminal cooldown when no active duplicate exists. Failed connect, sensor omissions,
investigation-only input, and unresolved identity produce `InvestigationOnly`; stale or
conflicting proof, an unsafe target, coverage failure, TTL failure, and cooldown produce
`Rejected` — distinguishing "not actionable but real signal" from "proof or safety failure".
Threshold changes are contract changes; the ordering is part of the byte-identical rebuild
guarantee.

For gate 11, configured capability names are normalized case-insensitively: `NET_ADMIN`,
`CAP_NET_ADMIN`, or `ALL` in `configured_cap_add` fails the gate; `configured_cap_drop` never
grants authority and cannot make an unsafe `configured_cap_add` acceptable (Docker accepts
multiple spellings, and a drop that "neutralizes" an add leaves the effective capability
ambiguous); `effective_cap_net_admin = true` always fails. A container with `CAP_NET_ADMIN` in
any configured or effective form can never become a containment candidate, because it could undo
the nftables deny.

### Exact integer-nanosecond timestamp arithmetic

All age and window arithmetic parses canonical RFC3339Nano UTC strings into exact integer
nanoseconds. `datetime.fromisoformat()`, `timestamp()`, floating-point seconds, and microsecond
truncation are forbidden in gate arithmetic; values with seven to nine fractional digits retain
every digit. Floating point and library datetime conversions lose or round nanosecond digits,
which would make Python and Go gate arithmetic diverge on boundary cases. The observer
deliberately truncates only the snapshot `decision_time` to microsecond precision so the required
public datetime wrapper can represent it exactly — truncating at the producer rather than the
consumer keeps the canonical bytes and the datetime representation identical. Trigger, inventory,
and coverage timestamps may retain all nine digits. Boundary comparisons (freshness, cooldown
expiry) are exact integer comparisons with shared cross-language parity vectors.

### Historical coverage proof and append-only late-gap invalidation

Correlation never reuses live `MutationReadiness` (the original design's use of it was rejected —
its monotonic lease cannot be replayed). For snapshot source sequence `S`, Core evaluates
authenticated coverage through `coverage_through_sequence == S-1` over the window
`[trigger.event_time - trigger.clock_uncertainty_ms, snapshot.decision_time]`. Negative trigger
age, negative inventory age, a decision before the window start, an incomplete structural prefix,
or any intersecting critical interval fails closed. The assessment is itself hashed:
`coverage_snapshot_sha256 = hex(SHA256("AGMIND_CORRELATION_COVERAGE_V1\0" ||
canonical_json({host_id, boot_id, trigger_event_id, trigger_source_sequence,
coverage_through_sequence, window_start, window_end, intersecting_intervals[],
coverage_event_ids[]})))`, with intervals sorted by `(opened_at, component, kind, open_event_id,
close_event_id-or-empty)` and `coverage_event_ids` containing every coverage event used. This
makes "the sensors were watching during the window" a replayable, tamper-evident claim bound into
the candidate. The candidate carries `coverage_snapshot_sha256`; coverage records are bound by
that hash and later invalidation rows but never enter the candidate's immutable `evidence_ids`.

A later authenticated coverage record proving an earlier intersecting gap adds an append-only
`candidate_invalidations` row (primary key `(candidate_id, coverage_event_id)`, plus the coverage
event's source sequence and content hash, with `reason_code` fixed to
`late_critical_coverage_gap`). Unlike retirable routine evidence, both key IDs reference live
projection rows — coverage records are protected and are not retired. Candidate bytes are never
deleted or rewritten — rewriting would break byte-identical rebuild and hash bindings — but the
candidate's admission view becomes invalid regardless of action state, and later action admission
also rechecks current mutation readiness. Admission logic must consult invalidations, not just
candidate existence, and invalidation is deterministic on replay.

### Duplicate key and ten-minute half-open cooldown

The logical duplicate key is `(host_id, boot_id, docker_container_id, docker_started_at,
detector_bundle_sha256, destination_ipv4)`. Authenticated stream order is authoritative: the
lower `(source_sequence, event_id)` is primary; later matches add only `candidate_evidence` rows
and never change candidate bytes or ID. Encountering an existing primary with a greater
source-order tuple is projection corruption. The key deliberately excludes destination port, L4
protocol, and TTL — including them was rejected because it would let an attacker or a noisy
detector mint many parallel candidates against one container/destination by varying ports. A
later otherwise-safe proof with different port/protocol/TTL values is supporting evidence for the
existing candidate, whose immutable values remain authoritative. The reducer must be fed in
authenticated source order.

Cooldown uses the duplicate key and covers `[terminal_at, terminal_at + 10 minutes)`; equality at
the upper boundary is expired (half-open semantics remove ambiguity at exactly +10 minutes). This
design accepts no arbitrary terminal setter: terminal observations must later derive from
verified actuator action records, because an arbitrary setter would let unverified state suppress
future candidates. Until then, production cooldown state is read-only and empty (unit tests use a
repository test double), so the `candidate_cooldown` gate cannot fire in production — a known,
deliberate gap. The only terminal states are `VERIFIED`, `EXPIRED`, `STALE_ABORT`, `REJECTED`,
`FAILED_DIRTY`, and `EXPIRED_UNAPPLIED`. If an active duplicate and a terminal observation are
both presented, the active duplicate wins and cooldown is not evaluated.

### Immutable Core facts with locked ID derivations and exact evidence binding

`IncidentV1` and `ContainmentCandidateV1` are strict, extra-forbid, deeply immutable models with
exact ordered field sets. They contain no raw Falco line, Docker inspect document, model output,
policy decision, command, PID, namespace handle, approval, or mutation authority. Incident IDs
are `"inc_" + hex(SHA256("AGMIND_INCIDENT_ID_V1\0" || primary_event_id))`; candidate IDs keep the
existing locked derivation over primary Falco event ID, container generation, destination, and
detector bundle hash — content-derived IDs make both deterministic across rebuilds. `created_at`
equals the signed snapshot `decision_time`; wall-clock `created_at` was rejected. The candidate's
immutable `evidence_ids` is exactly the sorted pair `(snapshot_event_id, trigger_event_id)` with
the snapshot as `authority_event_id`; a direct investigation incident has
`evidence_ids=(trigger_event_id,)` and `authority_event_id=trigger_event_id`. Later duplicates
live only in append-only `candidate_evidence` rows, and coverage records never enter immutable
`evidence_ids` (append-only side tables were chosen instead). `authority_event_id` identifies the
protected snapshot carrying the retained trigger projection, so the retired trigger needs no
events foreign key.

### SQLite remains a projection: V2 schema, authenticated atomic rebuild only

SQLite remains a rebuildable projection: no live response, wall-clock sample, model output, or
SQLite-only terminal transition can create or preserve a candidate. Projection V2 has exactly
`incidents`, `candidates`, `candidate_evidence`, and `candidate_invalidations`.
`candidate_evidence` rows are `(candidate_id, evidence_event_id, evidence_source_sequence,
evidence_content_sha256, role, authority_snapshot_event_id)` with role in `{primary_trigger,
correlation_snapshot, supporting_trigger, supporting_snapshot}` and primary key `(candidate_id,
evidence_event_id, role, authority_snapshot_event_id)`. `evidence_event_id` deliberately has no
events foreign key — routine evidence may be retired, and a foreign key would either block
retention or break referential integrity — while `authority_snapshot_event_id` references the
protected snapshot that does remain in events. Content hashes plus the protected snapshot
reference preserve provenance without pinning retired rows. Logical snapshot order is full
primary-key order for both new tables.

Opening a V1 projection cache never migrates rows in place: in-place migration would create
projection rows whose provenance was never re-derived from authenticated evidence. After
authenticated evidence recovery, Core performs its existing held-directory atomic rebuild into
the exact V2 schema and verifies the V2 logical snapshot before activation. The table layout,
schema metadata, snapshot domain, reopen verification, retention rebuild, and late-gap
invalidation tests change together. V2 activation cost is a full rebuild, and the rebuild must be
proven byte-identical before and after routine trigger retention. See
[ADR 0005](0005-historical-projection-authority.md) for the projection-authority design in
detail.

### Replay after retention: proved absence only, never fabricated envelopes

On historical replay after retention, absence of the routine trigger is legal only when
authenticated retired-range evidence covers the trigger sequence; "the trigger is legitimately
gone" is itself an authenticated claim. Core then validates the snapshot's internal bindings
without fabricating a `VerifiedEnvelope` or requiring a deleted trigger row — fabricating an
envelope during rebuild would create authority from projection data, and keeping retired triggers
as events-table foreign keys was rejected because evidence may be retired. The live wrapper and
the projection path call the same pure kernel: `incident_from_verified_falco` handles the live
no-proof investigation path and `incident_from_retained_trigger` handles the protected retained
projection.

### Investigation-only incidents ride routine evidence

Investigation-only events create ordinary incidents directly from their routine evidence
(`evidence_ids = (trigger_event_id,)`, `authority_event_id = trigger_event_id`) and may age out
with that evidence. Only active or rejected candidate decisions use the protected snapshot
authority — spending a protected proof event on every investigation-only signal would waste the
bounded receipt/boundary journals and protected-quota budget on decisions that carry no
containment authority. Investigation-only incidents are therefore not guaranteed to survive
retention, by design; proof-backed incidents are.

### The correlation layer grants no enforcement authority

No part of this design — contracts, pure correlation, producer and transport, historical coverage
and projection V2 — introduces policy, AI, approval, actuator, or nftables authority. Correlation
output is evidence and candidates only: the correlation layer proves and proposes, while
admission, approval, and enforcement live in later layers with their own gates (see
[ADR 0001](0001-proof-carrying-containment.md)). Any future authority addition to correlation is
a boundary violation, not an increment.

## Current state (2026-08-11)

One frozen constant has been superseded by current code: the design capped
`correlation-requests.agf` at 4,096 records, but when append-only late coverage invalidations
landed (2026-08-03) the record cap in `core/agmind_immune/ingest/correlation_journal.py:67` was
raised to 12,291, and a separate 4,096-item bound (`_MAX_COMPLETED_BATCH`, `:70`, enforced at
`:2389`) was added for authenticated completed-batch evaluation. The 16 MiB verified-byte
cap and 64 KiB frame cap are unchanged. Every other decision stands as designed. The one
design-time reversal — live observer inventory and live coverage state as correlation inputs —
was rejected before implementation and is recorded above as the rejected alternative to the
protected-snapshot and historical-coverage decisions.

Verified in code on 2026-08-11:

- Snapshot-only correlation input and pure function: `core/agmind_immune/correlation/pcc.py:2346`
  (`correlate_pcc` takes only `AuthenticatedPCCInput` + `CorrelationContext`), `:2322`
  (`correlate_pcc_facts` kernel); capability issuance in
  `core/agmind_immune/correlation/authority.py` (`EvidenceRef` binding at `:546`, `:1133-1149`).
- Request contract and journal: `core/agmind_immune/contracts.py:696`
  (`PCCCorrelationSnapshotRequestV1`), `core/agmind_immune/ingest/service.py:89`
  (`PCC_CORRELATION_TTL_SECONDS = 120`), `core/agmind_immune/ingest/correlation_journal.py:67-70`
  (caps as amended: 12,291 records / 16 MiB / 64 KiB plus the 4,096 completed-batch bound),
  `:111` (phase literal), `:135`/`:982` (TTL 120 enforced), `:144-150` (selected phase omits
  snapshot identity).
- Safety pins and hash domains: `host/observerd/pcc_pins.go:16-19` (the exact four paths), `:109`
  and `:122` (root-process fail-closed load); domain constants in
  `core/agmind_immune/canonicaljson.py:26-30` and
  `internal/contracts/pcc_correlation_proof.go:17-26`;
  `core/agmind_immune/contracts.py:738` (`falco_version: Literal["0.44.1"]`); pinned special-use
  digest present in both mirrors plus `host/observerd/pcc_pins.go`; strict registry loader at
  `core/agmind_immune/correlation/primitives.py:345` and `core/agmind_immune/main.py:125`.
- Snapshot and projection contracts: `core/agmind_immune/contracts.py:718`
  (`PCCFalcoTriggerProjectionV1`), `:884` (`PCCDockerNetworkV1`), `:1099`
  (`PCCCorrelationSnapshotV1`), `:1138` (hard-limits literal), `:1316` (complete/failed
  discriminated-shape validation), `:1020-1037` (the closed 14-value failure-reason set).
- Docker boundary: `host/observerd/docker.go:57-60` (`NetworkList` on the reader interface),
  `:219` (Moby implementation), `host/observerd/inventory.go:663-665` (unfiltered walk).
- Producer fence and receipts: `host/observerd/pcc_publish.go:488`, `:539`, `:776`
  (`MutationReadOnly` gates assembly and publication); `host/observerd/pcc_receipts.go:32-36`
  (exact five receipt fields), `:19-21` (receipt journal caps);
  `host/observerd/pcc_boundary_archive.go:19-21` (boundary journal caps) with A/B/C recovery;
  `host/observerd/envelope.go:91,94` (V5 anchors).
- Correlation gates and keys: `core/agmind_immune/correlation/pcc.py:57-59` (30 s / 10 s /
  10 min thresholds in integer ns), `:140` (`parse_rfc3339nano_utc_ns`), `:2116` (clock
  uncertainty 2,000 ms), `:2233` (TTL 30..300), `:2279` (half-open cooldown), `:128-134`
  (six-field `CandidateDuplicateKey`), `:1547`/`:1570` (live and retained incident paths),
  `:1710-1711` (gate 11 case-insensitive unsafe set `net_admin`/`cap_net_admin`/`all`),
  `:2224-2231` (gate 11 never consults `configured_cap_drop`; `effective_cap_net_admin` must be
  exactly false).
- Coverage and projection: `core/agmind_immune/coverage/historical.py`
  (`AGMIND_CORRELATION_COVERAGE_V1` domain); `core/agmind_immune/evidence/projection_v2.py:338`
  (`candidate_evidence`), `:350` (`candidate_invalidations`), `:381-382` (trigger/snapshot
  evidence reducer steps), `:900`/`:924` (candidate-evidence row encode/decode);
  `core/agmind_immune/incidents/models.py:170`/`:322`
  (immutable facts), `core/agmind_immune/canonicaljson.py:360` (incident-ID preimage);
  `core/tests/evidence/test_projection_replay_boundary.py` exists.

Recorded but not line-verified as of 2026-08-11 (the cited files exist; the specific semantics
were not re-checked): the exact envelope binding rules; the step-by-step eight-step lock order in
`host/observerd/pcc_publish.go`; receipt-permanence semantics in `host/observerd/pcc_receipts.go`;
the Core orchestration ordering in `core/agmind_immune/ingest/service.py`; exact
`CorrelationResult`/reason-code union membership; the V1-to-V2 rebuild-activation path; and the
individual numeric Docker-network limits.

## Notes

- Size invariant other contracts depend on: a complete snapshot's entire canonical normalized
  object is at most 24 KiB, a fixed margin beneath the existing 32 KiB envelope limit; the
  canonical `docker_networks` array alone is capped at 16 KiB; there is no truncation path.
- The boot-transition hop count is bounded to 1..1024, and the boundary A/B/C union
  (`observer_boot_boundary`, `observer_key_transition` + adjacent `observer_key_epoch_start`
  pairs) was frozen before this design and is reused, not redefined, by the chain proof.
- The existing observer public-key metadata cap of 16 epochs is unchanged; the V4-to-V5 state
  migration deliberately does not raise it.
- Known deliberate gap: until verified actuator action records exist, production cooldown state
  is read-only and empty, so the `candidate_cooldown` gate cannot fire in production; unit tests
  use a repository test double.
- Design-time acceptance gating: no repo-wide or native-Linux suite run was part of this work's
  gate — only the focused contract, correlation, producer, and coverage/projection test gates —
  and the historical coverage and projection work additionally required an independent security
  review before dependent work began.
- Exact deployment pins referenced by multiple contracts:
  `adapter_schema_version_ascii="agmind.falco-connect.v1"`, `falco_version_ascii="0.44.1"`,
  `special_use_registry_sha256=e3e39e76d00b1677335db8e9a805c7b9480ea2f4dc9e33f0b93cd3a905128d73`
  — all present in both the Python and Go mirrors as of 2026-08-11.
- `correlation-requests.agf` lives in the evidence root and is operational authority, never a
  SQLite projection; recovery verifies `request_sha256` by re-deriving canonical bytes from the
  nested request (there is no stored canonical-bytes field to diverge).
- The two-language mirror discipline is load-bearing throughout: every hash domain, pin, and
  contract field set exists in both `core/agmind_immune` (Python) and `internal/contracts` +
  `host/observerd` (Go), with shared parity vectors. Changing one side without the other breaks
  verification.
- Timestamp precision contract: only the snapshot `decision_time` is truncated to microseconds
  (for exact public datetime representability); trigger, inventory, and coverage timestamps may
  retain all nine fractional digits, and all gate arithmetic is integer-nanosecond.
