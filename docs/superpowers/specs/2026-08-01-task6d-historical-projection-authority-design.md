# Task 6D historical coverage and Projection V2 design

**Status:** approved refinement of the frozen Task 6 proof-carrying
containment design. This document closes the authority gap between the durable
PCC transport delivered by 6C and Manual-Only policy admission in Task 7.

## Outcome

Task 6D turns an authenticated `pcc_correlation_snapshot` into a durable,
rebuildable containment candidate only when all of the following are true:

1. the snapshot is an exact post-commit `AuthenticatedPCCInput`;
2. its historical coverage prefix is complete and has no critical interval
   intersecting the correlation window;
3. the Core-owned detector and special-use pins match the snapshot;
4. the deterministic correlation gates pass under an issued local context;
5. the incident, candidate, evidence links, and later invalidations are
   committed atomically to Projection V2.

The result is not action authority. It is the last evidence-derived fact before
OPA, local approval, and the actuator. OPA, a model, an HTTP caller, and a
caller-constructed `ContainmentCandidateV1` cannot create or repair this fact.

## Why Task 7 cannot safely precede 6D

The public correlation API intentionally rejects every complete proof today:
`correlation_context_is_issued()` always returns false. Projection V1 treats a
PCC snapshot as an untyped `other` event and has no incident, candidate,
evidence-link, or invalidation rows. Sending a caller-created candidate to OPA
would therefore make OPA validate a claim rather than an authenticated Core
decision.

Task 7 may be developed in isolation, but it cannot be wired to containment or
emit an intent until the authority described here exists.

## Considered approaches

### A. Send parsed PCC facts directly to OPA

Rejected. A valid signature on the PCC snapshot does not by itself prove
historical Core coverage, duplicate ordering, or late invalidation state. OPA
would also become the place where evidence authority is accidentally minted.

### B. Let any `CorrelationContext` that passes field validation create a candidate

Rejected. `CorrelationContext`, `HistoricalCoverageAssessment`, and
`ContainmentCandidateV1` are public value types. Field correctness is not
provenance. A caller can construct all three.

### C. Evidence-bound projection issuer

Selected. The same recovered `SegmentStore`, verifier lifecycle, ACK prefix,
Core pin authority, and Projection V2 transaction issue the correlation
context. The issued context is non-serializable, lifecycle-bound, and checked
again at use. Projection persists canonical facts; the controller later issues
a cursor-bound admission capability under its lock.

## Trust boundaries

Trusted for candidate creation:

- the enrolled observer trust root and verified event chain;
- the recovered `SegmentStore` lifecycle and exact `EvidenceRef`;
- the same-root completed `CorrelationRequestJournal` binding for that ref;
- the ACK-confirmed prefix used by Projection V2;
- the deterministic historical coverage reducer;
- Core's fixed-loader detector pin and digest-pinned special-use registry;
- the pure correlation kernel;
- the Projection V2 transaction and verified logical snapshot.

Explicitly untrusted:

- SQLite bytes before schema and logical-prefix verification;
- public Pydantic/dataclass constructors;
- PCC request callers and network responses before durable verification;
- OPA, DeepSeek, model text, labels, prompts, and HTTP metadata;
- Docker live state after the signed snapshot;
- wall-clock or monotonic time not carried by the signed proof;
- candidate IDs without the exact canonical candidate bytes.

## Historical coverage authority

### Inputs

The evaluator accepts only:

- an issued `AuthenticatedPCCInput` for snapshot sequence `S`;
- the same-store historical coverage timeline replayed from authenticated
  protected coverage history through `S - 1`;
- the same-store authenticated path anchored at the retained trigger and ending
  at `S - 1`;
- strictly decoded coverage records from that prefix.

It does not accept `MutationReadiness`, a `datetime.now()` value, SQLite rows
from a caller, or an arbitrary list of intervals.

For a complete snapshot the following bindings are mandatory:

```text
authenticated.source_sequence == S
snapshot.coverage_through_sequence == S - 1
snapshot.trigger.source_sequence < S
snapshot.trigger host/boot == authenticated host/boot
1 <= S - snapshot.trigger.source_sequence <= 4096
```

The full timeline is required so a critical episode opened before the trigger
but still overlapping its uncertainty window cannot disappear. Its retained
state is bounded to active episode summaries and the exact recent proof path;
it is not an unbounded list of lifetime events.

The evaluator is invoked only while projecting the ACK-confirmed snapshot.
The exact snapshot ref must still resolve through the same recovered verifier
lifecycle. Structural completeness covers
`[trigger.source_sequence, S - 1]`. Surviving authenticated positions,
store-authenticated retired routine ranges, and exact signed sequence-gap
records form the proof without enumerating the range one sequence at a time.
Authenticated retention omissions are legal. An exact signed, still-open
structural sequence gap makes the deterministic assessment incomplete. An
unexplained source range, provisional retention state, deferred PCC recovery,
unhealthy store, changed lifecycle, or inability to re-resolve the proof is
authority unavailable/corrupt: projection does not advance its cursor and does
not persist a synthetic `historical_coverage_incomplete` incident.

### Exact time window

All arithmetic uses integer nanoseconds parsed by
`parse_rfc3339nano_utc_ns()`:

```text
window_start_ns = trigger.event_time_ns
                  - trigger.clock_uncertainty_ms * 1_000_000
window_end_ns   = snapshot.decision_time_ns
```

The assessment is incomplete when subtraction falls outside years `0001..9999`,
`window_end_ns < window_start_ns`, or any timestamp is not canonical
RFC3339Nano UTC. Negative trigger and inventory ages retain their earlier
ordered `event_stale` and `inventory_stale` correlation reasons; historical
coverage does not replace those gates. The
canonical `window_start` is rendered without floating point, with `Z`, and
with the shortest exact fractional representation (no fraction for an exact
second; otherwise trailing fractional zeroes are removed).

`HistoricalCoverageAssessment.window_start` is an exact string when that value
is representable and is absent only for the deterministic year-underflow
outcome. An absent start therefore requires `complete=false`,
`critical_gap=false`, and no hash. A reversed but representable window keeps
its exact rendered start and has the same incomplete/no-hash outcome.

The interval is closed: a critical point exactly at either boundary
intersects and fails closed.

### Coverage episode normalization

Historical coverage and live `CoverageState` must share one strict coverage
record classifier. Task 6D extracts the existing exact Docker-gap,
sequence-gap, Falco lifecycle, boot/start, and generic-critical grammar into a
private shared reducer primitive. It does not reinterpret free-form
`component`, `kind`, or `reason_code` values from SQLite.

A normalized critical episode contains exactly:

```text
scope_boot_id?                # required only for process-local episodes
component
kind                         # the opening assertion's kind
opened_at
closed_at?                   # absent means open through the assessed prefix
open_event_id
close_event_id?
open_source_sequence
close_source_sequence?
```

The opening assertion is an exact authenticated CRITICAL coverage form. Episode
keys are closed by grammar:

```text
Docker gap:       (component, opened_at, reconcile_generation)
sequence gap:     (component, opened_at, affected_start, affected_end)
Falco generic:    (boot_id, component, kind, opened_at)
persistent other: (component, kind, opened_at)
```

Its close, where that coverage grammar permits one, must be the one exact later
matching recovery/close record. Cumulative updates with the same logical key
keep component, kind, opened_at, severity, counter presence, and scope
immutable. Source payload and normalized hashes may change and the latest
primary update supersedes the earlier counter value. Bounded state retains the
earliest open and latest primary update, not every lifetime update ID.

The Falco adapter's reason is diagnostic, not interval identity. Its exact
closed grammar permits these open/update and close reasons:

```text
kind                          open/update reasons                     close
falco_parse_rejection         invalid_falco_body                      valid_heartbeat_recovered
falco_queue_drop              routine_capacity_exceeded               routine_queue_recovered
falco_delivery_failure        observer_delivery_failed                observer_delivery_recovered
falco_heartbeat_gap           awaiting_initial_heartbeat |            recovered
                              falco_heartbeat_timeout
falco_configuration_mismatch  falco_version_mismatch |                recovered
                              falco_engine_mismatch |
                              falco_config_hash_mismatch |
                              falco_rules_hash_mismatch |
                              falco_counter_rollback
falco_kernel_event_drop       falco_kernel_drop_counter_increase      recovered
falco_outputs_queue_drop      falco_outputs_queue_counter_increase    recovered
```

The parse, queue, kernel-drop, and outputs-drop kinds require
`dropped_count` on every open/update/close. It strictly increases, except that
`MAX_UINT64 -> MAX_UINT64` is a lawful saturated update. The other three kinds
must omit it. A close preserves the latest counter and uses only its listed
recovery reason. Below-maximum equality, disappearance, introduction on an
uncounted kind, or rollback is conflict. Non-Falco generic grammars keep their
opening reason immutable unless an exact source-specific rule says otherwise.

`observer_spool_drop` is the exact persistent observer-loss grammar. Its INFO
`observer_spool_drop_recovered` point says that pressure ended but cannot
restore discarded evidence and never closes the critical loss episode.
That recovery form requires `opened_at == closed_at`, reason
`routine_spool_recovered`, a positive `dropped_count`, exact
`["storage_pressure"]` flags, and normalized/source-hash binding.

`docker_logging_visibility_degraded` is the exact accepted non-critical
observer point: `WARNING`, reason `docker_logging_unavailable`, positive
`reconcile_generation`, `inventory_generation` equal to it, event time equal
to `opened_at`, exact `["docker_logging_unavailable"]` flags, and
normalized/source-hash binding. It opens and closes no critical episode.
Unknown component/kind/reason combinations are validation failures, not
free-form generic intervals.

A self-contained CRITICAL record with `closed_at` is historical authority even
if an earlier pending open was lawfully coalesced out of the observer outbox;
in that case `open_event_id == close_event_id`. An exact transport replay is
removed by projection dedup before episode reduction. A second logical close,
ambiguous close, backwards time, counter rollback, or conflicting immutable
identity is projection corruption rather than an arbitrary soft choice.

An episode intersects the correlation window when:

```text
opened_at_ns <= window_end_ns
and (closed_at is absent or closed_at_ns >= window_start_ns)
```

An observer sequence-gap assertion also intersects when its affected source
range overlaps `[trigger.source_sequence, S - 1]`, even if its reporting
timestamp is later. This prevents a late description of an earlier missing
range from being laundered by timestamp choice. At the assessed prefix an
unclosed structural sequence gap makes the assessment incomplete and carries
no hash. An open generic critical interval is structurally complete but has
`critical_gap = true`.

WARNING and INFO points are not critical episodes. They can only close or
structurally support an episode where the shared closed grammar explicitly
allows that role.

### Boot scope

Every historical record carries its exact `boot_id`. A change of envelope
`boot_id`, not a key-rotation event type by itself, ends the old process-local
Falco epoch. Active `falco-adapter` episodes from the prior boot are discarded
at that authenticated boundary and cannot be closed by the new boot. A
same-boot key rotation does not reset them.

Structural sequence gaps, Docker reconciliation gaps, and persistent observer
loss are host-scoped and survive boot changes until their own exact grammar
resolves them. This prevents reboot laundering of missing evidence while not
making a dead Falco process appear open forever. The live and historical
reducers apply this identical split. A complete PCC still requires the trigger
and snapshot to name the same target boot and no intervening boot change in
`[trigger,S]`.

### Logical-primary identity

Projection V1's boot-blind dedup remains unchanged until the atomic V2
activation. Projection V2 and historical coverage use the new frozen identity:

```text
hex(SHA256("AGMIND_PROJECTION_DEDUP_V2\0" || kind || "\0" || canonical_json(key)))

Falco key:    (host_id, boot_id, event_type, source_payload_hash)
coverage key: (host_id, boot_id, event_type,
               normalized_fields_sha256, source_payload_hash)
other key:    (event_id,)
```

Including `boot_id` prevents replayed prior-boot sensor bytes from suppressing
a new critical assertion. One neutral helper owns both frozen V1 and V2
derivations. Active V1 continues to call V1; the dormant V2 reducer,
historical reducer, and later promoted Projection V2 call V2.

Historical code never keeps a lifetime `seen` set. A transaction-bound
logical-primary oracle is issued only while V2 is being built from
authenticated source order or after its complete logical prefix has been
revalidated. It returns the first source-order event for an exact V2 key. A
pure constant-memory prefix probe is used by tests and as the fail-closed
fallback; a V2 index is only an accelerator, never caller authority.

For a close or reopen whose episode is no longer active, the same oracle probes
earlier logical-primary records with that episode key. No earlier record allows
an exact grammar-approved self-contained generic close. An earlier closed
episode makes another close or reopen conflict. This detects lifetime second
closes without an unbounded tombstone set.

### Bounded target-specific reduction

Reduction is target-specific and streaming. It retains only:

- active episode summaries;
- closed pre-trigger episodes that intersect the exact target window;
- logical-primary coverage IDs in `(trigger,S-1]`;
- structural endpoint/dependency IDs used by the target path;
- the final intersecting intervals and sorted-unique ID set.

Completed irrelevant lifetime episodes are discarded after their exact close;
their episode-prefix status remains queryable through the bound primary
oracle. The active, pre-trigger, recent-path, recent-primary, final-interval,
and final-ID collections each have an independent 4,096 cap checked with
cap-plus-one before storage. No lifetime count is truncated and no one cap is
shared with another.

`HistoricalPathAuthority` has no public constructor and is not exported from
`coverage.__init__`. Only the same recovered `SegmentStore` issues it for one
exact authenticated PCC. Its private binding rechecks the store lifecycle,
verifier generation, full PCC ref, host/boot, trigger identity,
`S/coverage_through=S-1`, surviving-ref fingerprints, clipped authenticated
retired routine ranges, acceptance cursor, and healthy repair/retention state.
Copy, serialization, mutation, restart, cross-store use, or namespace drift
revokes it.

The live protected PCC at `S` is the terminal anchor; `S-1` need not have a
live ref. A retired trigger is covered structurally by exactly one
authenticated routine-only retired range while its event/content identity
comes from the retained PCC request and snapshot. Protected coverage can never
be justified by a retired range. The path binding is revalidated inside the
Projection V2 source-order transaction before use.

A closed sequence-gap proof adds its own open/close IDs and the exact matched
Docker gap open/recovery IDs that establish its baseline-advancing reconcile.
If an earlier Docker recovery supplies the comparison baseline, its matching
open/recovery IDs are dependencies too. All dependency IDs enter the same
sorted-unique final coverage-ID set and its independent cap.

### Locked coverage hash

For a structurally complete assessment, including one that reports a critical
gap, the hash is:

```text
hex(SHA256("AGMIND_CORRELATION_COVERAGE_V1\0" || canonical_json({
  "host_id": host_id,
  "boot_id": boot_id,
  "trigger_event_id": trigger.event_id,
  "trigger_source_sequence": trigger.source_sequence,
  "coverage_through_sequence": S - 1,
  "window_start": canonical_window_start,
  "window_end": snapshot.decision_time,
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

Intervals use the frozen sort order
`(opened_at, component, kind, open_event_id, close_event_id-or-empty)`.
`coverage_event_ids` is the sorted-unique set of every logical-primary coverage
event in `(trigger.source_sequence, S - 1]`; for an intersecting episode that
opened before the trigger, it adds only the earliest open, the latest effective
primary update when distinct, and the close when present; it also adds the
open/close records of every structural sequence range used by the anchored
path. Intermediate pre-trigger updates are not hash inputs because their
semantic fields are superseded and are not used to establish the assessed
interval state. Transport duplicates are excluded. This set and the interval
set are each capped at
4,096 entries; overflow is authority/resource unavailable, rolls the projection
transaction back, and is never truncated or persisted as an evidence-derived
rejection. The proof path is already capped at 4,096 events by 6C.

Construction is also bounded, not merely the final serialization. Reducers use
cap-plus-one checks while streaming; active episodes, recent path events, and
pre-trigger endpoint summaries are each capped at 4,096. State-cap overflow is
authority unavailable and stalls projection with no cursor advance. It never
drops an episode and never issues a partial assessment.

Incomplete assessments carry no hash and must set `critical_gap = false`.
Complete assessments set `critical_gap = bool(intersecting_intervals)`.

### Late evidence

When a later authenticated coverage event is projected, an indexed query reads
at most 4,097 candidate matches on the same host whose snapshot precedes that
event. More than 4,096 matches is authority/resource overflow: the whole event
transaction rolls back and the projection cursor does not advance. For the
bounded set, the reducer appends an invalidation if either:

- the new critical episode intersects the candidate's exact signed time
  window; or
- a new sequence-gap affected range overlaps the candidate's
  `[primary_source_sequence, snapshot_sequence - 1]` range.

The window is always reconstructed from the protected PCC snapshot referenced
by the candidate; it is never copied from a caller or inferred from candidate
`created_at` alone. Candidate and incident bytes are not changed or deleted.
Repeated application of the same coverage event is idempotent by the
`(candidate_id, coverage_event_id)` key.

## Core pin authority

An issued `CorrelationProjectionAuthority` binds:

- the exact detector bundle hash produced by
  `pcc_detector_bundle_sha256()` from the Core-visible root-owned rule bytes;
- an issued digest-pinned `SpecialUseRegistry`;
- the recovered evidence lifecycle for which it is installed.

The special-use registry issuer stores a private canonical binding of the
entries and search index, not only object identity. Every authority use
rechecks that binding so `object.__setattr__` cannot mutate an issued registry
into a different policy.

The sole compile-time allowlisted production path is
`/etc/falco/rules.d/agmind-pcc.yaml`, matching the Falco deployment path. The
runtime image copies the exact repository rule bytes there as `root:root`, mode
`0444`, below `root:root` mode-`0755` parents before dropping to the `sais`
user. Python production dependencies are installed in a root-owned virtual
environment below `/opt`, readable and executable by `sais`; the runtime does
not depend on `/root/.local` or the root user's site-packages. The image input
contains every exact Core production dependency pinned in `pyproject.toml`,
including `cryptography`. The production detector loader opens without
following symlinks and requires a root-owned single-link regular file under
root-owned non-writable parents. A container-image smoke test runs the real
fixed loader as `sais` and compares its hash with the repository rule bytes.
The test filesystem factory is private and is not reachable from production
composition.

M1 supports one detector bundle at a time. Updating the detector while old PCC
history is retained is outside Task 6D; startup must fail closed on a historical
hash that is unavailable rather than rebuild different candidate facts. A
future content-addressed detector archive can add rotation without changing
candidate semantics.

## Issued correlation context

`CorrelationContext` remains a public immutable fact type for pure unit tests,
but public construction never grants candidate authority.

Before the projection issuer runs, the same-root
`CorrelationRequestJournal` must return one exact completed binding for the
snapshot ref. The binding reauthenticates the request, request hash, trigger,
snapshot event/content identity, and `phase="completed"`. A PCC accepted
directly without that durable completed state is evidence but cannot become a
production candidate.

The projection issuer:

1. revalidates the exact post-commit PCC capability;
2. creates the historical assessment from the same prefix;
3. computes the duplicate key from the PCC facts;
4. reads the active duplicate observation inside the same SQLite transaction;
5. binds the Core pin authority;
6. registers a one-use context binding over the exact PCC canonical bytes,
   `EvidenceRef`, request hash, completed-journal capability, predecessor
   cursor/generation, every context fact, and evidence lifecycle.

`correlate_pcc()` atomically consumes that binding for the one exact PCC proof
inside the source-order projection transaction. Cross-proof, cross-store,
second-use, mutation, cursor advance, rebuild, or close fails. Issued contexts
cannot be copied, pickled, serialized, or revived after their owner lifecycle
closes. The public API remains fail closed for raw contexts.

## Canonical candidate fact hash

`candidate_id` selects the deterministic primary candidate but does not bind
all action-relevant fields. Task 6D therefore defines:

```text
candidate_facts_sha256 = hex(SHA256(
    "AGMIND_CANDIDATE_FACTS_V1\0" || canonical_json(candidate)
))
```

Future policy, approval, and actuator records bind this hash in addition to
`candidate_id`. Rebuilding the same evidence and pins must produce identical
candidate bytes and this hash.

## Projection V2

### Schema identity

```text
schema_version  = agmind.projection-schema.v2
reducer_version = agmind.projection-reducer.v2
dedup_version   = AGMIND_PROJECTION_DEDUP_V2
snapshot_layout = AGMIND_PROJECTION_SNAPSHOT_V2
snapshot domain = "AGMIND_PROJECTION_SNAPSHOT_V2\0"
```

The exact logical table order is:

```text
schema_meta
events
projection_dedup
coverage_intervals
containers
process_observations
network_observations
incidents
candidates
candidate_evidence
candidate_invalidations
ingest_cursors
```

The full primary-key order of each table is part of the V2 logical snapshot.
Non-unique lookup indexes cover the duplicate key plus primary order,
`candidate_evidence(candidate_id, authority_snapshot_event_id)`,
`candidate_invalidations(candidate_id)`, and
`coverage_intervals(source_sequence, event_id)`. The duplicate key is not
unique because a future verified terminal/cooldown transition may legally
permit a later candidate with the same key.

### Incidents

Projection V2 creates direct `InvestigationOnly` incidents from failed or
investigation-only routine Falco evidence by calling
`incident_from_verified_falco()`. A candidate-capable routine trigger waits for
its protected PCC and creates no early candidate incident. Direct routine
incidents exist only while their routine authority event exists; an
authenticated retention rebuild lawfully removes both. Proof-backed incidents
use the retained PCC and survive routine-trigger retirement byte-identically.

Each incident row stores every `IncidentV1` field, in the frozen model order,
with these storage rules:

```text
incident_id                       primary key
all uint64 values                 fixed-width 20-digit text
all Boolean values                0 | 1
all tuple values                  exact canonical JSON arrays
primary_event_id                  deliberately no events FK
authority_event_id                FK events(event_id), routine trigger or protected PCC
result_kind                       candidate | investigation | duplicate | rejected
```

For a proof-backed result the authority event is the protected, retained
snapshot. For a direct result it is the live routine trigger and the row ages
out with that evidence during rebuild. Parsing a row must strictly rebuild
`IncidentV1` and reproduce its ID. `result_kind` is reducer metadata and is not
part of incident canonical bytes.

### Candidates

Each candidate row stores every `ContainmentCandidateV1` field in the frozen
model order, followed by its exact full-facts hash:

```text
candidate_id                      primary key
incident_id                       unique FK incidents(incident_id)
all uint64 values                 fixed-width 20-digit text
all tuple values                  exact canonical JSON arrays
primary_event_id                  deliberately no events FK
correlation_snapshot_event_id     unique FK events(event_id)
candidate_facts_sha256            exact domain-separated hash
```

The indexed duplicate key is the exact tuple
`(host_id, boot_id, docker_container_id, docker_started_at,
detector_bundle_sha256, destination_ipv4)`. Every indexed value is compared
with the reparsed candidate before use, and the full model must reproduce
`candidate_facts_sha256`.

### Candidate evidence

The table uses the frozen fields and no foreign key on `evidence_event_id`:

```text
candidate_id                      FK candidates(candidate_id)
evidence_event_id
evidence_source_sequence          fixed-width uint64 text
evidence_content_sha256
role                              primary_trigger | correlation_snapshot |
                                  supporting_trigger | supporting_snapshot
authority_snapshot_event_id       FK events(event_id)
primary key (candidate_id, evidence_event_id, role,
             authority_snapshot_event_id)
```

A new candidate gets the exact primary trigger/snapshot pair. A later safe
duplicate adds its exact supporting trigger/snapshot pair and never changes the
candidate row.

### Candidate invalidations

```text
candidate_id                      FK candidates(candidate_id)
coverage_event_id                 FK events(event_id)
coverage_source_sequence          fixed-width uint64 text
coverage_content_sha256
reason_code                       exactly late_critical_coverage_gap
primary key (candidate_id, coverage_event_id)
```

Invalidations are append-only reducer output. There is no update or delete API.

### Atomic reducer behavior

For one PCC snapshot, the existing event/dedup insert, historical assessment,
correlation, incident insert, candidate/evidence inserts, cursor advance, and
commit are one SQLite transaction. Any exception rolls back all of them. An
ambiguous commit latches the projection unhealthy exactly as it does today.

For one later coverage event, the event/coverage row, every deterministic
invalidation row, cursor advance, and commit are likewise atomic.

The reducer outcomes are:

- `CandidateCreated`: incident + candidate + two primary evidence rows;
- `Duplicate`: its proof-backed incident + two supporting evidence rows on the
  existing active candidate;
- `InvestigationOnly` or `Rejected`: incident only;
- local pin/history authority unavailable: projection error and no cursor
  advance, never a synthetic evidence rejection.

An invalidated candidate remains the active duplicate primary. A later proof
adds supporting evidence to the same invalid candidate and cannot launder the
gap by minting a new ID. With no actuator terminal records in Task 6, terminal
cooldown observations remain empty.

## V1-to-V2 activation and rebuild

Projection rows are never migrated or copied.

On open:

1. bind the existing regular database and sidecars using the current namespace
   checks;
2. if the exact V2 schema is present, verify its schema and authenticated
   logical prefix normally;
3. if the database matches the frozen exact V1 schema, freeze one healthy ACK
   snapshot and authenticated evidence lifecycle;
4. build a new V2 database under a random held-directory temporary name by
   replaying authenticated evidence only;
5. verify schema, logical snapshot, counts, cursor, foreign keys, and the
   unchanged ACK snapshot;
6. checkpoint, fsync the temporary file, atomically replace the V1 cache,
   fsync the parent, reopen, and verify again;
7. on any failure before rename, leave V1 untouched; on uncertainty after
   rename, latch unhealthy and require restart/reverification.

`schema_v1.sql` is retained only to classify the old cache; none of its rows is
candidate authority. An unknown schema is not treated as V1. It fails closed.
A forged or stale V1 row that is absent from authenticated evidence never
appears in V2. The old `_retired_record_from_projection_event` path is removed
from security-fact reconstruction; authenticated retired ranges establish
structural presence but never donate cached event bytes.

Routine retention rebuild uses the same V2 replay. Candidate/proof-backed
incident canonical bytes, candidate fact hash, primary/supporting evidence rows
backed by protected snapshots, and invalidations backed by protected coverage
events must be identical before and after the original routine trigger is
removed. The global projection snapshot may legitimately differ because the
routine `events`, process, network, and direct-investigation rows were retired;
the protected security facts above may not.

That replay runs while retention is pending and therefore requires the exact
retention-completion capability bound to the same evidence-store lifecycle and
completed retained prefix. It is the only permitted pending-retention rebuild
scope; ordinary correlation/history reads remain blocked. The reopened V2
database is revalidated before the authority accepts its fresh rebuild epoch.

## Admission view boundary

Projection exposes no `get_candidate()` method that returns action authority.
The controller exposes an opaque, non-copyable, non-serializable
`CandidateAdmissionView` under its existing async lock. Before issuance it
catches projection up, obtains a fresh live `MutationReadiness`, and requires:

```text
readiness.ready == true
evidence_head == acceptance_cursor == confirmed_through == projection_cursor
candidate.boot_id == current observer boot_id
candidate invalidation count == 0
```

This current readiness hash is distinct from the immutable historical coverage
hash. The view contains or binds:

```text
candidate
candidate_facts_sha256
authority_snapshot_event_id
projection cursor identity     host_id + sequence + event_id +
                               content_sha256 + frame_sha256
exact terminal EvidenceRef fingerprint
restart-local rebuild epoch    increments on rebuild
hidden authority revision      rotates on issue/apply/rebuild/close
evidence lifecycle identity
live readiness hash and cursors
```

The view is issued only after strict row reparse and hash/index verification.
The candidate row is reparsed strictly, its full-facts hash is recomputed, and
its protected PCC/request/coverage bindings are reauthenticated before the view
is issued. Task 7 must reacquire the controller lock and consume/revalidate the
same view after the OPA response and before its decision journal commit. Any
accepted-but-unprojected evidence makes live readiness false; any cursor or
epoch/revision change, lifecycle change, new invalidation, row mismatch, unhealthy
projection, rebuild, restart, or controller close invalidates the old view.

The numeric rebuild epoch is not persisted projection data. After exact schema
and authenticated-prefix verification, a fresh owner lifecycle starts at epoch
1, including for an empty projection. Apply advances cursor and hidden revision;
rebuild advances epoch and revision; close/restart changes lifecycle and
revision. This keeps independent authenticated rebuild hashes byte-identical
without creating rollbackable state outside the logical snapshot.

The capability exists only for a currently valid candidate; it has no
`valid=false` state. A separate frozen `CandidateStatusObservation` may report
candidate facts and invalidation IDs for UI/audit, but it is publicly
constructible, explicitly non-authoritative, and cannot be consumed by policy
or an intent builder. `CandidateAdmissionView` is a local admission capability,
not a network contract and not an intent.

## Failure and restart invariants

- No candidate is visible before its SQLite transaction commits.
- A crash before commit replays the same snapshot and produces the same bytes.
- A crash after an ambiguous commit makes the live projection unhealthy; it
  does not retry under an assumed outcome.
- Reopen verifies schema, logical prefix, candidate hashes, evidence links,
  invalidations, cursor, and ACK identity before issuing a view.
- A late coverage event and all invalidations appear in one transaction.
- Retention can remove a routine trigger only after the protected snapshot and
  its candidate reconstruction path are already durable and rebuild-proven.
- Missing Core pins, historical pin mismatch, incomplete prefix, corrupt PCC,
  ambiguous duplicate order, or row/hash mismatch cannot yield a candidate or
  an admission view.

## Deliberate non-goals

Task 6D does not:

- call OPA or a model;
- create `TemporaryEgressDenyIntentV1`;
- approve, prepare, or execute containment;
- inspect live Docker state;
- add terminal action/cooldown projection records;
- support detector-bundle rotation;
- preserve routine-only investigation incidents through retention;
- change the 6C request, producer, receipt, ACK ordering, or transport bounds.

## Focused verification

The implementation gate is intentionally bounded:

1. historical coverage hash vectors, nanosecond boundaries, interval grammar,
   source-range gaps, malformed/conflicting episodes, and late evidence;
2. raw versus issued context, copy/pickle/mutation/lifecycle attacks, and exact
   candidate fact hash;
3. Projection V2 schema/table/snapshot identity, atomic PCC result writes,
   duplicate evidence, invalidation idempotency, and strict row reparse;
4. V1 evidence-only activation at every crash point;
5. byte-identical candidate facts before/after routine retention and two
   independent rebuilds;
6. controller-lock admission view issuance and stale-view rejection;
7. the existing Task 6 contract, correlation, PCC delivery, projection, and
   retention tests only, followed by an independent security review.

No repo-wide or native Linux suite is part of the inner 6D loop.
