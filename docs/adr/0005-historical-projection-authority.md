# ADR 0005: Historical projection authority

- Status: accepted
- Date: 2026-08-01 (recorded retroactively on 2026-08-11)

## Context

[ADR 0003](0003-correlation-proof.md) defines the deterministic PCC correlation proof;
[ADR 0004](0004-proof-production-and-transport.md) records how that proof is produced and moved
durably into Core. This ADR records what Core does with an accepted proof: how an authenticated
`pcc_correlation_snapshot` becomes a durable, rebuildable containment candidate in Projection V2,
and the authority model that guards every step — who may assert historical coverage, how the
candidate binds its evidence, how the projection activates, rebuilds, and survives retention, and
what "admission" means when a later stage asks whether a candidate may proceed.

The governing idea: a valid signature on a PCC snapshot does not prove historical Core coverage,
duplicate ordering, or late-invalidation state, and field correctness of public value types is not
provenance. Authority must come from the evidence chain — the recovered `SegmentStore`, the
verifier lifecycle, the ACK prefix, Core's pin authorities, and the Projection V2 transaction —
never from any caller-constructed object. The candidate this pipeline produces is explicitly an
evidence-derived fact, not action authority; policy evaluation, approval, and actuation are out of
scope here (see the non-goals in Notes).

The capability discipline below (non-copyable, non-serializable, lifecycle-bound issued objects,
rechecked at every use) defends the composition against confused-deputy paths and accidental
misuse. [ADR 0006](0006-trusted-linearization-boundary.md) later classified arbitrary in-process
attackers as TCB compromise; the two records should be read together.

## Decisions

### Candidate authority is minted only by an evidence-bound projection issuer

The correlation context that can create a containment candidate is issued only by the same
recovered `SegmentStore`, verifier lifecycle, ACK prefix, Core pin authority, and Projection V2
transaction. The issued context is non-serializable, lifecycle-bound, and re-checked at use;
Projection persists canonical facts, and the controller later issues a cursor-bound admission
capability under its lock.

Rejected alternatives: (a) sending parsed PCC facts directly to OPA — rejected because OPA would
become the place where evidence authority is accidentally minted; (b) letting any
`CorrelationContext` that passes field validation create a candidate — rejected because
`CorrelationContext`, `HistoricalCoverageAssessment`, and `ContainmentCandidateV1` are public
constructible value types.

Consequences: OPA, a model, an HTTP caller, and a caller-constructed `ContainmentCandidateV1` can
never create or repair a candidate. Public `CorrelationContext` construction remains legal for
pure unit tests but grants no authority. The OPA admission stage depends on this fact existing
before it may emit an intent.

### Five mandatory conditions before a PCC snapshot becomes a durable candidate

An authenticated `pcc_correlation_snapshot` becomes a durable, rebuildable containment candidate
only when all five hold: (1) it is an exact post-commit `AuthenticatedPCCInput`; (2) its
historical coverage prefix is complete with no critical interval intersecting the correlation
window; (3) Core-owned detector and special-use pins match the snapshot; (4) the deterministic
correlation gates pass under an issued local context; (5) incident, candidate, evidence links, and
later invalidations commit atomically to Projection V2.

The candidate is the last evidence-derived fact before OPA, local approval, and the actuator;
every link that could be forged or skipped must be closed before policy sees it. The result is
explicitly not action authority. A complete PCC without one exact completed correlation-journal
state is never projected as a candidate; a PCC accepted directly without durable completed state
remains evidence but cannot become a production candidate.

### Explicit trust boundary for candidate creation

Trusted inputs: the enrolled observer trust root and verified event chain; the recovered
`SegmentStore` lifecycle and exact `EvidenceRef`; the same-root completed
`CorrelationRequestJournal` binding; the ACK-confirmed prefix; the deterministic historical
coverage reducer; Core's fixed-loader detector pin and digest-pinned special-use registry; the
pure correlation kernel; the Projection V2 transaction and verified logical snapshot.

Explicitly untrusted: SQLite bytes before schema/logical-prefix verification; public
Pydantic/dataclass constructors; PCC request callers and network responses before durable
verification; OPA, the Hunter model, model text, labels, prompts, HTTP metadata; Docker live state after
the signed snapshot; wall-clock or monotonic time not carried by the signed proof; candidate IDs
without the exact canonical candidate bytes.

Every rejected approach in this design failed because it trusted something on the untrusted list;
the boundary makes that enumeration explicit and testable. Consequences: cached SQLite coverage
rows are never historical authority; time comparisons must use proof-carried timestamps;
`candidate_id` alone is never sufficient identity.

### candidate_facts_sha256: a domain-separated full-facts candidate hash

`candidate_facts_sha256 = hex(SHA256("AGMIND_CANDIDATE_FACTS_V1\0" || canonical_json(candidate)))`.
Future policy, approval, and actuator records bind this hash in addition to `candidate_id`.
`candidate_id` selects the deterministic primary candidate but does not bind all action-relevant
fields (TTL, port, image, coverage); same-ID candidates with altered fields must be
distinguishable, and rebuilding the same evidence and pins must produce identical candidate bytes
and hash. Relying on `candidate_id` alone was rejected as under-binding.

Consequences: the candidates table stores the hash; every read reparses the row and must
reproduce it; same-ID altered candidate facts cannot be inserted or admitted.

### Boot-aware Projection V2 dedup identity; V1 kept frozen, never migrated

V2 logical-primary identity is
`hex(SHA256("AGMIND_PROJECTION_DEDUP_V2\0" || kind || "\0" || canonical_json(key)))` with keys:
Falco `(host_id, boot_id, event_type, source_payload_hash)`; coverage
`(host_id, boot_id, event_type, normalized_fields_sha256, source_payload_hash)`; other
`(event_id,)`. Including `boot_id` prevents replayed prior-boot sensor bytes from suppressing a
new critical assertion; reusing the boot-blind V1 dedup for historical coverage was rejected as
replay-launderable. One neutral helper owns both the frozen V1 and the V2 derivations, so the two
projections cannot drift; active V1 kept calling the V1 derivation until atomic activation.
Consequences: exact prior-boot sensor bytes are distinct V2 primaries; V1 rows are never migrated
or copied into V2.

### Locked coverage hash, integer-nanosecond time model, and a closed window

For a structurally complete assessment (including one reporting a critical gap):
`hex(SHA256("AGMIND_CORRELATION_COVERAGE_V1\0" || canonical_json({host_id, boot_id,
trigger_event_id, trigger_source_sequence, coverage_through_sequence=S-1, window_start,
window_end, intersecting_intervals, coverage_event_ids})))`. Intervals sort by
`(opened_at, component, kind, open_event_id, close_event_id-or-empty)`; `coverage_event_ids` is
the sorted-unique logical-primary set in `(trigger, S-1]`, plus — for a pre-trigger episode only —
the earliest open, latest effective primary update, and close, plus structural sequence-range
open/close records; transport duplicates are excluded and optional keys canonically omitted. The
hash must be deterministic across independent rebuilds and must not include superseded
intermediate updates whose semantic fields do not establish assessed interval state. Incomplete
assessments carry no hash and must set `critical_gap=false`; complete assessments set
`critical_gap=bool(intersecting_intervals)`. Both the interval set and the ID set are capped at
4,096; overflow is authority unavailable, never truncation.

All historical-coverage arithmetic uses integer nanoseconds from `parse_rfc3339nano_utc_ns()`:
`window_start_ns = trigger.event_time_ns - clock_uncertainty_ms*1_000_000`,
`window_end_ns = snapshot.decision_time_ns`. The interval is closed — a critical point exactly at
either boundary intersects and fails closed. The assessment is incomplete when subtraction falls
outside years 0001..9999, when `window_end < window_start`, or when any timestamp is non-canonical
RFC3339Nano UTC; `window_start` is absent only for deterministic year underflow (then
`complete=false`, `critical_gap=false`, no hash). Canonical rendering uses no floating point, a
`Z` suffix, and the shortest exact fraction. Reusing the existing microsecond datetime ordering
for historical facts was explicitly forbidden: it loses nanosecond distinctions, and
deterministic proofs require exact integer comparison with a fail-closed boundary rule. Negative
trigger/inventory ages keep their earlier ordered `event_stale`/`inventory_stale` correlation
reasons — historical coverage does not replace those gates.

### One closed coverage grammar, enforced on both producer and consumer

Four related decisions close the coverage-record grammar end to end:

- **One strict shared classifier.** Historical coverage and live `CoverageState` share exactly one
  strict coverage record classifier (extracted, not duplicated). Episode keys are closed by
  grammar: Docker gap `(component, opened_at, reconcile_generation)`; sequence gap
  `(component, opened_at, affected_start, affected_end)`; Falco generic
  `(boot_id, component, kind, opened_at)`; persistent other `(component, kind, opened_at)`.
  Free-form component/kind/reason values from SQLite are never reinterpreted; unknown combinations
  are validation failures, not generic intervals. Cumulative updates keep
  component/kind/opened_at/severity/counter-presence/scope immutable; the latest primary update
  supersedes earlier counter values; a close, where the grammar permits one, is the one exact
  later matching recovery record. A second logical close, an ambiguous close, backwards time, a
  counter rollback, or conflicting immutable identity is projection corruption (conflict), not a
  soft choice. A self-contained CRITICAL record with `closed_at`
  (`open_event_id == close_event_id`) is legal historical authority when the pending open was
  coalesced out of the observer outbox. Two divergent classifiers would let the live and
  historical paths disagree about what is critical; open grammars would let malformed or
  attacker-shaped rows create or suppress intervals.
- **Exact Falco per-kind reason/counter grammar with saturating uint64.** Each Falco episode kind
  has a closed set of open/update reasons and exactly one close reason (e.g.
  `falco_parse_rejection`: `invalid_falco_body` -> `valid_heartbeat_recovered`). The parse, queue,
  kernel-drop, and outputs-drop kinds require `dropped_count` on every open/update/close, strictly
  increasing except that `MAX_UINT64 -> MAX_UINT64` is a lawful saturated update; the other three
  kinds must omit the counter. Below-maximum equality, counter disappearance, a counter on an
  uncounted kind, or rollback is conflict. The Falco adapter's reason is diagnostic, not interval
  identity. Counter monotonicity plus a closed reason set makes replay, rollback, and laundering
  of drop counters detectable; saturation stays lawful because the wire counter is uint64. Legal
  transitions are enumerable and testable; any new reason requires a grammar change on both
  producer and consumer.
- **Spool loss is permanent; logging degradation is non-critical.** `observer_spool_drop` is the
  exact persistent observer-loss grammar; its INFO `observer_spool_drop_recovered` point
  (`opened_at == closed_at`, reason `routine_spool_recovered`, positive `dropped_count`, exact
  `["storage_pressure"]` flags, normalized/source-hash binding) says pressure ended but never
  closes the critical loss episode — discarded evidence cannot be restored by a pressure-recovery
  message, and letting a recovery point close the loss episode would launder permanently missing
  evidence. `docker_logging_visibility_degraded` is the exact accepted non-critical WARNING point
  (reason `docker_logging_unavailable`, positive `reconcile_generation` equal to
  `inventory_generation`, event time equal to `opened_at`, exact flags); it opens and closes no
  critical episode. Malformed variants fail validation. Permanent observer loss survives until
  its own grammar resolves it; WARNING/INFO points can only close or structurally support an
  episode where the shared grammar explicitly allows that role.
- **The grammar is closed on the producer side too.** The Go observer's Docker reconcile reason
  grammar is closed: an unknown Docker reason cannot be signed or mutate state, spool, or
  inventory. Re-review exposed a producer/consumer protocol mismatch — a failing test proved an
  unknown observer Docker reason was signed and mutated state (fixed `b0d6314`) — showing that
  consumer-only validation leaves the wire format open. Adding a coverage reason therefore
  requires coordinated producer and consumer changes.

### Boot scoping and window intersection

A change of envelope `boot_id` (not a key-rotation event) ends the old process-local Falco epoch:
active falco-adapter episodes from the prior boot are discarded at the authenticated boundary and
cannot be closed by the new boot; same-boot key rotation resets nothing. Structural sequence gaps,
Docker reconciliation gaps, and persistent observer loss are host-scoped and survive boot changes
until their own grammar resolves them. Live and historical reducers apply the identical split, and
a complete PCC still requires trigger and snapshot to name the same target boot with no
intervening boot change in `[trigger, S]`. Uniform scoping (all-process-local or all-host-scoped)
was rejected during design preflight as contradicting production wire behavior; the mixed scope
was made normative. It prevents reboot laundering of missing evidence without making a dead Falco
process appear open forever. Every historical record carries its exact `boot_id`, and Falco
episode keys include it.

An observer sequence-gap assertion intersects the correlation window when its affected source
range overlaps `[trigger.source_sequence, S-1]`, even if its reporting timestamp is later or
outside the window; a generic episode intersects when `opened_at_ns <= window_end_ns` and
(`closed_at` absent or `closed_at_ns >= window_start_ns`). At the assessed prefix, an unclosed
structural sequence gap makes the assessment incomplete with no hash; an open generic critical
interval is structurally complete with `critical_gap=true`. Timestamp-only intersection was
implemented first, found as a Critical defect in review, and fixed in commit `00edb9d`: a late
description of an earlier missing range must not be laundered by timestamp choice. A closed
sequence gap whose timestamp misses the window but whose affected range overlaps still reports a
critical gap.

### Bounded state: a prefix oracle instead of seen-sets, and independent 4,096 caps

Historical code never keeps a lifetime seen set or tombstone collection. A transaction-bound
logical-primary oracle is issued only while V2 is built from authenticated source order or after
its complete logical prefix is revalidated; it returns the first source-order event for an exact
V2 key and probes earlier records to detect replay, second close, and reopen. A pure
constant-memory prefix probe is the fail-closed fallback; a V2 SQLite index is only an
accelerator, never caller authority. Logical-primary direction is derived from authenticated
source order, never trusted from SQLite (fix `631d45a`) — trusting the index would let cached
bytes forge ordering, and SQLite-derived source order was found as a blocking gap in review and
removed. Second-close/reopen detection thus works without unbounded memory, and completed
irrelevant lifetime episodes can be discarded after close while their prefix status stays
queryable.

Active episode summaries, pre-trigger summaries, recent path events, recent primary IDs, final
intervals, and final coverage-ID sets each have an independent 4,096 cap checked with cap-plus-one
while streaming (no cap shared with another); late-evidence invalidation queries read at most
4,097 candidate matches. Any overflow raises authority/resource unavailable: the whole transaction
rolls back, the cursor does not advance, and nothing is truncated, dropped, or persisted as an
evidence-derived rejection. Truncation would silently weaken a proof; a partial assessment is
worse than no assessment. The 4,096/4,097 boundary is a locked, natively tested contract (the
mutation `LIMIT cap+1` -> `LIMIT cap` is itself a regression). The proof path itself was already
capped at 4,096 events by the transport design ([ADR 0004](0004-proof-production-and-transport.md));
these caps are additional and independent.

### Store-issued path authority and structural completeness

`HistoricalPathAuthority` has no public constructor and is not exported from
`coverage.__init__`; only the exact recovered `SegmentStore` issues it, for one issued
`AuthenticatedPCCInput`. Its private binding rechecks store lifecycle, verifier generation, the
full PCC ref, host/boot, trigger identity, `S`/`coverage_through = S-1`, surviving-ref
fingerprints, clipped authenticated retired routine ranges, the acceptance cursor, and healthy
repair/retention state at every use. Copy, serialization, mutation, restart, cross-store use, or
namespace drift revokes it, and it is revalidated inside the Projection V2 source-order
transaction before use. Review found PCC input authority was not bound to its exact
`SegmentStore` lifecycle (Critical, fixed in `00edb9d`): a path proof detached from its store can
be replayed against a different or mutated store. Raw retired-range tuples as inputs were
explicitly rejected. Structural path coverage can only be asserted by the store that owns the
evidence.

Structural completeness of `[trigger.source_sequence, S-1]` is proven by surviving authenticated
positions, store-authenticated retired routine ranges, and exact signed sequence-gap records —
without enumerating the range one sequence at a time. The live protected PCC at `S` is the
terminal anchor (`S-1` need not have a live ref). A retired trigger is covered structurally by
exactly one authenticated routine-only retired range while its event/content identity comes from
the retained PCC request and snapshot. Protected coverage can never be justified by a retired
range. Authenticated retention omissions are legal; a still-open signed structural gap makes the
assessment incomplete. A closed sequence-gap proof also carries its matched Docker open/recovery
dependency IDs into the final coverage-ID set. Enumerating every sequence would be unbounded;
retired ranges are the only honest way to cover retention without letting retention hide
protected evidence. Proof-path and assessment stability survive routine-trigger retirement;
retired ranges establish structural presence but never donate event bytes.

### Completed-journal delivery is reauthenticated by a private capability

An internal `completed_for_snapshot(ref)` issuer on the `CorrelationRequestJournal` returns a
non-copyable, non-serializable capability only for the exact completed state: it binds request
hash, request, trigger, snapshot ref/content, same store, journal lifecycle, and current journal
bytes, and must reissue and validate `AuthenticatedPCCInput` through the same store/verifier
before returning. Selected/proof-observed states cannot issue it; ambiguous or corrupt journal
state never returns a partial result; recovery issues a new capability for byte-identical
completed state. Authenticated journal bytes are replay-bound: the capability derives phase maps,
indexes, digest, size, record count, and chain head from strict held-byte replay, with
token/registry identity rechecked under the journal lock before and after validation (fix
`fdc32c3`). Review found a Critical gap here: authority derived from mutable in-memory phase
caches rather than the durable journal bytes could be desynchronized from what was actually
persisted; trusting the in-memory phase cache was rejected. `pending()` public behavior stays
unchanged, and direct PCC acceptance without durable completed journal state can never yield
candidate authority.

### Detector pin: one compile-time path, hardened loader, runtime image contract, one bundle

The sole allowlisted production detector path is `/etc/falco/rules.d/agmind-pcc.yaml`, matching
the Falco deployment path. The loader walks the path through held descriptors with
`O_NOFOLLOW`/`O_DIRECTORY`, requires a root-owned single-link regular file, mode `0444`, under
root-owned non-writable (`0755`) parents, reads bounded one-shot bytes, verifies inode/stat
stability across the read, and returns `pcc_detector_bundle_sha256()` over the bytes. Wrong
path/type/owner/mode/link count, oversize, replace-during-read, or a read error cannot issue pin
authority. The test filesystem adapter is private and unreachable from production composition;
production has no caller-selected path. A caller-configurable rule path was rejected: the
detector pin is Core's authority over what Falco rule bundle produced the evidence, and a
selectable or symlink-followable path would let a non-root process substitute rules. Deployment
must place the rule exactly there before dropping privileges; the loader and the image contract
are two sides of one permission contract.

The runtime image is the other side: it uses a digest-pinned Python base
(`python:3.12.13-slim-trixie@sha256:229a2c5b...`); installs the repository rule at the fixed path
as `root:root 0444` under `root:root 0755` parents before `USER sais`; installs Python production
dependencies in a root-owned virtualenv at `/opt/agmind-venv` copied intact between stages (never
`/root/.local` or root's site-packages — a root-user-site install is unreadable after dropping
privileges); and `requirements.txt` must contain every Core production dependency from
`pyproject.toml` at the identical exact version (including `cryptography` — no reliance on
transitive installs). Unpinned bases change SQLite semantics: the old ARM64 image's SQLite 3.40.1
produced false-NULL `WITHOUT ROWID` integrity checks, fixed by the digest pin in `90bccfa`.
`make test-core-detector-pin-image` builds the real image, runs the real fixed loader as `sais`
with `--network none --read-only`, and compares the loaded hash with the repository rule bytes; a
static Dockerfile assertion alone was explicitly rejected as insufficient, because only running
the loader inside the real image proves the two sides of the file-permission contract agree. The
image gate is part of the acceptance gate for detector-pin changes, and base-image bumps must
preserve SQLite integrity-check semantics.

Only one detector bundle is supported at a time in M1
([ADR 0001](0001-proof-carrying-containment.md)). A protected historical PCC naming a
detector hash unavailable from the fixed Core pin authority aborts V1 activation/rebuild with V1
untouched; it is never rewritten as a different rejection or candidate (rewriting
unavailable-pin history as rejections was explicitly rejected — rebuilding different candidate
facts for the same evidence because the pin changed would break rebuild determinism, the core
invariant of the projection). Detector rotation with retained old-PCC history is out of scope; a
future content-addressed detector archive can add rotation without changing candidate semantics.
Updating the Falco rule bundle while old PCC history is retained therefore requires a future
archive design, not a hot swap.

### A one-use issued context, consumed atomically, with the predecessor validated twice

The projection issuer: revalidates the exact post-commit PCC capability; builds the historical
assessment from the same prefix; computes the duplicate key from PCC facts; validates the
projection predecessor under the Core authority lock; reads the duplicate observation inside the
same SQLite transaction; revalidates the predecessor while binding the Core pin authority; then
registers a one-use weak-key context binding over the exact PCC canonical bytes, `EvidenceRef`,
request hash, completed-journal capability, predecessor cursor/generation, every context fact,
and evidence lifecycle. `correlate_pcc()` consumes the binding atomically. Cross-proof,
cross-store, second-use, mutation, copy, pickle, cursor advance, rebuild, close, or lifecycle end
fails; the public API stays fail-closed for raw contexts. The authority has one exact
store/lifecycle owner, one live context revision, restart-local rebuild epochs, detached hidden
proof facts, and candidate-free failed-PCC handling; exact-type checks reject equality-laundered
PCC facts (`b24507b`). A context that could be replayed, copied, or used across proofs would let
one authenticated decision authorize a different candidate. Exact failed-PCC behavior remains
authority-free and unchanged; failed rejections bind to the issued snapshot (`53829d4`).

Predecessor validation is deliberately doubled. A private authority check validates the exact
projection predecessor under the authority lock before the reducer queries SQLite duplicate
state; the context issuer independently revalidates the same predecessor after the query. The
pre-query check is strictly read-only — it neither advances the predecessor nor rotates or
revokes the current context revision. Inside the reducer transaction, the predecessor cursor,
completed-journal capability, evidence lifecycle, and authenticated path are revalidated again
before duplicate state is read; pre-transaction validation alone is insufficient. A repo-fit
audit proved the issuer originally validated the predecessor only after the caller had already
observed duplicate state, allowing decisions on stale or forged duplicate observations (fixed in
`5634480`). A predecessor change before or during the check rolls back with no rows and no cursor
advance.

### Special-use registry authority binds canonical content, not object identity

The special-use registry issuer stores a private weak-key canonical binding over the exact
entries and search index — not an identity-only `WeakSet` — and every authority use rechecks that
binding. Equality-laundered scalar values are rejected by exact-type checks: a subclass or an
equal-but-different object is not the issued object. `object.__setattr__` on a frozen dataclass
can mutate an issued registry into a different policy while keeping the same identity, so
identity-only and equality-based acceptance both fail against this (review finding, fixed
`362f0f5`; equality laundering closed in `b24507b`). The identity-only `WeakSet` was the original
implementation and was replaced. Copy, pickle, and non-issued parsed registries fail;
`special_use_registry_is_issued()` returns false after any entries/`_index` mutation.

### Projection V2 schema identity, strict row codecs, and deliberate asymmetries

V2 identity: `schema_version agmind.projection-schema.v2`, `reducer_version
agmind.projection-reducer.v2`, `dedup_version AGMIND_PROJECTION_DEDUP_V2`, snapshot layout/domain
`AGMIND_PROJECTION_SNAPSHOT_V2\0`. There is an exact 12-table logical order (`schema_meta`,
`events`, `projection_dedup`, `coverage_intervals`, `containers`, `process_observations`,
`network_observations`, `incidents`, `candidates`, `candidate_evidence`,
`candidate_invalidations`, `ingest_cursors`), and the full primary-key order of each table is
part of the logical snapshot. V2 pins the literal schema SHA-256
(`d4a5d563ca3964cbe4ed276882a4b4def95fb756fc67a6777fddf5de38b1619d`) rather than self-defining at
runtime — runtime schema self-definition was found forgeable in review (fixed `6e40dd5`). Any
schema edit changes the pinned hash and is therefore an explicit act; a schema/row/hash/index
mismatch raises `ProjectionConflict`. The candidate duplicate key
`(host_id, boot_id, docker_container_id, docker_started_at, detector_bundle_sha256,
destination_ipv4)` is indexed but deliberately NOT unique: a future verified terminal/cooldown
transition may legally permit a later candidate with the same key, and a unique constraint would
block that lifecycle transition at the schema level.

Row codecs are strict: all uint64 values are stored as fixed-width 20-digit text (keeping SQLite
ordering identical to numeric ordering); Booleans as `0|1`; tuples as exact canonical JSON
arrays; result/role/reason columns carry closed CHECK constraints. `primary_event_id`
deliberately has NO foreign key to `events` (retention may lawfully remove the trigger event),
and `candidate_evidence.evidence_event_id` likewise carries none, while `authority_event_id`
has an FK (the retained routine trigger or protected PCC) — the asymmetry encodes which
references retention is allowed to break. Parsing any row must strictly
rebuild the frozen model and reproduce its ID and hash; equality-laundered record/ref values and
forged Pydantic encoder inputs are rejected; `result_kind` is reducer metadata, not part of
incident canonical bytes. Evidence roles are exactly
`primary_trigger | correlation_snapshot | supporting_trigger | supporting_snapshot`. Hostile or
drifted rows fail closed at read; V2 code never commits or rolls back a caller-owned snapshot
transaction (`6e40dd5`). Strict reparse is what makes cached SQLite bytes non-authoritative.

### Incidents, duplicates, and append-only late invalidations

Failed or investigation-only routine Falco evidence creates direct `InvestigationOnly` incidents
via `incident_from_verified_falco()`. A candidate-capable routine trigger creates no early
incident — it waits for its protected PCC, because an early incident would create authority
before the proof exists. Direct routine incidents exist only while their routine authority event
exists and are lawfully removed by authenticated retention rebuild; proof-backed incidents use
the retained protected PCC as authority event and survive routine-trigger retirement
byte-identically. Routine-only investigation incidents are deliberately not preserved through
retention (a stated non-goal).

A new candidate gets exactly its primary trigger/snapshot evidence pair. A later safe duplicate
creates its own proof-backed incident plus a supporting trigger/snapshot pair on the existing
candidate and never changes the candidate row. An invalidated candidate remains the active
duplicate primary: a later otherwise-safe proof adds supporting evidence to the same invalid
candidate and cannot mint a replacement candidate ID. Minting a replacement after invalidation
was explicitly rejected as gap laundering — if invalidation released the duplicate slot, an
attacker could launder a critical coverage gap by re-triggering and receiving a fresh,
uninvalidated candidate. Admission must therefore check the invalidation count (zero required);
UI/audit can still see the invalidated candidate as primary.

`candidate_invalidations` has primary key `(candidate_id, coverage_event_id)`, `reason_code`
exactly `late_critical_coverage_gap`, and no update or delete API. A later authenticated coverage
event invalidates a bounded candidate set when the new critical episode intersects the
candidate's exact signed time window, or a new sequence-gap affected range overlaps
`[primary_source_sequence, snapshot_sequence - 1]`. The window is always reconstructed from the
protected PCC snapshot the candidate references — never copied from a caller or inferred from
candidate `created_at`, since insertion timing must not alter which candidates a gap invalidates.
Candidate and incident bytes are never changed or deleted; repeated application of the same
coverage event is idempotent; close/recovery never removes an invalidation. The coverage event,
all its invalidation rows, and the cursor commit in one transaction; more than 4,096 matches
rolls the whole event back. Mutating or deleting candidates on invalidation was rejected:
append-only invalidation preserves the audit trail and rebuild determinism.

### One BEGIN IMMEDIATE transaction per source event; adverse facts vs unavailable authority

For one PCC snapshot: event/dedup insert, historical assessment, correlation, incident insert,
candidate/evidence inserts, cursor advance, and commit are one SQLite `BEGIN IMMEDIATE`
transaction; for one later coverage event: the event row, every invalidation, and the cursor are
likewise one transaction. Any exception rolls back everything; an ambiguous commit latches
projection unhealthy (no retry under an assumed outcome). The exact predecessor cursor,
completed-journal capability, evidence lifecycle, and authenticated path are revalidated inside
the transaction before duplicate state is read — pre-transaction-only validation was explicitly
ruled insufficient. Exact retry/reopen reproduces identical rows and hashes; duplicate retry
reauthenticates the retained primary candidate, and reopen chains final ACK stabilization checks
(`631d45a`); failed close handles are retained for a later cleanup attempt. "One source event,
all of its reducer rows, and the cursor commit atomically" is a locked invariant: partial writes
would create rows without cursor coverage or vice versa, breaking rebuild determinism. No
candidate is visible before commit; crash-before-commit replays to identical bytes; every
`_APPLY_STEPS` crash point plus candidate substeps is all-or-none.

Reducer outcomes are split into two load-bearing classes. Evidence-derived adverse outcomes
persist an incident AND advance the cursor with no candidate: authenticated still-open structural
gap -> `historical_coverage_incomplete`; structurally complete intersecting episode ->
`critical_coverage_gap`; safely loaded detector hash mismatch -> `detector_bundle_not_pinned`;
safely loaded special-use hash mismatch -> `correlation_proof_mismatch`. By contrast, unexplained
source ranges, provisional retention state, deferred PCC recovery, an unhealthy store, a changed
lifecycle, unavailable/mutable loaders, cap overflow, or inability to re-resolve the proof are
authority unavailable: a raised projection error, full rollback, no incident, no cursor advance —
never a synthetic evidence-derived rejection. Conflating "the evidence proves a problem" with "we
cannot currently prove anything" would let transient local failures manufacture durable
rejections, or let real gaps be silently skipped. The projection stalls (retriable) on authority
failure instead of recording false history.

### Projection generation is a restart-local authority epoch, never persisted

There is no durable projection-generation column, dynamic metadata value, or extra state table. A
verified open starts a new local owner epoch at generation 1 (including for an empty projection);
apply rotates cursor and hidden revision; rebuild rotates generation and revision; close/restart
rotates lifecycle and revision. Verified reopen may reset the numeric epoch to 1 because old
capabilities are already invalidated by owner/lifecycle identity. Persisting the epoch would make
byte-identical authenticated rebuilds history-dependent; omitting it from the snapshot while
persisting it elsewhere would make it rollbackable unauthenticated state. Restart-local epochs
give staleness detection without either flaw (a durable generation column and a generation inside
the logical snapshot were both rejected). Identical authenticated rebuilds retain identical
logical snapshot hashes; every capability (context, admission view) binds the restart-local epoch
plus the hidden revision, becoming stale on any lifecycle event.

### V1-to-V2 activation only by authenticated evidence rebuild; rows never migrated

Projection rows are never migrated or copied. On open: an exact V2 database verifies schema and
authenticated logical prefix; an exact frozen V1 database triggers a rebuild — freeze one healthy
ACK snapshot, build a new V2 under a random held-directory temp name by replaying authenticated
evidence only, verify (schema, logical snapshot, counts, cursor, FKs, unchanged ACK), checkpoint,
fsync, atomically replace, fsync the parent, reopen, verify again. Failure before the rename
leaves V1 untouched; uncertainty after the rename latches unhealthy and requires
restart/reverification. An unknown or modified schema is NOT treated as V1 — it fails closed.
`schema_v1.sql` is retained only to classify the old cache; none of its rows is candidate
authority, and forged or stale V1 rows never enter V2. There is no intermediate active reducer
version: a new or V1 database becomes V2 only with PCC and invalidation reduction already
enabled, and a fresh database is born directly as complete V2 that cannot advance past a PCC
without its incident/candidate result. Migration would launder unauthenticated cached bytes into
the security projection; partial activation would create a database that skips security facts for
events already past the cursor. Row migration/copying and incremental reducer activation were
both rejected. Two V2 rebuilds must be byte-identical in security fact rows; empty-to-empty
rebuilds preserve identical hashes.

One rebuild-verification rule was superseded during this design's own hardening: the original
behavior rejected any ACK movement past the frozen rebuild boundary on all paths. The dormant V2
regression gate exposed the contradiction — legitimate ACK progress during a rebuild was rejected
after the rename, making rebuilds fail on live systems — so ordinary rebuild now accepts a valid
ACK extension beyond the frozen boundary only as an authenticated monotonic extension; rollback,
substitution, pending replacement, and source-prefix mutation are still rejected, and retention
rebuild and future activation remain strict (no extension). Fixed in `cedfa9b`; reopen
verification chains acceptance/cursor/snapshot/ACK checks while permitting proven monotonic ACK
extension.

### Retention rebuild runs only under the exact retention-completion capability

Retention replay while `retention_pending=true` is permitted only under the exact
retention-completion capability bound to the same evidence-store lifecycle and completed retained
prefix — there is no general pending-retention bypass, and ordinary correlation/history reads
remain blocked. The reopened V2 database is revalidated before the authority accepts the fresh
rebuild epoch. Across routine-trigger retirement: candidate canonical bytes, the candidate fact
hash, proof-backed incidents, primary/supporting evidence rows backed by protected snapshots, the
coverage hash, and invalidations backed by protected coverage events must be identical before and
after; the global snapshot may differ because routine events and process/network/direct-
investigation rows were retired. Retention can remove a routine trigger only after the protected
snapshot and its candidate reconstruction path are already durable and rebuild-proven. Retention
rebuilds authenticate the retained prefix from the tombstone authority and reconstruct retained
Falco incidents from frozen accepted evidence, not mutable live input. Retention is the one
moment cached bytes could replace evidence; scoping the rebuild to a capability bound to the
completed retained prefix prevents any other caller from rebuilding under pending retention (a
general pending-retention rebuild path was explicitly rejected). Failed post-unlink retention
rebuilds latch unhealthy (`36f8586`); pre/post completion validation cannot leave retired state
healthy.

### Live rebuild publication: g+1 reservation, one-shot guard, descriptor-proof reopen

A live non-empty V2 rebuild stages without publishing early: staging reserves exactly generation
g+1, verifies the complete old SQLite image, and binds a factory-only opaque guard to the current
owner and the exact held old `(device, inode)`. Publication materializes and checkpoints an exact
temp V2 image, validates and removes only its bound empty sidecars, closes the sole old
connection, enters SUSPENDED, and performs the replace edge through held namespace descriptors.
The old image may be reopened only before the replace arm, proven by a duplicated descriptor of
the unique newly opened regular `O_RDWR` SQLite-main fd; byte-identical alternate inodes and
ambiguous extra opens are rejected. Pre-arm failure rebases onto the exact old inode/reopened
connection, releases (never consumes) an active retention lease, and records FAILED;
mutated-then-raised replace and fsync/reopen failures are classified from exact inode/link state
with no post-edge rollback — post-arm ambiguity makes the owner unhealthy and clears
authority/reservation conservatively. Success adopts the reopened new inode, consumes the
prevalidated retention lease exactly once, and exposes PUBLISHED only after
connection/generation/authority/retention/stage/reservation are coherent. Correlation authority
replacement commits through one lifecycle-owner registry edge; success and exact fallback both
mint a fresh g+1 authority and invalidate the old, requiring singleton live ownership; generic
staged abort/commit routes reject an armed rebuild guard.

The replace edge is the single point where the projection's identity changes on disk; attempting
rollback after an ambiguous rename can silently resurrect the old image while capabilities
reference the new one, so fail-shut after the arm is the only honest recovery. Post-edge rollback
and equality-based old-image identification were explicitly rejected (the latter in favor of
`(device, inode)` plus descriptor proof). PUBLISHED is strictly last; retention leases have
exactly-once consumption semantics; cleanup of a guarded rebuild must use the exact fallback
path.

### Admission is a controller-lock capability; coverage proof and live readiness stay distinct

Projection exposes no `get_candidate()` returning action authority. The controller issues an
opaque, non-copyable, non-serializable `CandidateAdmissionView` under its async lock, only after
catching the projection up and sampling fresh live `MutationReadiness`, requiring:
`readiness.ready == true`; `evidence_head == acceptance_cursor == confirmed_through ==
projection_cursor`; `candidate.boot_id ==` the current observer boot_id; and candidate
invalidation count `== 0`. Lookup accepts only `candidate_id` and strictly reparses/rebinds the
protected PCC and the candidate full-facts hash. The view binds the candidate, its hash, the
authority snapshot event, the full projection cursor identity, the exact terminal `EvidenceRef`
fingerprint, the restart-local rebuild epoch plus hidden revision, evidence/controller lifecycle,
and the live readiness hash/cursors. Any cursor advance, epoch/revision change, lifecycle change,
new invalidation, row mismatch, unhealthy projection, rebuild, restart, or close invalidates it.
The admission consumer (the OPA stage) must reacquire the lock and consume/revalidate the same
view after the OPA response and before its decision journal commit; a stale capability rejects,
an unchanged one accepts exactly once. The capability has no `valid=false` state — a view with a
validity flag was rejected; the capability simply does not exist for an invalid candidate.
Admission is stale after any generation/cursor/lifecycle change (a locked invariant); an OPA
round-trip is a window in which the world can change, so the decision must be revalidated under
the same lock that ordered it. Live post-open SQLite mutation of candidate rows must be caught by
reauthentication, latch unhealthy, and issue nothing.

A separate frozen `CandidateStatusObservation` may report candidate facts and invalidation IDs
for UI/audit but is publicly constructible, explicitly non-authoritative, and cannot be consumed
by policy or an intent builder. The synchronous `mutation_readiness()` remains observation-only;
admission must not call it outside the locked path. `CandidateAdmissionView` is a local admission
capability, not a network contract and not an intent; accepted-but-unprojected late evidence
blocks admission via live readiness before any invalidation row exists.

Finally, the immutable historical coverage hash (`AGMIND_CORRELATION_COVERAGE_V1`, bound into
candidate facts) and the current live readiness hash (sampled at admission) are distinct values
in distinct domains and are never substituted for each other. One proves what the evidence said
about the past window at candidate creation; the other proves the projection is currently caught
up. Conflating them would let a stale-but-once-complete proof stand in for current readiness, or
vice versa. Admission checks both: the candidate's frozen coverage proof and a fresh readiness
sample under the lock.

### Offline replay binds the same authorities and fails closed without a replacement

The public `rebuild_projection()` entry point for offline authenticated replay opens and binds
the same correlation journal and fixed pin authority as the live path; missing or mismatched
historical detector pins fail closed and abort without producing a replacement projection. Active
Projection/Core composition requires the exact same store, ACK journal, correlation journal,
historical timeline, and pin authority passed explicitly — no optional production default or
compatibility shim in constructors (both explicitly rejected: an offline replay with weaker
authority bindings would produce a projection that diverges from what the live reducer would have
built, and constructor defaults would let a composition silently omit an authority). Every
`ProjectionStore`/`CoreController` factory call site passes explicit same-root authorities.

## Current state (2026-08-11)

Verified in code at recording time:

- Evidence-bound issuer and one-use context:
  `core/agmind_immune/correlation/authority.py` (`CorrelationProjectionAuthority`);
  `core/agmind_immune/correlation/pcc.py:1239-1328` (private weak-key one-use context binding,
  replacing the earlier always-false validator).
- The five-condition chain: `core/agmind_immune/coverage/historical.py:169`
  (`authenticated_pcc_input_is_issued` gate);
  `core/agmind_immune/ingest/correlation_journal.py:1180` (`completed_for_snapshot`);
  `core/agmind_immune/evidence/projection_v2.py:2828` (`BEGIN IMMEDIATE` reducer transaction).
- `candidate_facts_sha256`: `core/agmind_immune/canonicaljson.py:31`
  (`_CANDIDATE_FACTS_DOMAIN`) and `:385` (`candidate_facts_sha256`); the
  `core/agmind_immune/evidence/schema.sql` candidates table stores the hash.
- Dedup V2: `core/agmind_immune/evidence/dedup.py:11-12,17-75` (both domains, boot-bound key,
  v1/v2 helpers); `core/agmind_immune/evidence/schema.sql:9` (`AGMIND_PROJECTION_DEDUP_V2`).
- Coverage hash and caps: `core/agmind_immune/coverage/historical.py:46`
  (`_COVERAGE_HASH_DOMAIN`), `:48` (`_COLLECTION_CAP = 4_096`); independent caps at
  `historical.py:48,250,257,632,688,778,1545` and
  `core/agmind_immune/evidence/projection_v2.py:194,7399,7521`.
- Nanosecond time model: `core/agmind_immune/coverage/grammar.py:17-23`
  (`parse_rfc3339nano_utc_ns` import, `_MIN`/`_MAX_TIMESTAMP_NS` at years 0001/9999).
- Falco per-kind grammar: `core/agmind_immune/coverage/grammar.py:75-110` (per-kind open-reason
  frozensets and close-reason map); observer coverage points at `grammar.py:506,535,568`
  (`observer_spool_drop`, `observer_spool_drop_recovered`,
  `docker_logging_visibility_degraded`).
- Path authority: `core/agmind_immune/coverage/historical.py:1481-1496` (class raises
  `TypeError` "issued only by SegmentStore"); `coverage/__init__.py` `__all__` omits it.
- Detector pin and image: `core/agmind_immune/correlation/authority.py:48,154-216,298` (fixed
  rule name, `st_nlink`/`0o444`/root checks, `O_NOFOLLOW`, `pcc_detector_bundle_sha256`);
  `Dockerfile:4` (digest-pinned base), `:20-21,43-44` (`/opt/agmind-venv`), `:52-54` (rule
  install), `:81` (`USER sais`).
- Special-use registry binding: `core/agmind_immune/correlation/primitives.py:146-154`
  (`_RegistryBinding`, `_canonical_registry_binding`).
- V2 schema identity: `core/agmind_immune/evidence/schema.sql:7-10` — the active file's SHA-256
  was recomputed on 2026-08-11 and equals the pinned
  `d4a5d563ca3964cbe4ed276882a4b4def95fb756fc67a6777fddf5de38b1619d`;
  `core/agmind_immune/evidence/projection_v2.py:163-166`; the non-unique duplicate-key index at
  `schema.sql:234-236`. Row codecs at `schema.sql:159-250` (20-digit GLOB checks, closed role
  CHECK at `:246-248`, PK at `:250`).
- Late invalidations: `core/agmind_immune/evidence/schema.sql:258-272` (table, PK, CHECK
  `reason_code='late_critical_coverage_gap'`); bounded match query at
  `projection_v2.py:193-194`.
- Transactions: `core/agmind_immune/evidence/projection_v2.py:2828,7079` (`BEGIN IMMEDIATE`).
- Restart-local generation: `schema.sql` contains no projection-generation column (only
  inventory/`reconcile_generation` domain fields).
- Activation layout: active `schema.sql` is V2 (hash-verified); `schema_v1.sql` is retained and
  hashes to the frozen pin
  `e27ea065b3659197aae7b58939695a5e79439faeb0b841dc600c6c822b1919f2`; `schema_v2.sql` was
  removed after promotion.
- Admission: `core/agmind_immune/incidents/admission.py:16-198` (`CandidateAdmissionView`,
  `CandidateStatusObservation`); `core/agmind_immune/controller.py:940-1060` (readiness
  sampling, four-cursor independent-equality check near `:1038`, shared-lifecycle composition
  check). Separate domains: `coverage/historical.py:46` (coverage hash domain) vs
  `coverage/state.py` (`MutationReadiness`).
- Rejection reason strings: all four (`historical_coverage_incomplete`,
  `critical_coverage_gap`, `detector_bundle_not_pinned`, `correlation_proof_mismatch`) exist in
  production at `core/agmind_immune/correlation/pcc.py:2061-2147`.

Unverified (the decision is recorded from the design record; the cited behavior was not traced
line-by-line at recording time):

- The trust-boundary enumeration as a whole (it is distributed across the mechanisms above).
- Classifier parity between live and historical paths (the grammar tables are verified; the
  single-extracted-classifier claim is not).
- The boot-scope split semantics (`boot_id` is threaded through `grammar.py` and
  `historical.py`; the discard-at-boundary behavior is not traced).
- Affected-range sequence-gap intersection; the bounded logical-primary/prefix oracle;
  structural completeness via surviving refs plus retired ranges; single-bundle startup
  fail-closed on an unavailable historical detector hash; the read-only pre-query predecessor
  check; ephemeral direct incidents; duplicate/supporting-evidence reducer semantics (the
  `candidate_evidence` schema at `schema.sql:239-256` is verified, the reducer behavior is not);
  cursor advance/no-advance semantics for the adverse-vs-unavailable split; the
  retention-completion capability; the monotonic ACK-extension rule; producer-side grammar
  closure in the Go observer.
- Live rebuild publication: the staging/guard machinery exists
  (`core/agmind_immune/evidence/projection_publication.py:95-119` —
  `_V2RebuildFilesystemPublisher`, `_V2RebuildOldReopener`), but the detailed
  arm/reopen/fallback semantics are untraced, and the surviving verification record for that
  work covers only four focused publication tests — no broad suite and no 4,096/4,097 replay
  run accompanied it.
- Offline replay authority binding (`core/agmind_immune/replay.py:163` exists; binding details
  untraced).

Superseded: no decision recorded here has been superseded by later code as of 2026-08-11.
Several decisions replaced their own first implementations during the design's hardening rounds,
recorded inline above: timestamp-only window intersection (fixed `00edb9d`), the identity-only
registry `WeakSet` (fixed `362f0f5`, `b24507b`), runtime-derived schema identity (fixed
`6e40dd5`), SQLite-derived logical-primary order (fixed `631d45a`), post-query-only predecessor
validation (fixed `5634480`), and the strict frozen-boundary rebuild rule (relaxed to monotonic
ACK extension in `cedfa9b`).

## Notes

- The acceptance gate for this scope is deliberately bounded: the focused Python security gate
  (`core/tests/incidents`, correlation, coverage, contract regressions, correlation
  journal/delivery, projection/retention/controller tests, `tests/replay/test_rebuild.py`) plus
  ruff, mypy, `make test-core-detector-pin-image`, and `git diff --check` — no repo-wide or
  native Linux suite in the inner loop. Two independent read-only reviews
  (authority/forgery/replay/readiness/late-gap, and projection schema/rebuild/retention/crash)
  must approve, and every P0/P1/P2 finding gets a focused regression, before production OPA
  wiring begins. Note that at recording time the repo-wide `make contracts` gate was red on an
  unrelated contract test, so verification claims here rest on the focused gate and the code
  citations above, not on a green repo-wide run.
- The runtime base image digest
  `python:3.12.13-slim-trixie@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36`
  was chosen specifically because the older ARM64 image's SQLite 3.40.1 produced false-NULL
  `WITHOUT ROWID` integrity checks; the image gate expects SQLite >= 3.46.1 semantics with
  `quick_check` and `integrity_check` both `[("ok",)]`. Base-image bumps must re-check SQLite
  integrity semantics.
- The 4,096/4,097 late-candidate boundary was proven natively exactly once (one-run rule) in a
  network-none, read-only container as user `sais` over the final image: 4,096 publishes
  coherent owner state, 4,097 rejects with no projection rows and no cursor advance
  (`test_projection_replay_boundary.py::test_controller_late_candidate_limit_4096_accepts_4097_fails_closed`,
  660 s). The test patches no cap, connection, fsync, reducer, or production function — it
  drives the real dormant owner transaction.
- Failure/restart invariants later work relies on: no candidate is visible before its SQLite
  transaction commits; crash before commit replays the same snapshot to identical bytes;
  ambiguous commit latches unhealthy without retry under an assumed outcome; reopen verifies
  schema, logical prefix, candidate hashes, evidence links, invalidations, cursor, and ACK
  identity before issuing any admission view; missing Core pins, a historical pin mismatch, an
  incomplete prefix, a corrupt PCC, ambiguous duplicate order, or a row/hash mismatch can never
  yield a candidate or an admission view.
- Deliberate non-goals of this design (a scope fence other records reference): no OPA or model
  calls; no `TemporaryEgressDenyIntentV1` creation; no approval, preparation, or execution of
  containment; no live Docker inspection; no terminal action/cooldown projection records; no
  detector-bundle rotation; routine-only investigation incidents are not preserved through
  retention; the request/producer/receipt/ACK ordering and transport bounds of
  [ADR 0004](0004-proof-production-and-transport.md) are unchanged.
- An import cycle (`coverage.historical` -> `correlation.pcc` -> `correlation.__init__` ->
  `correlation.authority` -> `coverage.historical`) is broken by a lazy public authority
  re-export in `correlation/__init__` (commit `9aaa0a5`); refactors must not reintroduce an
  eager import.
- Open flag: a follow-on requirement — that no security reconstruction call
  `_retired_record_from_projection_event` — could not be confirmed at recording time. The
  function still exists at `core/agmind_immune/evidence/projection.py:838` and is called at
  `:1670` inside retired-prefix reconstruction; whether that call site is the removed
  security-fact path or a permitted structural/classification path needs verification before any
  record claims that requirement complete.
- Baseline anchors: proof transport complete at commit `ef40b64`
  ([ADR 0004](0004-proof-production-and-transport.md)); same-root retention compatibility at
  `1ee711f`. Key commits for this scope: `362f0f5` (pin binding), `e0b3196`/`bfce55a`/`b0d6314`
  (grammar), `b3133f1`/`00edb9d` (historical reducer/path authority), `124bc46`/`fdc32c3`
  (completed delivery), `2baab09` (detector pin/image), `6f3633c`/`1286ca8`/`53829d4`/`b24507b`
  (context authority), `a00af2a`/`6e40dd5` (V2 schema), `5634480` (predecessor pre-query),
  `19e5501`/`631d45a` (V2 reducer), `cedfa9b`/`36f8586` (rebuild ACK/retention latch),
  `90bccfa` (SQLite pin).
