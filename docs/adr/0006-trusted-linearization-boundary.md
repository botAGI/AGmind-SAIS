# ADR 0006: Trusted linearization boundary

- Status: accepted
- Date: 2026-08-03 (recorded retroactively on 2026-08-11)

## Context

The product premise, fixed in [ADR 0001](0001-proof-carrying-containment.md), is that an
uncensored model is isolated from enforcement: evidence, proof, and action form a chain in which
no untrusted party can forge a link. The deterministic correlation proof
([ADR 0003](0003-correlation-proof.md)), its production and transport
([ADR 0004](0004-proof-production-and-transport.md)), and the historical projection authority
([ADR 0005](0005-historical-projection-authority.md)) all assume that the process replaying and
linearizing evidence is itself trustworthy.

Before this ADR, that assumption was defended in-process: the replay path tried to survive
arbitrary Python mutation inside `agmind-core` (monkeypatching, module-global replacement, hook
injection). Five successive hardening rounds failed the same structural way — validators bound one
function but called another through mutable module globals, test callbacks running inside trusted
lock regions could replace the validators themselves, closing one same-process construction path
exposed another, and administrative counters omitted work performed by nested helpers. Capturing
every transitive helper is not a finite task in Python. This ADR
redraws the trust boundary instead of continuing to defend an indefensible one, and records the
redesigned Projection V2 replay linearization that the new boundary made possible.

## Decisions

### agmind-core is inside the TCB; in-process attacks are out of scope for M1

M1 does not claim that a Python process remains authoritative after arbitrary code execution
inside that same process. `agmind-core` and its loaded code are part of the trusted computing
base, alongside the Linux kernel and the Docker daemon. `sys.modules` replacement, monkeypatching,
frame/closure walking, debugger injection, and native memory writes inside core are classified as
TCB compromise, handled by process/container isolation, image integrity, and host controls — not
by in-process defenses.

Rejected alternatives: continuing in-process anti-monkeypatch hardening (not finite, and no real
guarantee against an arbitrary in-process attacker); a memory-safe native replay/seal sidecar
(deferred as a post-M1 hardening option — it adds a new protocol, build chain, and operational
component before the M1 vertical slice works). The selected option is a narrow trusted core plus a
process boundary.

Consequences: untrusted parties — the model, OPA, sensor payloads, model text, HTTP metadata,
SQLite bytes before verification, public value constructors, protected workloads — communicate
with core only through versioned, bounded, serialized interfaces with no callbacks. Tests
asserting survival of arbitrary in-process mutation were deleted; the security test surface
targets hostile serialized inputs and sanctioned concurrency instead.

### The model adapter is untrusted, annotation-only, and read-only

The DeepSeek adapter (on DGX Spark) is explicitly outside the TCB. It receives only an
incident-scoped, field-allowlisted, read-only investigation snapshot. Its response is annotation
data only: it cannot create evidence, policy decisions, approvals, or actions, and it has no
import, callback, plugin, filesystem-write, Docker, policy-publication, approval, or actuator
capability. The model connection is outbound/read-only and cannot route an action response.

The whole product premise is isolating the uncensored model from enforcement; any capability
channel from the model into core would collapse the boundary this ADR establishes. Any future
model-integration feature must go through the bounded serialized interface; adding a callback or
plugin channel for the model would violate this ADR.

### The TCB claim is enforced at the process boundary: deployment hardening and the privilege split

Because in-process integrity after arbitrary code execution is explicitly not claimed, the
security of the linearization boundary rests on what surrounds the process. Two decisions enforce
that:

**Deployment hardening.** Core must run as a signed, version-pinned image, non-root, with a
read-only root filesystem and explicit writable state paths; no Docker socket, actuator
credential, shell, package installer, or model plugin directory; a seccomp/AppArmor profile with
dropped capabilities; and a deterministic startup measurement that records the core image/config
digest in evidence. Process/container hardening tests, not in-process sentinel tests, cover the
actual boundary. A deployment change that adds a shell, Docker socket, or writable code path to
the core container breaks the threat model.

**Privilege split.** `agmind-core` is trusted but unprivileged; it produces a canonical admitted
intent plus proof references. `agmind-actuatord` is a separate trusted root process with a minimal
API that requires local TTY approval before making an exact nftables change with TTL rollback.
Even a fully compromised core cannot act directly: enforcement requires the separate privileged
process and a local interactive human approval, so the blast radius of core compromise is bounded
to proposing intents. Core must never hold actuator credentials, and the actuator API surface must
stay minimal.

### Replay linearization: optimistic snapshot, pure compute, revalidate-then-publish

Projection V2 replay freezes an immutable `_ReplayInputSnapshot` under a fixed short lock order,
releases all locks, computes deterministically from values and held read-only descriptors, then
reacquires the same locks, compares every captured revision, lifecycle, descriptor, fact, and pin
against live authority, and publishes atomically only if nothing changed. Any change discards the
computation and returns a retryable or fail-closed result. No replay, hashing hook, test hook,
network call, model call, policy call, or user callback runs while the locks are held, and no
external callback runs between the last validation and publication.

Callbacks executed inside trusted lock regions were the root cause of the prior failure mode: they
could replace the validators themselves. The previous lock-held seal-capture model with callback
protocols was explicitly replaced. Optimistic concurrency makes sanctioned concurrent writers safe
by construction: they either complete before the validation snapshot, change a revision and cause
rejection, or wait until publication finishes — a mixed report is impossible. All authority
classes (source store, ACK journal, correlation authority, correlation-request journal) grew
gate/capture/revalidate/close snapshot APIs and mutation revisions; sanctioned-writer tests
coordinate through public APIs and bounded barriers only.

The redesign replaced the seams, not the whole preceding round. Deliberately retained from that
round: the exact replay reservation/generation cleanup and one-shot lifecycle, the explicit
probing states and one-shot versioned tickets, strict typed predecessor facts, immutable PCC/memo
leaf shapes, the source/ACK/correlation revision guards, and the exact cleanup and bounded-work
fixtures. What was replaced is precisely the executable
surface: module-global test seams became returned immutable diagnostics or public-API barriers,
lock-held seal capture became short snapshot construction with out-of-lock computation, the
post-hoc timeline traversal became reducer-emitted leaf facts, and same-process monkeypatch threat
tests became process-boundary and sanctioned-concurrency tests.

### Fixed lock order, with corruption fences drained only after the stack unwinds

Freeze and final validation acquire locks in exactly this order: owner projection mutex ->
`SegmentStore._source_gate` -> `AckJournal._retention_lock` -> correlation `binding.lock` ->
`_ISSUED_AUTHORITIES_LOCK` (reentrant, held across the correlation gate's yield) ->
`CorrelationRequestJournal._lock`. Acquiring the journal before the correlation binding is
forbidden: the ordinary V2 compatibility path already acquires the correlation binding before the
journal, so the journal must be deepest to prevent deadlock. The source gate must stay
nonreentrant. Two alternatives — an RLock on the source gate, and reversing the documented order
— were explicitly considered and forbidden, because neither fixes the cross-thread inversion found
in review; both would only mask it. VALIDATING status is published only after the journal lock is
held, and the journal lock remains held through publication so final revalidation and publish are
atomic with respect to journal writers.

Corruption or conflict discovered while any replay lock is held only latches a finite pending
health-fence value; the ACK and correlation-journal gates never call back into the store
health/source gate while nested. Orchestration drains the pending fences
(`AckJournal._drain_replay_corruption_fences`,
`CorrelationRequestJournal._drain_replay_corruption_fences`) only after the entire journal ->
issued-authority -> correlation -> ACK -> source stack unwinds, attaching secondary fence failures
to the primary error. Ordinary public correlation-journal operations likewise release the journal
lock before entering store read-only state, eliminating the journal->source lock edge. An
independent review had found that nested health fencing could re-enter or invert the held source
gate, producing deadlock. The consequence is that store read-only/fail-closed transitions
triggered by replay-observed corruption are deferred: the primary error always surfaces with fence
failures as attachments, and liveness is preserved under concurrent public journal writers.

### Pure compute accepts only frozen values — no callables, no live authority objects

`_compute_replay` reads only the exact-typed `_ReplayInputSnapshot` and immutable duplicated file
descriptors. It accepts no `Callable`, `SegmentStore`, `AckJournal`, correlation authority,
registry authority, journal capability, replay handle, or path authority, and enforces exact types
on entry. Any decode, hash, range, identity, or limit failure returns no artifact. It builds its
projection in a private SQLite connection serialized to bytes and is deterministic: the same
snapshot twice yields equal computations without mutating the live owner. A compute phase that can
reach live mutable authority or invoke supplied code re-creates the exact seam this redesign
eliminated; a values-only kernel makes the deterministic-replay claim checkable by type
inspection. Projection-local facts the old code fetched live (`active_duplicate`,
`terminal_observation`) are derived by compute from its own private SQLite state and rebound onto
detached seeds; `incident_from_verified_falco` was split into a values-only body so compute never
constructs `AuthenticatedFalcoInput` authority.

The same rule shapes how completed PCCs enter compute. Freeze captures each completed PCC as a
detached seed containing only the detached authenticated proof, detached pinned-registry facts,
detector pin, and deterministic duplicate key, with `coverage=None` (failed proofs get a
failed-only context). Freeze never precomputes historical coverage assessment — that would perform
historical reduction under locks, violating the short-freeze rule. Compute derives the assessment
from its own frozen source facts, then `_rebind_frozen_pcc_projection_context` purely rebinds it
plus projection-local duplicate/terminal observations onto the seed, recomputing canonical context
bytes and facts digest with no issuance or global-registry lookup, before calling the facts-only
kernel `_correlate_frozen_pcc`. Issuance of a proof is checked exactly once, while freezing under
the correlation binding. The bounded authentication needed to copy exact journal and PCC facts is
classified as snapshot construction, not replay: it invokes no supplied callable and performs no
historical reduction. No batch authority, evaluator, registered context, live registry, or
verifier object escapes the freeze section into compute. The correlation-journal snapshot returns
issued proofs only as an ephemeral second value; they are frozen into detached seeds immediately
with the live registry and pins held, and every issued-proof reference is discarded before locks
release. The pre-rebind `context.coverage` equality rejection was removed from compute; exact
detector and lookup-key checks remain.

### Source bytes are pinned by descriptor identity; descriptors close exactly once

The source snapshot duplicates read-only segment descriptors with `os.dup`, binds each to exact
device/inode/size (`os.fstat`) and the maximum byte prefix referenced by the frozen records, and
reads via `os.pread`. Computation never reopens a segment or journal by pathname: pathname reopen
is a TOCTOU seam through which a sanctioned retention writer, or an attacker with filesystem
access, could swap the file between freeze and compute. A held descriptor pinned to
device/inode/size makes the frozen bytes the only bytes compute can see (verified by tests that
unlink or rename the paths after capture). Revalidation compares lifecycle token, source revision,
terminal `EvidenceRef`, retained ranges, and every descriptor binding. The snapshot owns
descriptors from the moment `dup` succeeds and closes every one in a lexical `finally`, including
partial-construction and validation-mismatch paths. As a consequence, retention-state publication
had to join the source mutation gate so real retention writers are linearized with replay source
snapshots.

Descriptor ownership is consumed before the first close attempt. Publication and outer cleanup
move each ACK/source snapshot into a local owned variable and null the orchestration owner before
calling the close helper, so each numeric file descriptor receives at most one close attempt even
if a later close in the same snapshot raises; a partial close failure is never retried against the
same numeric descriptor. A failed close followed by a retry can close an unrelated descriptor,
because the numeric FD may already have been reused by another thread — a mutation test with the
old clear-after-close order showed every source descriptor receiving two close attempts. Cleanup
helpers must follow the transfer-then-close discipline on every path.

### Split base/publish generations with exact uint64 arithmetic

The replay reservation carries both `base_generation` and `publish_generation`, requiring
`publish_generation == base_projection_generation + 1`. Validation checks the frozen correlation
predecessor at the base generation while the computation and report terminal predecessor are
sealed for the publish generation. A single generation number cannot distinguish "what I validated
against" from "what I am publishing as", which allowed ambiguity about which state a sealed
computation belongs to. Generation arithmetic is exact uint64; a maximum-generation replay fails
before any artifact, before reservation installation. Once the fallible predecessor rebuild
succeeds, the remaining owner assignments are non-throwing. The atomic-adoption sequence (verify
seal, hydrate and verify the private SQLite image, construct the report, close descriptors,
rebuild the predecessor to base+1, adopt the connection, record the generation, clear the
reservation) must keep everything fallible before the first live mutation.

### Canonical typed encoding, not dataclass equality, decides validation

`_ProjectionPredecessor` and the other frozen facts are encoded before any untrusted boundary with
a pure typed value encoder: exact model type, exact int/str/None scalar types (bool-for-int and
scalar subclasses rejected), explicit presence and type tags, validated ranges and formats, fixed
field order, and domain separation. The validation phase compares exact bound object identity plus
canonical bytes and correlation revision; no dataclass `__eq__` participates. Dataclass equality
dispatches through overridable methods, which an attacker-shaped input (or subclass) could satisfy
without being the same value; canonical typed bytes plus identity comparison remove executable
comparison from the decision. Module-function replacement during validation is not a supported
interleaving (it is TCB compromise), so this closes every supported forgery path. Hostile-input
tests feed bool-for-int, scalar subclasses, malformed optional tags, wrong detector digests, and
wrong registry facts through serialized construction rather than object mutation. `report_bytes`
are domain-separated canonical typed bytes binding every computation field except itself;
`prefix_sha256` is the logical `_v2_snapshot_hash`, not SQLite file-layout bytes.

### The historical reducer emits leaf facts inline; administrative work is provably linear

The historical reducer returns `_HistoricalReductionResult` containing the public timeline plus
immutable leaf facts (interval/event canonical bytes, domain-separated digests, counts) produced
in the same loops that materialize the final ordered interval/event tuples — never by a second
traversal of the completed timeline. Terminal sealing visits O(R + C + P) leaves; the required
semantic prefix reduction remains exactly P(P+1) visits and is reported separately. Counters are
values returned by the deterministic reducer, incremented in the actual bounded loops — never
reconstructed post hoc from output lengths — and checked after computation outside locks. There is
no production instrumentation callback: `_fold_replay_timeline` and the callback
fold/sink/seal-visit helpers were deleted, and the prefix oracle callbacks were replaced by an
immutable precomputed prefix index with O(1) primary lookups. Post-hoc traversal both doubled the
administrative cost and required instrumentation callbacks to count work; reducer-owned counters
make the linearity claim honest (observed values, not formulas) and remove the last executable
hook from the semantic path. `_build_replay_memo_leaf` consumes `_HistoricalReductionResult`
rather than a completed timeline; the memo leaf stores counts and digests only, and independent
validation re-executes the same deterministic reducer and compares independently produced leaves.

### Every sanctioned writer is observable: mutation revisions and durable file identity

Optimistic validation needs, for each authority, a single monotonic fact that every sanctioned
writer is guaranteed to change; without it, a writer that leaves observable fields byte-identical
could slip between freeze and publish.

**ACK journal.** `AckJournal` maintains `_mutation_revision`, bumped by
`_bump_mutation_revision_locked` from the central durable mutation/retention/health transitions
before `_retention_lock` is released. The ACK replay snapshot captures this revision plus
generation, confirmed/pending state, committed prefix size and sha256, retention state, and an
exact prefix descriptor bound to device/inode/size; revalidation rejects any change.
Retention-state publication participates in the source mutation gate. The prior
`_evaluate_unpublished_anchor` model, which required a callback under `_retention_lock`, was
replaced. Any new ACK mutation path must route through the central transition that bumps the
revision, or replay validation silently loses soundness.

**Correlation-request journal.** `_CorrelationJournalReplaySnapshot` (journal/store lifecycles,
mutation revision, verifier generation, journal device/inode/size/digest/record count/chain head,
and canonical completed-PCC facts) never enters `_compute_replay`; only the immediately-detached
PCC seeds do. The journal is the deepest lock, and letting its snapshot reach compute would hand
compute journal authority. Completed proofs are captured through the strict terminal in
deterministic source order. Final revalidation compares the exact mutation revision, lifecycles,
verifier generation, durable inode/size/digest/chain/count, completed indexes, and every canonical
PCC fact while the journal lock remains held through publication. Public journal completion
between freeze and validation deterministically rejects publication (tested via a real completed
writer through the public journal API).

### Fail-closed publication: everything fallible happens before the first live mutation

After compute and before reacquiring live authority locks, `_validate_and_hydrate_replay` verifies
the computation's typed seal, deserializes the database image into a fresh private SQLite
connection, verifies exact schema, integrity, cursor, terminal predecessor, logical snapshot hash,
transcript count, invalidation rows, and source terminal, and preconstructs the unpublished
report. Only after final in-lock revalidation succeeds does the owner close the old connection and
snapshot descriptors, rebuild the correlation predecessor to exactly base+1, and atomically adopt
the already-validated private connection with non-throwing assignments. Hydration calls no live
owner, historical session, batch evaluator, context issuer, apply path, or replay hook. A crash or
validation failure at any point before publish leaves the prior durable projection authoritative —
the fail-closed rule requires that no partially-adopted state can ever exist. A crash during the
later atomic file replace follows the existing checkpoint/fsync/replace/parent-fsync/reopen
protocol.

The failure and cleanup contract is uniform. All freeze locks use lexical `with` scopes. Snapshot
construction returns a complete immutable value or nothing. Validation mismatch returns no
artifact and advances no projection state. Every reservation and owned replay descriptor is
cleared or closed in `finally` on any `BaseException`, including partial freeze. One outer
`finally` preserves the primary `BaseException`, closes an unpublished hydrated connection and
still-owned descriptors, clears the exact reservation last, records a FAILED status if publication
did not complete, and attaches cleanup failures as notes. The invariant chain (evidence -> proof
-> action, [ADR 0001](0001-proof-carrying-containment.md)) only holds if a failed replay is
indistinguishable from a replay that never started; leaked reservations or descriptors would wedge
the owner or corrupt a later replay. Tests inject only the finite `_ReplayFaultPhase` data value
(raising `KeyboardInterrupt` at fixed points: after complete freeze, at compute entry, after final
revalidation before live mutation) to prove cleanup at every phase — never injected code.

### Test observability is data-only; false-TCB tests were deleted without shims

Replay status is a frozen `_ReplayStatus` guarded by `_replay_state_lock`, a small lock separate
from the projection mutex, so tests can observe COMPUTING and lock-held VALIDATING without
injecting hooks. A test may pre-register one exact enum phase through a bounded data-only
`Condition` handshake; production waits only for that registered phase, for at most five seconds,
and invokes no supplied callable. Other owner operations acquire mutex -> replay-state-lock and
reject the exact reservation while compute runs with the projection mutex released. COMPUTING is
set only after freeze locks release; VALIDATING is published only after the journal (deepest) lock
is held. The old model's observable seams were module-global executable hooks running under
trusted locks — the exact mechanism that made every helper a security boundary. Data-only
observation preserves testability of concurrency phases without reopening that hole.

The test surface exercises hostile serialized records and PCCs, stale or wrong-store capabilities,
exact V1/V2 replay parity with conflict and late-invalidation behavior, real sanctioned writers
through public APIs, revision-change rejection, mixed-report impossibility, `BaseException`
cleanup, and exact linear counters. Tests whose only claim was
survival after arbitrary in-process mutation (module-function replacement during critical
sections, private-class construction via module-global enumeration, `object.__setattr__` during
trusted execution, executable hooks under locks) were deleted, with no source-text assertions that
old private symbols are absent and no compatibility shim preserving the exhausted private
session/factory model. Those tests asserted survival after arbitrary code execution in the TCB,
which is not an M1 security claim; keeping or shimming them would keep pretending in-process
integrity is defensible and would preserve the unclosable seams. Each boundary test was accepted
only after a genuine RED run — a security test that has never failed for the right reason is not
coverage.

### Production capacity cap of 4,096 with fail-closed overflow, proven by one genuine run

The controller-owned late-candidate/invalidation-closure limit is 4,096: a replay with 4,096
authenticated PCCs publishes a coherent report; 4,097 fails closed with no partial artifact and no
cursor advance, proving the overflow path is fail-closed rather than merely truncating. The gate
test uses real authenticated records and production limits — no patching of the cap, connection,
fsync, reducer, or descriptors. A capacity claim proven with a patched cap or synthetic shortcut
proves nothing. The genuine boundary node runs exactly once, after all implementation work and two
independent reviews, and is deselected from every other run: running the expensive genuine case
exactly once after review keeps it authoritative rather than a flaky routine cost. The explicit
`--deselect` in the focused command is load-bearing — whole-file collection otherwise includes the
boundary node, and an accidental earlier collection is diagnostic evidence only, not the
authoritative run.

### The historical replay broker/session/capability graph was deleted

The exhausted `_ReplayHandle`, `_ReplayAccess`, `_ReplayEventToken`, replay path/access records,
session and broker registries, dispatch, probes, callback final-seal helpers, the replay-only
completed-batch authority family (issue/claim/revalidate/seal/revoke), and the correlation
terminal callback evaluator were all removed. Pure replay has no live capability object to
preserve, and keeping the broker graph in production (flagged as an Important review finding) kept
dead authority surfaces reachable. Historical coverage issuance has exactly one ordinary
exact-store path taking `(store, proof)`, and terminal validation is direct non-callback
validation. Preserved for the dormant ordinary V2 apply path until activation:
`_evaluate_completed_snapshot_batch`, the single completed snapshot authority,
`_issue_correlation_context`, and `_IssuedContextBinding`. The planned deletion of the ACK anchor
family was not fully carried out — see Current state.

### Active V1 stays byte-identical; V2 activation is gated on acceptance

Throughout this work, the active evidence schema, active `projection.py`, V1 behavior, and public
APIs remained unchanged. Projection V2 may activate only after all eight acceptance gates pass
(listed under Notes), including two independent reviews approving the new threat boundary itself —
not just the code — and the single genuine capacity boundary run. The replacement of the trust
model must not silently alter the running product; gating activation on independent review of the
boundary makes the trust-model change an explicit, reviewed event. The dormant ordinary V2
live-context issuance/registration compatibility path used by apply was intentionally not migrated
during this work; it migrated with V2 activation.

## Current state (2026-08-11)

Verified in code at the time of recording:

- TCB scope and false-TCB test deletion: `core/agmind_immune/evidence/projection_v2.py:2077`
  rejects anything but an exact `_ReplayInputSnapshot`;
  `core/tests/evidence/test_historical_path.py` deleted as planned; grep finds no
  `_ReplayHandle`/`_ReplayAccess`/`_ReplayEventToken` anywhere
  under `core/agmind_immune/`; the boundary suite lives in
  `core/tests/evidence/test_projection_replay_boundary.py`.
- Freeze/compute/revalidate orchestration: `projection_v2.py:480` (`_ReplayInputSnapshot`),
  `:2782` (`_compute_replay`), `:3056` (validate/hydrate), `:4821-4856` (freeze-then-compute);
  authority gates at `segments.py:2960/3053/3543`, `ack_journal.py:1204/1257/1371`,
  `correlation_journal.py:2080/2197/2276`.
- Fence drain after unwind: `_drain_replay_corruption_fences` at
  `core/agmind_immune/ingest/ack_journal.py:935` and
  `core/agmind_immune/ingest/correlation_journal.py:785`; landed in commit `6d98a69`.
- Values-only compute and typed rejection: `projection_v2.py:2077-2091`, `:2782`, `:3032`.
- PCC seed freeze/rebind: `core/agmind_immune/correlation/pcc.py:801`
  (`_freeze_replay_pcc_seed`), `:1857` (`_correlate_frozen_pcc`), `:1910`
  (`_rebind_frozen_pcc_projection_context`).
- Descriptor-pinned source snapshot: `core/agmind_immune/evidence/segments.py:545`
  (`_ReplaySourceSnapshot` with descriptor/device/inode/size/maximum-prefix fields),
  `:3162/4803` (`os.dup`), `:1452-1544` (identity-checked `os.fstat`/`os.pread` reads).
- Split generations: `projection_v2.py:458-463` (`_ReplayReservation` with `base_generation` and
  `publish_generation`).
- Reducer-owned leaf facts: `core/agmind_immune/coverage/historical.py:346`
  (`_HistoricalReductionResult`), `:518` (`_reduce_historical_coverage_result`), `:1041`
  (compatibility wrapper); `_fold_replay_timeline` is absent from the file.
- ACK mutation revision: `ack_journal.py:298` (`_mutation_revision`), `:892-896`
  (`_bump_mutation_revision_locked`), `:901` (call from the central transition);
  `_AckReplaySnapshot` at `:204`.
- Correlation-journal snapshot: `correlation_journal.py:229`
  (`_CorrelationJournalReplaySnapshot`), `:2080/2197/2276` (gate/capture/revalidate).
- Fail-closed hydrate/publish and cleanup: `projection_v2.py:3056-3071`, `:435-446`
  (`_ReplayFaultPhase`), `:4568-4587` (finite fault-phase parameter).
- Data-only observability: `projection_v2.py:450` (`_ReplayStatus`), `:3184/3302-3303`
  (`_replay_state_lock`, `_replay_state_condition`), `:3672` (`_replay_status_for_test`).
- Capacity cap: `projection_v2.py:7399` (late-candidate cap) and `:7521` (invalidation-closure
  cap); `test_projection_replay_boundary.py:1935`
  (`test_controller_late_candidate_limit_4096_accepts_4097_fails_closed`).

Recorded but not re-verified against code at recording time:

- The model-adapter constraints and the core deployment hardening requirements (no code citation
  in the extraction; deployment manifests and adapter code were not inspected).
- The privilege split: `host/actuatord/` exists and the repository audit places the real limits
  in `host/actuatord/limits.go`, but the intent/approval path was not inspected for this record.
- The exact lock acquisition order inside the orchestration was not traced line by line; all
  named gates exist, and the implementation report attests the documented left-to-right order.
- The one-shot-close call sites: the close helpers exist (`segments.py:580`,
  `ack_journal.py:219`) and the fix landed in commit `6d98a69`, but the ownership-transfer call
  sites were not traced.
- The typed value encoder itself was not read; the snapshot dataclasses do carry `*_canonical`
  bytes fields (`projection_v2.py:480ff`).

Completed as designed (not superseded): the activation gate held. Projection V2 has since been
activated — commit `cd3df13` "feat(core): activate authenticated Projection V2", after `57b6b1d`
"prepare exact V2 activation". `projection.py:248` now knows the V2 schema kind and
`projection.py:2538-2560` performs V2 publication recovery. The gating decision completed rather
than being contradicted.

Known discrepancy: the planned deletion of the ACK anchor family after its callers migrated was
only partly carried out. `_AckUnpublishedAnchor`, `_capture_unpublished_anchor`,
`_revalidate_unpublished_anchor`, and `_evaluate_unpublished_anchor` still exist at
`core/agmind_immune/ingest/ack_journal.py:185/1586/1627/1634`, and the family is not dead code:
the ordinary V2 unpublished path in `projection_v2.py` still imports `_AckUnpublishedAnchor` and
calls capture/revalidate (`projection_v2.py:3552`, `:3589`,
`_freeze_unpublished_ack_anchor`/`_revalidate_unpublished_ack_anchor`), consistent with the
compatibility path preserved until activation. Only `_evaluate_unpublished_anchor` — the lock-held
callback evaluator this design replaced — has no callers anywhere and is dead code awaiting
deletion.

Extension since 2026-08-03: V2-activation work extended the replay state machinery —
`_ReplayPhase` gained STAGED and SUSPENDED, a `_ReplayPurpose` enum (INITIAL / V2_REBUILD) was
added, `_ReplayReservation` gained a `purpose` field and an optional `through_key`,
`_ReplayStatus` gained `failure_phase`, and `_ReplayFaultPhase` gained
STAGE_HANDOFF/POST_CALLBACK/PRE_COMMIT and four REBUILD_* phases (`projection_v2.py:419-463`).
The design recorded here remains the substrate; this ADR describes the design decisions, not the
frozen 2026-08-03 enum shapes.

## Notes

- The eight acceptance gates required before V2 activation: (1) pure compute accepts no callbacks
  or live authority objects; (2) no executable test hook under the trusted lock order; (3) freeze
  and validate compare the exact documented revisions and facts; (4) leaf construction adds no
  second cumulative timeline traversal; (5) the focused semantic/concurrency/cleanup/counter
  gates pass; (6) two independent reviews approve the threat boundary and implementation; (7) the
  single genuine 4,096/4,097 boundary run passes; (8) active V1 stays byte-identical until
  activation work begins.
- Invariant constants other documents reference: the semantic prefix reduction is exactly P(P+1)
  visits as the sum of the projecting and validating reductions — 20 at P=4, 72 at P=8 (a single
  reduction is P + P(P-1)/2, i.e. 10/36); terminal administrative sealing is O(R + C + P);
  administrative counters are exactly linear (eight-PCC counts are exactly double four-PCC
  counts).
- A crash during the projection atomic file replace follows the pre-existing checkpoint -> fsync
  -> replace -> parent-fsync -> reopen protocol, owned by the activation work and referenced here
  as a dependency.
- Independent review of the linearization implementation found 0 Critical and 3 Important issues,
  all resolved in commit `6d98a69`: nested ACK/correlation health fencing could re-enter or
  invert the source gate; the historical session/broker graph remained in production; and a
  partial snapshot close could retry a reused FD number. These findings are the origin of the
  fence-drain, broker-deletion, and one-shot-close decisions above.
- Implementation commits for archaeology: `10ef65f` "feat(core): freeze completed PCC replay
  facts", `cbe3a38` "refactor(core): publish replay after exact revalidation", `6d98a69`
  "fix(core): drain replay fences after lock unwind" (base `91b33e4`).
- Deadlock regression tests run corrupt replay cases in forked children so an expected pre-fix
  deadlock cannot retain the process-global issued-authority lock and contaminate later test
  nodes. Reuse this technique for any test touching `_ISSUED_AUTHORITIES_LOCK`.
- Verification during the implementation slice was deliberately narrow: no broad suite ran, and
  no active V1, schema, specification, or plan file was modified; the genuine capacity boundary
  run was deferred to the acceptance phase.
- The original design note this ADR descends from has been removed from the repository; this ADR
  is now the design authority for the trusted linearization boundary.
