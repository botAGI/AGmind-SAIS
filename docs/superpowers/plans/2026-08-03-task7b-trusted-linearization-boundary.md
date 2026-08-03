# Task 7B Trusted Linearization Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the exhausted same-process anti-monkeypatch replay model with a deterministic snapshot → pure compute → validate/publish pipeline that is authoritative against hostile serialized inputs, stale capabilities, crashes, and sanctioned concurrent writers.

**Architecture:** `agmind-core` is a trusted unprivileged process; DeepSeek, OPA, sensors, model text, and protected workloads remain out of process and untrusted. Replay freezes exact source/ACK/correlation facts under a fixed short lock order, computes from immutable values and held read-only descriptors with no callbacks or live authorities, then reacquires the same locks to revalidate and publish atomically. Historical leaf facts are emitted during the reducer's existing materialization loops, so terminal administrative work is linear.

**Tech Stack:** Python `>=3.12.13,<3.13`, frozen/slotted dataclasses, SQLite, POSIX `dup`/`fstat`/`pread`, pytest, Ruff, mypy.

## Global Constraints

- Design authority: `docs/superpowers/specs/2026-08-03-task7b-trusted-linearization-boundary-design.md`.
- Arbitrary Python execution, `sys.modules` replacement, monkeypatching, frame/closure walking, debugger injection, and native memory writes inside `agmind-core` are TCB compromise, not supported M1 interleavings.
- DeepSeek, OPA, model output, sensor payloads, HTTP metadata, SQLite bytes before verification, and public value constructors remain untrusted.
- Active `core/agmind_immune/evidence/schema.sql`, active `projection.py`, V1 behavior, and public APIs remain unchanged throughout this plan.
- Pure replay compute accepts no `Callable`, `SegmentStore`, `AckJournal`, correlation authority, registry authority, journal capability, replay handle, or path authority.
- No hashing hook, test hook, model/policy/network call, or arbitrary callback executes while source, ACK, correlation, issued-authority, or projection locks are held.
- Fixed lock order: projection mutex → source snapshot gate → ACK retention lock → correlation binding lock → issued-authority lock.
- Snapshot compute reads only duplicated read-only descriptors and never reopens a segment/journal by pathname.
- Every duplicated descriptor and replay reservation is released on every `BaseException`, including partial freeze and validation mismatch.
- Terminal administrative work is `O(R + C + P)`; semantic prefix reduction remains exactly `P(P+1)` visits, 20 at `P=4` and 72 at `P=8`.
- Tests use real serialized inputs, real public writer APIs, immutable returned diagnostics, and bounded phase observation; they do not replace core functions or execute callbacks under trusted locks.
- Run the genuine 4,096/4,097 boundary exactly once, after all tasks and two independent reviews approve the focused implementation.

---

### Task 1: Reducer-emitted immutable historical leaves

**Files:**
- Modify: `core/agmind_immune/coverage/historical.py:327-937,1141-1680`
- Modify: `core/tests/coverage/test_historical.py`
- Create: `core/tests/evidence/test_projection_replay_boundary.py`

**Interfaces:**
- Consumes: exact ordered `tuple[StoredEvidenceRecord, ...]` and ordinary historical scalar inputs.
- Produces:

```python
@dataclass(frozen=True, slots=True)
class _HistoricalReductionDiagnostics:
    prepared_records: int
    primary_checks: int
    interval_materializations: int
    event_materializations: int
    leaf_materializations: int
    semantic_prefix_visits: int


@dataclass(frozen=True, slots=True)
class _HistoricalReductionResult:
    timeline: HistoricalCoverageTimeline
    assessment_digest: bytes
    interval_count: int
    interval_digest: bytes
    event_count: int
    event_digest: bytes
    semantic_digest: bytes
    diagnostics: _HistoricalReductionDiagnostics
```

- Exact function signature: `_reduce_historical_coverage_result(records: tuple[StoredEvidenceRecord, ...], *, host_id: str, boot_id: str, trigger_event_id: str, trigger_source_sequence: int, trigger_event_time: str, clock_uncertainty_ms: int, coverage_through_sequence: int, window_end: str) -> _HistoricalReductionResult`.

- The existing `_reduce_historical_coverage(...) -> HistoricalCoverageTimeline` remains as the compatibility wrapper for unchanged internal callers and returns `.timeline` from the result kernel.

- [ ] **Step 1: Write RED reducer/leaf tests**

Add exact nodes:

```python
def test_replay_reduction_returns_immutable_ordered_leaf_facts() -> None:
    result = _reduce_historical_coverage_result(**four_pcc_fixture())
    assert type(result) is _HistoricalReductionResult
    assert type(result.timeline.intersecting_intervals) is tuple
    assert type(result.timeline.coverage_event_ids) is tuple
    assert result.interval_count == len(result.timeline.intersecting_intervals)
    assert result.event_count == len(result.timeline.coverage_event_ids)
    assert len(result.assessment_digest) == 32
    assert len(result.interval_digest) == 32
    assert len(result.event_digest) == 32
    assert len(result.semantic_digest) == 32


def test_replay_reduction_reports_exact_admin_and_semantic_work_at_four_and_eight() -> None:
    four = _reduce_historical_coverage_result(**four_pcc_fixture())
    eight = _reduce_historical_coverage_result(**eight_pcc_fixture())
    # One reduction performs P main visits plus P(P-1)/2 prefix visits.
    # Task 5 sums the projecting and validation reductions to 20 / 72.
    assert four.diagnostics.semantic_prefix_visits == 10
    assert eight.diagnostics.semantic_prefix_visits == 36
    assert four.diagnostics.primary_checks == 10
    assert eight.diagnostics.primary_checks == 36
    assert eight.diagnostics.prepared_records == 2 * four.diagnostics.prepared_records
    assert eight.diagnostics.leaf_materializations == 2 * four.diagnostics.leaf_materializations
```

The fixtures use literal expected hashes and distinct cumulative interval/event facts; they do not compute expected digests with the production encoder.

- [ ] **Step 2: Run the two nodes and verify RED**

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest -q \
  core/tests/evidence/test_projection_replay_boundary.py::test_replay_reduction_returns_immutable_ordered_leaf_facts \
  core/tests/evidence/test_projection_replay_boundary.py::test_replay_reduction_reports_exact_admin_and_semantic_work_at_four_and_eight
```

Expected: collection or assertion failure because `_HistoricalReductionResult` and returned diagnostics do not exist and the current `_fold_replay_timeline` performs a post-hoc traversal.

- [ ] **Step 3: Implement the pure reduction result**

Replace `_HistoricalPrefixOracle` callbacks with an immutable prefix index:

```python
@dataclass(frozen=True, slots=True)
class _HistoricalPreparedPrefix:
    prepared: tuple[_PreparedHistoricalRecord, ...]
    primary: tuple[bool, ...]

    def before(self, source_sequence: int) -> tuple[_PreparedHistoricalRecord, ...]:
        return tuple(
            item
            for item in self.prepared
            if item.envelope.source_sequence < source_sequence
        )
```

Precompute the primary mask once from exact `(dedup_kind, logical_key_sha256)` keys and bind it to an immutable exact source-sequence/ordinal index, so each primary lookup is `O(1)`. A reducer-local counter increments on every main record visit, yielded prefix record, and primary lookup; diagnostics snapshot those observed values instead of deriving a formula from `N`. While materializing the final ordered interval and event tuples, create their canonical bytes and update the leaf digests in the same loops. Delete `_fold_replay_timeline`, `_replay_timeline_sink`, `_replay_leaf_fold_visit`, `_replay_seal_visit`, and `_replay_validation_compact_visit`. Change `_build_replay_memo_leaf` to consume `_HistoricalReductionResult` rather than a completed timeline.

- [ ] **Step 4: Run focused GREEN and ordinary reducer parity**

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest -q \
  core/tests/evidence/test_projection_replay_boundary.py::test_replay_reduction_returns_immutable_ordered_leaf_facts \
  core/tests/evidence/test_projection_replay_boundary.py::test_replay_reduction_reports_exact_admin_and_semantic_work_at_four_and_eight \
  core/tests/coverage/test_historical.py::test_historical_and_live_reducers_share_the_exact_classifier \
  core/tests/coverage/test_historical.py::test_historical_conflict_matrix
```

Expected: 4 nodes pass with no warnings.

- [ ] **Step 5: Static check and commit**

```bash
.venv/bin/ruff check core/agmind_immune/coverage/historical.py core/tests/coverage/test_historical.py core/tests/evidence/test_projection_replay_boundary.py
.venv/bin/mypy core/agmind_immune/coverage/historical.py
git diff --check
git add core/agmind_immune/coverage/historical.py core/tests/coverage/test_historical.py core/tests/evidence/test_projection_replay_boundary.py
git commit -m "refactor(core): emit historical replay leaves in reducer"
```

---

### Task 2: Held-descriptor source replay snapshot

**Files:**
- Modify: `core/agmind_immune/evidence/segments.py:2383-2669,6537-6722,10249-10477`
- Modify: `core/tests/evidence/test_projection_replay_boundary.py`

**Interfaces:**
- Consumes: a healthy recovered `SegmentStore` and exact terminal `EvidenceRef` under `_source_gate`.
- Produces:

```python
@dataclass(frozen=True, slots=True)
class _ReplaySegmentDescriptor:
    descriptor: int
    device: int
    inode: int
    size: int
    maximum_prefix_bytes: int
    relative_path: str


@dataclass(frozen=True, slots=True)
class _ReplayRecordDescriptor:
    ref: EvidenceRef
    accepted_at: str
    canonical_record: bytes
    segment_index: int


@dataclass(frozen=True, slots=True)
class _ReplaySourceSnapshot:
    lifecycle_token: bytes
    source_revision: int
    terminal_ref: EvidenceRef
    retained_ranges: tuple[tuple[int, int], ...]
    records: tuple[_ReplayRecordDescriptor, ...]
    segments: tuple[_ReplaySegmentDescriptor, ...]


```

- Exact function signatures: `SegmentStore._replay_source_snapshot_gate() -> Iterator[None]`, `SegmentStore._capture_replay_source_locked(terminal_ref: EvidenceRef) -> _ReplaySourceSnapshot`, `SegmentStore._revalidate_replay_source_locked(snapshot: _ReplaySourceSnapshot) -> None`, and `_close_replay_source_snapshot(snapshot: _ReplaySourceSnapshot) -> None`.

- [ ] **Step 1: Write RED descriptor ownership tests**

```python
def test_source_snapshot_reads_held_descriptors_without_path_reopen(tmp_path: Path) -> None:
    store, terminal = build_file_backed_source(tmp_path)
    with store._replay_source_snapshot_gate():
        snapshot = store._capture_replay_source_locked(terminal)
    unlink_or_rename_source_paths(store)
    assert decode_snapshot_records(snapshot) == expected_record_literals()
    _close_replay_source_snapshot(snapshot)


def test_source_snapshot_revalidation_rejects_revision_or_descriptor_change(tmp_path: Path) -> None:
    store, terminal = build_file_backed_source(tmp_path)
    with store._replay_source_snapshot_gate():
        snapshot = store._capture_replay_source_locked(terminal)
    store.append(next_signed_record())
    with store._replay_source_snapshot_gate(), pytest.raises(ProjectionAuthorityError):
        store._revalidate_replay_source_locked(snapshot)
    _close_replay_source_snapshot(snapshot)


def test_partial_source_snapshot_failure_closes_every_owned_descriptor(tmp_path: Path) -> None:
    snapshot, owned_fds = force_real_second_descriptor_failure(tmp_path)
    assert snapshot is None
    assert all_descriptor_fstats_fail_with_ebadf(owned_fds)
```

- [ ] **Step 2: Run the three nodes and verify RED**

Expected: missing snapshot API and current callback-based `_evaluate_source_terminal` cannot satisfy descriptor ownership.

- [ ] **Step 3: Implement capture/revalidation/close**

Use `os.dup`, `os.fstat`, and `os.pread`; bind device/inode/size and the maximum byte prefix referenced by the frozen records. Snapshot construction owns descriptors as soon as `dup` succeeds and closes partial state in `except BaseException`. Revalidation compares lifecycle token, source revision, terminal ref, retained ranges, and every descriptor binding. Retain the existing `_evaluate_source_terminal` unchanged only as a staged compatibility path for the still-dormant `projection_v2.py` caller; Task 6 removes that method and caller together when orchestration migrates. Retain `_source_gate`, `_source_revision`, `_begin_source_mutation`, and `_end_source_mutation`; no new code may call the compatibility evaluator.

- [ ] **Step 4: Run focused GREEN**

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest -q \
  core/tests/evidence/test_projection_replay_boundary.py::test_source_snapshot_reads_held_descriptors_without_path_reopen \
  core/tests/evidence/test_projection_replay_boundary.py::test_source_snapshot_revalidation_rejects_revision_or_descriptor_change \
  core/tests/evidence/test_projection_replay_boundary.py::test_partial_source_snapshot_failure_closes_every_owned_descriptor
```

- [ ] **Step 5: Static check and commit**

```bash
.venv/bin/ruff check core/agmind_immune/evidence/segments.py core/tests/evidence/test_projection_replay_boundary.py
.venv/bin/mypy core/agmind_immune/evidence/segments.py
git diff --check
git add core/agmind_immune/evidence/segments.py core/tests/evidence/test_projection_replay_boundary.py
git commit -m "feat(core): freeze replay source descriptors"
```

---

### Task 3: Revisioned ACK replay snapshot without lock-held callbacks

**Files:**
- Modify: `core/agmind_immune/ingest/ack_journal.py:163-199,945-1400,1543-1593`
- Modify: `core/tests/evidence/test_projection_replay_boundary.py`

**Interfaces:**

```python
@dataclass(frozen=True, slots=True)
class _AckReplaySnapshot:
    lifecycle_token: bytes
    mutation_revision: int
    generation: int
    confirmed: tuple[int, str, str] | None
    pending: tuple[int, str, str] | None
    committed_prefix_size: int
    committed_prefix_sha256: bytes
    retention_pending: bool
    descriptor: int
    device: int
    inode: int
    size: int


```

- Exact function signatures: `AckJournal._replay_ack_snapshot_gate() -> Iterator[None]`, `AckJournal._capture_replay_ack_locked(acceptance_cursor: int) -> _AckReplaySnapshot`, `AckJournal._revalidate_replay_ack_locked(snapshot: _AckReplaySnapshot) -> None`, and `_close_replay_ack_snapshot(snapshot: _AckReplaySnapshot) -> None`.

- [ ] **Step 1: Write RED ACK revision tests**

```python
def test_ack_snapshot_revision_changes_for_every_sanctioned_writer(tmp_path: Path) -> None:
    journal, confirmed = build_ack_journal(tmp_path)
    with journal._replay_ack_snapshot_gate():
        snapshot = journal._capture_replay_ack_locked(confirmed.source_sequence)
    journal.record_pending(next_ref(confirmed))
    with journal._replay_ack_snapshot_gate(), pytest.raises(ProjectionAuthorityError):
        journal._revalidate_replay_ack_locked(snapshot)
    _close_replay_ack_snapshot(snapshot)


def test_ack_snapshot_has_no_callback_and_owns_exact_prefix_descriptor(tmp_path: Path) -> None:
    snapshot = capture_ack_snapshot(tmp_path)
    assert snapshot.committed_prefix_sha256 == literal_expected_ack_prefix_sha256()
    assert callable_fields(snapshot) == ()
    _close_replay_ack_snapshot(snapshot)
```

Parameterize the first node over pending, confirmed, retention acquire/release, close, and fail-closed health transitions through their real APIs.

- [ ] **Step 2: Run and verify RED**

Expected: no mutation revision/snapshot API; current `_evaluate_unpublished_anchor` requires a callback under `_retention_lock`.

- [ ] **Step 3: Implement the revisioned snapshot**

Add `_mutation_revision` and `_bump_mutation_revision_locked()`; call it from the central durable mutation/retention/health transitions before releasing `_retention_lock`. Reuse exact prefix and descriptor checks from `_validate_unpublished_anchor_locked`. Delete `_AckUnpublishedAnchor`, `_capture_unpublished_anchor`, `_revalidate_unpublished_anchor`, and `_evaluate_unpublished_anchor` after callers migrate in Task 6.

- [ ] **Step 4: Run focused GREEN**

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest -q \
  core/tests/evidence/test_projection_replay_boundary.py::test_ack_snapshot_revision_changes_for_every_sanctioned_writer \
  core/tests/evidence/test_projection_replay_boundary.py::test_ack_snapshot_has_no_callback_and_owns_exact_prefix_descriptor
```

- [ ] **Step 5: Static check and commit**

```bash
.venv/bin/ruff check core/agmind_immune/ingest/ack_journal.py core/tests/evidence/test_projection_replay_boundary.py
.venv/bin/mypy core/agmind_immune/ingest/ack_journal.py
git diff --check
git add core/agmind_immune/ingest/ack_journal.py core/tests/evidence/test_projection_replay_boundary.py
git commit -m "feat(core): snapshot replay ACK authority"
```

---

### Task 4: Typed correlation snapshot and facts-only PCC kernel

**Files:**
- Modify: `core/agmind_immune/correlation/authority.py:337-460,513-788,991-1320`
- Modify: `core/agmind_immune/correlation/pcc.py:788-944,1320-1669`
- Modify: `core/tests/evidence/test_projection_replay_boundary.py`

**Interfaces:**

```python
@dataclass(frozen=True, slots=True)
class _FrozenPCCCorrelationInput:
    proof: AuthenticatedPCCInput
    context: CorrelationContext
    proof_canonical: bytes
    context_canonical: bytes
    facts_sha256: bytes


@dataclass(frozen=True, slots=True)
class _CorrelationReplaySnapshot:
    lifecycle_token: bytes
    revision: object
    predecessor: _ProjectionPredecessor
    predecessor_canonical: bytes
    detector_bundle_sha256: str
    registry_facts_canonical: bytes
```

- Exact function signatures: `_correlate_frozen_pcc(input: _FrozenPCCCorrelationInput) -> CorrelationResult`, `_correlation_projection_snapshot_gate(authority: CorrelationProjectionAuthority) -> Iterator[_ProjectionAuthorityBinding]`, `_capture_correlation_replay_locked(authority: CorrelationProjectionAuthority, binding: _ProjectionAuthorityBinding, expected: _ProjectionPredecessor) -> _CorrelationReplaySnapshot`, and `_revalidate_correlation_replay_locked(authority: CorrelationProjectionAuthority, binding: _ProjectionAuthorityBinding, snapshot: _CorrelationReplaySnapshot) -> None`.

- [ ] **Step 1: Write RED facts-only and revision tests**

```python
def test_frozen_pcc_kernel_accepts_values_only_and_matches_live_result() -> None:
    frozen, expected = build_real_issued_frozen_pcc_input()
    assert _correlate_frozen_pcc(frozen) == expected
    assert callable_fields(frozen) == ()


def test_correlation_snapshot_rechecks_typed_predecessor_revision_and_pins() -> None:
    authority, binding, expected = build_real_correlation_authority()
    with _correlation_projection_snapshot_gate(authority) as held:
        snapshot = _capture_correlation_replay_locked(authority, held, expected)
    advance_with_real_successor(authority)
    with _correlation_projection_snapshot_gate(authority) as held, pytest.raises(CorrelationProjectionError):
        _revalidate_correlation_replay_locked(authority, held, snapshot)
```

Also feed bool-for-int, scalar-subclass, malformed optional tags, wrong detector digest, and wrong registry facts through serialized/frozen input construction; do not mutate Python objects during validation.

- [ ] **Step 2: Run and verify RED**

Expected: facts-only kernel and snapshot API absent; current claimed-context evaluator calls a callback under authority.

- [ ] **Step 3: Implement frozen facts and snapshot validation**

Split `_correlate_pcc_kernel` into a values-only body that does not call `authenticated_pcc_input_is_issued`; issuance is checked exactly once while freezing. Encode predecessor, proof, context, detector pin, and registry facts with exact types and domain-separated canonical bytes. Gate order inside correlation is `binding.lock` then `_ISSUED_AUTHORITIES_LOCK`. Task 6 deletes `_evaluate_correlation_projection_terminal_authority` and every terminal replay caller. Preserve `_evaluate_issued_context`, evaluator registration, and `_IssuedContextBinding` for the dormant ordinary V2 `apply` compatibility path; Task 8 migrates that path when V2 activates.

- [ ] **Step 4: Run focused GREEN and result parity**

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest -q \
  core/tests/evidence/test_projection_replay_boundary.py::test_frozen_pcc_kernel_accepts_values_only_and_matches_live_result \
  core/tests/evidence/test_projection_replay_boundary.py::test_correlation_snapshot_rechecks_typed_predecessor_revision_and_pins \
  core/tests/evidence/test_projection_pcc.py::test_completed_safe_pcc_persists_candidate_and_primary_evidence
```

- [ ] **Step 5: Static check and commit**

```bash
.venv/bin/ruff check core/agmind_immune/correlation/authority.py core/agmind_immune/correlation/pcc.py core/tests/evidence/test_projection_replay_boundary.py
.venv/bin/mypy core/agmind_immune/correlation/authority.py core/agmind_immune/correlation/pcc.py
git diff --check
git add core/agmind_immune/correlation/authority.py core/agmind_immune/correlation/pcc.py core/tests/evidence/test_projection_replay_boundary.py
git commit -m "refactor(core): freeze correlation replay facts"
```

---

### Task 5: Pure Projection V2 replay computation

**Files:**
- Modify: `core/agmind_immune/evidence/projection_v2.py:343-364,859-1265,2491-3740`
- Modify: `core/agmind_immune/coverage/historical.py`
- Modify: `core/agmind_immune/correlation/pcc.py`
- Modify: `core/tests/evidence/test_projection_replay_boundary.py`
- Modify: `core/tests/evidence/test_projection_pcc.py`

**Interfaces:**

```python
@dataclass(frozen=True, slots=True)
class _ReplayInputSnapshot:
    source: _ReplaySourceSnapshot
    ack: _AckReplaySnapshot
    correlation: _CorrelationReplaySnapshot
    pcc_inputs: tuple[_FrozenPCCCorrelationInput, ...]
    schema_domain: bytes
    projection_generation: int


@dataclass(frozen=True, slots=True)
class _ReplayComputation:
    database_image: bytes
    transcript_count: int
    transcript_digest: bytes
    pcc_leaves: tuple[_ReplayPCCLeaf, ...]
    memo_leaves: tuple[_ReplayMemoLeaf, ...]
    late_invalidations: tuple[object, ...]
    terminal_predecessor: _ProjectionPredecessor
    administrative_visits: int
    semantic_prefix_visits: int
    report_bytes: bytes
    prefix_sha256: str
```

- Exact function signature: `_compute_replay(snapshot: _ReplayInputSnapshot) -> _ReplayComputation`.

Plan-gap resolutions approved before implementation:

- `active_duplicate` and `terminal_observation` are projection-local derived
  facts, not freeze-time external authority. Add one private values-only helper
  in `correlation/pcc.py` that rebinds those exact optional observations onto a
  detached `_FrozenPCCCorrelationInput`, recomputes its context canonical bytes
  and facts digest, and performs no issuance/global-registry query. Compute
  derives the observations from its private SQLite state before calling
  `_correlate_frozen_pcc`.
- Split `incident_from_verified_falco` into its unchanged issued compatibility
  wrapper plus one private values-only body over exact decoded Falco/record
  scalars. Pure compute calls only the values body; it does not construct or
  consult `AuthenticatedFalcoInput` authority.
- `prefix_sha256` is the existing logical `_v2_snapshot_hash(connection)`, not
  a hash of SQLite file-layout bytes. `report_bytes` is domain-separated
  canonical typed bytes that bind every computation field except itself,
  including the database-image digest, schema/generation, transcript, leaf and
  invalidation facts, terminal predecessor, counters, and logical prefix hash.
  `administrative_visits` is incremented in the actual bounded processing
  loops, never reconstructed post hoc from output lengths. Semantic visits are
  the honest sum of independent project and validation reductions: 20 at
  `P=4`, 72 at `P=8`.

- [ ] **Step 1: Write RED pure-compute boundary tests**

```python
def test_compute_accepts_only_frozen_value_snapshot() -> None:
    snapshot = build_complete_replay_input_snapshot()
    computation = _compute_replay(snapshot)
    assert type(computation) is _ReplayComputation
    assert callable_fields(snapshot) == ()
    assert live_authority_fields(snapshot) == ()
    with pytest.raises(TypeError):
        _compute_replay(replace(snapshot, source=live_segment_store()))


def test_compute_is_deterministic_and_does_not_mutate_live_projection() -> None:
    snapshot, owner = build_snapshot_and_empty_owner()
    before = owner.logical_snapshot_hash()
    first = _compute_replay(snapshot)
    second = _compute_replay(snapshot)
    assert first == second
    assert owner.logical_snapshot_hash() == before
```

Add parity cases for direct investigation, safe candidate, failed PCC rejection, compact conflict, late critical invalidation, different-host non-invalidation, sequence-range invalidation, non-intersecting window, retry, and transport duplicate.

- [ ] **Step 2: Run new pure-compute nodes and verify RED**

Expected: `_compute_replay` does not exist and current owner mutates SQLite while consulting live authorities/callbacks.

- [ ] **Step 3: Implement local compute-owned projection**

Create a private V2 SQLite connection, load the frozen schema, decode only snapshot record bytes/held descriptors, reduce with `_reduce_historical_coverage_result` and `_correlate_frozen_pcc`, and serialize the resulting database with `sqlite3.Connection.serialize()`. The function body must not accept or import a live store/journal/authority. Return immutable rows/leaves/counters/report facts and close the private connection in `finally`.

- [ ] **Step 4: Run focused GREEN and semantic parity group**

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest -q \
  core/tests/evidence/test_projection_replay_boundary.py::test_compute_accepts_only_frozen_value_snapshot \
  core/tests/evidence/test_projection_replay_boundary.py::test_compute_is_deterministic_and_does_not_mutate_live_projection \
  core/tests/evidence/test_projection_pcc.py::test_direct_investigation_incident_waits_only_for_no_pcc \
  core/tests/evidence/test_projection_pcc.py::test_completed_safe_pcc_persists_candidate_and_primary_evidence \
  core/tests/evidence/test_projection_pcc.py::test_late_critical_coverage_inclusively_invalidates_completed_candidate \
  core/tests/evidence/test_projection_pcc.py::test_fresh_unpublished_replay_reproduces_late_invalidation_rows_and_hash \
  core/tests/evidence/test_projection_pcc.py::test_unpublished_compact_history_preserves_prefix_conflicts
```

- [ ] **Step 5: Static check and commit**

```bash
.venv/bin/ruff check core/agmind_immune/evidence/projection_v2.py core/agmind_immune/coverage/historical.py core/agmind_immune/correlation/pcc.py core/tests/evidence/test_projection_replay_boundary.py core/tests/evidence/test_projection_pcc.py
.venv/bin/mypy core/agmind_immune/evidence/projection_v2.py core/agmind_immune/coverage/historical.py core/agmind_immune/correlation/pcc.py
git diff --check
git add core/agmind_immune/evidence/projection_v2.py core/agmind_immune/coverage/historical.py core/agmind_immune/correlation/pcc.py core/tests/evidence/test_projection_replay_boundary.py core/tests/evidence/test_projection_pcc.py
git commit -m "refactor(core): compute replay from frozen facts"
```

---

### Task 6: Freeze → compute → validate/publish orchestration

**Files:**
- Modify: `core/agmind_immune/evidence/projection_v2.py:380-430,1268-2250,2254-3905,4800-4900`
- Modify: `core/agmind_immune/evidence/segments.py`
- Modify: `core/agmind_immune/ingest/ack_journal.py`
- Modify: `core/agmind_immune/ingest/correlation_journal.py`
- Modify: `core/agmind_immune/correlation/authority.py`
- Modify: `core/agmind_immune/correlation/pcc.py`
- Modify: `core/tests/ingest/test_correlation_journal.py`
- Modify: `core/tests/evidence/test_projection_replay_boundary.py`
- Modify: `core/tests/evidence/test_projection_pcc.py`

**Interfaces:**

```python
class _ReplayPhase(StrEnum):
    IDLE = "idle"
    FREEZING = "freezing"
    COMPUTING = "computing"
    VALIDATING = "validating"
    PUBLISHED = "published"
    FAILED = "failed"


class _ReplayFaultPhase(StrEnum):
    FREEZE = "freeze"
    COMPUTE = "compute"
    PUBLISH = "publish"


@dataclass(frozen=True, slots=True)
class _ReplayStatus:
    generation: int
    phase: _ReplayPhase
    reservation_present: bool


@dataclass(frozen=True, slots=True)
class _ReplayReservation:
    token: object
    base_generation: int
    publish_generation: int
    through_key: tuple[str, str, int, int, str, str, int, str]


@dataclass(frozen=True, slots=True)
class _CompletedPCCReplayFacts:
    ref_key: tuple[str, str, int, int, str, str, int, str]
    state_canonical: bytes
    state_fields_set: frozenset[str]
    operation_key: str
    request_sha256: str
    proof_canonical: bytes
    request_canonical: bytes
    request_fields_set: frozenset[str]
    snapshot_canonical: bytes
    snapshot_fields_set: frozenset[str]


@dataclass(frozen=True, slots=True)
class _CorrelationJournalReplaySnapshot:
    journal_lifecycle: object
    store_lifecycle: object
    mutation_revision: object
    verifier_generation: int
    journal_device: int
    journal_inode: int
    journal_size: int
    journal_digest: bytes
    journal_record_count: int
    journal_chain_head: bytes
    completed_facts: tuple[_CompletedPCCReplayFacts, ...]
```

- Exact owner status signature: `_V2ProjectionOwner._replay_status_for_test() -> _ReplayStatus`.
- Exact journal signatures: `_correlation_journal_replay_gate(journal: CorrelationRequestJournal) -> Iterator[None]`, `_capture_correlation_journal_replay_locked(journal: CorrelationRequestJournal, *, through_sequence: int) -> tuple[_CorrelationJournalReplaySnapshot, tuple[AuthenticatedPCCInput, ...]]`, and `_revalidate_correlation_journal_replay_locked(journal: CorrelationRequestJournal, snapshot: _CorrelationJournalReplaySnapshot) -> None`.
- Replace `_ReplayInputSnapshot.projection_generation` with exact `base_projection_generation: int` and `publish_generation: int`. Require `publish_generation == base_projection_generation + 1`; validate the frozen correlation predecessor at the base generation and build the computation/report terminal predecessor at the publish generation.
- Exact pure PCC signatures: `_freeze_replay_pcc_seed(proof: AuthenticatedPCCInput, *, detector_bundle_sha256: str, registry: SpecialUseRegistry, registry_facts_canonical: bytes) -> _FrozenPCCCorrelationInput` and `_rebind_frozen_pcc_projection_context(input: _FrozenPCCCorrelationInput, coverage: HistoricalCoverageAssessment | None, active_duplicate: ActiveCandidateObservation | None, terminal_observation: TerminalCandidateObservation | None) -> _FrozenPCCCorrelationInput`.
- Exact hydration signature: `_validate_and_hydrate_replay(snapshot: _ReplayInputSnapshot, computation: _ReplayComputation) -> tuple[sqlite3.Connection, _UnpublishedV2ReplayReport]`.

The journal snapshot is validation-only and never enters `_compute_replay`; only its immediately detached PCC seeds enter `_ReplayInputSnapshot`. Capture all completed PCC proofs through the strict terminal in deterministic source order. Final revalidation compares the exact mutation revision, lifecycle/store/verifier generation, durable inode/size/digest/chain/count, completed indexes and every canonical PCC fact while the journal lock remains held through publication.

Production uses replay status internally; tests only poll immutable status under `_replay_state_lock` and never inject a callback. `_ReplayFaultPhase | None` is finite data accepted by the private replay entry and supplied only from its test wrapper/tests; it raises `KeyboardInterrupt` after complete freeze, at compute entry, or after final revalidation before live mutation, never by calling injected code. The status lock is separate from `_mutex`, so lock-held `VALIDATING` remains observable.

- [ ] **Step 1: Write RED journal-snapshot, PCC-seed and generation tests**

```python
def test_correlation_journal_replay_snapshot_rejects_real_completed_writer() -> None:
    journal, terminal = completed_journal_fixture()
    with _correlation_journal_replay_gate(journal):
        snapshot, proofs = _capture_correlation_journal_replay_locked(
            journal,
            through_sequence=terminal.source_sequence,
        )
    complete_another_request_through_public_journal_api(journal)
    with _correlation_journal_replay_gate(journal), pytest.raises(
        CorrelationRequestJournalAuthorityError
    ):
        _revalidate_correlation_journal_replay_locked(journal, snapshot)
    assert proofs


def test_replay_pcc_seed_binds_only_compute_owned_coverage() -> None:
    seed, reduction, expected = replay_seed_fixture()
    assert seed.context.coverage is None
    rebound = _rebind_frozen_pcc_projection_context(
        seed,
        reduction.timeline.assessment,
        None,
        None,
    )
    assert _correlate_frozen_pcc(rebound) == expected


def test_compute_replay_uses_base_and_next_publish_generation() -> None:
    snapshot = build_complete_replay_input_snapshot(
        base_projection_generation=7,
        publish_generation=8,
    )
    computation = _compute_replay(snapshot)
    assert snapshot.correlation.predecessor.generation == 7
    assert computation.terminal_predecessor.generation == 8
```

- [ ] **Step 2: Run the three RED nodes**

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest -q \
  core/tests/ingest/test_correlation_journal.py::test_correlation_journal_replay_snapshot_rejects_real_completed_writer \
  core/tests/evidence/test_projection_replay_boundary.py::test_replay_pcc_seed_binds_only_compute_owned_coverage \
  core/tests/evidence/test_projection_replay_boundary.py::test_compute_replay_uses_base_and_next_publish_generation
```

Expected: missing journal gate/snapshot, seed rebind and split-generation contracts.

- [ ] **Step 3: Implement values-only completed-PCC freeze and pure coverage rebind**

The fixed nesting is:

```text
owner._mutex
  -> SegmentStore._source_gate
  -> AckJournal._retention_lock
  -> correlation binding.lock
  -> _ISSUED_AUTHORITIES_LOCK
  -> CorrelationRequestJournal._lock
```

Make `_correlation_projection_snapshot_gate` hold the reentrant issued-authority lock across its yield. The journal is deepest; never acquire journal then correlation binding. Journal capture authenticates exact completed states/proofs without any supplied callable and returns issued proofs only as an ephemeral second return value. Freeze those proofs immediately with the live registry/pins held by the correlation binding, retain only detached seeds, and discard every issued proof reference before releasing locks. Do not construct a completed-batch authority or register a correlation context.

For a complete proof `_freeze_replay_pcc_seed` builds a detached raw context with exact detector, parsed registry and duplicate key but `coverage=None`; failed proofs use `CorrelationContext.failed_snapshot()`. `_rebind_frozen_pcc_projection_context` requires exact computed coverage for complete proofs and `None` for failed proofs, rebinds projection-local observations, and recomputes canonical context/facts without issuance or global-registry lookup. Remove the pre-rebind `context.coverage != reduction.timeline.assessment` rejection from `_compute_replay`; keep exact detector and lookup-key checks.

- [ ] **Step 4: Run focused primitive GREEN and commit**

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest -q \
  core/tests/ingest/test_correlation_journal.py::test_correlation_journal_replay_snapshot_rejects_real_completed_writer \
  core/tests/evidence/test_projection_replay_boundary.py::test_replay_pcc_seed_binds_only_compute_owned_coverage \
  core/tests/evidence/test_projection_replay_boundary.py::test_compute_replay_uses_base_and_next_publish_generation \
  core/tests/evidence/test_projection_pcc.py::test_compute_projection_parity_scenarios
.venv/bin/ruff check core/agmind_immune/ingest/correlation_journal.py core/agmind_immune/correlation/authority.py core/agmind_immune/correlation/pcc.py core/agmind_immune/evidence/projection_v2.py core/tests/ingest/test_correlation_journal.py core/tests/evidence/test_projection_replay_boundary.py core/tests/evidence/test_projection_pcc.py
.venv/bin/mypy core/agmind_immune/ingest/correlation_journal.py core/agmind_immune/correlation/authority.py core/agmind_immune/correlation/pcc.py core/agmind_immune/evidence/projection_v2.py
git diff --check
git add core/agmind_immune/ingest/correlation_journal.py core/agmind_immune/correlation/authority.py core/agmind_immune/correlation/pcc.py core/agmind_immune/evidence/projection_v2.py core/tests/ingest/test_correlation_journal.py core/tests/evidence/test_projection_replay_boundary.py core/tests/evidence/test_projection_pcc.py
git commit -m "feat(core): freeze completed PCC replay facts"
```

- [ ] **Step 5: Write RED sanctioned-writer, reservation and cleanup tests**

```python
@pytest.mark.parametrize(
    "writer",
    ["append", "retention", "ack", "correlation_authority", "journal"],
)
def test_snapshot_revision_change_before_validate_rejects_no_report(writer: str) -> None:
    owner, worker = start_existing_owner_replay_with_real_fixture()
    wait_until_status(owner, _ReplayPhase.COMPUTING)
    perform_real_public_writer(writer)
    with pytest.raises(ProjectionAuthorityError):
        finish_replay(worker)
    assert owner._generation == original_generation()
    assert no_projection_artifact_was_published(owner)


@pytest.mark.parametrize(
    "writer",
    ["append", "retention", "ack", "correlation_authority", "journal"],
)
def test_writer_started_during_validate_publish_cannot_make_mixed_report(writer: str) -> None:
    owner, worker = start_existing_owner_replay_with_real_fixture()
    wait_until_status(owner, _ReplayPhase.VALIDATING)
    blocked_writer = start_real_public_writer(writer)
    assert_writer_is_blocked(blocked_writer)
    report = finish_replay(worker)
    assert report == literal_pre_snapshot_report()
    assert_writer_completed_after_publish(blocked_writer)


@pytest.mark.parametrize("phase", ["freeze", "compute", "publish"])
def test_baseexception_at_replay_phase_cleans_fds_reservation_and_generation(phase: str) -> None:
    owner, through = build_owner_with_fault_phase(phase)
    with pytest.raises(KeyboardInterrupt):
        owner._replay_unpublished_prefix(
            through,
            _factory=_UNPUBLISHED_REPLAY_FACTORY,
            _fault_phase=_ReplayFaultPhase(phase),
        )
    assert owner._replay_status_for_test().reservation_present is False
    assert owner._generation == original_generation()
    assert all_snapshot_fds_closed(owner)
    assert no_projection_artifact_was_published(owner)
```

- [ ] **Step 6: Run and verify orchestration RED**

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest -q \
  core/tests/evidence/test_projection_replay_boundary.py::test_snapshot_revision_change_before_validate_rejects_no_report \
  core/tests/evidence/test_projection_replay_boundary.py::test_writer_started_during_validate_publish_cannot_make_mixed_report \
  core/tests/evidence/test_projection_replay_boundary.py::test_baseexception_at_replay_phase_cleans_fds_reservation_and_generation
```

Expected: current nested source/ACK/correlation callback protocol cannot expose immutable status, cannot perform out-of-lock compute, and leaks the old replay private model into orchestration.

- [ ] **Step 7: Rewrite `_replay_unpublished_prefix` into three phases**

Add `_replay_state_lock`, `_replay_reservation` and `_replay_status` to `_V2ProjectionOwner`. Install the exact reservation under `_mutex -> _replay_state_lock`, capture the source/ACK/correlation/journal snapshots and detached seeds under the fixed lock order, then release every authority lock and `_mutex`. All other owner operations acquire `_mutex -> _replay_state_lock` and reject the reservation while compute is active.

Set `COMPUTING` only after freeze locks release. Call `_compute_replay(snapshot)`, then call `_validate_and_hydrate_replay` before final locks. Hydration reconstructs `report_bytes`, deserializes into a fresh private SQLite connection, verifies exact schema/integrity/cursor/terminal predecessor/logical hash/transcript count/invalidation rows/source terminal, and preconstructs `_UnpublishedV2ReplayReport`. It calls no live owner, historical session, batch evaluator, `_issue_correlation_context`, `_apply_prepared`, or replay hook.

Reacquire the full lock order and set `VALIDATING` only after the journal lock is held. Revalidate every snapshot and exact reservation. Raise the finite publish fault before live mutation. Close source/ACK descriptors and the original empty connection, call `_rebuild_correlation_projection_authority(authority, computation.terminal_predecessor)`, then perform only non-throwing assignments of the hydrated connection, publish generation and `PUBLISHED` status. A max-generation owner fails before reservation installation.

One outer `finally` preserves the primary `BaseException`, closes an unpublished hydrated connection, closes any still-owned ACK/source descriptors, then clears the exact reservation last and records `FAILED(base_generation, False)` if publication did not complete. Attach cleanup failures as notes. Capture helpers retain their own partial-construction cleanup.

Delete replay handle/access/event/state-seal imports and plumbing, nested `under_ack_guard`/`under_correlation_guard`, source terminal callback, `terminal_external_authority_check`, returned `final_authority_check`, the replay-only `_issue_completed_snapshot_batch`/item/seal/revoke authority family and replay-path `_step_hook` calls. Remove their journal unit tests. Preserve ordinary V2 `_evaluate_completed_snapshot_batch`, `_issue_correlation_context`/`_IssuedContextBinding` compatibility, active V1 and dormant V2 entry points.

- [ ] **Step 8: Run focused concurrency/cleanup GREEN**

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest -q \
  core/tests/evidence/test_projection_replay_boundary.py::test_snapshot_revision_change_before_validate_rejects_no_report \
  core/tests/evidence/test_projection_replay_boundary.py::test_writer_started_during_validate_publish_cannot_make_mixed_report \
  core/tests/evidence/test_projection_replay_boundary.py::test_baseexception_at_replay_phase_cleans_fds_reservation_and_generation \
  core/tests/evidence/test_projection_pcc.py::test_unpublished_replay_failure_returns_no_artifact_and_closes_resources \
  core/tests/evidence/test_projection_pcc.py::test_unpublished_final_seal_binds_authenticated_retired_ranges
```

Rewrite the two legacy nodes in this command to use a real public journal/retention writer and status barrier; do not retain `_step_hook`, private-range mutation or terminal callback injection.

- [ ] **Step 9: Run post-orchestration semantic/crash slice**

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest -q \
  core/tests/evidence/test_projection_pcc.py::test_late_sequence_range_invalidates_despite_later_report_timestamp \
  core/tests/evidence/test_projection_pcc.py::test_nonintersecting_late_window_and_range_do_not_invalidate \
  core/tests/evidence/test_projection_pcc.py::test_late_invalidation_survives_close_event_and_exact_retry \
  core/tests/evidence/test_projection_pcc.py::test_transport_duplicate_late_coverage_is_idempotent \
  core/tests/evidence/test_projection_pcc.py::test_complete_pcc_without_completed_journal_rolls_back_event_and_cursor \
  core/tests/evidence/test_projection_pcc.py::test_invalidation_write_crash_rolls_back_coverage_event_and_cursor \
  core/tests/evidence/test_projection_pcc.py::test_candidate_write_crash_points_roll_back_and_retry_exactly
```

- [ ] **Step 10: Static check and commit**

```bash
.venv/bin/ruff check core/agmind_immune/evidence/projection_v2.py core/agmind_immune/evidence/segments.py core/agmind_immune/ingest/ack_journal.py core/agmind_immune/ingest/correlation_journal.py core/agmind_immune/correlation/authority.py core/agmind_immune/correlation/pcc.py core/tests/ingest/test_correlation_journal.py core/tests/evidence/test_projection_replay_boundary.py core/tests/evidence/test_projection_pcc.py
.venv/bin/mypy core/agmind_immune/evidence/projection_v2.py core/agmind_immune/evidence/segments.py core/agmind_immune/ingest/ack_journal.py core/agmind_immune/ingest/correlation_journal.py core/agmind_immune/correlation/authority.py core/agmind_immune/correlation/pcc.py
git diff --check
git add core/agmind_immune/evidence/projection_v2.py core/agmind_immune/evidence/segments.py core/agmind_immune/ingest/ack_journal.py core/agmind_immune/ingest/correlation_journal.py core/agmind_immune/correlation/authority.py core/agmind_immune/correlation/pcc.py core/tests/ingest/test_correlation_journal.py core/tests/evidence/test_projection_replay_boundary.py core/tests/evidence/test_projection_pcc.py
git commit -m "refactor(core): publish replay after exact revalidation"
```

---

### Task 7: Retire false TCB tests and run the single boundary gate

**Files:**
- Modify: `core/tests/evidence/test_projection_pcc.py`
- Delete: `core/tests/evidence/test_historical_path.py`
- Modify: `core/tests/evidence/test_projection_replay_boundary.py`
- Modify: `docs/superpowers/progress/2026-07-27-proof-carrying-containment-progress.md`

**Interfaces:**
- Consumes: completed Task 1-6 implementation and immutable replay diagnostics/status.
- Produces: a focused supported-boundary test surface and one exact controller cap gate.

- [ ] **Step 1: Remove/reclassify exhausted private-TCB tests**

Delete tests whose only claim is survival after module enumeration/replacement, private replay session construction, copied-context private dispatch, `object.__setattr__` during trusted execution, or executable hooks under locks. Preserve their supported-boundary intent in the Task 1-6 nodes for hostile serialized inputs, wrong-store/stale snapshots, public writers, cleanup, and exact counters. Do not retain source-text assertions saying old private symbols are absent.

- [ ] **Step 2: Add the single controller-owned cap node**

```python
def test_controller_late_candidate_limit_4096_accepts_4097_fails_closed() -> None:
    accepted = build_controller_replay_with_authenticated_pcc_count(4096)
    accepted_report = accepted.run_public_replay()
    assert accepted_report is not None
    assert accepted_report.pcc_count == 4096
    assert accepted.projection_cursor == accepted.evidence_cursor

    rejected = build_controller_replay_with_authenticated_pcc_count(4097)
    assert rejected.run_public_replay() is None
    assert rejected.projection_cursor is None
    assert rejected.has_partial_projection_artifact() is False
```

The fixture uses real authenticated records and production limits. It does not patch the cap, connection, fsync, reducer, or descriptors.

- [ ] **Step 3: Run all non-boundary focused Task 7B nodes once**

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest -q \
  core/tests/evidence/test_projection_replay_boundary.py \
  core/tests/coverage/test_historical.py::test_historical_and_live_reducers_share_the_exact_classifier \
  core/tests/coverage/test_historical.py::test_historical_conflict_matrix \
  core/tests/evidence/test_projection_pcc.py::test_completed_safe_pcc_persists_candidate_and_primary_evidence \
  core/tests/evidence/test_projection_pcc.py::test_fresh_unpublished_replay_reproduces_late_invalidation_rows_and_hash \
  core/tests/evidence/test_projection_pcc.py::test_unpublished_compact_history_preserves_prefix_conflicts \
  core/tests/evidence/test_projection_pcc.py::test_late_invalidation_survives_close_event_and_exact_retry \
  core/tests/evidence/test_projection_pcc.py::test_candidate_write_crash_points_roll_back_and_retry_exactly
```

Expected: all focused nodes pass with no warnings. Do not include the 4,096/4,097 node in this command.

- [ ] **Step 4: Static final gate and commit test-surface cleanup**

```bash
.venv/bin/ruff check core/agmind_immune core/tests/evidence/test_projection_replay_boundary.py core/tests/evidence/test_projection_pcc.py core/tests/coverage/test_historical.py
.venv/bin/mypy core/agmind_immune/coverage/historical.py core/agmind_immune/evidence/segments.py core/agmind_immune/ingest/ack_journal.py core/agmind_immune/correlation/authority.py core/agmind_immune/correlation/pcc.py core/agmind_immune/evidence/projection_v2.py
git diff --check
git add core/tests/evidence/test_projection_pcc.py core/tests/evidence/test_historical_path.py core/tests/evidence/test_projection_replay_boundary.py docs/superpowers/progress/2026-07-27-proof-carrying-containment-progress.md
git commit -m "test(core): align replay gates with process trust boundary"
```

- [ ] **Step 5: Request two independent read-only reviews**

Reviewer A verifies spec coverage, pure-compute type boundary, exact revision/fact comparison, cleanup, and active V1 dormancy. Reviewer B verifies concurrency/liveness, descriptor ownership, no callback under trusted locks, real 4/8 counter accounting, and that removed tests asserted only TCB compromise. Neither reviewer reruns the reported focused group.

- [ ] **Step 6: Run the genuine boundary exactly once after both reviews approve**

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest -q \
  core/tests/evidence/test_projection_replay_boundary.py::test_controller_late_candidate_limit_4096_accepts_4097_fails_closed
```

Expected: one node passes; its internal first case publishes a coherent 4,096-PCC report and its independent second case rejects 4,097 with no partial artifact or cursor advance. Do not repeat this command after a clean run.

- [ ] **Step 7: Record Task 7B completion**

Append exact commits, focused counts, review verdicts, boundary runtime/result, active V1 hashes, and remaining concerns to the progress ledger. Task 8 may start only after this line is committed and the worktree is clean.
