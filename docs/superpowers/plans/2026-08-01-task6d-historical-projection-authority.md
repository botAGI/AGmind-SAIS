# Task 6D historical coverage and Projection V2 implementation plan

> **Execution rule:** implement each task RED -> focused GREEN -> review ->
> commit. Do not run repo-wide or native Linux suites inside the inner loop.

**Goal:** turn completed, authenticated PCC snapshots into deterministic,
rebuildable Projection V2 candidates with historical coverage proofs,
append-only late invalidation, and a fresh controller-owned admission
capability.

**Design:**
[`2026-08-01-task6d-historical-projection-authority-design.md`](../specs/2026-08-01-task6d-historical-projection-authority-design.md)

**Baseline:** 6C is complete at `ef40b64`; the same-root compatibility sweep is
complete at `1ee711f`.

## Locked execution invariants

- A public model or raw `CorrelationContext` never creates candidate authority.
- A complete PCC without one exact completed correlation-journal state is not
  projected as a candidate.
- Historical coverage and live mutation readiness remain separate domains and
  hashes.
- One source event, all of its reducer rows, and the cursor commit atomically.
- Candidate bytes never change; later gaps only append invalidations.
- An invalidated candidate remains the duplicate primary.
- V1 rows are never migrated or copied into V2.
- Admission requires all four cursors equal under `CoreController._lock` and is
  stale after any generation/cursor/lifecycle change.

## Task 1 — Lock full candidate hashes and immutable pin bindings

**Files**

- Modify: `core/agmind_immune/canonicaljson.py`
- Modify: `core/agmind_immune/correlation/primitives.py`
- Modify: `core/tests/test_contract_regressions.py`
- Modify: `core/tests/correlation/test_primitives.py`
- Modify: `core/tests/correlation/test_pcc_capability.py`

### RED

Add one locked `candidate_facts_sha256` vector and a table proving every
`ContainmentCandidateV1` field changes the full-facts hash. Keep the existing
candidate-ID vector unchanged and prove that same-ID candidates with changed
TTL, port, image, or coverage have different full-facts hashes.

Add an issued-registry mutation matrix that changes `entries` and `_index` via
`object.__setattr__`; `special_use_registry_is_issued()` must then return false.
Copy/pickle/non-issued parsed registries must also fail.

Run and confirm RED:

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest \
  core/tests/test_contract_regressions.py \
  core/tests/correlation/test_primitives.py \
  core/tests/correlation/test_pcc_capability.py -q
```

### GREEN

Implement exactly:

```text
candidate_facts_sha256 = hex(SHA256(
  "AGMIND_CANDIDATE_FACTS_V1\0" || canonical_json(candidate)
))
```

Replace the registry identity-only `WeakSet` with a weak-key canonical binding
over exact entries and index; recheck the binding at every authority use.

Focused quality gate:

```bash
.venv/bin/ruff check \
  core/agmind_immune/canonicaljson.py \
  core/agmind_immune/correlation/primitives.py \
  core/tests/test_contract_regressions.py \
  core/tests/correlation/test_primitives.py \
  core/tests/correlation/test_pcc_capability.py
.venv/bin/mypy \
  core/agmind_immune/canonicaljson.py \
  core/agmind_immune/correlation/primitives.py
git diff --check
```

Commit:

```bash
git add core/agmind_immune/canonicaljson.py \
  core/agmind_immune/correlation/primitives.py \
  core/tests/test_contract_regressions.py \
  core/tests/correlation/test_primitives.py \
  core/tests/correlation/test_pcc_capability.py
git commit -m "fix(core): bind immutable correlation pins"
```

## Task 2 — Build the bounded historical coverage reducer

**Files**

- Create: `core/agmind_immune/coverage/grammar.py`
- Create: `core/agmind_immune/coverage/historical.py`
- Create: `core/agmind_immune/evidence/dedup.py`
- Create: `core/tests/coverage/test_grammar.py`
- Create: `core/tests/coverage/test_historical.py`
- Create: `core/tests/evidence/test_dedup.py`
- Create: `core/tests/evidence/test_historical_path.py`
- Modify: `core/agmind_immune/coverage/__init__.py`
- Modify: `core/agmind_immune/coverage/state.py`
- Modify: `core/agmind_immune/correlation/pcc.py`
- Modify: `core/agmind_immune/evidence/projection.py`
- Modify: `core/agmind_immune/evidence/segments.py`
- Modify: `core/tests/coverage/test_state.py`
- Modify: `core/tests/correlation/test_pcc.py`
- Modify: `core/tests/evidence/test_pcc_retention_restart.py`

Implement this task as two reviewed commits: 2A locks the shared grammar,
nanosecond/window model, and boot scope; 2B adds V2 logical-primary identity,
the store-bound path capability, target-specific reducer, and hash.

### RED

Write locked tests for:

- RFC3339Nano parse/format round trips at 0/1/6/9 fractional digits and years
  0001/9999, plus `window_start` year underflow and
  `window_end < window_start` as deterministic incomplete assessments;
- nullable `HistoricalCoverageAssessment.window_start` only for underflow,
  with incomplete/critical/hash invariants locked in `test_pcc.py`;
- inclusive window intersections at both exact boundaries;
- exact frozen hash vectors for empty clean history, an open interval with
  absent optional keys, a closed self-contained interval, and a pre-trigger
  cumulative episode that includes earliest-open/latest-effective-update/close
  IDs while excluding intermediate updates;
- a multi-interval vector locking canonical optional-key omission, interval
  sort order, coverage-event ID sort/dedup, and structural-gap endpoint IDs;
- Docker open/recovery, sequence-gap open/close, exact Falco
  open/update/close, closed critical point, and self-contained close;
- every Falco per-kind reason/counter form, legal heartbeat/config reason
  transitions, strict counter growth, lawful `MAX_UINT64 -> MAX_UINT64`, and
  rejection of equality below maximum, count disappearance, or count on an
  uncounted kind;
- exact persistent `observer_spool_drop` and proof that its INFO pressure
  recovery point has the full fixed wire form and cannot close lost evidence;
- exact `docker_logging_visibility_degraded` WARNING wire form is accepted as
  non-critical/no-op; malformed variants fail validation;
- an actual boot-ID change clears only process-local Falco episodes; same-boot
  key rotation clears nothing, while sequence, Docker, and permanent observer
  gaps survive;
- a closed sequence gap whose timestamp misses the window but affected range
  overlaps `[trigger,S-1]` and therefore still reports a critical gap;
- V1 dedup vectors remain byte-identical, V2 vectors bind `boot_id`, and exact
  prior-boot sensor bytes are distinct V2 primaries;
- logical-primary transport replay versus cumulative primary update, plus
  second-close/reopen detection through the bounded prefix-status oracle;
- a pre-trigger open interval that overlaps the trigger window;
- structural path coverage by surviving refs plus authenticated retired ranges;
- terminal anchoring at the live protected PCC `S`, including a retired
  routine `S-1` and retired routine trigger whose identity remains bound by the
  retained PCC request/snapshot;
- path capability mutation/copy/pickle/cross-store/restart/retention-drift and
  raw retired-range tuple rejection;
- an open structural sequence gap producing `complete=false`, no hash, and
  `critical_gap=false`;
- independent 4,096/4,097 no-truncation cases for interval IDs,
  coverage-event IDs, active episodes, recent path events, recent primary IDs,
  and pre-trigger summaries, without a lifetime episode/tombstone collection;
- backwards, ambiguous, and unmatched closes; immutable key/non-Falco opening
  reason changes; counter rollback; and INFO/WARNING records that cannot open
  critical episodes;
- a sequence-gap close whose coverage IDs include its exact gap endpoints,
  matched Docker open/recovery, and prior baseline pair when present;
- a parity assertion that live and historical paths invoke the same strict
  coverage record classifier;
- proof-path and assessment stability when the routine trigger is retired.

Run and confirm RED:

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest \
  core/tests/coverage/test_grammar.py \
  core/tests/coverage/test_historical.py \
  core/tests/coverage/test_state.py \
  core/tests/correlation/test_pcc.py \
  core/tests/evidence/test_dedup.py \
  core/tests/evidence/test_historical_path.py \
  core/tests/evidence/test_pcc_retention_restart.py::test_historical_path_survives_routine_trigger_retirement \
  -q
```

### GREEN

Implement immutable internal facts:

```text
HistoricalCoverageRecord
HistoricalCriticalEpisode
HistoricalCoverageTimeline
HistoricalPathAuthority
HistoricalCoverageUnavailable
HistoricalCoverageConflict
```

Extract only the strict coverage record classifier shared with live
`CoverageState`; keep historical episode retention separate from live
`MutationReadiness`. The classifier uses the exact per-kind Falco grammar from
the design and scopes process-local episodes by real `boot_id` changes. It uses
integer nanosecond comparisons throughout; do not reuse the current
microsecond `datetime` ordering for historical facts.

Extract neutral frozen V1/V2 logical-primary helpers into `evidence/dedup.py`.
Calling the V1 helper from active Projection V1 must be byte-for-byte behavior
preserving. Historical coverage calls only V2, whose key includes `boot_id`;
the dormant V2 projection will use the same helper.

Retain bounded active summaries, target-intersecting pre-trigger summaries,
recent primaries, path facts, and final hash inputs. Completed irrelevant
lifetime episodes are discarded. A private logical-primary/episode-prefix
oracle detects replay, second close, and reopen without a lifetime in-memory
set; production binds that oracle to source-order V2 construction or a fully
revalidated V2 prefix.

`HistoricalPathAuthority` is factory-only, non-copyable/non-serializable, and
issued only by the exact recovered `SegmentStore` for an issued
`AuthenticatedPCCInput`. It is not exported from `coverage.__init__`. Recheck
its complete weak-key binding at every use. The pure hash function may accept
exact internal values for locked tests; only Task 4 can combine its result with
the completed-journal and correlation authorities.

#### 2A focused quality gate and commit

```bash
.venv/bin/ruff check \
  core/agmind_immune/coverage/grammar.py \
  core/agmind_immune/coverage/state.py \
  core/agmind_immune/correlation/pcc.py \
  core/tests/coverage/test_grammar.py \
  core/tests/coverage/test_state.py \
  core/tests/correlation/test_pcc.py
.venv/bin/mypy \
  core/agmind_immune/coverage/grammar.py \
  core/agmind_immune/coverage/state.py \
  core/agmind_immune/correlation/pcc.py
git diff --check
git add core/agmind_immune/coverage/grammar.py \
  core/agmind_immune/coverage/state.py \
  core/agmind_immune/correlation/pcc.py \
  core/tests/coverage/test_grammar.py \
  core/tests/coverage/test_state.py \
  core/tests/correlation/test_pcc.py
git commit -m "fix(core): normalize historical coverage grammar"
```

#### 2B focused quality gate and commit

```bash
.venv/bin/ruff check \
  core/agmind_immune/coverage/historical.py \
  core/agmind_immune/coverage/__init__.py \
  core/agmind_immune/evidence/dedup.py \
  core/agmind_immune/evidence/projection.py \
  core/agmind_immune/evidence/segments.py \
  core/tests/coverage/test_historical.py \
  core/tests/evidence/test_dedup.py \
  core/tests/evidence/test_historical_path.py \
  core/tests/evidence/test_pcc_retention_restart.py
.venv/bin/mypy \
  core/agmind_immune/coverage/historical.py \
  core/agmind_immune/evidence/dedup.py \
  core/agmind_immune/evidence/projection.py \
  core/agmind_immune/evidence/segments.py
git diff --check
git add core/agmind_immune/coverage/historical.py \
  core/agmind_immune/coverage/__init__.py \
  core/agmind_immune/evidence/dedup.py \
  core/agmind_immune/evidence/projection.py \
  core/agmind_immune/evidence/segments.py \
  core/tests/coverage/test_historical.py \
  core/tests/evidence/test_dedup.py \
  core/tests/evidence/test_historical_path.py \
  core/tests/evidence/test_pcc_retention_restart.py
git commit -m "feat(core): derive historical coverage proofs"
```

## Task 3 — Reauthenticate completed correlation delivery

**Files**

- Modify: `core/agmind_immune/ingest/correlation_journal.py`
- Modify: `core/tests/ingest/test_correlation_journal.py`
- Modify: `core/tests/ingest/test_correlation_delivery.py`

### RED

Add tests for a private, opaque completed-proof capability:

- selected and proof-observed states cannot issue it;
- completed state binds exact request hash, request, trigger, snapshot ref,
  snapshot content, same store, journal lifecycle, and current journal bytes;
- direct PCC acceptance without journal state cannot issue it;
- different ref/content/request, mutation, copy, pickle, close, and restart-old
  lifecycle fail;
- recovery issues a new capability for the byte-identical completed state;
- ambiguous/corrupt journal state never returns a partial result.

Run and confirm RED:

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest \
  core/tests/ingest/test_correlation_journal.py \
  core/tests/ingest/test_correlation_delivery.py -q
```

### GREEN

Add an internal `completed_for_snapshot(ref)` issuer. It must reissue and
validate `AuthenticatedPCCInput` through the same store/verifier before
returning a non-copyable, non-serializable capability. Keep `pending()` public
behavior unchanged.

Focused quality gate and commit:

```bash
.venv/bin/ruff check \
  core/agmind_immune/ingest/correlation_journal.py \
  core/tests/ingest/test_correlation_journal.py \
  core/tests/ingest/test_correlation_delivery.py
.venv/bin/mypy core/agmind_immune/ingest/correlation_journal.py
git diff --check
git add core/agmind_immune/ingest/correlation_journal.py \
  core/tests/ingest/test_correlation_journal.py \
  core/tests/ingest/test_correlation_delivery.py
git commit -m "feat(core): reauthenticate completed PCC delivery"
```

## Task 4 — Issue one-use proof-bound correlation contexts

**Files**

- Modify: `Dockerfile`
- Modify: `Makefile`
- Modify: `requirements.txt`
- Create: `core/agmind_immune/correlation/authority.py`
- Create: `core/tests/correlation/test_authority.py`
- Create: `core/tests/correlation/test_authority_image_contract.py`
- Modify: `core/agmind_immune/correlation/pcc.py`
- Modify: `core/agmind_immune/correlation/__init__.py`
- Modify: `core/tests/correlation/test_pcc.py`
- Modify: `core/tests/correlation/test_pcc_capability.py`

### RED

Add a matrix proving that a production context binds:

- the exact issued PCC canonical bytes/ref/content/request;
- the exact completed-journal capability;
- same evidence lifecycle and predecessor projection generation/cursor;
- exact historical assessment, detector pin, special-use registry, duplicate
  observation, and empty terminal observation.

Raw, mutated, copied, pickled, cross-proof, cross-store, after-cursor-advance,
after-rebuild, after-close, and second-use contexts must not create a candidate.
Exact failed PCC behavior remains authority-free and unchanged.

Add fixed detector-loader tests for the one compile-time allowlisted absolute
path `/etc/falco/rules.d/agmind-pcc.yaml`, no symlink following,
regular/single-link file, root ownership,
non-writable root-owned parents, bounded one-shot bytes, inode/stat stability,
and exact `pcc_detector_bundle_sha256()`. Wrong path/type/owner/mode/link count,
oversize, replace-during-read, or read error cannot issue pin authority. Use a
private filesystem adapter only in tests; production has no caller-selected
path.

Lock the deployment contract in `test_authority_image_contract.py`: the
Dockerfile must install the exact repository rule source at the fixed path as
`root:root` mode `0444`, create its parents as `root:root` mode `0755`, and do
so before `USER sais`. It must install dependencies in a root-owned virtual
environment below `/opt` that `sais` can execute, never `/root/.local`.
`requirements.txt` must include every Core production dependency from
`pyproject.toml` at the identical exact version; in particular, loading
`canonicaljson.py` in the runtime image must not rely on a transitive
`cryptography` install.

Run and confirm RED:

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest \
  core/tests/correlation/test_authority.py \
  core/tests/correlation/test_authority_image_contract.py \
  core/tests/correlation/test_pcc.py \
  core/tests/correlation/test_pcc_capability.py -q
```

### GREEN

Create an opaque `CorrelationProjectionAuthority` from fixed-loader pins and
same-store owners. Replace the always-false context validator with a private
weak-key exact binding. Consume the binding atomically inside
`correlate_pcc()`; do not expose a public issuer or sentinel.

Install `deploy/falco/rules.d/agmind-pcc.yaml` in the runtime image at the fixed
path before dropping privileges:

```dockerfile
RUN install -d -o root -g root -m 0755 /etc/falco/rules.d
COPY --chown=0:0 --chmod=0444 deploy/falco/rules.d/agmind-pcc.yaml \
  /etc/falco/rules.d/agmind-pcc.yaml
```

Replace the builder's root-user-site install with a root-owned runtime virtual
environment, copied intact between stages:

```dockerfile
RUN python -m venv /opt/agmind-venv && \
    /opt/agmind-venv/bin/pip install --no-cache-dir -r requirements.txt
COPY --from=builder /opt/agmind-venv /opt/agmind-venv
ENV PATH="/opt/agmind-venv/bin:${PATH}"
```

Synchronize all exact Core production pins from `pyproject.toml` into
`requirements.txt`; preserve the additional legacy app-only dependencies.

Add `make test-core-detector-pin-image`: build the real runtime image, run it
as its configured `sais` user with `--network none --read-only`, invoke the
real fixed detector loader with `PYTHONPATH=/app/core`, and compare the loaded
hash with `pcc_detector_bundle_sha256()` over the repository rule bytes. This
is the deployment integration check; a static Dockerfile assertion alone is
not sufficient.

Strengthen `HistoricalCoverageAssessment` invariants:

```text
complete=false => critical_gap=false and hash absent
complete=true  => exact window_start and hash present
window_start absent => deterministic underflow and complete=false
```

Focused quality gate and commit:

```bash
.venv/bin/ruff check core/agmind_immune/correlation core/tests/correlation
.venv/bin/mypy \
  core/agmind_immune/correlation/authority.py \
  core/agmind_immune/correlation/pcc.py
make test-core-detector-pin-image
git diff --check
git add Dockerfile Makefile requirements.txt \
  core/agmind_immune/correlation/authority.py \
  core/agmind_immune/correlation/__init__.py \
  core/agmind_immune/correlation/pcc.py \
  core/tests/correlation/test_authority.py \
  core/tests/correlation/test_authority_image_contract.py \
  core/tests/correlation/test_pcc.py \
  core/tests/correlation/test_pcc_capability.py
git commit -m "feat(core): issue proof-bound correlation contexts"
```

## Task 5 — Define Projection V2 schema and strict row codecs

**Files**

- Create: `core/agmind_immune/evidence/schema_v1.sql`
- Create: `core/agmind_immune/evidence/schema_v2.sql`
- Create: `core/agmind_immune/evidence/projection_v2.py`
- Create: `core/tests/evidence/test_projection_v2.py`

### RED

Copy the committed V1 DDL byte-for-byte into `schema_v1.sql`, stage the future
DDL in `schema_v2.sql`, then add tests
that demand:

- exact V2 metadata including `AGMIND_PROJECTION_DEDUP_V2`, table set/order,
  DDL, indexes, and snapshot domain;
- V2 uses the Task 2 boot-aware helper for every dedup row and never the
  boot-blind V1 identity;
- full frozen Incident/Candidate column order and round-trip codecs;
- 20-digit uint64, 0/1 Boolean, canonical tuple JSON, closed result/role/reason
  checks, FKs, and no trigger-event FK where retention forbids it;
- candidate full-facts hash revalidation;
- stable logical snapshot ordering for all four new tables;
- schema/row/hash/index mismatch raises `ProjectionConflict`.

Run and confirm RED:

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest \
  core/tests/evidence/test_projection_v2.py \
  core/tests/evidence/test_projection.py \
  tests/replay/test_rebuild.py -q
```

### GREEN

Implement dormant V2 metadata, snapshot domain, table layout, schema verifier,
logical hash helper, and strict row encoders/decoders in `projection_v2.py`.
Tests may construct an in-memory V2 connection through a module-private test
factory.

Do not change active `schema.sql`, `_SCHEMA_PATH`, `_SCHEMA_META`,
`_SNAPSHOT_DOMAIN`, or `_TABLE_LAYOUT` in `projection.py`. Production continues
to create/open exact V1 until the complete V2 reducer and authenticated
activation land together in Task 8. No fresh intermediate database may advance
past a PCC snapshot without security rows.

Focused quality gate and commit:

```bash
.venv/bin/ruff check \
  core/agmind_immune/evidence/projection_v2.py \
  core/tests/evidence/test_projection_v2.py
.venv/bin/mypy core/agmind_immune/evidence/projection_v2.py
git diff --check
git add core/agmind_immune/evidence/schema_v1.sql \
  core/agmind_immune/evidence/schema_v2.sql \
  core/agmind_immune/evidence/projection_v2.py \
  core/tests/evidence/test_projection_v2.py
git commit -m "feat(core): define Projection V2 facts"
```

## Task 6 — Reduce direct incidents and PCC results atomically

**Files**

- Modify: `core/agmind_immune/evidence/projection_v2.py`
- Modify: `core/tests/evidence/test_projection_v2.py`
- Create: `core/tests/evidence/test_projection_pcc.py`

### RED

Test source-order transactions for:

- failed/investigation-only routine Falco -> direct incident only;
- candidate-capable routine Falco -> no incident until PCC;
- completed failed PCC -> rejected proof-backed incident;
- completed safe PCC -> incident + candidate + exact primary trigger/snapshot
  evidence rows;
- authenticated still-open structural gap -> persisted
  `historical_coverage_incomplete` incident and cursor advance, but no candidate;
- structurally complete intersecting episode -> persisted
  `critical_coverage_gap` incident and cursor advance, but no candidate;
- unexplained/provisional/lifecycle/cap/resource authority failure -> raised
  projection error, full transaction rollback, no incident, and no cursor
  advance;
- safely loaded detector hash mismatch -> persisted
  `detector_bundle_not_pinned` incident and cursor advance;
- safely loaded special-use hash mismatch -> persisted
  `correlation_proof_mismatch` incident and cursor advance;
- detector/registry loader unavailable or mutable -> authority error, rollback,
  no incident, and no cursor advance;
- safe duplicate -> new incident + supporting evidence on unchanged primary;
- invalidated primary remains the duplicate target;
- complete PCC with no/mismatched completed journal or absent/mutable Core
  authority -> no cursor;
- the exact authenticated predecessor/correlation-journal/coverage prefix is
  revalidated inside `BEGIN IMMEDIATE` before duplicate observation; a change
  before or during that check rolls back with no rows/cursor;
- same-ID altered candidate facts cannot be inserted;
- every existing `_APPLY_STEPS` crash point plus candidate substeps is all-or-none;
- exact retry/reopen reproduces identical rows and hash.

Run and confirm RED:

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest \
  core/tests/evidence/test_projection_pcc.py \
  core/tests/evidence/test_projection_v2.py -q
```

### GREEN

Implement the dormant V2 source-order reducer in `projection_v2.py`. Reconstruct
the exact request, obtain the completed-journal/PCC capability, derive history
only from the same-store authenticated protected coverage timeline plus exact
authenticated/retired path authority, issue/consume the context, and persist
the result before the cursor in one `BEGIN IMMEDIATE` transaction. Cached
SQLite coverage rows are never historical authority.

Inside that transaction, revalidate the exact predecessor cursor, completed
journal capability, evidence lifecycle, and authenticated path before querying
duplicate state. A pre-transaction validation alone is insufficient.

Exercise the dormant reducer through the module-private V2 test factory. Do not
wire active `ProjectionStore` or `CoreController` before Task 8.

Focused quality gate and commit:

```bash
.venv/bin/ruff check \
  core/agmind_immune/evidence/projection_v2.py \
  core/tests/evidence/test_projection_pcc.py \
  core/tests/evidence/test_projection_v2.py
.venv/bin/mypy core/agmind_immune/evidence/projection_v2.py
git diff --check
git add core/agmind_immune/evidence/projection_v2.py \
  core/tests/evidence/test_projection_v2.py \
  core/tests/evidence/test_projection_pcc.py
git commit -m "feat(core): project authenticated containment candidates"
```

## Task 7 — Append deterministic late invalidations

**Files**

- Modify: `core/agmind_immune/coverage/historical.py`
- Modify: `core/agmind_immune/evidence/projection_v2.py`
- Modify: `core/tests/coverage/test_historical.py`
- Modify: `core/tests/evidence/test_projection_pcc.py`

### RED

Test:

- inclusive backdated interval invalidates all bounded matching candidates;
- affected sequence range invalidates even with a later report timestamp;
- non-intersecting host/window/range does not invalidate;
- duplicate coverage is idempotent;
- close/recovery never removes an invalidation;
- end-to-end anti-laundering: create a candidate, invalidate it with an actual
  later coverage event, then project a later otherwise-safe duplicate and prove
  it adds supporting evidence to the same invalid candidate without minting a
  replacement;
- 4,096 matches commit atomically; 4,097 rolls back event, invalidations, and
  cursor with no truncation;
- crash at every invalidation substep is all-or-none;
- replay in source order reproduces the same invalidation rows.

Run and confirm RED:

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest \
  core/tests/coverage/test_historical.py \
  core/tests/evidence/test_projection_pcc.py -q
```

### GREEN

Use the candidate/coverage indexes and a cap-plus-one query. Reconstruct each
window from its protected PCC, not candidate `created_at`. Insert the new
coverage row, every invalidation, and cursor in one transaction.

Focused quality gate and commit:

```bash
.venv/bin/ruff check \
  core/agmind_immune/coverage/historical.py \
  core/agmind_immune/evidence/projection_v2.py \
  core/tests/coverage/test_historical.py \
  core/tests/evidence/test_projection_pcc.py
.venv/bin/mypy \
  core/agmind_immune/coverage/historical.py \
  core/agmind_immune/evidence/projection_v2.py
git diff --check
git add core/agmind_immune/coverage/historical.py \
  core/agmind_immune/evidence/projection_v2.py \
  core/tests/coverage/test_historical.py \
  core/tests/evidence/test_projection_pcc.py
git commit -m "feat(core): append late coverage invalidations"
```

## Task 8 — Activate V2 by authenticated rebuild only

**Files**

- Modify: `core/agmind_immune/evidence/schema.sql`
- Delete after promotion: `core/agmind_immune/evidence/schema_v2.sql`
- Modify: `core/agmind_immune/evidence/projection.py`
- Modify: `core/agmind_immune/evidence/projection_v2.py`
- Modify: `core/agmind_immune/controller.py`
- Modify: `core/agmind_immune/replay.py`
- Modify: `core/tests/evidence/test_projection.py`
- Modify: `core/tests/evidence/test_projection_v2.py`
- Modify: `core/tests/evidence/test_projection_pcc.py`
- Modify: `core/tests/evidence/test_retention_restart.py`
- Modify: `core/tests/test_controller.py`
- Modify: `core/tests/test_controller_retention.py`
- Modify: `core/tests/test_controller_retention_public.py`
- Modify: `tests/replay/test_rebuild.py`

### RED

Add the exact V1/new/V2 classification matrix and crash matrix:

- exact V1 activates by replaying authenticated evidence only;
- a fresh database is born directly as complete V2 and cannot advance past a
  PCC without its incident/candidate result;
- exact V2 reopen verifies the complete reducer prefix and never performs an
  implicit security-fact backfill;
- unknown/modified V1 schema fails closed;
- forged/stale V1 rows never enter V2;
- failure before rename leaves V1 inode/bytes usable and unchanged;
- uncertainty after rename latches unhealthy;
- ACK/source change during build or reopen rejects activation;
- a protected historical PCC naming a detector hash unavailable from the fixed
  Core pin authority aborts V1 activation/rebuild with V1 untouched; it is not
  rewritten as a different rejection/candidate;
- two V2 rebuilds are byte-identical in security fact rows;
- routine trigger retention removes routine/direct rows while preserving exact
  proof-backed incident, candidate, evidence, coverage hash, and invalidations;
- no security reconstruction calls `_retired_record_from_projection_event`;
- active Projection/Core composition requires the exact same store, ACK
  journal, correlation journal, historical timeline, and pin authority;
- offline authenticated replay opens and binds the same correlation journal and
  fixed pin authority; missing/mismatched historical pins fail closed;
- `tests/replay/test_rebuild.py` invokes the public `rebuild_projection()`
  entry point with an actual completed PCC; the success case persists its exact
  result, while missing or mismatched fixed detector pins abort without a
  replacement projection;
- every changed ProjectionStore/CoreController test factory passes explicit
  same-root authorities; no optional production default or compatibility shim.

Run and confirm RED:

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest \
  core/tests/evidence/test_projection.py \
  core/tests/evidence/test_projection_v2.py \
  core/tests/evidence/test_projection_pcc.py \
  core/tests/evidence/test_retention_restart.py \
  core/tests/evidence/test_pcc_retention_restart.py \
  core/tests/evidence/test_retention.py \
  core/tests/evidence/test_retention_ack_restart.py \
  core/tests/evidence/test_retention_unlink.py \
  core/tests/ingest/test_pcc_correlation_snapshot.py \
  core/tests/ingest/test_retention_delivery.py \
  core/tests/test_controller.py \
  core/tests/test_controller_retention.py \
  core/tests/test_controller_retention_public.py \
  tests/replay/test_rebuild.py -q
```

### GREEN

Promote the reviewed `schema_v2.sql` bytes to active `schema.sql`, switch active
metadata/layout/domain only in this commit, and remove the staging file.
Integrate the complete V2 reducer with `ProjectionStore.apply()` and bind it to
the same-root correlation journal, historical timeline, and pin authority.
Update `CoreController` and every constructor call site explicitly.

Refactor the existing held-directory rebuild so an exact V1 connection can be
replaced without first passing V2 schema validation. Reuse checkpoint/fsync/
replace/parent-fsync/reopen verification. Keep the old database untouched until
the atomic replace. There is no intermediate active reducer version: a new/V1
database becomes V2 only with PCC and invalidation reduction already enabled.

Focused quality gate and commit:

```bash
.venv/bin/ruff check \
  core/agmind_immune/evidence/projection.py \
  core/agmind_immune/evidence/projection_v2.py \
  core/agmind_immune/controller.py \
  core/agmind_immune/replay.py \
  core/tests/evidence/test_projection.py \
  core/tests/evidence/test_projection_v2.py \
  core/tests/evidence/test_projection_pcc.py \
  core/tests/evidence/test_retention_restart.py \
  core/tests/test_controller.py \
  core/tests/test_controller_retention.py \
  core/tests/test_controller_retention_public.py \
  tests/replay/test_rebuild.py
.venv/bin/mypy \
  core/agmind_immune/evidence/projection.py \
  core/agmind_immune/evidence/projection_v2.py \
  core/agmind_immune/controller.py \
  core/agmind_immune/replay.py
git diff --check
git add core/agmind_immune/evidence/schema.sql \
  core/agmind_immune/evidence/schema_v2.sql \
  core/agmind_immune/evidence/projection.py \
  core/agmind_immune/evidence/projection_v2.py \
  core/agmind_immune/controller.py \
  core/agmind_immune/replay.py \
  core/tests/evidence/test_projection.py \
  core/tests/evidence/test_projection_v2.py \
  core/tests/evidence/test_projection_pcc.py \
  core/tests/evidence/test_retention_restart.py \
  core/tests/test_controller.py \
  core/tests/test_controller_retention.py \
  core/tests/test_controller_retention_public.py \
  tests/replay/test_rebuild.py
git commit -m "feat(core): rebuild Projection V2 from evidence"
```

## Task 9 — Issue and revalidate fresh admission capabilities

**Files**

- Create: `core/agmind_immune/incidents/admission.py`
- Create: `core/tests/incidents/test_admission.py`
- Modify: `core/agmind_immune/incidents/__init__.py`
- Modify: `core/agmind_immune/evidence/projection.py`
- Modify: `core/agmind_immune/controller.py`
- Modify: `core/tests/test_controller.py`
- Create: `core/tests/test_controller_admission.py`

### RED

Test:

- lookup accepts only `candidate_id`, strictly reparses/rebinds the protected
  PCC and candidate full-facts hash, and rejects caller-created candidates;
- invalidated, wrong-boot, corrupt-row, unhealthy, or cursor-lagged candidate
  cannot issue a capability;
- live post-open mutation/deletion of candidate, candidate-evidence, or
  candidate-invalidation rows from a second SQLite connection, with no pending
  evidence to trigger catch-up, is detected by admission reauthentication,
  latches projection unhealthy, and issues no capability;
- accepted but unprojected late evidence blocks via live readiness before an
  invalidation row exists;
- the capability binds full `ProjectionCursor`, terminal `EvidenceRef`,
  projection generation, evidence/controller lifecycle, and live readiness;
- copy/pickle/restart/rebuild/close/any cursor advance makes it unusable;
- an `object.__setattr__` mutation matrix replacing candidate, candidate hash,
  cursor, terminal ref, projection generation, readiness hash/cursors,
  controller owner, or lifecycle makes consume/revalidate fail; cross-candidate
  and cross-controller reuse also fail;
- non-authoritative `CandidateStatusObservation` can report invalidations but
  cannot be consumed as admission;
- concurrent poll/retention and lookup have only the two serialized outcomes;
- after a simulated OPA wait, locked revalidation rejects stale capability and
  accepts an unchanged one exactly once.

Run and confirm RED:

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest \
  core/tests/incidents/test_admission.py \
  core/tests/test_controller.py \
  core/tests/test_controller_admission.py -q
```

### GREEN

Implement opaque restart-local capability issuance/consumption. Add async
controller methods that hold `_lock`, catch projection up, sample readiness,
require exact four-cursor equality/current boot/zero invalidations, and then
delegate strict row/proof validation to Projection V2.

The existing synchronous `mutation_readiness()` remains an observation only;
admission must not call it outside the locked path.

Focused quality gate and commit:

```bash
.venv/bin/ruff check \
  core/agmind_immune/incidents/admission.py \
  core/agmind_immune/evidence/projection.py \
  core/agmind_immune/controller.py \
  core/tests/incidents/test_admission.py \
  core/tests/test_controller.py \
  core/tests/test_controller_admission.py
.venv/bin/mypy \
  core/agmind_immune/incidents/admission.py \
  core/agmind_immune/evidence/projection.py \
  core/agmind_immune/controller.py
git diff --check
git add core/agmind_immune/incidents/admission.py \
  core/agmind_immune/incidents/__init__.py \
  core/agmind_immune/evidence/projection.py \
  core/agmind_immune/controller.py \
  core/tests/incidents/test_admission.py \
  core/tests/test_controller.py \
  core/tests/test_controller_admission.py
git commit -m "feat(core): issue fresh candidate admission authority"
```

## Task 10 — Bounded Task 6 gate and independent review

**Files**

- Modify: `docs/superpowers/progress/2026-08-01-task6d-historical-projection-authority.md`

Run only the security-relevant Python gate:

```bash
TMPDIR=/Users/testbot/.codex/tmp-agmind-tests \
  .venv/bin/python -m pytest \
  core/tests/incidents \
  core/tests/correlation \
  core/tests/coverage \
  core/tests/test_contract_regressions.py \
  core/tests/ingest/test_correlation_journal.py \
  core/tests/ingest/test_correlation_delivery.py \
  core/tests/evidence/test_projection.py \
  core/tests/evidence/test_projection_v2.py \
  core/tests/evidence/test_projection_pcc.py \
  core/tests/evidence/test_retention_restart.py \
  core/tests/evidence/test_pcc_retention_restart.py \
  core/tests/evidence/test_retention.py \
  core/tests/evidence/test_retention_ack_restart.py \
  core/tests/evidence/test_retention_unlink.py \
  core/tests/ingest/test_pcc_correlation_snapshot.py \
  core/tests/ingest/test_retention_delivery.py \
  core/tests/test_controller.py \
  core/tests/test_controller_retention.py \
  core/tests/test_controller_retention_public.py \
  core/tests/test_controller_admission.py \
  tests/replay/test_rebuild.py -q
```

Run the exact final static and image gates:

```bash
.venv/bin/ruff check \
  core/agmind_immune/canonicaljson.py \
  core/agmind_immune/correlation \
  core/agmind_immune/coverage \
  core/agmind_immune/ingest/correlation_journal.py \
  core/agmind_immune/evidence/projection.py \
  core/agmind_immune/evidence/projection_v2.py \
  core/agmind_immune/incidents \
  core/agmind_immune/controller.py \
  core/agmind_immune/replay.py
.venv/bin/mypy \
  core/agmind_immune/canonicaljson.py \
  core/agmind_immune/correlation \
  core/agmind_immune/coverage \
  core/agmind_immune/ingest/correlation_journal.py \
  core/agmind_immune/evidence/projection.py \
  core/agmind_immune/evidence/projection_v2.py \
  core/agmind_immune/incidents \
  core/agmind_immune/controller.py \
  core/agmind_immune/replay.py
make test-core-detector-pin-image
git diff --check
```

Request two independent read-only reviews:

1. authority/forgery/replay/readiness/late-gap review;
2. projection schema/rebuild/retention/crash review.

Fix every P0/P1/P2 finding with a focused regression before declaring 6D
complete. Record exact commands and counts in the progress ledger. Do not begin
production OPA wiring until both reviews approve.

The progress ledger path is exactly
`docs/superpowers/progress/2026-08-01-task6d-historical-projection-authority.md`.
Record each task commit, RED command/failure, GREEN command/pass count, static
gate, image-smoke result, review finding and resolution there; no vague
"tests pass" entries.

Update that file with the final exact results, then commit it explicitly:

```bash
git diff --check
git add docs/superpowers/progress/2026-08-01-task6d-historical-projection-authority.md
git commit -m "docs: record Task 6D verification"
```
