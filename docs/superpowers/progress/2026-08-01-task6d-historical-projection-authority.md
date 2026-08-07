# Task 6D verification ledger

This ledger records exact RED/GREEN commands, pass counts, commits, and review
resolutions for Task 6D. An entry is added only from observed command output.

## Accepted baseline

- Task 6C transport: commit `ef40b64`; focused Python gate `91 passed`.
- Same-root retention compatibility: commit `1ee711f`; focused Python gate
  `120 passed in 1.91s`; Ruff, `py_compile`, and `git diff --check` passed.

## Design and plan audit

- Historical coverage audit: `APPROVE`.
- Authority/forgery audit: `APPROVE` after binding, anti-laundering, replay,
  mutation, and final-gate corrections.
- Projection/deployment audit: `APPROVE` after runtime rule packaging,
  non-root dependency-path, replay-entry-point, and exact-gate corrections.

## Implementation

### Task 1 — candidate facts and immutable pin binding

- RED: focused Task 1 pytest gate: `8 failed, 123 passed`; failures were the
  absent `candidate_facts_sha256()` contract and equality-based `WeakSet`
  authority acceptance.
- GREEN: the same focused gate: `131 passed in 1.19s`.
- Static gate: Ruff passed; mypy passed for both changed production files;
  `git diff --check` passed.
- Independent security/code review: `APPROVE`, no P0/P1/P2 findings.
- Commit: `362f0f5` (`fix(core): bind immutable correlation pins`).

### Task 2 — historical coverage

- Baseline: `core/tests/coverage/test_state.py`: `9 passed`.
- Preflight stopped RED before filesystem changes. It found repo-fit conflicts
  in Falco reason/counter updates, boot scoping, lifetime dedup, underflow
  representation, retired-range authority, and sequence-gap dependencies.
- Resolution: mixed boot scope, exact production wire grammar, boot-aware V2
  dedup, bounded prefix oracle, nullable underflow, store-issued path authority,
  and complete structural dependencies are now normative.
- Refinement reviews: coverage/repo-fit `APPROVE`; bounded-state `APPROVE`;
  store/dedup/path authority `APPROVE`. No Task 2 production result has been
  claimed.

#### Task 2A — shared grammar, exact time, and boot scope

- Initial RED: focused Task 2A gate: `37 failed, 37 passed`; failures covered
  the absent strict classifier/window facts and the prior boot/key behavior.
- Initial GREEN: the same gate: `75 passed in 1.60s`; commit `e0b3196`
  (`fix(core): normalize historical coverage grammar`).
- Independent task review found one Important fail-open Docker reason grammar
  and one missing counted exact-replay regression.
- Fix round 1 RED/GREEN: `1 failed, 1 passed` to `2 passed`; full gate
  `80 passed in 1.57s`; commit `bfce55a`
  (`fix(core): close Docker coverage reason grammar`). The scoped re-review
  confirmed both findings but exposed a producer/consumer protocol mismatch.
- Fix round 2 RED proved an unknown observer Docker reason was signed and
  mutated state, spool, and inventory. The focused three-test Go GREEN passed;
  full Python Task 2A GREEN was `80 passed in 1.53s`; commit `b0d6314`
  (`fix(observer): close Docker reconcile reason grammar`).
- Controller verification on the final commits: focused Go gate passed in
  `4.402s`; Python gate `80 passed in 1.78s`; Ruff and mypy passed; `gofmt -d`
  and commit whitespace checks were clean.
- Final scoped re-review: all findings addressed, no new Critical/Important
  breakage.

#### Task 2B — bounded historical reducer and store-bound path authority

- Initial RED/GREEN: focused Task 2 gate moved from `12 failed, 80 passed` to
  `96 passed`; Projection V1 preservation gate was `29 passed`; commit
  `b3133f1` (`feat(core): derive historical coverage proofs`).
- Independent review found three Critical defects: PCC input authority was not
  bound to its exact `SegmentStore` lifecycle, open sequence gaps ignored
  timestamp-only intersections, and CRITICAL `falco_stop` points were omitted.
  A proposed cumulative-ID finding was withdrawn after reconciling it with the
  locked post-trigger-primary rule. The review also required production-path
  boundary and lifecycle regressions instead of helper-only cap checks.
- Fix round 1 RED/GREEN: the exact clone-store, timestamp-only sequence-gap,
  and Falco-stop regressions moved from `3 failed, 1 passed` to `4 passed`;
  commit `00edb9d` (`fix(core): bind historical coverage authority`).
- Controller verification on the final commits: exact Task 2B gate
  `125 passed in 40.49s`; Ruff passed; mypy passed for all four production
  files; `git diff --check` and worktree status were clean.
- Final scoped re-review: all confirmed findings addressed, withdrawn
  cumulative semantics unchanged, production 4,096/4,097 and lifecycle tests
  materially lock the brief, and no new Critical/Important breakage was found.

### Task 3 — completed correlation delivery authority

- Initial RED/GREEN: the focused two-file gate moved from
  `13 failed, 53 passed` to `66 passed in 2.96s`; commit `124bc46`
  (`feat(core): reauthenticate completed PCC delivery`).
- Independent review found one Critical durable-authority gap: authenticated
  journal bytes were not replay-bound to the mutable in-memory phase caches.
  It also found missing request/state index validation and a capability-token
  mutation race during JIT validation.
- Fix round 1 RED/GREEN: six targeted bypasses moved from
  `6 failed, 67 passed` to `73 passed`; commit `fdc32c3`
  (`fix(core): bind completed authority to journal replay`).
- Controller verification on the final commits: exact Task 3 gate
  `73 passed in 3.25s`; Ruff passed; mypy passed; `git diff --check` and
  worktree status were clean.
- Two scoped re-reviews confirmed that strict held-byte replay now derives and
  binds the complete phase maps, indexes, digest, size, record count, and chain
  head; token/registry identity is rechecked under the journal lock before and
  after validation. All findings are addressed with no new Critical/Important
  breakage.

### Task 4A — fixed detector pin and runtime image contract

- RED/GREEN: the focused detector/runtime gate moved from `64 failed` to
  `64 passed in 0.22s`; commit `2baab09`
  (`feat(core): pin correlation detector runtime`).
- The production loader is fixed to the packaged Falco rule, walks the path
  through held descriptors, rejects links/type/ownership/mode/size and
  metadata drift fail-closed, and returns the canonical bundle hash.
- The runtime image uses a digest-pinned Python base, a root-owned virtualenv,
  a root-owned mode-`0444` rule below protected parents, and runs as UID 1000
  user `sais`.
- Controller verification: focused pytest `64 passed in 0.21s`; Ruff and mypy
  passed; `git diff --check` was clean.
- Native image verification: `make test-core-detector-pin-image` built and ran
  successfully on Docker `29.4.0` (`linux/arm64`) with `--network none` and
  `--read-only`; the real production loader hash matched the repository rule.
- Independent specification and code/security reviews found no
  Critical/Important defects. Both additionally confirmed non-root runtime
  execution (`uid=1000 gid=1000 sais`) and a clean worktree.

### Task 4B — one-use projection correlation authority

- Initial RED/GREEN progressed from `36 failed, 127 passed`, through review
  regressions `5 failed, 163 passed` and the issuance-epoch RED
  `1 failed, 168 passed`, to `169 passed`; commit `6f3633c`
  (`feat(core): issue proof-bound correlation contexts`).
- The first review fix round proved five lifecycle, ownership, detachment,
  class-swap, and failed-path bypasses RED, then passed the six targeted tests
  and the `175 passed` focused gate; commit `1286ca8`
  (`fix(core): close correlation authority bypasses`).
- A deterministic snapshot detach/restore race failed for both public
  entrypoints, then passed four targeted cases and the `177 passed` gate;
  commit `53829d4` (`fix(core): bind failed rejection to issued snapshot`).
- Equality-laundered scalar authority failed for both public entrypoints, then
  passed after exact-type PCC fingerprint and issued-registry validation;
  commit `b24507b` (`fix(core): reject equality-laundered PCC facts`).
- Final controller verification: exact correlation gate `179 passed in
  6.48s`; Ruff and mypy passed; `git diff --check` and status were clean.
  Native `make test-core-detector-pin-image` passed on Docker `29.4.0`
  (`linux/arm64`) as non-root `sais` with no network and a read-only rootfs.
- Independent final reviews found no remaining Critical/Important defect.
  The authority has one exact store/lifecycle owner, one live context revision,
  restart-local rebuild epochs, detached hidden proof facts, and candidate-free
  failed-PCC handling.

### Projection V2 preflight repairs

- Fresh import-order RED exposed `coverage.historical -> correlation.pcc ->
  correlation.__init__ -> authority -> coverage.historical`. A lazy public
  authority re-export passed both fresh-process orders and review; commit
  `9aaa0a5` (`fix(core): break correlation authority import cycle`).
- The dormant V2 regression gate exposed a V1 rebuild contradiction: a valid
  ACK extension beyond a frozen rebuild boundary was rejected after rename.
  RED covered monotonic extension, rollback, substitution, pending replacement,
  exact scalars, source-prefix mutation, and the real retention path. Initial
  GREEN was `74 passed`; commit `cedfa9b`
  (`fix(core): preserve frozen ACK rebuild authority`). Ordinary rebuild now
  accepts only an authenticated monotonic extension while retention and future
  activation remain strict. Post-review RED proved pre/post completion
  validation could still leave retired state healthy; both seams turned GREEN
  and the exact gate reached `76 passed`; commit `36f8586`
  (`fix(core): latch failed retention rebuild authority`). Ruff and mypy passed;
  every failed post-unlink rebuild now latches unhealthy.

### Task 5 — Projection V2 schema and strict facts

- Four TDD slices froze the dormant V2 schema, strict incident/candidate/link
  codecs, hostile-row rejection, and deterministic full-primary-key snapshot;
  commit `a00af2a` (`feat(core): define Projection V2 facts`). The first exact
  controller gate passed `106` tests while active V1 remained byte-identical.
- Independent review found runtime schema self-definition, non-exact evidence
  locators, forged Pydantic encoder inputs, and caller-transaction rollback.
  Each exploit was reproduced RED and closed in commit `6e40dd5`
  (`fix(core): harden Projection V2 authority boundaries`). V2 now pins the
  literal schema SHA-256, strictly reconstructs all persisted security facts,
  rejects equality-laundered record/ref values, and never commits or rolls back
  a caller-owned snapshot transaction.
- Final controller verification passed the exact `129`-test gate in `3.86s`;
  Ruff, mypy, V1 schema byte comparison, and `git diff --check` passed. The V2
  schema hash remains
  `d4a5d563ca3964cbe4ed276882a4b4def95fb756fc67a6777fddf5de38b1619d`.
  Both scoped re-reviews were clean with no remaining Critical/Important
  finding.

### Task 6 preflight — predecessor before duplicate lookup

- Repo-fit audit proved the existing context issuer validated the projection
  predecessor only after the caller had already observed duplicate state.
  Nine focused cases reproduced the missing pre-query boundary RED.
- Commit `5634480` (`feat(core): validate correlation predecessor before
  lookup`) added an exact, read-only validation under the authority lock. It
  rejects stale, closed, mutated, subclassed, and equality-laundered facts
  without advancing the clock or revoking an issued context; context issuance
  independently revalidates the predecessor again after the lookup.
- Controller verification passed `184` authority/PCC tests in `7.11s`; Ruff,
  mypy, and diff checks passed. Independent re-review found no remaining
  Critical/Important defect in this boundary.

### Task 6 — atomic direct/PCC Projection V2 reducer

- Initial implementation commit `19e5501` (`feat(core): project authenticated
  containment candidates`) added the dormant, private V2 owner. It binds one
  exact evidence lifecycle, ACK journal, completed-correlation journal, fixed
  registry/detector authority, SQLite connection, and correlation predecessor.
  One `BEGIN IMMEDIATE` now covers event/dedup facts, historical correlation,
  incident/candidate/evidence rows, cursor, and commit. The controller-focused
  gate passed `104` tests in `10.46s`; Ruff and mypy passed.
- Independent reviews found four blocking integrity gaps: source-order logical
  primary direction was trusted from SQLite, duplicate retry did not
  reauthenticate the retained primary candidate, reopen lacked a final ACK
  stabilization pass, and fail-once cleanup discarded retry handles. All eight
  focused regressions failed before the fix.
- Fix commit `631d45a` (`fix(core): authenticate Projection V2 retry state`)
  derives each logical primary from authenticated source order, validates the
  full authenticated prefix before exact retry, chains two final reopen
  acceptance/cursor/snapshot/ACK checks while permitting proven monotonic ACK
  extension, and retains failed close handles for a later cleanup attempt.
- Final controller verification passed the exact Task 6 gate with `115 passed
  in 13.24s`; Ruff, mypy, and `git diff --check` passed on clean HEAD. Scoped
  re-review marked all four findings addressed and found no new Critical or
  Important breakage.

### Task 7B Task 7 phase A — supported replay gates

- Base: `2437c728ee343c4bce5bcb433fef0a94e9b956ea`. The obsolete
  `test_historical_path.py` private-capability surface and private replay,
  monkeypatch, copied-context, and callback-under-lock tests in
  `test_projection_pcc.py` were retired. Their supported intent remains covered
  by the Task 1-6 hostile serialized-input, wrong-store/stale snapshot, public
  writer, cleanup, exact retry, conflict, and bounded-work nodes.
- A single controller-owned 4,096/4,097 node now builds real accepted records,
  completed correlation journal state, ACK state, correlation snapshots, and
  authenticated PCC inputs. It patches no cap, connection, fsync, reducer,
  descriptor, or production function. The node locks the mutation
  `LIMIT cap + 1 -> LIMIT cap`: 4,096 must publish, while 4,097 must reject
  without an artifact or cursor advance.
- The written Step 3 command selected the whole replay-boundary file despite
  also saying not to include the new boundary node. Its one execution therefore
  attempted the prohibited heavy node before review: the 58 intended
  non-boundary nodes passed, while the accepted 4,096 fixture failed during
  PCC-seed freeze, before replay or cap evaluation, with
  `ValueError: replay PCC detector pin changed` (`1 failed, 58 passed in
  168.62s`). The 4,097 case was never constructed.
- Root cause: `_complete_snapshot` supplied the test sentinel detector pin
  `"1" * 64`, while controller authority issuance captured the repository
  detector digest. The test-only fixture now computes the repository digest
  once and feeds that same value into every signed PCC snapshot and controller
  authority issuance. A count-one construction micro-check passed and proved
  every frozen authenticated proof/context pin equals the captured correlation
  authority pin. The 4,096/4,097 node and the 58-node group were not rerun.
- Static gate: the exact mypy command passed all six selected production files.
  The first exact Ruff command found seven stale test imports plus one
  behavior-free production import, `_exact_coverage_record_key`, that `rg`,
  `git show 2437c72:core/agmind_immune/coverage/historical.py`, and `git blame`
  proved was already unused at base (introduced by `d81976a0`). Under the
  controller-approved plan-gap resolution, Task 7 removed only those imports;
  the exact Ruff rerun passed, and `git diff --check` passed. The earlier mypy
  result remains authoritative because the only later production edit deleted
  that unused import and the other deletions were test imports outside the
  six-source mypy set.
- Active `evidence/schema.sql`, `evidence/projection.py`, V1 behavior, and
  public APIs remain unchanged. Two independent read-only reviews and the one
  final authoritative boundary run remain pending. Task 8 must not start.
