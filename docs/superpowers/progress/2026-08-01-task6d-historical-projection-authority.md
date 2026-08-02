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
