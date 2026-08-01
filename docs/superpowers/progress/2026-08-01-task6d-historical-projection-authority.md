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
