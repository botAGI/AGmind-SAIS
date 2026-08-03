# Task 6 implementation report

## Commit range

- Base: `91b33e4fb8664a9cb6e360f7fc4657251006d4cd`
- Initial implementation range: `91b33e4fb8664a9cb6e360f7fc4657251006d4cd..cbe3a38e3d74070461f23083d86d86cc83587204` (two focused commits)
- `10ef65f feat(core): freeze completed PCC replay facts`
- `cbe3a38e3d74070461f23083d86d86cc83587204 refactor(core): publish replay after exact revalidation`

## RED evidence

- Primitive RED: the exact Task 6 primitive command produced `3 failed in 0.54s`.
  The failures established the missing values-only correlation-journal replay
  snapshot API, coverage-free PCC seed freeze/rebind, and split base/publish
  generation behavior.
- Orchestration RED: the exact three-node command produced `13 failed in
  2.99s`. The failures established the missing immutable replay status,
  reservation protocol, sanctioned-writer boundary, and finite
  `_ReplayFaultPhase` cleanup behavior.
- Two earlier orchestration fixture-only attempts also produced 13 failures:
  first from a missing test import and then from an unpinned detector loader.
  Those setup defects were corrected before accepting the behavioral RED.

## GREEN evidence

- Primitive/parity slice: `14 passed in 1.64s`.
- Three-node orchestration slice: `13 passed in 4.13s`.
- Required concurrency/cleanup slice, including the two rewritten legacy
  nodes: `15 passed in 4.99s`; final verification `15 passed in 4.76s`.
- Post-orchestration semantic/crash slice: `16 passed in 7.00s`; final
  verification `16 passed in 6.95s`.

## Static checks

- Ruff on the exact nine Task 6 files: `All checks passed!`
- mypy on the exact six Task 6 source files: `Success: no issues found in 6 source files`
- `git diff --check`: passed.

## Implemented boundary

- Added values-only completed-PCC journal capture/revalidation and detached
  coverage-free PCC replay seeds.
- Split base and publish generations and validate/hydrate the private SQLite
  image before reacquiring live authority locks.
- Added exact owner reservation and immutable replay status, with a bounded
  data-only `Condition` handshake for sanctioned concurrency tests. No
  callback or callable is injected into replay.
- Freeze and final validation use the required left-to-right lock order:
  owner, source, ACK, correlation binding, issued-authority registry, journal.
  `VALIDATING` is published only after the journal lock is held.
- Final publication revalidates every captured authority, closes snapshot
  descriptors, rebuilds the correlation predecessor, and adopts the already
  validated private connection without replaying into the live owner.
- Retention-state publication now participates in the source mutation gate so
  real retention writers are linearized with replay source snapshots.

## Deleted legacy surfaces

- Removed `_replay_unpublished_prefix_legacy` and its nested ACK/correlation
  callback guards, terminal source callback, final authority callback, and
  replay-path step-hook protocol.
- Removed projection-side replay handle/access/event/session plumbing and its
  optional parameters/branches.
- Removed the replay-only completed-batch authority/item issue, claim,
  revalidate, seal, and revoke family plus its six unit tests.
- Removed the correlation terminal callback evaluator; terminal validation is
  now a direct non-callback validation.
- Preserved ordinary `_evaluate_completed_snapshot_batch`, single completed
  snapshot authority, `_issue_correlation_context`, `_IssuedContextBinding`,
  and dormant live V2 compatibility as required.

## Remaining concerns and scope confirmation

- Task 7 still owns removal of obsolete false-TCB tests that refer to the
  deleted historical replay seams. They were intentionally not broadened into
  this task.
- No broad suite, Task 7/8 node, or real 4,096/4,097 boundary node ran.
- No active V1, schema, specification, or plan file was modified.
