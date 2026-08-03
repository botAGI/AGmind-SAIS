# Task 6 implementation report

## Commit range

- Base: `91b33e4fb8664a9cb6e360f7fc4657251006d4cd`
- Initial implementation range: `91b33e4fb8664a9cb6e360f7fc4657251006d4cd..cbe3a38e3d74070461f23083d86d86cc83587204` (two focused commits)
- `10ef65f511c7c8fad83d6140c7f347dd9a0c7e25 feat(core): freeze completed PCC replay facts`
- `cbe3a38e3d74070461f23083d86d86cc83587204 refactor(core): publish replay after exact revalidation`
- Review-fix amended-doc base:
  `2da687c0f304205fa47898348c0dcaecf57013e7`
- Review-fix code commit:
  `6d98a69e9d3024145e9c9abd055b23b7da7b7d2d fix(core): drain replay fences after lock unwind`

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
- Review-fix RED: the exact new three-node command produced `4 failed in
  20.74s`. The two parameterized replay cases timed out while corruption
  fencing re-entered the held source gate, the public conflict case left both
  source→journal and journal→source workers blocked, and the initial FD case
  exposed that its reuse fixture needed an exact `dup2` target.
- After correcting only that FD fixture, a mutation run of the same exact
  command with the old clear-after-close order produced `1 failed, 3 passed in
  0.66s`: every source snapshot descriptor received two close attempts. This
  is the accepted one-shot ownership RED.

## GREEN evidence

- Primitive/parity slice: `14 passed in 1.64s`.
- Three-node orchestration slice: `13 passed in 4.13s`.
- Required concurrency/cleanup slice, including the two rewritten legacy
  nodes: `15 passed in 4.99s`; final verification `15 passed in 4.76s`.
- Post-orchestration semantic/crash slice: `16 passed in 7.00s`; final
  verification `16 passed in 6.95s`.
- Review-fix lock-unwind/ownership slice: final verification `4 passed in
  0.66s`.
- Review-fix prior concurrency/cleanup slice: final verification `15 passed in
  4.74s`.
- Review-fix prior semantic/crash slice: final verification `16 passed in
  6.88s`.
- The deadlock regressions run corrupt replay cases in forked children so an
  expected pre-fix deadlock cannot retain the process-global issued-authority
  lock and contaminate the later nodes. Test names and production semantics
  remain exactly those specified in the fix-round plan.
- One pre-verification GREEN attempt collected no nodes because the mechanical
  broker deletion duplicated an `__all__` line. The syntax-only defect was
  corrected before accepting any GREEN evidence.

## Static checks

- Ruff on the exact nine Task 6 files: `All checks passed!`
- mypy on the exact six Task 6 source files: `Success: no issues found in 6 source files`
- `git diff --check`: passed.
- Review-fix final static rerun used the same exact Task 6 commands: Ruff
  `All checks passed!`, mypy `Success: no issues found in 6 source files`, and
  `git diff --check` passed.

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
- ACK and correlation replay corruption now enter replay-owned finite queues;
  ordinary operations cannot consume those queues between a deepest-lock
  release and the outer source-gate unwind. Orchestration drains both only
  after the complete freeze/validation stack releases and attaches secondary
  fence failures to the primary error.
- Public correlation journal operations serialize journal mutation with an
  after-unlock fence drain, eliminating the journal→source edge while keeping
  the required replay source→journal order and the nonreentrant source lock.
- Publication and outer cleanup consume ACK/source snapshot ownership before
  the first close attempt, so a partially failed close is never retried
  against a reused numeric descriptor.

## Deleted legacy surfaces

- Removed `_replay_unpublished_prefix_legacy` and its nested ACK/correlation
  callback guards, terminal source callback, final authority callback, and
  replay-path step-hook protocol.
- Removed projection-side replay handle/access/event/session plumbing and its
  optional parameters/branches.
- Removed the remaining historical `_ReplayHandle`, `_ReplayAccess`,
  `_ReplayEventToken`, replay path/access records, session/broker registries,
  dispatch, probes and callback final-seal helpers. Historical coverage now
  has one ordinary exact `(store, proof)` path issuer and no replay-access
  branch.
- Removed the replay-only completed-batch authority/item issue, claim,
  revalidate, seal, and revoke family plus its six unit tests.
- Removed the correlation terminal callback evaluator; terminal validation is
  now a direct non-callback validation.
- Preserved ordinary `_evaluate_completed_snapshot_batch`, single completed
  snapshot authority, `_issue_correlation_context`, `_IssuedContextBinding`,
  and dormant live V2 compatibility as required.

## Review disposition

- Important — nested ACK/correlation health fencing could re-enter or invert
  the source gate: resolved with replay-owned queues and post-stack drains.
- Important — the historical session/broker graph remained in production:
  resolved by deleting the graph and routing ordinary V2 through the exact
  store/proof path issuer while preserving context registration/evaluation and
  completed-batch compatibility.
- Important — partial snapshot close could retry a reused FD number: resolved
  by one-shot ownership transfer before every publication/cleanup close.
- Disposition: all `0 Critical, 3 Important` review findings are resolved in
  `6d98a69e9d3024145e9c9abd055b23b7da7b7d2d`.

## Remaining concerns and scope confirmation

- Task 7 still owns removal of obsolete false-TCB tests that refer to the
  deleted historical replay seams. They were intentionally not broadened into
  this task.
- No broad suite, Task 7/8 node, or real 4,096/4,097 boundary node ran.
- No active V1, schema, specification, or plan file was modified.
