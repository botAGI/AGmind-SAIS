# Task 8 slice 2b3 report

Base: `8e38532ffa4f26259bf779dabd51854879334159`.

## Delivered scope

- A live non-empty Projection V2 can now rebuild from the authenticated evidence
  prefix without publishing early. Staging reserves exactly generation `g + 1`,
  verifies the complete old SQLite image, and binds a factory-only opaque guard to
  the current owner and exact held old `(device, inode)`.
- The shared replay reducer remains the sole projection reducer. Retention rebuilds
  authenticate the retained prefix from the tombstone authority, re-run the full
  persisted-prefix verifier, and reconstruct retained Falco incidents from frozen
  accepted evidence rather than from mutable live input.
- Filesystem publication materializes and checkpoints an exact temporary V2 image,
  validates and removes only its bound empty sidecars, syncs it, closes the sole old
  connection, enters `SUSPENDED`, and performs the replace edge through held
  namespace descriptors. Mutated-then-raised replace and fsync/reopen failures are
  classified from exact inode/link state; no post-edge rollback is attempted.
- The old SQLite image can be reopened only before the replace arm. The proof is a
  duplicated descriptor of the unique newly opened regular `O_RDWR` SQLite-main fd;
  byte-identical alternate inodes and ambiguous extra SQLite opens are rejected.
- Correlation authority replacement is prepared without visibility and committed
  through one lifecycle-owner registry edge. Success and exact fallback both mint a
  fresh `g + 1` authority, invalidate the old authority, and require singleton live
  ownership. Any ambiguous error after that edge directly fails the fresh authority
  shut.
- Pre-arm failure rebases onto the exact old inode and reopened connection, releases
  (never consumes) an active retention lease, and records `FAILED`. Successful
  publication adopts the reopened new inode, consumes the prevalidated retention
  lease exactly once, and exposes `PUBLISHED` only after connection, generation,
  authority, retention, stage, and reservation state are coherent.
- Generic staged abort/commit routes reject an armed V2 rebuild guard. Guarded
  cleanup must use the exact fallback path, while post-arm ambiguity makes the owner
  unhealthy and clears authority/reservation conservatively.

## TDD evidence

The first combined RED on the four required nodes was the expected missing live-V2
rebuild API:

```text
4 failed in 1.20s
```

The final combined GREEN on the same four nodes is:

```text
4 passed in 10.70s
```

The four tests cover:

1. non-empty staging, no early publication, generation exhaustion before artifacts,
   corrupt-base rejection, cross-owner rejection, same-owner wrong-inode rejection,
   opaque one-shot guard, and exact guarded cleanup;
2. temp materialization, staged checkpoint/close and pre-arm failures, exact old-inode
   fallback, a genuinely reopened old connection, fresh `g + 1` authority, old
   authority invalidation, singleton ownership, and successful retry;
3. old-close ambiguity, `-journal` / `-wal` / `-shm`, hardlink anomalies, replace
   no-mutation and mutation-then-raise, parent-fsync and reopen failures, observable
   `SUSPENDED`, no rollback after the arm, and conservative fail-shut state;
4. non-cursor retained-base tampering, retention-bearing fallback without
   consumption, retry success, `PUBLISHED`-last ordering, exact inode/link outcomes,
   authority rollover, one-shot retention consumption, and finalization.

No broad suite and no 4096/4097 replay run was performed.

## Final static gates

```text
Ruff (four changed Python files): All checks passed!
mypy (three production files): Success: no issues found in 3 source files
py_compile (three production files): passed
git diff --check: passed
```

## Review result

Independent read-only review of the current dirty diff returned **CLEAN** with no
Critical or Important production-correctness finding. The review explicitly covered
the opaque/current-owner authority edge and fail-shut behavior, tombstone-authenticated
full retained prefix and frozen Falco closure, guarded fallback, one-shot exact reopen
descriptor/header proof, retention release/consume ordering, and all four focused test
nodes including same-owner wrong-inode rejection.
