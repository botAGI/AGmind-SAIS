# Task 6 correlation-proof implementation plan

## 6A — Final proof contracts

1. Add RED Python/Go tests for the narrow request, retained trigger projection,
   Docker network, strict complete/failed snapshot union, encoded-size bounds,
   canonical arrays, safety/detector hashes, boot-transition-chain hash, and
   request/output separation.
2. Implement strict Python and Go request/trigger/network/snapshot mirrors.
3. Admit only exact `pcc_correlation_snapshot` envelopes in the verifier,
   require same-stream trigger binding on initial admission, allow only
   retired-range-proved trigger absence on replay, and classify them protected.
4. Run only the new contract/verifier tests, formatting, and targeted type
   checks.

## 6B — Pure correlation

1. Add RED immutable model and incident-ID vectors.
2. Add one table-driven ordered gate/boundary/result suite, including absence of
   any model parameter, duplicate evidence separation, and cooldown boundary.
3. Implement models, context/result variants, and side-effect-free
   `correlate_pcc`.
4. Run only `core/tests/incidents` and `core/tests/correlation`.

## 6C — Producer and transport

1. Extend `DockerReader` only with Moby v1.55's read-only `NetworkList`, perform
   a complete unfiltered list plus exact-ID inspect walk, and atomically persist
   one bounded global-network snapshot in the same generation as container
   identities.
2. Add RED producer tests for exact retry, two-hash receipt, conflict fence,
   stale/mismatched trigger, inventory race, complete/overflow networks,
   root-owned pins, failed proof form, protected quota, crash recovery, and
   exact source-sequence binding. Include list/inspect disagreement and
   disappearance cases.
3. Implement the specialized observer route and durable publication receipt
   under the frozen lock order.
4. Add the bounded fsynced correlation-request journal and Core transport call
   between durable trigger append and trigger ACK, including exact retry.
5. Add a restart interleaving test: after durable trigger/request selection but
   before proof publication, restart under a new kernel boot, then require the
   strict `Rejected(observer_boot_changed)` proof with a recomputed protected
   boot-boundary-chain hash and source-order ACK recovery. Cover more than one
   consecutive boot transition and reject a missing/reordered boundary. Cover
   dedicated boundary path A and both combined boot/key-rotation paths B/C,
   including missing, reordered, non-adjacent, wrongly flagged, or incorrectly
   signed transition/start companions.

## 6D — Historical coverage and projection V2

1. Implement historical interval assessment and locked coverage hash.
2. Add projection schema/reducer/snapshot V2 with incidents, candidates,
   candidate evidence, and append-only late invalidations.
3. Add authenticated V1-to-V2 rebuild activation; never migrate cache rows.
4. Prove byte-identical rebuild before/after routine trigger retention and
   deterministic late-gap invalidation.
5. Run the bounded Task 6 gate and independent security review before Task 7.

No repo-wide or native Linux suite runs before these focused gates are green.
