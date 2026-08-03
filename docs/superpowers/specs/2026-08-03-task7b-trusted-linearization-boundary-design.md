# Task 7B: Trusted Linearization Boundary Design

Date: 2026-08-03  
Status: approved under the user's standing full implementation approval  
Scope: replace the exhausted Task 7 in-process anti-monkeypatch model before
Projection V2 activation

## 1. Decision

M1 will not claim that a Python process remains authoritative after arbitrary
code execution inside that same process. `agmind-core` and its loaded code are
part of the trusted computing base (TCB), just as the existing product design
already treats the Linux kernel and Docker daemon as TCB.

The untrusted DeepSeek service, OPA input/output, sensor payloads, model text,
HTTP metadata and protected workloads remain outside the TCB. They communicate
with core only through versioned, bounded, serialized interfaces. DeepSeek
receives a read-only investigation view and has no import, callback, plugin,
filesystem-write, Docker, policy-publication, approval or actuator capability.

Task 7B therefore replaces executable in-process validation seams with a
deterministic core pipeline. It proves integrity against hostile serialized
inputs, stale capabilities, sanctioned concurrent writers, crashes and process
restart. It does not pretend to survive `sys.modules` replacement, arbitrary
monkeypatching, frame/closure walking, debugger injection, native memory writes
or arbitrary Python execution inside core. Those are TCB compromise and are
handled by process/container isolation, image integrity and host controls.

## 2. Why Task 7 is reset

Five fix rounds showed a repeating structural failure:

- each terminal validator bound one Python function but called another through
  mutable module globals;
- test callbacks executed inside trusted lock regions and could replace the
  validators themselves;
- preventing one reachable factory exposed another same-process construction
  path;
- administrative counters omitted work performed by nested helpers;
- testing arbitrary in-process mutation made every Python helper a security
  boundary, which cannot be closed without moving the TCB boundary.

This is not the product threat model. The requested system isolates the
uncensored model from enforcement; it does not load model-generated Python into
the enforcement process.

## 3. Considered approaches

### A. Continue in-process anti-monkeypatch hardening

Rejected. Capturing every transitive helper is not finite in Python, and any
arbitrary in-process attacker can replace callables, class methods, imports or
memory reachable by the interpreter. More sentinels would add tests without a
real security guarantee.

### B. Narrow trusted core plus process boundary

Selected for M1. Core runs deterministic code with no untrusted callbacks.
The model and policy engine are separate unprivileged processes. Core validates
serialized facts, performs optimistic replay, publishes only after exact
revision revalidation and hands an admitted intent to a separate privileged
actuator that still requires local human approval.

### C. Native replay/seal sidecar

Deferred. A memory-safe native worker could reduce the TCB further, but it
would add a new protocol, build chain and operational component before the M1
vertical slice is working. It remains a post-M1 hardening option.

## 4. Process and privilege boundary

```text
untrusted inputs / DeepSeek / OPA
              |
              | bounded versioned messages, no callbacks
              v
      agmind-core (trusted, unprivileged)
      evidence -> deterministic replay -> candidate/admission
              |
              | canonical admitted intent + proof references
              v
      agmind-actuatord (trusted, root, minimal API)
      local TTY approval -> exact nftables change -> TTL rollback
```

Core deployment requirements:

- signed/version-pinned image;
- non-root user, read-only root filesystem and explicit writable state paths;
- no Docker socket, actuator credential, shell, package installer or model
  plugin directory;
- seccomp/AppArmor profile and dropped capabilities;
- model connection is outbound/read-only and cannot route an action response;
- deterministic startup measurement records the core image/config digest in
  evidence.

The DeepSeek adapter on DGX Spark is explicitly untrusted. It receives only an
incident-scoped, field-allowlisted snapshot. Its response is annotation data;
it cannot create evidence, policy decisions, approvals or actions.

## 5. Replay linearization

Task 7B uses optimistic snapshot/validate/publish rather than callbacks held
inside locks.

### 5.1 Freeze

Under the fixed lock order

```text
projection mutex
  -> source snapshot gate
  -> ACK retention lock
  -> correlation binding lock
  -> issued-authority lock
```

core captures an immutable `_ReplayInputSnapshot` containing:

- store lifecycle identity and source revision;
- exact terminal `EvidenceRef` and authenticated retained ranges;
- immutable record descriptors through the terminal;
- duplicated read-only segment descriptors bound to exact device/inode/size
  and prefix limits; computation never reopens a segment by pathname;
- ACK generation, confirmed descriptor and retention state;
- exact correlation predecessor revision and typed canonical facts;
- detector pin and issued-registry facts;
- projection generation and expected schema domain.

No replay, hashing hook, test hook, network call, model call, policy call or
user callback runs while these locks are held. Locks are released after the
snapshot is constructed. The snapshot owns its duplicated descriptors and
closes every one in a lexical `finally`, including partial-construction and
validation-mismatch paths.

### 5.2 Compute

The deterministic reducer reads only `_ReplayInputSnapshot` and immutable
file descriptors/content. It produces `_ReplayComputation`:

- compact transcript digest and count;
- ordered PCC leaves;
- ordered memo leaves;
- late invalidations;
- terminal predecessor facts;
- exact administrative and semantic counters;
- candidate report bytes, not yet publishable.

The reducer has no access to live store/ACK/correlation objects. It accepts no
callable parameters. Any decode, hash, range, identity or limit failure returns
no artifact.

### 5.3 Validate and publish

Core reacquires the same locks in the same order and compares every captured
revision, lifecycle, descriptor, typed fact and pin against live authority.
If any value changed, it discards the computation and returns a retryable or
fail-closed result according to the existing state machine.

If unchanged, the same critical section:

1. verifies the computation's typed seal;
2. constructs the unpublished report;
3. closes replay snapshot resources and clears the exact reservation;
4. publishes/returns the already constructed report;
5. records the projection generation transition.

There is no external callback between the last validation and publication.
Sanctioned writers either complete before the validation snapshot, change a
revision and cause rejection, or wait until publication finishes.

## 6. Linear semantic leaves

The historical reducer emits a `_HistoricalReductionResult` containing both
the public timeline and immutable leaf facts. Leaf facts are produced while the
reducer materializes the final ordered intervals/events; they are not derived
by traversing the completed timeline again.

For each PCC reduction:

- interval canonical bytes are created when the final ordered interval tuple
  is materialized;
- event canonical bytes are created when the final ordered event tuple is
  materialized;
- domain-separated digest accumulators are updated in those same loops;
- the assessment digest is built from exact scalar facts;
- the memo leaf stores counts and digests only;
- independent validation executes the same deterministic reducer and compares
  its independently produced leaves.

Terminal sealing visits `O(R + C + P)` transcript/compact/PCC/memo leaves. The
required semantic prefix work remains `P(P+1)` and is reported separately.
There is no production instrumentation callback. Counters are values returned
by the deterministic reducer and checked after computation, outside locks.

## 7. Exact predecessor validation

`_ProjectionPredecessor` is encoded by a pure typed value encoder before any
untrusted boundary:

- exact model type;
- exact `int`/`str`/`None` scalar types;
- explicit presence and type tags;
- validated ranges and formats;
- fixed field order and domain separation.

The validation phase compares exact bound object identity plus canonical bytes
and correlation revision. No dataclass equality participates. Because no
untrusted callback runs inside validation/publish, module-function replacement
is not a supported interleaving; arbitrary replacement is TCB compromise.

## 8. Failure and cleanup

- All freeze locks use lexical `with` scopes.
- Snapshot construction either returns a complete immutable value or nothing.
- Computation owns no live lock or authority.
- Validation mismatch returns no artifact and advances no projection state.
- Every reservation and owned replay descriptor is cleared/closed in `finally`
  on any `BaseException`.
- A crash before publish leaves the prior durable projection authoritative.
- A crash during a later Task 8 atomic replace follows the existing
  checkpoint/fsync/replace/parent-fsync/reopen protocol.

## 9. Test model

Tests exercise supported boundaries rather than arbitrary TCB takeover.

Required tests:

- hostile serialized records/PCCs and stale/wrong-store capabilities;
- exact V1/V2 replay parity, conflict and late invalidation behavior;
- real sanctioned append, retention, ACK and correlation writers coordinated
  through bounded barriers at public mutation APIs;
- snapshot revision changes before validation reject publication;
- writers started during final validate/publish cannot create a mixed report;
- `BaseException` at freeze, compute and publish boundaries cleans reservation
  and leaves no artifact;
- four/eight administrative counters are exactly linear while semantic visits
  remain 20/72;
- one genuine controller-owned 4,096 success plus 4,097 fail-closed boundary;
- active V1 and public API stay unchanged until Task 8 activation.

Removed/reclassified tests:

- replacing module functions during a core critical section;
- constructing private classes by enumerating module globals;
- mutating interpreter objects with `object.__setattr__` while trusted core is
  executing;
- test hooks that invoke arbitrary code under trusted locks.

Those cases assert survival after arbitrary code execution in the TCB and are
not M1 security claims. Process/container hardening tests cover the actual
boundary instead.

## 10. Migration from `6a24ec2`

Keep the useful round-5 work:

- exact replay reservation/generation cleanup and one-shot lifecycle;
- explicit probing states and one-shot versioned tickets;
- strict typed predecessor facts;
- immutable PCC/memo leaf shapes;
- source/ACK/correlation revision guards;
- exact cleanup and bounded-work fixtures.

Replace:

- module-global executable test seams with returned immutable diagnostics or
  public-API barriers;
- lock-held seal capture with short snapshot construction and out-of-lock
  computation;
- post-hoc `_fold_replay_timeline` traversal with reducer-emitted leaf facts;
- same-process monkeypatch threat tests with process-boundary and sanctioned
  concurrency tests.

The exhausted `_ReplayHandle`, `_ReplayAccess`, `_ReplayEventToken`, replay
path and broker-dispatch surfaces are removed; pure replay has no live
capability object to preserve.

No compatibility shim preserves the exhausted private session/factory model.

## 11. Acceptance

Task 7B is complete only when:

1. the deterministic replay compute path accepts no callbacks or live authority
   objects;
2. no executable test hook runs under the trusted lock order;
3. freeze and validate compare the exact documented revisions/facts;
4. leaf construction adds no second cumulative timeline traversal;
5. focused Task 7 semantic, concurrency, cleanup and counter gates pass;
6. two independent reviews approve the new threat boundary and implementation;
7. the single genuine 4,096/4,097 boundary passes;
8. active V1 remains byte-identical until Task 8 begins.

Only after these gates may Task 8 activate Projection V2.
