# ADR 0001: Proof-carrying containment: M1 scope and invariants

- Status: accepted
- Date: 2026-07-27 (recorded retroactively on 2026-08-11)

## Context

AGmind-SAIS M1 is a single-host containment product: a curated Falco event becomes signed
tamper-evident evidence, is correlated deterministically against fresh Docker identity, may be
investigated by an LLM that is treated as hostile, passes a deny-default OPA admission step, and —
only after exact local human approval — results in a short-lived, kernel-expiring egress deny
inside one container's network namespace, with the whole chain replayable offline.

This ADR records the milestone's scope and the design invariants decided on 2026-07-27, plus one
refinement dated 2026-07-29 that superseded part of the original correlation design. The coexisting
legacy Python prototype and its retention condition are recorded separately in
[ADR 0002](0002-retain-legacy-generation.md). Later refinements of the correlation and proof
pipeline are recorded in [ADR 0003](0003-correlation-proof.md),
[ADR 0004](0004-proof-production-and-transport.md),
[ADR 0005](0005-historical-projection-authority.md), and
[ADR 0006](0006-trusted-linearization-boundary.md).

## Decisions

### One narrow evidence-bound containment path, not a SOC

M1 implements exactly one end-to-end path: curated Falco event -> tamper-evident signed evidence ->
deterministic correlation against fresh Docker identity -> bounded read-only LLM investigation ->
deterministic OPA admission (deny/manual only) -> actuator-prepared kernel-bound plan -> local
one-use approval of the plan hash -> short-lived nftables destination deny inside the exact
container netns with a native kernel TTL -> replayable decision/action record. The milestone is
successful only if replacing the LLM with an intentionally malicious implementation cannot produce
an unauthorized state change.

This path exercises the hardest product boundary (hostile evidence -> untrusted model ->
deterministic facts and policy -> exact human authorization -> minimal privileged effect ->
independent expiry -> replayable proof). If this boundary is correct, more sensors can be added
behind stable contracts; if it is wrong, adding AI, MCP, or scanners only increases blast radius.
A broad SOC, a generic MCP gateway, and an autonomous remediation platform were explicitly rejected
as the first milestone.

Everything else is deferred to separate post-M1 projects and is never silently folded into M1:
additional sensors (Trivy, CrowdSec, YARA-X, Suricata, ClamAV), authenticated web approval and
RBAC, an AI/MCP action gateway, a detection rule forge with shadow mode, desired-state/backup
recovery, deception-lite, a microVM lab, and IPv6/cgroup-BPF/Kubernetes/multi-node evidence
anchoring. Deployment-policy tests must reject a default profile containing any of them. M1 blocks
only one exact public IPv4 destination — no CIDR, domains, ports, protocols, or inbound.

Consequently, M1 may claim only "evidence-bound runtime investigation and guarded, expiring
containment for supported Docker containers, with the AI model treated as untrusted". It must not
claim complete cyber immunity, autonomous SOC replacement, zero-config protection, post-root
protection, universal visibility, automatic recovery, or immutable single-host evidence.

### I1 — No model authority; the hunter is a bounded, tool-less client

No model output, confidence value, free-form text, tool request, or generated rule can directly or
indirectly authorize a state change. The LLM returns only hypotheses, supporting evidence IDs,
refuting questions, narrative, and limitations. Action candidates originate exclusively from
versioned deterministic correlation rules and authoritative inventory facts; the correlation
function does not even accept a model parameter, and candidate bytes must be byte-identical whether
the model output is benign, hostile, or absent. The legacy prototype's confidence-driven automation
is explicitly not carried forward.

The model (a locally hosted, uncensored model on operator hardware) is reached through a fixed
OpenAI-compatible endpoint with concurrency exactly 1, a bounded queue (32 items, 60 s TTL),
bounded input (32 KiB) and output (16 KiB, 2,048 tokens), temperature 0, no streaming, no tools, no
MCP, no model-managed memory, no redirects, 3 s/45 s timeouts, and a circuit breaker (3 failures in
60 s opens for 60 s). Input separates system instructions from an
`UNTRUSTED_EVIDENCE_BEGIN`/`END` block containing only allowlisted redacted facts — never command
arguments, environment, labels, filenames, raw logs, credentials, approval/action fields, or
namespace internals. Output must be exactly one JSON object matching `HunterOutputV1` with
`supporting_evidence_ids` a subset of the submitted IDs; anything else is a typed non-authoritative
failure. Only Core may reach the Hunter model-host URL, and its resolved IPs are pinned into the management
denylist hashed into every plan, so the containment primitive can never be aimed at the model host.

Consequences: unknown evidence IDs, action fields, commands, tool calls, and schema extensions
invalidate hunter output; LLM failure never blocks deterministic incident creation or manual
containment (only `ai_enrichment_status` changes); AI results are written only to
`ai_investigations` and cannot enter candidate, policy, intent, plan, or approval serializers;
truncation drops lowest-priority evidence records rather than cutting JSON. Evidence:
`core/agmind_immune/hunter/client.py:29-31` (`HUNTER_SYSTEM_V1` with the delimiters),
`contracts/v1/hunter-output.schema.json`, `core/agmind_immune/correlation/pcc.py` (candidates built
from a `CorrelationContext` with no model parameter).

### I2 — Separate trust domains, no generic privileged interface, UDS-only control plane

Observation (`agmind-observerd`, a Go host service owning the Docker socket), deterministic
decision-making (`agmind-core`, an unprivileged Python container), policy (OPA, unprivileged), and
privileged mutation (`agmind-actuatord`, a separate Go root host service) are separate processes
with typed, bounded Unix-socket contracts between them. The deployment is one product and one
installer, not one privileged container; the model host is never in the privileged path. Folding
observation and mutation into one privileged process would make every parser in it a root attack
surface.

The AI and Core receive none of: the Docker socket, host PID namespace, host filesystem, raw
nftables commands, arbitrary shell, arbitrary paths, BPF loading, actuator approval credentials, or
generic MCP tools. Core is explicitly not a security boundary for mutation: a fully compromised
Core still cannot prepare the final kernel-bound target, approve it, or apply an action, because
approval lives on a root/admin-group Unix socket Core never mounts. The adversarial suite must
include a malicious-Core simulation proving intent spam produces zero nft backend calls without
local approval, and compose hardening rejects any rendering that gives Core/OPA/adapter the
`docker.sock`, host PID/network, privileged mode, added capabilities, or another trust boundary's
socket.

All inter-component traffic is HTTP/1.1 strict-JSON over Unix domain sockets — five sockets with
distinct ownership (`observer-ingest` root:agmind-sensor 0660, `observer-core` root:agmind-core
0660, `observer-actuator` root:root 0600, `actuator-intent` root:agmind-core 0660, `actuator-admin`
root:agmind-admin 0660). Servers capture `SO_PEERCRED` and bounded `SO_PEERGROUPS` at accept time;
administrative operations require UID 0, the configured primary GID, or a supplementary GID from
that socket-bound snapshot, failing closed if `SO_PEERGROUPS` is unavailable or oversized.
PID-indexed `/proc/<peer-pid>` data is never used for authorization (PID reuse is racy). Each
listener atomically publishes a newly created 0750 parent, holds a persistent root:root 0600
sidecar lock, and uses a pending->active owner-marker FSM recording the socket device/inode;
restart may unlink only a socket justified by matching provenance. The actuator has no TCP listener
at all, and the non-Linux build returns `ErrUnsupportedPlatform` rather than fake identity.

Evidence: `deploy/systemd/agmind-actuatord.service:45` (`InaccessiblePaths` covering
`docker.sock` and the observer sockets), `agmind-observerd.service:50` (actuator sockets
inaccessible to the observer), `internal/uds/{server,peercred_linux,socket_owner_linux}.go`.

### I3 — Exact target binding; the actuator alone resolves kernel identifiers

A `TemporaryEgressDenyIntent` may contain only: full Docker container ID, exact destination IPv4,
TTL, evidence IDs, policy/rule versions and hashes, and the Core-observed inventory facts. It may
never contain a PID, network-namespace path or inode, interface, nftables expression, or host
command — those are resolved by the root actuator itself (via the private observer lookup) and
become part of the `PreparedTemporaryEgressDenyPlan` whose hash is shown for approval. The plan
binds host ID, boot ID, full container ID, Docker `StartedAt`, image ID, immutable-spec hash,
inventory generation/revision, PID start identity, cgroup identity, netns inode, destination,
policy versions, TTL, evidence IDs, safety-snapshot hashes, nonce, and plan hash. Every
precondition is re-resolved and compared immediately before apply; any mismatch is `STALE_ABORT`,
and the actuator never retries or retargets by name, service, PID, or IP. Letting Core supply a PID
or netns would let a compromised Core aim the containment at an arbitrary namespace; exact binding
plus re-resolution defeats redeploy, PID-reuse, and IP-reuse races.

The actuator never performs a process-wide `setns`. It opens `/proc/<pid>/ns/net`
(`O_RDONLY|O_CLOEXEC`), verifies PID start ticks and cgroup membership before and after the open,
fstats the inode, checks netns uniqueness via the private observer API, and passes the descriptor
to `nftables.New(nftables.WithNetNSFd(fd))`. The preparation-time descriptor is closed before the
plan is journaled: holding an FD across human approval is forbidden because it could keep an
obsolete namespace alive. A fresh descriptor is opened immediately before apply after full
re-validation, and the actuator's own netns inode is compared before and after to prove no
namespace change.

Consequences: container redeploy before apply produces `STALE_ABORT`; PID/IP/name reuse cannot
retarget; injected PID/netns/path/interface fields in an intent are strict-decode rejections; every
disappeared file, PID reuse, cgroup mismatch, generation change, shared inode, or capability change
between prepare and apply is `STALE_ABORT` with no replacement plan prepared. Evidence:
`internal/contracts/validation.go:1002`, `contracts/v1/temporary-egress-deny-intent.schema.json`,
`contracts/v1/prepared-temporary-egress-deny-plan.schema.json`,
`host/actuatord/{plan.go,target_linux.go}`, `host/actuatord/journal.go:441-474`.

### I4 — Independent expiry: a canonical owned nftables ruleset with native kernel TTL

The containment primitive is an nftables set element with a native kernel timeout installed inside
the target container's own network namespace. If Core, the LLM, OPA, or the actuator crashes after
apply, the deny still expires; a destroyed or restarted container loses the namespace and the rule
with it; the action is never restored after host reboot. Expiry audit is observation-only: the
actuator never re-adds an element, extends a timeout, or restores after reboot. Enforcement
lifetime must not depend on any control-plane process surviving. Host-wide source-IP rules were
explicitly avoided because container restart and IP reuse would misfire and unrelated host firewall
state would be touched.

The only kernel object shape is: table `ip agmind_pcc`; base chain `output` (filter, hook output,
priority -10, policy accept); set `blocked_v4` (ipv4_addr, timeout); rule
`ip daddr @blocked_v4 counter drop`; one element with the approved destination and native TTL,
installed in one atomic netlink batch. Every object carries the ASCII ownership marker
`agmind:pcc:v1` where supported. An existing object with the same name but different
family/type/hook/priority/policy/expression/owner is `foreign_nft_collision` and apply fails
closed; an existing destination element is accepted only when the journal proves it belongs to the
same idempotent plan. `github.com/google/nftables` is used behind a narrow `NftBackend` interface;
no shell, `nft` subprocess, arbitrary expression, CIDR, port, protocol, or host-namespace
connection is permitted. Accept-policy chain plus timeout set means the objects are inert without
an element and a name-squatting attacker cannot trick the actuator into adopting foreign rules.

Consequences: native acceptance must prove kernel TTL expiry after killing Core and the actuator,
and a two-phase reboot test must prove no restore; empty AGmind-owned table/chain/set may remain
after expiry (accept policy, no effect without an element); verification queries the complete
structure, exact element, counter, and timeout through the same namespace-bound connection, and
ambiguous acknowledgement is `FAILED_DIRTY` plus kill switch, never optimistic success. Evidence:
`host/actuatord/nft.go:13-15`, `nft_linux.go:83` (`WithNetNSFd`), `nft_linux.go:108` (the drop
rule), `host/actuatord/expiry.go`, `nft_linux_native_test.go`.

### I5 — Durable journal before mutation; the action lifecycle is a fail-dirty saga

The action journal and evidence references must be durably recorded (fsync'd) before apply; if that
write fails, mutation is forbidden. The kernel is touched only after the approved action state is
durable, and an injected journal-sync failure must produce zero nft backend calls. A mutation that
cannot be proven afterwards is worse than no mutation. Every security-critical transition uses
framed append-only records with length, CRC32C, previous-record hash, and fsync before
acknowledgement.

Kernel mutation cannot be rolled back transactionally, so the lifecycle is an explicit saga, not an
ACID transaction: `PROPOSED -> POLICY_ADMITTED -> PREPARED -> APPROVED -> APPLIED -> VERIFIED ->
EXPIRED`, with explicit terminal branches — precondition mismatch -> `STALE_ABORT`; pre-apply
failure or operator denial -> `REJECTED`; approval timeout -> `EXPIRED_UNAPPLIED`; partial or
uncertain apply -> `FAILED_DIRTY`, which atomically persists a global mutation kill switch and
raises a critical local alert. Transitions are journaled as hash-chained Ed25519-signed records;
duplicate delivery of an identical record is idempotent; restart reconstructs pending plans,
consumed nonces, active capacity, rate limits, and kill-switch state solely from the verified
journal and only observes expiry — it never re-applies.

Consequences: kill-switch clear requires proving the referenced element is absent or the namespace
destroyed; a manual lock clears only when no dirty action exists; existing kernel timeouts are
never removed or extended by the kill switch. Evidence: `internal/durablefile/{frame,journal,
atomic}.go` (the AGF1 fsync-before-ack primitive), `host/actuatord/apply.go` (state persisted
before `Flush`), `apply_journal.go`, `journal.go:441-474`, `kill_switch.go`, `recovery.go`,
`contracts/v1/action-record.schema.json`.

### I6 — Coverage is evidence; incomplete intervals block mutation

Sensor drops, restarts, clock uncertainty, stale inventory, and unavailable collectors are stored
as first-class signed coverage events. An incomplete critical interval overlapping
`[event_time - clock_uncertainty, decision_time]` cannot support a mutating action. Coverage
transitions are priority records that survive pressure shedding. Absence of telemetry must never be
silently treated as absence of threat or as license to act — a gap in observation is itself a
security-relevant fact.

Consequences: Falco heartbeat loss (more than 15 monotonic seconds), parse rejections, drop-counter
increases, Docker event-stream gaps, and observer restarts all open CRITICAL coverage intervals
that fence candidate admission until a signed close/reconcile. Evidence:
`contracts/v1/coverage-event.schema.json`, `host/observerd/coverage.go`,
`core/agmind_immune/coverage/state.py`.

### I7 — Explicit budgets and a fixed shedding order

Security components have explicit CPU, RAM, disk, queue, and LLM-call budgets (combined target
under 2 GiB RSS excluding Falco and the model server; AI concurrency exactly 1). Under pressure the
system sheds in fixed order: queued AI enrichment first, then routine duplicate observations, then
routine uncorrelated Falco observations. It never sheds coverage transitions, active
incidents/candidates, policy decisions, prepared plans, approvals, action records, expiry records,
retention tombstones, or key transitions — the protected classes are exactly what makes the proof
chain replayable, and a security layer that starves the protected workload or drops its own
approval records under pressure defeats its purpose.

Consequences: every queue has a fixed capacity (observer spool 256 MiB with a 32 MiB priority
reserve, AI queue 32 items with 60 s TTL, adapter queue 1,024, pending plans 32, and so on);
priority-evidence exhaustion sets persistent mutation read-only; evidence retention defaults to
7 days or 5 GiB, whichever comes first. Evidence: `host/observerd/spool.go` (priority spool),
`host/actuatord/limits.go:24` (`MaxPendingPlans=32`), the hunter config contract.

### I8 — Single-host honesty: kernel and Docker daemon are the TCB

The Linux kernel and the Docker daemon are the trusted computing base. After host-root or kernel
compromise, local evidence and enforcement are not authoritative. M1 evidence is described as
tamper-evident after collection, never tamper-proof — a single host cannot anchor its own evidence
against a root attacker, and claiming otherwise would be dishonest. Multi-node evidence anchoring
is an explicitly deferred project. The observer's Docker-socket authority is explicitly documented
as root-equivalent and confined only by the read-broker allowlist.

Consequences: documentation tests must reject phrases like "tamper-proof single-host evidence";
product claims are limited to the proven scope.

### The observer is an allowlisted read broker for the Docker socket

`agmind-observerd` alone owns the Docker socket and exposes a versioned allowlisted read API
(`ContainerList`, `ContainerInspect`, `ImageInspect`, `NetworkInspect`, `Events` — nothing else).
Docker mutations, exec/archive/copy, arbitrary API proxying, parsing LLM output, calling the
actuator, and storing model credentials are forbidden. A read-only bind mount of `docker.sock` is
explicitly not considered read-only authorization — the Docker HTTP API cannot be made safe by
mount flags; only the protocol allowlist enforces the boundary. The observer strips `Config.Env`,
registry credentials, labels, host mount sources, and command text before anything crosses an API
boundary; the immutable-spec hash covers image ID, entrypoint/command hashes, network mode,
privilege flags, sorted capabilities, read-only flag, and mount tuples, and never contains
environment values or paths.

Consequences: Falco's short `container.id` is only a prefix hint — observerd must resolve it to
exactly one running full Docker ID or fail closed to an investigation-only event; a separate
private root-only lookup socket (container identity, netns uniqueness, integrity) serves only the
actuator, and Core cannot call it. Evidence: `host/observerd/docker.go` (the narrow
`DockerReader`), `inventory.go:81,238,818` (`immutable_spec_sha256`), `private_api.go`; canary
tests assert env and host-path values never appear in canonical identity output.

### Signed envelopes, a pinned install-time trust root, and a host-global sequence

The installer creates a per-install Ed25519 source-envelope key; observerd is the only reader of
the private key, and Core receives the public key as an immutable pinned trust root (`host_id`,
`key_id`, `key_epoch=1`, `public_key`) in root-owned configuration. Key rotation is an explicit
offline root-only command producing a dual-signed (old+new key) consecutive epoch transition
followed by an exact-adjacent `observer_key_epoch_start` signed by the candidate key; only
acceptance of that start activates the epoch. Loss of the key, non-consecutive epochs, rollback,
signature failure, chain break, or unexplained sequence rollback puts mutation processing into
read-only mode. Replacing the pin requires the explicit re-enrollment runbook; neither restart nor
rotation performs trust-on-first-use. Evidence is only tamper-evident if its signing identity
cannot be silently replaced — a self-served key list would let whoever controls the observer state
rewrite history. Observer-served public-key metadata is only transition evidence, never a
self-authorizing replacement; historical signatures stay verifiable (keys carry no validity
timestamps); a separate per-install actuator Ed25519 key signs every action record.

`source_sequence` is one host-global unsigned counter per `host_id`, starting at 1, surviving
process restart, kernel reboot, and key rotation, never reset or reused; `boot_id` and `key_epoch`
are signed dimensions of an event, not separate sequence domains. A changed `boot_id` is accepted
only as the first successfully published event from a closed union: (A) a dedicated
`observer_boot_boundary` event, (B) a dual-signed key transition first in the new boot, or (C) its
adjacent epoch start first in the new boot; exactly one event claims the boot transition. Sequence
holes are closed only by signed critical `observer_sequence_gap` evidence whose range exactly
covers the missing reservations. A crash between sequence reservation and durable append creates a
gap, never counter reuse. A graceful-shutdown predecessor requirement was deliberately rejected
because crashes and power loss cannot provide one. Unexplained rollback, historical boot reuse, a
non-boundary first publication, or unprovable legacy state persists mutation read-only; ordering
uses boot ID and monotonic sequence, never wall clock.

Evidence: `internal/contracts/signing.go`, `trust_root_test.go`,
`contracts/v1/observer-trust-root.schema.json`, `contracts/v1/key-transition.schema.json`,
`contracts/v1/observer-boot-boundary.schema.json`, `host/observerd/envelope.go`,
`internal/contracts/boot_boundary_test.go`, `core/agmind_immune/ingest/envelope.py`.

### AGmind Canonical JSON v1 and domain-separated identifier derivations

All contracts use AGmind Canonical JSON v1: UTF-8, recursively code-point-sorted keys, no
insignificant whitespace, no duplicate keys, no floats/NaN/Infinity, integers only in
-2^63..2^64-1 (lexical `-0` invalid), at most 64 nested containers, optional fields omitted rather
than null, and identical custom string escaping in Go and Python. Every identifier is a
domain-separated SHA-256 derivation (`AGMIND_EVENT_ID_V1`, `AGMIND_RELEASE_ID_V1`,
`AGMIND_CANDIDATE_ID_V1`, `AGMIND_INTENT_ID_V1`, `AGMIND_PLAN_ID_V1`, `AGMIND_PLAN_HASH_V1`,
`AGMIND_ACTION_RECORD_V1`, `AGMIND_EVENT_ENVELOPE_V1`, `AGMIND_KEY_TRANSITION_V1`). The plan nonce
is exactly 32 random bytes rendered as 64 lowercase hex characters; `PlanHash` clears only
`plan_hash`, never the nonce or preconditions. Cross-language byte-identical fixtures are the
compatibility gate: signatures and hashes over JSON are only meaningful if Go and Python produce
identical bytes, and domain separation prevents hash confusion between contract families.

Consequences: every privileged parser rejects duplicate keys, unknown fields, unsupported versions,
floats, overlong strings/arrays, oversize frames, and trailing data; the sole exception is the
exact Falco internal metrics rule, which may contain bounded decimal tokens only in discarded
fields. Evidence: `internal/contracts/canonicaljson.go`, `strictjson.go`, `identifiers.go:36`
(`AGMIND_EVENT_ID_V1` preimage) and `:122` (`AGMIND_PLAN_HASH_V1`);
`core/agmind_immune/canonicaljson.py`; `contracts/fixtures/v1`.

### Non-configurable actuator hard limits and a pinned public-IPv4 decision

The actuator independently enforces compile-time hard limits, because the policy layer and Core are
less trusted than the actuator — the last privileged component holds its own floor so no upstream
compromise or misconfiguration can widen the blast radius. The limits: the only verb is
`temporary_egress_deny`; TTL 30–300 s (default 120); approval expires after 5 minutes; at most one
active deny per container generation and five per host; the destination must be one public,
globally-reachable unicast IPv4 (loopback, link-local, multicast, RFC1918, special-use, Docker
infrastructure, and management destinations are always rejected); the target must be a running,
non-privileged, no-`CAP_NET_ADMIN` container on an unshared Docker bridge namespace with a netns
inode unique among running containers; rejected/expired/stale plans are never retried or
retargeted; intents are rate-limited to 3/minute and 20/hour per Core UID with windows
reconstructed from the durable journal. Configuration may only narrow these limits, never raise
them. A daemon restart does not reset rate windows; a sixth host action or a second same-generation
action rejects atomically.

The shared Go/Python destination decision is pinned to the committed IANA IPv4 Special-Purpose
Address Registry snapshot (SHA-256
`e3e39e76d00b1677335db8e9a805c7b9480ea2f4dc9e33f0b93cd3a905128d73`), uses longest-prefix match, and
permits only addresses whose most-specific entry has Globally Reachable=True; it additionally
denies multicast, limited broadcast, current Docker network subnets and gateways, the operator
denylist, and management destinations (including the resolved Hunter model-endpoint IPs). Hardcoded
CIDR lists rot and disagree between languages; pinning the registry by hash makes the decision
reproducible and cross-language identical. Every prepared plan embeds
`special_use_registry_sha256`, `management_denylist_sha256`, `docker_network_snapshot_sha256`, and
`hard_limits_version`, so the safety data that gated the plan is part of the approved hash; a
registry, denylist, or network-snapshot change between prepare and apply is `STALE_ABORT`. The
actuator reads Docker network facts only from its private observer socket and management
destinations only from `/etc/agmind-sais/management-destinations.json`.

Evidence: `host/actuatord/limits.go:20-31` (`MinTTLSeconds=30`, `DefaultTTLSeconds=120`,
`MaxTTLSeconds=300`, `ApprovalTTL=5min`, `MaxPendingPlans=32`, `PerMinuteIntents=3`,
`PerHourIntents=20`, the pinned registry SHA-256), `apply.go:289-309` (five-active-per-host cap),
`internal/specialuse/registry.go`, `contracts/v1/ipv4-special-use.csv`,
`host/actuatord/safety_files.go`.

### OPA admission is manual-only and deny-default; policy can only narrow

`data.agmind.pcc.decision` defaults to deny with reason `policy_default_deny`. The only admitted
effect is `manual_approval_required` with `max_ttl_seconds = min(requested, 120)` and only the
candidate's own evidence IDs. OPA never returns allow/automatic approval, an action, command, PID,
namespace, or approval token; Core fails closed on unknown effects, widened TTL, added evidence,
hash or version mismatch, timeout, or malformed responses. No M1 production-impact action is
automatically approved. Core computes `policy_bundle_sha256` from the exact mounted `pcc.rego`
bytes and rejects a response whose hash differs. M1 deliberately requires exact local human
approval for every mutation; the policy layer exists to deny and to narrow, never to authorize, so
a compromised or misloaded policy cannot create authority. OPA unavailability means no new admitted
plans (the incident stays visible with `policy_unavailable`).

The 2026-08-11 audit sharpened the honest framing: `pcc.rego` decides little substantively (the
real limits live in `host/actuatord/limits.go`), and OPA's management API was unauthenticated on
the shared control network. Both gaps were fixed (commit `794ed2f` default-denies OPA's own API so
the admission policy cannot be replaced; commit `ec2a2fb` verifies the `pcc.rego` copy OPA actually
loads). OPA is a narrowing filter, not the boundary. Evidence: `policies/pcc.rego:139-152` (only
`manual_approval_required` or deny), `core/agmind_immune/policy/client.py`.

### Approval is a local CLI bound to the complete plan hash with a one-use nonce

M1 approval is deliberately a host-local CLI (`agmindctl`) over the root/admin-group Unix socket —
not a web button and not an API endpoint. The CLI strict-decodes the persisted plan, locally
recomputes the plan hash and refuses a mismatch, renders only deterministic safe fields
(attacker-controlled text and AI narrative are excluded from the approval prompt), requires the
interactive input `approve <last-12-plan-hash-chars>`, and submits the full hash plus nonce.
Approval is atomically one-use under the journal mutex; replay, modified hash/nonce, and
post-5-minute approvals are rejected; there is no `--yes` flag, environment-based approval, stdin
JSON, or remote listener. Approval only queues the plan — apply happens separately, so operator
response and mutation are separately auditable. The human is the only authorization authority in
M1; binding approval to the exact prepared-plan hash means what was approved is provably what is
applied, and excluding attacker text defeats prompt/terminal injection into the operator's
decision. Authenticated web approval with RBAC was explicitly deferred to a post-M1 project.

Consequences: tests must drive the real interactive prompt through a pseudo-terminal; rendering
must strip terminal control characters; Core sending an altered intent after preparation fails on
hash/nonce mismatch. Evidence: `host/actuatord/approval.go` and `approval_test.go` (atomic one-use
consumption), `cmd/agmindctl/main.go` (the admin client, safe rendering, and the last-12-characters
confirmation at `main.go:363-367`) with the pseudo-terminal helpers in `cmd/agmindctl/tty_linux.go`;
the admin socket is root:agmind-admin with `SO_PEERCRED` checks.

### Evidence store: append-only hash-chained segments are truth; SQLite is disposable

Authoritative storage is append-only AGF1-framed segment files with per-record previous-hash
chaining, immutable per-segment manifests chained by `previous_manifest_sha256` from an all-zero
genesis, and a chain-head file that is a location cache, never authority. SQLite (WAL,
`synchronous=FULL`) holds only rebuildable projections: deleting the database and rebuilding from
segments must reproduce a byte-identical canonical snapshot hash. Core evidence never
auto-truncates: an incomplete frame is repairable only at the active `.open` tail through a
two-phase observer-signed authorization/completion protocol; closed-segment, complete-frame, or
non-tail corruption is permanent and forces mutation read-only. Retention deletes only routine
payloads behind signed tombstones (7 days / 5 GiB), preserving protected segments and all
key-transition proofs; manifests are never deleted or rewritten. A rebuildable projection keeps
queries fast without letting a mutable database become the record; hash chaining plus signed repair
means every byte removed from evidence has a signed explanation — which is what "tamper-evident"
means in practice.

Consequences: `python -m agmind_immune.replay verify`/`rebuild` must reproduce identical snapshot
hashes offline; four durable cursors are kept (evidence head, signed-or-covered acceptance,
observer ACK, projection), and projection lag or ACK-journal problems block mutation readiness.
Evidence: `core/agmind_immune/evidence/{frames,segments,manifest,retention,projection}.py` with
`schema.sql`, `internal/durablefile/frame.go`,
`contracts/v1/evidence-repair-{authorize,complete}.schema.json`.

### Falco is a pinned monitor-only sensor behind a strict redacting adapter

Falco 0.44.1 runs unchanged, version-pinned, monitor-only (modern eBPF, no Docker socket, no
response plugins, no actuator/model/API credentials, read-only rootfs, explicit budgets) with
exactly one curated rule ("AGmind PCC Suspicious Process Outbound Connect", source syscall,
priority Notice, sole tag `agmind-pcc-rules-v1`, twelve pinned output fields), posting one JSON
body per HTTP POST to the adapter's only route `/v1/falco/raw` (0.0.0.0:8765) on a dedicated
internal sensor network. The adapter accepts only the pinned field mapping, hashes then discards
output/cmdline/args/labels/env, always emits `investigation_only=true` with no Docker-authority
fields (only observerd may resolve authority and clear the flag), and delivers at-least-once
through one worker with a single inflight item, a 1,024-item routine queue, and coalesced priority
coverage. A 5-second Falco metrics heartbeat is a 15-monotonic-second lease: heartbeat leases are
the sole delivery items allowed to expire; connect events and negative coverage never expire.
Mutation readiness requires a fresh lease strictly newer than the latest adapter stop, with both
ingest and decision within 15 s of `opened_at`. The sensor and its parser are attacker-facing;
pinning versions, rules, and the exact field contract turns "whatever Falco emits" into a closed
contract, and the lease design makes sensor silence fail closed instead of invisible.

Consequences: a candidate-capable event requires every sensor fact, complete observer Docker
authority, a locked successful connect tuple (`evt_res=SUCCESS` with `rawres>=0`, or exactly
`EINPROGRESS`/`EINPROGRESS(115)` with absent/negative `rawres`), and an empty
`missing_required_fields` list; `missing_required_fields` names only omitted sensor facts, never
Docker resolution failures (those are observer coverage flags); rule updates are pinned and never
automatic. Evidence: `core/agmind_immune/falco_adapter/{main,parser,redaction}.py`
(`main.py:1003-1004` binds 0.0.0.0:8765), `contracts/v1/falco-connect.schema.json`,
`deploy/falco/rules.d`, and the shared contract validation in `internal/contracts/validation.go`.

### Deterministic correlation gates; live enrichment superseded by signed snapshots

Every candidate is created by a pure deterministic function evaluating gates in fixed order:
schema/rule pin, successful connect, complete authoritative identity, event age <= 30 s, inventory
age <= 10 s, clock uncertainty <= 2,000 ms, no critical coverage overlap, exact host/container
generation match, public IPv4 plus safety denysets, running unshared-bridge non-privileged
no-`CAP_NET_ADMIN` target, TTL 30–300 s, a 10-minute cooldown on
`(container_id, docker_started_at, detector_bundle_sha256, destination_ipv4)` after any terminal
state, and a deterministic duplicate check. A gate failure is never repaired by later enrichment.
For equivalent duplicate events, the lower `(source_sequence, event_id)` is primary evidence
without changing the candidate ID. Only a deterministic, replayable gate order makes candidate
creation provable and model-independent; freshness bounds prevent acting on stale identity, and
cooldown prevents flapping re-proposals. Reason codes are stable enums, and duplicate or
out-of-order delivery returns the same candidate ID.

**Superseded in part (2026-07-29):** the original design had correlation consume fresh live
observer enrichment. That shape was superseded: a candidate now requires a protected
observer-signed `pcc_correlation_snapshot` carrying the retained Falco projection, a
same-generation complete global Docker-network snapshot, root-owned safety pins, and historical
coverage. Live Docker data, `MutationReadiness`, model output, and SQLite-only facts cannot create
or preserve a candidate; live inventory is never replay authority. Live enrichment made candidate
creation non-replayable and let mutable runtime state influence a security decision; a signed
snapshot makes the correlation input itself part of the proof chain. The snapshot model and its
follow-on refinements are recorded in [ADR 0003](0003-correlation-proof.md),
[ADR 0004](0004-proof-production-and-transport.md),
[ADR 0005](0005-historical-projection-authority.md), and
[ADR 0006](0006-trusted-linearization-boundary.md); the snapshot model is authoritative wherever
older correlation text disagrees.

Evidence: `core/agmind_immune/correlation/pcc.py` and `incidents/` (the gates),
`internal/contracts/identifiers.go` and `canonicaljson.py` (candidate ID derivation),
`internal/contracts/types.go:67,144-147` (`PCCCorrelationSnapshotRequestV1`/
`PCCCorrelationSnapshotV1`), `internal/contracts/pcc_correlation_proof.go`,
`core/agmind_immune/correlation/authority.py`.

### The Core management API is read-only, loopback, token-file authenticated

The Core API binds loopback (or a dedicated management network); `/health` is the only
unauthenticated endpoint and returns only liveness/version/coarse readiness. Every other endpoint
requires a bearer token read from a root-owned file on every request (compared with a constant-time
digest), rate-limited 60/min with burst 20, bounded pagination (default 50, max 100), no CORS
middleware, and attacker-controlled fields escaped and marked `untrusted_text`. There is
deliberately no API endpoint for approval, policy modification, or any mutation in M1; the approval
boundary is the host-local CLI and actuator admin socket. The token is generated by the installer,
never stored in YAML or an image; rotation via `agmindctl token rotate` is immediate because the
file is re-read per request. A read-only API cannot become a mutation path even if its token leaks.

Consequences: tests must assert that no route containing approve/reject/policy/execute accepts
POST/PUT/PATCH/DELETE and that anonymous requests to non-health endpoints get 401. Evidence:
`core/agmind_immune/api/{server,provider}.py`; the config contract pins `api_bind_host` to
`0.0.0.0` and port 8787 *inside the Core container* (`core/agmind_immune/config.py:35-36`) while
the compose file publishes only `127.0.0.1:8787:8787` on the host
(`deploy/compose/compose.yaml:188`), so the loopback-only exposure decided here is enforced at the
publish boundary, not the in-container bind; `cmd/agmindctl/token.go`.

### An exhaustive fail-closed failure matrix is a contract

Every failure mode has a specified fail-closed behavior: LLM unavailable or invalid -> the
deterministic pipeline continues, AI status only; OPA unavailable -> no new admitted plans; Core
unavailable -> observers spool, existing nft timeouts continue; observer unavailable -> stale
coverage, no candidates; actuator unavailable -> no mutations, applied rules expire; Docker event
gap -> full reconcile fence; Falco drop or restart -> coverage gap blocks overlapping candidates;
duplicate or out-of-order events -> idempotent ingest; disk pressure -> shed routine first; clock
change -> ordering by boot ID plus monotonic sequence, TTL by kernel timeout; container redeploy ->
`STALE_ABORT`; approval replay -> one-use nonce rejects; altered intent after approval -> hash
mismatch rejects; partial nft apply -> `FAILED_DIRTY` plus kill switch; host reboot -> containment
never restored. Fail-open behavior in any single row would break the end-to-end claim; enumerating
the matrix makes "fail closed" testable instead of aspirational.

Consequences: parameterized adversarial tests must cover every row; crash-restart behavior for each
daemon is derived from durable journals only. Evidence:
`host/actuatord/{recovery,kill_switch,expiry}.go` and the core failure-safety tests implement the
verified rows.

### Pinned immutable digests and an idempotent installer behind a preflight gate

All toolchain and runtime images are pinned by exact version and multi-platform image-index digest
in `deploy/versions.env` (Go 1.26.5, Python 3.12.13, uv 0.11.32, Falco 0.44.1, OPA 1.18.2-static,
lab Docker Engine 29.6.2), with exact library pins (google/nftables v0.3.0, moby client
v0.5.0/api v1.55.0, FastAPI 0.140.0, Pydantic 2.13.4, and the rest in `go.mod` and the lockfiles).
CI verifies expected architectures and refuses a changed digest; digests must contain linux/amd64
and linux/arm64, and the Go binaries build for both — the mandatory end-to-end run is linux/amd64
on the reference host. The contracts are pinned to exact sensor and policy behavior (the
Falco 0.44.1 output contract, the OPA response shape); an unpinned upgrade would silently
invalidate the proof chain's assumptions. Offline operation after install is a supported
requirement, so all images must be locally present; `make contracts` depends on the pinned uv
image being pulled locally.

`scripts/preflight-linux.sh` emits one read-only JSON support report (systemd, cgroup v2, rootful
single-daemon Docker, kernel >= 5.8 with BTF, tracefs, nftables, bridge networks, disk/RAM floors,
safe socket parents, digest-correct images, model-host resolution matching the pinned management list);
active containment is refused unless all gates pass. `scripts/install-linux.sh` requires root plus
a clean preflight; installs atomically; creates users and groups (agmind-observer/core/sensor
users; agmind-core/sensor/admin groups); generates observer and actuator Ed25519 keys only if
absent; resolves and hash-pins the Hunter model-host addresses; starts services in dependency order; and reports
mutation readiness only after reconcile/key/evidence/journal health. Re-running preserves keys,
host ID, and journals — nothing rotates implicitly. An installer that silently rotates keys or
half-installs would break the pinned trust root and the evidence chain. The original design gave
the observer key mode 0440 root:agmind-observer for a dedicated `agmind-observer` service user; as
built, observerd ships as a root host service (the `agmind-observer` user exists but is reserved
for a post-M1 privilege split — `deploy/sysusers.d/agmind-sais.conf`), so the installer ships both
private keys and `host-id` at 0400 root:root and non-secret configs at 0444
(`scripts/install-linux.sh:538-540`).

Consequences: the installer ships several artifacts read-only (0400/0444), which interacts with the
durable-file reader contract (see the durable-file decision below); `host_id` is created once as a
lowercase UUIDv4 at `/var/lib/agmind-sais/identity/host-id`. Evidence: `deploy/versions.env`,
`go.mod`, `scripts/{install-linux.sh,preflight-linux.sh}`, `deploy/sysusers.d`,
`deploy/tmpfiles.d`; commit `ec2a2fb` hardened the OPA policy-copy verification after the
2026-08-11 audit — the OPA-mounted `pcc.rego` is now re-checked on every service start against the
`PCC_POLICY_SHA256` pin in `deploy/versions.env`.

### Native Linux acceptance is the only acceptance; Darwin can never satisfy it

Production-impacting claims require the native gate on a dedicated rootful Linux host (reference:
one dedicated lab host; the preflight, not the hardware name, decides support): real Falco field
validation, identity races, target-only blocking with an unaffected control container at exactly
1.1.1.1:443, actuator and Core death after apply with kernel TTL expiry, foreign-nft collision,
evidence replay, resource caps (under 2 GiB combined RSS), and a two-phase explicitly authorized
reboot/no-restore test. Darwin, Docker Desktop, OrbStack, and hidden VMs run only
contract/unit/replay/simulation tests and must report unsupported or skip fail-closed — they can
never satisfy M1 acceptance; the design requires any non-Linux verification wrapper to end with an
explicit `native_acceptance=false`. No success claim may be made from simulation-only tests, and
the README completion claim is gated on every mandatory native row being green. The privileged
path (netns, nftables, cgroups, pidfd, eBPF) does not exist on macOS and behaves differently in
hidden VMs; a green suite on the wrong platform is how the project previously shipped an installer
whose files the product could not read.

Consequences: the integration orchestrator requires root, `AGMIND_DEDICATED_TEST_HOST=1`, a clean
preflight, unique lab prefixes, trap-safe teardown, and byte-identical host nft state outside the
target netns; the native CI workflow requires a self-hosted dedicated runner label, never a hosted
runner. Evidence: `scripts/{verify-linux-integration.sh,preflight-linux.sh,
smoke-containment-linux.sh}` (the orchestrator refuses to run without the dedicated-host
acknowledgement — `verify-linux-integration.sh:612`). The planned standalone Darwin wrapper and a
separate `tests/integration/linux/` pytest layout were not built; the native path lives in the
orchestrator script.

### Durable-file safety: AGF1 frames, atomic writes, torn-tail-only recovery (amended)

All durable state uses the AGF1 frame format (magic, big-endian length, previous-record SHA-256,
canonical JSON payload, CRC32C, domain-separated SHA-256) with fsync before acknowledging critical
records. Atomic writes use a same-directory 0600 temp file, fsync, rename, directory fsync.
Recovery truncates only an incomplete final frame; a CRC or hash failure in a complete frame, or
non-tail corruption, is fatal (mutation read-only). Files are owner-private regular single-link
files reached through a secure nofollow parent walk. Middle corruption being fatal rather than
repaired is what distinguishes tamper-evidence from self-healing that could mask tampering.

**Amended after the 2026-08-11 audit:** the reader originally demanded exactly mode 0600, which
made observerd unable to read installer-shipped artifacts (`observer.json` 0444, `host-id` and the
observer key 0400) — the shipped installer produced files the product refused to read while 356
tests were green, because the tests wrote their own 0600 fixtures instead of consuming the
installer's artifacts. The fix keeps 0600 for self-written state but adds an explicit allowlist
(`regularSingleLinkModes`) for installer-shipped 0400/0444 artifacts; every other property is
unchanged. Any future change to either the installer's modes or the reader's allowlist must be
tested against the actual installer-produced artifact. Evidence:
`internal/durablefile/atomic.go:71-97` (`defaultRegularMode` 0600 for writes;
`regularSingleLinkModes` allowlist; the comment at `:79-83` records the incident), `frame.go`,
`crash_test.go`, `repair_test.go`.

### Complete offline proof export is a first-class deliverable

`agmindctl actions export` produces a self-contained directory (export manifest, observer public
keys and transitions, evidence segments and manifests, policy bundle, incident, candidate, prepared
plan, action records, actuator public key) that `python -m agmind_immune.replay verify-export`
verifies fully offline: observer signatures, evidence and segment chains, policy hash, plan hash,
actuator signatures and action chain, and all cross-references, reproducing the same
incident/candidate/action states. The manifest is canonical and hash-addressed and contains no
secrets. The product claim is proof-carrying containment: a third party must be able to verify the
complete decision chain for any action without access to the live host. See
[ADR 0004](0004-proof-production-and-transport.md) for the later refinement of proof production and
transport.

Consequences: every mutating native test must export and verify its proof; the export refuses a
non-empty output directory. Evidence: `core/agmind_immune/replay.py`,
`core/agmind_immune/proof.py`, `scripts/export-proof-linux.sh`.

## Current state (2026-08-11)

Verified in code as of 2026-08-11 (citations inline above): the scope layout (`host/observerd`,
`host/actuatord`, `core/agmind_immune`, `policies/pcc.rego`, `cmd/agmindctl`, `contracts/v1`);
invariants I1–I6 including the model-free correlation signature, socket separation in the systemd
units, `STALE_ABORT`/`FAILED_DIRTY` handling, the namespace-bound nftables backend, and the AGF1
fsync-before-ack primitive; the observer read broker and immutable-spec hashing; the trust root,
key transition, and boot-boundary contracts; canonical JSON and identifier derivations; the
actuator hard limits and pinned IANA registry; OPA's manual-only policy and Core's strict client;
the one-use CLI approval; the evidence segment/manifest/retention stack; the Falco adapter and
pinned rule; the correlation-snapshot contracts; the read-only Core API; the version pins; the
native acceptance scripts; and the amended durable-file mode handling.

Recorded from the original design but not re-verified against code as of 2026-08-11: the full I7
budget table beyond the spool and `MaxPendingPlans`; the I8 documentation-claim tests; complete row
coverage of the failure matrix; the offline proof-export path end to end; and the
deployment-policy tests that reject deferred components in the default profile.

Superseded or amended since the original decisions:

- Live-enrichment correlation was superseded on 2026-07-29 by observer-signed correlation
  snapshots; see the correlation section above and [ADR 0003](0003-correlation-proof.md).
- The durable-file reader's 0600-only rule was amended post-audit with an explicit mode allowlist
  for installer-shipped artifacts (`internal/durablefile/atomic.go:71-97`).
- The OPA gaps found by the 2026-08-11 audit (unauthenticated management API; unverified policy
  copy) were fixed by commits `794ed2f` and `ec2a2fb`; the honest framing is that OPA narrows and
  the actuator's hard limits are the floor.
- The planned dedicated `agmind-observer` service user and 0440 observer-key mode were not adopted
  for M1: observerd ships as a root host service, the user is reserved for a post-M1 privilege
  split, and the installer ships both private keys 0400 root:root
  (`deploy/sysusers.d/agmind-sais.conf`, `scripts/install-linux.sh:538-540`).
- The Core API's loopback exposure is enforced by the compose publish (`127.0.0.1:8787:8787`)
  rather than the in-container bind, which is pinned to `0.0.0.0:8787`
  (`core/agmind_immune/config.py:35-36`, `deploy/compose/compose.yaml:188`).
- The legacy sensor was gated behind `AGMIND_LEGACY_SENSOR=1` at commit `ccfd70a` without deleting
  the tree, per [ADR 0002](0002-retain-legacy-generation.md).

Acceptance status: native Linux acceptance has never passed as of 2026-08-11 — earlier runs would
have died at the first step on the installer/reader file-mode conflict, which is now fixed. The
project status is therefore "implementation complete, native acceptance incomplete", and the
legacy-retention condition of ADR 0002 remains unmet. CI exists only as
`.github/workflows/ci.yml` (added at commit `fcdc9c0`; the repository had no CI at all before
2026-08-11); the planned native-acceptance workflow on a self-hosted dedicated runner, the planned
standalone Darwin verification wrapper, and the planned `tests/integration/linux/` pytest layout
are not yet realized.

## Notes

Load-bearing operational facts referenced by the decisions above:

- **M1 acceptance conditions** (the gate for retiring the legacy tree per ADR 0002): end-to-end
  native containment with target-only blocking, the malicious-LLM no-authority proof, kernel TTL
  expiry without a control plane, the two-phase reboot no-restore test, and a fully replayable
  chain. "Native acceptance passes" means exactly this gate, including the reboot test.
- **Mutation-readiness invariant** (referenced by many later documents): readiness requires a fresh
  signed `falco_heartbeat_lease` (`opened_at` within 15 s of both ingest and decision time,
  strictly newer than the latest adapter stop), a signed-or-covered contiguous sequence cursor, a
  projection cursor equal to the evidence acceptance cursor, no open critical coverage gap, a
  signed Docker reconcile open/close after any boot boundary, and healthy
  key/chain/manifest/clock/ACK-journal state. Adapter start alone never grants readiness.
- **Load-bearing freshness and capacity constants**: event age <= 30 s; authoritative inventory age
  <= 10 s; clock uncertainty <= 2,000 ms; cooldown 10 minutes; TTL 30–300 s (default 120 s);
  approval TTL 5 minutes; at most 1 active deny per container generation and 5 per host; intent
  rates 3/minute and 20/hour.
- **Projection dedup keys**: `falco_connect` dedups on `(host_id, event_type,
  source_payload_hash)` after requiring `raw_event_sha256 == envelope.source_payload_hash`;
  coverage dedups on `(host_id, event_type, normalized_fields_sha256, source_payload_hash)`; every
  distinct signed envelope is retained as evidence even when logically duplicate.
- **Normative precedence**: where the original design documents and the implementation plan differ,
  the locked implementation decisions (canonical JSON limits, identifier derivations, the socket
  table, bounded-interface budgets, crash semantics) are normative; the original correlation text
  is additionally superseded by the snapshot model of [ADR 0003](0003-correlation-proof.md) and its
  follow-ons ([ADR 0004](0004-proof-production-and-transport.md),
  [ADR 0005](0005-historical-projection-authority.md),
  [ADR 0006](0006-trusted-linearization-boundary.md)).
- **Open risk, accepted for M1**: the Falco event and the Docker inventory are independent trust
  inputs but not two independent threat detectors. M1 accepts this only because every action
  requires local human approval; any future automatic containment requires at least two
  independent fresh detection sources and is out of scope.
- **Plan hash discipline**: `PlanHash` clears only the `plan_hash` field (never nonce or
  preconditions); the nonce in the plan-ID derivation is the decoded 32 bytes, not the hex text;
  approval binds to the full 64-hex plan hash with interactive confirmation of its last 12
  characters.
- **Resource envelope** is an engineering budget, not marketing: Core + OPA + adapters + host
  services under 2 GiB RSS excluding Falco and the model server; AI concurrency exactly 1; evidence
  retention 7 days / 5 GiB. The native orchestrator must measure real cgroup peaks against it.
