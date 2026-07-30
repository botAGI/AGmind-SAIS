# AGmind Cyber Immune System — Proof-Carrying Containment M1

Status: proposed for implementation  
Date: 2026-07-27  
Target: one supported Linux host running rootful Docker Compose  
Repository state: existing AGmind-SAIS prototype is retained as legacy code until the new path passes acceptance tests

## 1. Decision

The first implementation milestone is not a broad SOC, a generic MCP gateway, or an autonomous remediation platform.

M1 implements one end-to-end, evidence-bound containment path:

1. Observe a curated Falco event that binds suspicious runtime behavior to an exact outbound destination.
2. Preserve its provenance in a tamper-evident evidence stream.
3. Bind the event to fresh authoritative Docker identity and deterministically create an incident and containment candidate.
4. Allow an untrusted local LLM to investigate the incident through a bounded read-only interface.
5. Admit or reject the candidate with deterministic policy.
6. Let the actuator resolve and durably journal the exact kernel-bound prepared plan.
7. Present that exact prepared plan and hash to a local administrator.
8. After one-use approval, install and verify a short-lived destination deny inside that network namespace, let it expire independently of the control plane, and preserve the complete decision/action record.

The milestone is successful only if replacing the LLM with an intentionally malicious implementation cannot produce an unauthorized state change.

## 2. Product claim for M1

M1 may claim:

> Evidence-bound runtime investigation and guarded, expiring containment for supported Docker containers, with the AI model treated as untrusted.

M1 must not claim:

- complete cyber immunity;
- autonomous SOC replacement;
- zero-config protection for every container runtime;
- protection after host-root or kernel compromise;
- universal application-, TLS-, SQL-, identity-, or MCP-level visibility;
- automatic recovery of stateful workloads;
- immutable evidence on a single compromised host.

## 3. Supported environment

M1 supports:

- Linux with systemd;
- rootful Docker Engine on the standard Unix socket;
- cgroup v2;
- containers with their own Linux network namespace;
- non-privileged target containers without `CAP_NET_ADMIN`;
- IPv4 exact-destination egress containment;
- Docker bridge networks;
- an existing local OpenAI-compatible inference endpoint, including vLLM or Ollama;
- offline operation after installation and rule/model availability.

M1 explicitly reports unsupported or degraded coverage for:

- Docker Desktop as a production target;
- rootless, nested, or multiple Docker daemons;
- `network_mode: host`;
- `network_mode: none` and shared `container:`/Compose `service:` network namespaces;
- privileged containers and containers with `CAP_NET_ADMIN`;
- macvlan/ipvlan containment;
- Windows containers;
- Kubernetes;
- IPv6 containment;
- encrypted application payload inspection;
- container logs unavailable through the configured Docker logging driver.

macOS remains a development environment. Production integration tests run on a real Linux VM or Linux CI host.

## 4. Security invariants

These invariants are implementation gates, not aspirations.

### I1. No model authority

No model output, confidence value, free-form text, tool request, or generated rule can directly or indirectly authorize a state change.

The LLM returns only:

- hypotheses;
- supporting evidence references;
- refuting questions;
- a concise investigation narrative.

Action candidates originate exclusively from versioned deterministic correlation rules and authoritative inventory facts.

### I2. No generic privileged interface

The AI and Core receive none of:

- Docker socket;
- host PID namespace;
- host filesystem;
- raw nftables commands;
- arbitrary shell;
- arbitrary paths;
- BPF loading;
- actuator credentials;
- generic MCP tools.

### I3. Exact target binding

Every prepared containment plan binds to:

- host ID and boot ID;
- full Docker container ID;
- container start time;
- image digest;
- normalized immutable-spec hash;
- inventory generation;
- target network namespace inode;
- exact destination IPv4 address;
- policy and rule versions;
- TTL;
- evidence IDs;
- nonce and plan hash.

Any mismatch immediately before apply produces `STALE_ABORT`. The actuator never retargets automatically by name, service, PID, or IP.

Core cannot supply or choose the network namespace inode, PID, interface, or other kernel identifiers. It submits a bounded containment intent. The actuator resolves those identifiers, constructs and journals the prepared plan, and returns its hash for local approval.

### I4. Independent expiry

The containment primitive uses a native nftables timeout inside the target network namespace.

If Core, the LLM, OPA, or the actuator crashes after apply:

- the deny still expires;
- a destroyed/restarted container loses the old network namespace and its rule;
- the action is not restored after reboot.

### I5. Evidence before mutation

The action journal and evidence references must be durably recorded before apply. If this write fails, mutation is forbidden.

### I6. Coverage is evidence

Sensor drops, restarts, clock uncertainty, stale inventory, and unavailable collectors are stored as first-class coverage events.

An incomplete critical interval cannot support a mutating action.

### I7. Workload priority

Security components have explicit CPU, RAM, disk, queue, and LLM-call budgets.

Under pressure, the system sheds routine telemetry and AI enrichment before affecting the protected workload. It preserves:

- coverage events;
- incidents;
- approval records;
- action journal;
- rollback/expiry state.

### I8. Single-host honesty

The Linux kernel and Docker daemon are trusted computing base. After host-root or kernel compromise, local evidence and enforcement are not authoritative.

M1 evidence is described as tamper-evident after collection, not tamper-proof.

## 5. Architecture

```text
Falco JSON             Docker inventory/events
    |                          |
    v                          v
falco-adapter         agmind-observerd (host)
    |                 read broker + envelope signer
    +--------------+-----------+
                   |
                   v
          signed canonical events
                   |
                   v
        agmind-core (unprivileged)
        - ingest and validation
        - evidence segments
        - SQLite projections
        - temporal correlation
        - incident/candidate state
        - bounded AI investigation
        - authenticated read-only API
                   |
             policy input
                   v
            OPA (unprivileged)
                   |
          admitted containment intent
                   v
       agmind-actuatord (host root)
       - pending-plan journal
       - exact plan preparation
       - local CLI approval
       - target re-resolution
       - netns nftables apply
       - verification and expiry audit
```

The deployment is one AGmind product and installer, not one privileged container.

## 6. Component boundaries

### 6.1 `agmind-observerd`

Implementation target: small Go host service.

Responsibilities:

- own the Docker socket;
- expose a versioned allowlisted read API over a Unix socket;
- subscribe to Docker lifecycle events;
- reconcile authoritative container inventory;
- remove `Config.Env`, registry credentials, and unapproved fields;
- assign per-boot monotonic sequence numbers;
- wrap canonical adapter events with source identity and signature;
- report source restarts, queue drops, and reconcile gaps;
- expose the minimum current container identity required for intent admission; kernel identifiers used for action remain actuator-owned.

`agmind-observerd` exposes a separate private lookup method to `agmind-actuatord` over an authenticated root-owned Unix socket. It accepts only a full Docker container ID and returns the current:

- full container ID;
- Docker `.State.StartedAt`;
- image ID and digest where available;
- normalized immutable-spec hash;
- init PID;
- network mode;
- privilege/capability flags;
- running state;
- monotonically increasing per-container inventory revision.

Core cannot call this private method. The actuator calls it during both preparation and apply.

Forbidden:

- Docker mutations;
- container exec/archive/copy;
- arbitrary Docker API proxying;
- parsing LLM output;
- calling the actuator;
- storing model credentials.

A read-only bind mount of `docker.sock` is not considered read-only authorization. Only the protocol allowlist enforces the boundary.

The installer creates a per-install Ed25519 source-envelope key owned by root. `agmind-observerd` is the only service allowed to read the private key. Core receives the public key. Key rotation creates a signed epoch-transition record; loss or unexplained rollback of the key puts mutation processing into read-only mode.

### 6.2 Falco engine

Falco remains an unchanged, version-pinned upstream sensor in monitor-only mode.

Deployment requirements:

- modern eBPF driver when supported by preflight;
- only the documented kernel capabilities and host mounts required by the selected driver;
- no Docker socket;
- no actuator, policy, model, or API credentials;
- no state-changing response plugin;
- read-only root filesystem except bounded runtime/output storage;
- explicit CPU, memory, and output-rate limits.

Falco sends one JSON body per internal HTTP POST to exact adapter route
`/v1/falco/raw` over a dedicated sensor network unavailable to protected
workloads. The adapter binds `0.0.0.0:8765` only. Loss, backpressure, restart,
parse rejection, heartbeat timeout, detector hash mismatch, or increasing Falco
drop counters creates bounded adapter-owned coverage and disables M1 candidate
admission for the affected interval.

### 6.3 `falco-adapter`

Implementation target: unprivileged process/container.

Responsibilities:

- consume version-pinned Falco JSON output as one bounded HTTP body;
- accept only selected stable rule/event fields;
- preserve top-level Falco `time` as normalized UTC `event_time`;
- require `container.id`, `container.start_ts`, `fd.rip`, `fd.rport`,
  `fd.l4proto`, `evt.type`, result fields, and process identity fields only for
  candidate capability; null/`<NA>` sensor facts become omitted
  investigation-only fields with exact normalized missing names;
- include `container.full_id` when Falco enrichment provides it;
- map events to the canonical schema;
- redact command arguments and other attacker-controlled strings before AI use;
- submit bounded canonical payloads to `agmind-observerd` for source wrapping;
- deliver every non-expired item at least once through one HTTPX UDS worker
  with exactly one inflight request, a 1,024-item routine queue, separate
  coalesced priority coverage, two-second requests, and retry backoff capped at
  five seconds;
- validate the exact five-second Falco metrics heartbeat, pinned version,
  modern-bpf engine, config/rule hashes, and monotonic output/kernel drop
  counters.

Connect documents reject every float, including ignored fields. The exact
internal metrics rule alone may contain finite bounded decimal tokens in
discarded fields; selected heartbeat identity, hashes, and counters remain
strict strings and integers. A connect is accepted only with top-level
priority `Notice` and the exact sole tag `agmind-pcc-rules-v1`.

M1 uses a curated minimal Falco rule subset. Rule updates are pinned and never automatic.

Falco's short `container.id` is not treated as final identity. `agmind-observerd` accepts it only as `falco_container_id_prefix`, resolves it to exactly one running full Docker ID, and enriches the canonical event with authoritative `docker_container_id`, Docker `.State.StartedAt`, image identity, spec hash, and inventory revision. No match or an ambiguous match fails closed.

Falco `container.start_ts` is retained only as sensor metadata; it is not compared directly with Docker `.State.StartedAt`. A containment candidate requires a successful `connect` result (`evt.rawres >= 0` or the non-blocking `EINPROGRESS` result) and the exact pinned output contract:

- Falco rule/version;
- `evt.type` and result;
- `container.id` prefix and optional `container.full_id`;
- `container.start_ts`;
- `proc.name`, executable path, and parent;
- `fd.rip`, `fd.rport`, and `fd.l4proto`.

The adapter always submits investigation-only events without Docker authority;
only observerd may resolve authority and clear the flag. Missing fields create
an investigation-only event. `missing_required_fields` contains only omitted
sensor facts; failed Docker resolution is represented by observer coverage
flags, never by adding `docker_container_id` to that list. Falco and its adapter
do not receive the Docker socket. The sensor UDS exposes exact Falco and
Falco-coverage POST routes, never a generic coverage route; observerd derives
coverage component/severity/flags.

The adapter is externally fail-closed across process lifecycle. Before
enabling intake it emits a closed INFO start point and opens a CRITICAL
awaiting-initial-heartbeat gap. Every fully valid heartbeat emits a closed INFO
`falco_heartbeat_lease`; stop is a closed CRITICAL point. Coverage/lease
timestamps use adapter wall receipt time, while a monotonic receipt clock alone
detects silence beyond 15 seconds. Counter rollback requires a second
identity/hash-exact sample monotonic against a pending reset baseline before
the mismatch closes or a lease renews. Parse rejection and each Falco drop
counter form cumulative open-to-close CRITICAL intervals.

Adapter transport is at-least-once except for expired positive heartbeat
leases. Only `falco_heartbeat_lease` delivery items expire locally, exactly 15
monotonic seconds after admission; the single worker checks before every post
or retry, discards an expired lease without recovery, and ticks the watchdog
on every retry cycle. Connect events and negative coverage never expire. Any
delivery-failure interval remains open and its priority open/close evidence is
delivered before readiness can reopen. The worker reads the common shutdown
deadline dynamically on every retry and after queue waits, while the outer
shutdown wait cancels an already-active request at that same deadline.

For non-expired items, if an observer response times out after durable append,
retry can create a second signed envelope sequence for the same raw payload.
Core retains both envelopes as evidence. It deduplicates
`falco_connect` by `(source_id,event_type,source_payload_hash)` and coverage by
`(source_id,event_type,normalized_fields_sha256,source_payload_hash)` before
projection/candidate creation. The exact raw payload hash remains in both
keys; the normalized hash prevents recurring coverage transitions from
colliding while identical transport retries remain idempotent.

Mutation readiness additionally requires the latest signed
`falco_heartbeat_lease` normalized `opened_at` and signed observer-envelope
`ingest_time` to satisfy both
`0 <= ingest_time - opened_at <= 15 seconds` and
`0 <= decision_time - opened_at <= 15 seconds`. Its `opened_at` must be
strictly newer than the latest signed `falco_adapter_stop.opened_at`; any
future-dated or late timestamp blocks readiness. Start alone never grants
readiness, stop blocks immediately, and a stale lease fails closed after an
unclean adapter exit.

### 6.4 `agmind-core`

Implementation target: Python 3.12 package and non-root container.

Responsibilities:

- validate signed event envelopes;
- append canonical events to hash-chained segment files;
- maintain rebuildable SQLite projections;
- build asset, process, network, evidence, and incident relations;
- run deterministic streaming and temporal correlation;
- create containment candidates;
- query OPA;
- construct bounded redacted LLM evidence bundles;
- validate structured LLM investigation output;
- expose health, coverage, inventory, incident, evidence, and proposal APIs;
- send admitted bounded containment intents to the actuator.

Core is not a security boundary for mutation. A fully compromised Core still cannot prepare the final kernel-bound target, approve it, or apply an action.

Core has no Docker socket and no actuator approval credential.

### 6.5 Evidence store

Authoritative storage:

- append-only segment files;
- segment manifest;
- source envelope signatures;
- previous-segment hash;
- explicit retention tombstones.

Rebuildable projections:

- SQLite WAL database;
- asset and release inventory;
- temporal edges;
- incidents;
- candidate state;
- coverage state;
- action outcome projection.

The graph is never the source of truth. It can be deleted and rebuilt from retained segments.

M1 stores normalized and redacted canonical evidence, plus a hash of any excluded raw source. It does not persist arbitrary full logs, environment values, packet payloads, or secrets.

### 6.6 OPA

OPA receives deterministic structured input:

- rule/candidate identity;
- exact target identity;
- evidence references and age;
- coverage state;
- destination;
- requested TTL;
- asset protection class;
- policy bundle version.

OPA returns:

- `deny`;
- `manual_approval_required`;
- reason codes;
- bounded parameter constraints.

OPA never executes an action. M1 has no automatically approved production-impact action.

### 6.7 AI Hunter

The hunter uses the existing configured local inference endpoint with:

- a separate API identity where supported;
- concurrency `1`;
- bounded queue and request TTL;
- bounded context and output;
- no tools or MCP;
- no model-managed memory;
- no raw secrets;
- circuit breaker and deterministic fallback.

Its input separates system instructions from `UNTRUSTED_EVIDENCE`.

Its output schema contains:

- `hypotheses[]`;
- `supporting_evidence_ids[]`;
- `refuting_questions[]`;
- `narrative`;
- `limitations[]`.

Unknown evidence IDs, action fields, commands, tool calls, and schema extensions invalidate the output.

LLM failure never blocks deterministic incident creation or manual containment.

### 6.8 `agmind-actuatord`

Implementation target: small Go host service, separate from observation.

Responsibilities:

- accept only a versioned `TemporaryEgressDenyIntent`;
- independently resolve the target and construct a `PreparedTemporaryEgressDenyPlan`;
- durably journal the complete prepared-plan hash before approval;
- expose pending plans only to the local administrative CLI;
- authenticate approval through Unix peer credentials and an installer-created admin group;
- atomically consume a one-use approval;
- re-resolve the exact container and network namespace;
- compare all preconditions;
- open a netlink connection explicitly bound to the approved network namespace file descriptor;
- install the owned nftables table/set/rule with a native timeout;
- verify the exact owned rule;
- record apply, verification, expiry observation, and errors.

Forbidden:

- TCP listener;
- arbitrary shell;
- arbitrary nftables expressions;
- arbitrary network namespace target;
- Docker mutations;
- filesystem mutation;
- process kill;
- rule persistence after reboot;
- accepting model output.

The intent may contain only the full container ID, exact destination IPv4 address, TTL, evidence IDs, policy/rule versions, and the inventory facts observed by Core. It may not contain PID, network namespace path/inode, interface, nftables expression, or host command. Those fields are resolved by the actuator and become part of the prepared plan shown for approval.

The actuator independently enforces non-configurable M1 hard limits:

- the only accepted verb is `temporary_egress_deny`;
- TTL is 30–300 seconds, default 120 seconds;
- approval expires after 5 minutes;
- at most one active deny per container generation;
- at most five active denies per host;
- destination must be one public unicast IPv4 address;
- loopback, link-local, multicast, RFC1918, Docker infrastructure, and configured management destinations are always rejected;
- target network mode must be an unshared Docker bridge namespace;
- target must not be privileged or have `CAP_NET_ADMIN`;
- target network namespace inode must be unique among running Docker containers;
- a rejected, expired, or stale plan is never automatically retried or retargeted;
- new intents are rate-limited independently of Core and OPA.

### 6.9 `agmindctl`

M1 approval is deliberately local CLI, not a web button.

The command displays deterministic fields:

- stable target identity;
- image/spec digest;
- exact destination;
- evidence IDs and detector names;
- coverage state;
- TTL;
- expected impact;
- expiry behavior;
- complete plan hash.

Attacker-controlled text and AI narrative are excluded from the approval prompt.

Supported commands:

- `agmindctl status`;
- `agmindctl coverage`;
- `agmindctl incident show <id>`;
- `agmindctl proposal show <id>`;
- `agmindctl proposal approve <id>`;
- `agmindctl proposal reject <id>`;
- `agmindctl actions list`;
- `agmindctl kill-switch enable`.

## 7. Canonical event envelope

Required fields:

```text
event_id
event_type
schema_version
source_id
source_version
host_id
boot_id
source_sequence
event_time
ingest_time
clock_uncertainty_ms
container_id
container_start_time
release_id
inventory_generation
normalized_fields
redaction_flags
coverage_flags
source_payload_hash
source_signature
```

Identity fields may be absent only when the source cannot observe them. Missing identity lowers coverage and prevents containment.

## 8. Deterministic M1 correlation

The proof-bearing refinement of this section is frozen in
[`2026-07-29-task6-correlation-proof.md`](2026-07-29-task6-correlation-proof.md).
Where the original text below speaks of fresh observer enrichment, the
authoritative input is a protected signed `pcc_correlation_snapshot`; live
inventory is never replay authority.

The first containment candidate requires both:

1. A curated Falco event such as a shell/downloader process opening an outbound connection, including an exact destination IPv4 address.
2. Fresh observerd enrichment that uniquely maps the Falco container ID prefix to a full running Docker ID and authoritative Docker generation, including supported unshared network mode and release identity.

The Falco event and Docker inventory are independent trust inputs, but they are not two independent threat detectors. Because M1 always requires exact local human approval, this is acceptable for the first vertical slice. Future automatic containment requires at least two independent fresh detection sources and is outside M1.

Additional gates:

- the Falco event and Docker inventory are fresh;
- no critical coverage gap overlaps the interval;
- inventory is fresh;
- destination is a single IPv4 address;
- destination is not loopback, link-local, RFC1918, Docker infrastructure, or an operator allowlist entry;
- target is not `network_mode: host`;
- requested TTL is within policy bounds;
- target generation is still running;
- candidate is not in cooldown.

The LLM cannot create, strengthen, or unblock this candidate. It may only explain evidence or identify uncertainty.

## 9. Action state machine

```text
PROPOSED
  -> POLICY_ADMITTED
  -> PREPARED
  -> APPROVED
  -> APPLIED
  -> VERIFIED
  -> EXPIRED

Any precondition mismatch -> STALE_ABORT
Any pre-apply failure     -> REJECTED
Partial/uncertain apply   -> FAILED_DIRTY + kill-switch + critical alert
Explicit operator denial -> REJECTED
Approval timeout         -> EXPIRED_UNAPPLIED
```

The action is a saga with explicit compensation/expiry behavior, not an ACID transaction.

## 10. Network-namespace containment

M1 avoids host-wide source-IP rules.

Apply sequence:

1. During `PREPARED`, resolve the full container ID and validate the submitted inventory facts.
2. Through the private observerd lookup, obtain the current Docker identity, init PID, network mode, privilege/capability flags, and inventory revision.
3. Verify the PID start identity and cgroup membership, open `/proc/<pid>/ns/net`, identify its inode, and reject a namespace shared by another running container.
4. Close the preparation namespace descriptor, then construct and journal the complete prepared plan, including the namespace inode and all preconditions. Holding the descriptor across human approval is forbidden because it could keep an obsolete namespace alive.
5. Return the deterministic prepared-plan display and hash for local approval.
6. Immediately before apply, repeat the private lookup, revalidate PID start/cgroup membership, open a new namespace descriptor, and compare Docker start time, image identity, spec hash, inventory revision, running state, PID identity, and namespace inode.
7. Open a netlink/nftables connection explicitly bound to the newly opened approved namespace descriptor; the actuator process itself never changes network namespace.
8. In one atomic netlink batch, create or validate the canonical IPv4 ruleset and add the destination element:

   ```text
   table:  ip agmind_pcc
   chain:  output, type filter, hook output, priority -10, policy accept
   set:    blocked_v4, type ipv4_addr, flags timeout
   rule:   ip daddr @blocked_v4 counter drop
   element timeout: approved TTL
   ```

   Every object includes the installation/action ownership marker where nftables supports comments/user data. If an existing object with the same name has a different structure or owner marker, apply fails closed.
9. Verify the complete structure, exact destination element, counter, and timeout through the same namespace-bound connection.
10. Close the connection and namespace descriptor.
11. Record the observed result.

Properties:

- container restart destroys the old namespace and containment state;
- an IP reused by another container is not targeted;
- actuator death does not prevent timeout;
- unrelated host and Docker firewall chains are untouched.

Expiry removes the destination set element. The empty AGmind-owned table, chain, set, and rule may remain until explicit cleanup or namespace destruction; they have an accept policy and no effect without an element.

M1 supports IPv4 exact destination only. It does not block CIDR ranges, domains, ports, protocols, or inbound traffic.

## 11. API and management exposure

Core API defaults:

- bind to loopback or a dedicated management network;
- authentication required for every non-health endpoint;
- no wildcard CORS;
- rate limits;
- bounded pagination;
- escaped attacker-controlled fields;
- no API endpoint for approval or policy modification in M1.

The approval boundary is the host-local CLI and actuator Unix socket.

The installer generates a random API token and stores it in a root-owned file mounted read-only where needed. It is never stored in the main YAML configuration or an image. M1 supports explicit token rotation through the local CLI.

## 12. Failure behavior

| Failure | Required behavior |
|---|---|
| LLM unavailable or invalid output | Deterministic pipeline continues; incident states AI enrichment unavailable |
| OPA unavailable | No new admitted plans |
| Core unavailable | Observers use bounded spool; no new actions; existing nft timeout continues |
| Observer unavailable | Coverage becomes stale; no new action candidate |
| Actuator unavailable | No new mutations; already applied rule expires |
| Docker event gap/restart | Full reconcile before candidate/action processing |
| Falco drop/restart | Coverage gap event; overlapping candidate cannot be admitted |
| Duplicate/out-of-order event | Idempotent ingest and deterministic ordering rules |
| Disk pressure | Drop routine evidence first; preserve coverage/incidents/action journal |
| Clock change | Ordering uses boot ID and monotonic sequence; TTL uses monotonic/kernel timeout |
| Container redeploy | Pending plan becomes `STALE_ABORT` |
| Approval replay | One-use nonce rejects replay |
| Core sends an altered intent after preparation/approval | Prepared-plan hash and one-use approval mismatch reject apply |
| Partial/uncertain nft apply | `FAILED_DIRTY`, disable new actions, critical local alert |
| Host reboot | Do not restore temporary containment automatically |

## 13. Resource profiles

M1 targets the `lite` profile so it can coexist with the current AGmind stack.

Initial engineering budgets to validate, not marketing guarantees:

- Core, OPA, adapters, and host services combined: target below 2 GiB RAM outside Falco and the existing model server;
- AI concurrency: `1`;
- AI queue: bounded with expiration;
- evidence storage default: 7 days or 5 GiB, whichever limit is reached first, with configurable lower limits and signed retention tombstones;
- no full PCAP;
- no always-on ClamAV;
- no Suricata in the default M1 profile;
- Trivy and additional scanners are later serialized jobs, not part of this vertical slice.

The installer must refuse active containment if required capabilities, nftables, namespace handling, or coverage checks fail.

## 14. Repository direction

The existing Python prototype is not extended into the privileged architecture. It remains available for reference until M1 acceptance.

New top-level structure:

```text
contracts/                 versioned JSON schemas and fixtures
host/
  observerd/               Go read broker and source envelope service
  actuatord/               Go typed actuator
core/
  agmind_immune/           Python deterministic core and AI investigator
policies/                  OPA bundles and policy tests
deploy/
  compose/                 unprivileged Core/OPA/Falco deployment
  systemd/                 host service units
cmd/
  agmindctl/               local administrative CLI
tests/
  adversarial/             hostile model/injection/replay/stale-target corpus
  integration/             Linux namespace/nftables tests
  replay/                  event and decision fixtures
legacy/                    created only when migration is explicitly approved
```

M1 does not move or delete the existing `app/` tree. Migration is a later explicit task.

## 15. Acceptance criteria

### End-to-end

- A controlled Linux lab scenario produces both deterministic signals.
- An incident and exact candidate are created without LLM authority.
- A malicious LLM response cannot change the candidate or create an action.
- Local approval binds to the complete plan hash.
- The actuator applies the deny only inside the exact container network namespace.
- The target connection is blocked.
- An unrelated container can still reach the destination.
- The deny expires without Core or actuator intervention.
- The complete evidence, policy, approval, apply, verification, and expiry chain is replayable.

### Adversarial

- Prompt injection in command arguments, image labels, filenames, and model output does not expand authority.
- Unknown model output fields are rejected.
- Replayed approval is rejected.
- Modified action parameters are rejected.
- Container redeploy before apply causes `STALE_ABORT`.
- PID, container IP, and container name reuse cannot retarget the action.
- Missing identity, stale inventory, or coverage gap prevents action.
- Core compromise simulation cannot bypass local approval.
- A direct Docker mutation is impossible from Core because the socket is absent.

### Failure safety

- LLM failure leaves deterministic detection operational.
- OPA failure prevents admission.
- Core crash after apply does not make the deny permanent.
- Actuator crash after apply does not make the deny permanent.
- Reboot does not restore the deny.
- Disk and queue pressure produce explicit degraded coverage.

### Quality

- All contracts have schema tests and malformed-input tests.
- Policy has table-driven allow/deny tests.
- Target resolution has stale/reuse tests.
- Action transitions are idempotent and replay-tested.
- Privileged parsers have size limits, timeouts, and fuzz/property tests where applicable.
- No success claim is made from simulation-only tests; Linux integration output is required.

Darwin runs only contract, Core, OPA, replay, and simulation/unit tests. Falco, Docker-generation, PID/cgroup, network-namespace, and nftables tests must report unsupported or be skipped fail-closed on Darwin; they can never satisfy M1 acceptance.

The mandatory integration runner is a dedicated rootful Linux VM with systemd, cgroup v2, nftables, Docker bridge networking, and the pinned Falco engine/rules. Its native test matrix includes:

- real Falco output-field validation and successful/non-blocking `connect` handling;
- missing and ambiguous container-prefix rejection;
- redeploy and PID-reuse races;
- shared network namespace rejection;
- privileged and `CAP_NET_ADMIN` target rejection;
- target-only blocking with an unrelated control container;
- actuator death immediately after apply;
- kernel timeout expiry without Core/actuator;
- collision with a foreign nftables object of the same name.

## 16. Deferred specifications

The following are separate projects after M1:

1. Additional sensor profiles: Trivy, CrowdSec, YARA-X, Suricata, ClamAV.
2. Authenticated web approval and multi-user RBAC.
3. AI/MCP Action Gateway with non-bypassable routing.
4. Detection rule forge with replay, shadow mode, and signed promotion.
5. Desired-state and backup recovery contracts.
6. Deception-lite.
7. MicroVM validation laboratory.
8. IPv6, cgroup-BPF enforcement, Kubernetes, and multi-node evidence anchoring.

None of these may be silently folded into M1.

## 17. Final rationale

This milestone is intentionally narrow but not cosmetic. It exercises the hardest product boundary:

```text
hostile evidence
  -> untrusted model
  -> deterministic facts and policy
  -> exact human authorization
  -> minimal privileged effect
  -> independent expiry
  -> replayable proof
```

If this boundary is correct, additional sensors and recovery adapters can be added behind stable contracts. If it is wrong, adding more AI, MCP, scanners, and automation only increases the blast radius.
