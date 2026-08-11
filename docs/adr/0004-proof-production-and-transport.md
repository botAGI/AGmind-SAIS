# ADR 0004: Proof production and transport

- Status: accepted
- Date: 2026-07-29 (recorded retroactively on 2026-08-11)

## Context

[ADR 0003](0003-correlation-proof.md) defines the deterministic PCC correlation proof: a signed
snapshot binding a Falco connect trigger to the host's container and network state and to the
safety pin set. This ADR records how that proof is produced and moved: the request contract
between Core and the observer, the observer-side production substrate (host inventory, safety
pins, durable journals, boot-boundary evidence), and the Core-side delivery state machine.

The governing invariant of this work: produce exactly one protected PCC correlation snapshot for
an exact, still-unacknowledged, candidate-capable trigger, and transport it into Core durably
**before any source acknowledgement advances past that trigger**. ACK is destructive — it
authorizes observer-side cleanup — so an unproven trigger must never be acknowledged.

Scope fence: nothing in this scope holds policy, model, approval, containment, actuator,
detector-rule, or Docker mutation authority (see [ADR 0001](0001-proof-carrying-containment.md)
for the M1 invariants). Retention and historical projection of accepted proofs are recorded in
[ADR 0005](0005-historical-projection-authority.md); the linearization boundary that consumes the
accepted stream is recorded in [ADR 0006](0006-trusted-linearization-boundary.md).

## Decisions

### Core alone owns the correlation TTL, fixed at 120 seconds

`requested_ttl_seconds` in the snapshot request is a Core-owned constant of 120 seconds. It is
not caller, model, policy, operator, environment, or configuration input, and the Core-side
journal rejects any recovered request whose TTL is not exactly 120. The TTL bounds how long a
containment intent can live; letting any external party choose it would let that party extend
containment authority. Pinning it in Core removes an entire input channel from the trust surface.
Making the TTL a caller/policy/config input was explicitly forbidden.

Consequences: the wire contract field admits 30–300, but every producer and consumer in Core pins
120, and policy evaluation additionally clamps to `min(requested, 120)`. Changing the TTL means
changing Core code, not configuration.

### The request is frozen at five fields with rederivable canonical bytes

`PCCCorrelationSnapshotRequestV1` carries exactly `schema_version`, `trigger_event_id`,
`trigger_content_sha256`, `trigger_source_sequence`, and `requested_ttl_seconds`. No deadline,
selection-time, or canonical-bytes field may be added. The canonical request bytes must be
rederivable from the persisted nested request object alone: `canonical_json(recovered.request)`
byte-equals the original, and its SHA-256 equals the stored `request_sha256`.

Byte-identical retry across crash and restart is the idempotency mechanism; any timestamp-like
field would make recovered requests diverge from the original bytes and break exact-retry
detection, and persisting the canonical bytes redundantly invites divergence between the copy and
the source of truth. Both were rejected. The Core journal record therefore stores only schema,
operation key, request hash, the nested request, phase, and phase-appropriate snapshot fields;
recovery re-canonicalizes and recomputes the hash. The request hash deliberately carries no
domain-separation prefix at this boundary.

### Operation key, byte-identical exact retry, and durable conflict fencing

The operation key is exactly `pcc_correlation_snapshot:<trigger_event_id>`. An exact retry must
present byte-identical canonical request bytes (same request SHA-256); the observer revalidates
receipt, spool event, envelope, request hash, and normalized hash before returning the existing
publication as `Created: false`. A **different** request hash arriving for an existing operation
key is a durable conflict: the observer persists `mutation_read_only` with reason
`observer_pcc_request_conflict` before returning the conflict.

One trigger event must never yield two different proofs; a conflicting request for the same key is
evidence of a forged or corrupted requester, so the observer fails closed permanently rather than
serving either version. Last-writer-wins and serving the stored receipt on hash mismatch were
rejected. Core must persist its request before POSTing and re-send the exact recovered bytes on
retry — never a regenerated object; the API maps the conflict to HTTP 409, which Core treats as
fatal.

### Persistent mutation_read_only is an absolute hard fence

When observer state is persistently `mutation_read_only`, PCC publication performs nothing at all:
no trigger lookup, no sequence reservation, no signing, no spool append, no receipt append, no
ACK. It returns a typed unavailable error immediately after the state snapshot. A fenced
observer's signing authority is suspect; producing even a signed "failed" snapshot would exercise
the very authority the fence exists to freeze. Publishing a signed failed-union snapshot with
reason `mutation_read_only` was explicitly rejected for the local persistent fence — the enum
value stays decodable in the contract (remotely produced or historical records must remain
parseable), but the local producer never synthesizes it.

Consequences: the API maps the fence to HTTP 503 with a fixed code; Core treats 503 as retryable,
leaving the journal phase `selected`, the ACK journal empty, and the trigger unacknowledged until
an externally recovered retry succeeds.

### Trigger authority is the exact unacknowledged spool item

The only valid trigger for a snapshot is a still-unacknowledged spool item matched on all three of
(`source_sequence`, `event_id`, `content_sha256`). The trigger projection is constructed only from
the signed envelope's data; caller-forged normalized trigger facts are rejected. The trigger must
strictly decode as `FalcoConnectV1` with `event_type=falco_connect`, a successful connect,
`InvestigationOnly=false`, and complete authoritative fields.

Core is a requester, not an evidence authority: if Core could describe the trigger, a compromised
Core could manufacture proofs about events that never happened. Trusting request-supplied trigger
facts, or matching on `event_id` alone, were rejected. The spool gained exact lookup helpers that
must return exactly one unacknowledged match or fail closed; an ACKed, missing, or mismatched
trigger is a typed failure, never a partial match.

### Docker read surface, snapshot bounds, and atomic inventory generations

Three related decisions govern the host evidence the proof embeds:

- **Closed read-only Docker surface.** The observer's `DockerReader` interface exposes exactly six
  methods — `ContainerInspect`, `ContainerList`, `Events`, `ImageInspect`, `NetworkInspect`,
  `NetworkList` — asserted by reflection in a test, so adding a method breaks the build. Network
  inventory is one unfiltered `NetworkList` followed by one exact-ID `NetworkInspect` per returned
  network; no filters, no partial selection. Any invalid IPAM fact rejects the whole walk rather
  than being skipped: skip-on-malformed would let an attacker make a network invisible by making
  it malformed.
- **Hard bounds, never truncation.** The normalized network snapshot is bounded at 64 networks,
  128 total subnets, 128 total gateways, 32 subnets or gateways per network, 16 KiB canonical
  network array, and 24 KiB for the complete normalized snapshot. Exceeding any bound is a
  validation failure. Truncation was rejected because a truncated proof silently omits networks;
  a host with more than 64 Docker networks cannot produce a complete snapshot, and that is a
  deliberate failure mode.
- **One atomic generation.** The container walk and the global network walk complete before the
  write lock; under one final lock a single next-generation number stamps every identity, and one
  disk state is persisted once and adopted once. Any walk or persistence error leaves the
  reconcile gap open with the previous records and network bytes intact and paired — retain
  prior, never partial-adopt. The correlation snapshot is taken under one read lock, requires no
  open reconcile gap, requires the record's generation to equal the state generation, and returns
  a deep clone. A proof must describe one consistent instant; mixing a container record from
  generation N with networks from generation N+1 would describe a host state that never existed.

### Safety pins: fixed paths, content digest, strict bounded denylists

The four pin inputs are compile-time constants — `/etc/falco/rules.d/agmind-pcc.yaml`,
`/usr/share/agmind-sais/ipv4-special-use.csv`, `/etc/agmind-sais/operator-denylist.json`,
`/etc/agmind-sais/management-destinations.json` — each read through the protected single-link
regular-file reader (root-owned, no symlink traversal). One same-boot publication attempt takes
exactly one immutable, deeply cloned pin snapshot; any input error yields no partial snapshot. The
paths are deliberately **not** in `Config`: if pin locations were configurable, whoever controls
observer configuration could redirect the trust inputs to files they control. Adding the paths to
`Config` for testability was rejected; tests inject a reader seam instead.

Two hardening decisions ride on the pin set:

- The raw bytes of `ipv4-special-use.csv` must hash to exactly
  `e3e39e76d00b1677335db8e9a805c7b9480ea2f4dc9e33f0b93cd3a905128d73`; any other digest fails the
  pin snapshot entirely. The registry defines which destinations are never containable or
  attributable, so a swapped registry could reclassify attacker infrastructure as special-use.
  Trusting ownership/mode alone was rejected; the digest is checked in addition to the
  protected-read policy. Updating the registry requires a coordinated change of the shipped CSV
  and both digest constants (observer and contracts packages).
- Operator and management denylists decode strictly (both `denied_addresses` and
  `denied_networks` required, unknown properties rejected), canonicalize IPv4 addresses and
  prefixes to sorted unique values, reject IPv4-mapped IPv6 and any count above 128, and are
  hashed under domain-separated prefixes (`AGMIND_OPERATOR_DENYLIST_V1`,
  `AGMIND_MANAGEMENT_DENYLIST_V1`). One malformed CIDR or a 129th entry fails the whole pin
  snapshot — no partial load.

### Observer state V5 anchors the PCC journals; migration only when both files are absent

Observer state V5 adds exactly six fields — `pcc_boundary_count`, `pcc_boundary_bytes`,
`pcc_boundary_head_sha256`, `pcc_receipt_count`, `pcc_receipt_bytes`, `pcc_receipt_head_sha256` —
with empty head hashes initialized to the journal zero hash. Migration from V4 (or any earlier
version) to V5 is legal only when both fixed PCC journal files (`spool/pcc-boundaries.agf`,
`spool/pcc-receipts.agf`) are absent; a pre-existing unanchored journal file fails closed as
corruption and leaves the durable legacy state bytes unchanged.

A journal file that exists before its state anchor exists is unowned history that could have been
planted; the anchor in signed state is what makes journal content authoritative (the same
fresh-state producer-boundary principle used for the earlier V3-to-V4 receipt migration).
Adopting or truncating a pre-existing journal during migration was rejected. Every recovery
recomputes count/bytes/head from frames and must match the V5 anchor exactly; unanchored tails,
complete or incomplete, are rejected — never truncated and adopted.

### Boot-boundary archive: derived transition path, commit ordering, capped key metadata

Boot-boundary evidence lives in a dedicated append-only AGF journal at
`<state>/spool/pcc-boundaries.agf` (schema `agmind.pcc-boundary-archive-record.v1`; bounds 1,024
records, 64 MiB verified bytes, 128 KiB frame). Each record stores the exact signed boundary
envelope plus an optional rotation companion envelope. The record **never** stores an A/B/C
transition-path discriminator: the path is re-derived at chain time from the signed envelopes'
grammar (signatures, boot IDs, key epochs, pair ordering and adjacency) and validated via
`PCCBootTransitionChainSHA256`, requiring the final hop to reach the current boot ID. Storing a
claimed path type would make the claim, not the cryptography, the authority; deriving it from
signed material means a forged or reordered history cannot assert a valid path. Retaining the
envelopes separately from the spool lets ordinary ACK cleanup proceed without destroying
cross-boot proof material.

Ordering: for a plain boot transition (path A) the archive record is appended before the boundary
state is marked committed; for rotation paths B/C the publication mutex is held through both
durable events and one archive record is appended only after the adjacent transition/epoch-start
pair is fully present and revalidated. The archive anchor is persisted in state before ordinary
ACK cleanup may remove the corresponding spool frames; any uncertain append or anchor persists
`mutation_read_only`. If cleanup could remove boundary frames before they were archived and
anchored, a crash in that window would permanently destroy the only evidence linking two boots.
Boundary commit latency therefore includes an archive fsync, and daemon startup fails if archive,
state, and spool evidence cannot be reconciled.

Finally, this work must not expand `PublicKeyMetadata`'s cap of 16 key epochs: cross-boot chains
authenticate from archived signed envelopes, not from a grown live key set. Expanding the cap to
cover longer histories was rejected because it would widen the live trust surface; a test asserts
the archive does not expand the metadata.

### Cross-boot production emits only an authenticated failed snapshot

When the trigger's boot ID differs from the current state boot ID, the producer emits only a
failed snapshot with `failure_reasons=["observer_boot_changed"]`, carrying the derived
authenticated boot-transition chain (count and chain hash), and performs no Docker walk, no pin
snapshot, no freshness check, no routine drop, and no same-boot readiness call. Post-reboot host
state cannot testify about a pre-reboot event — a complete snapshot would be a lie — but the
failure itself must be provable: the signed chain shows observer identity continuity across the
reboot rather than an attacker-forced identity reset. A best-effort complete snapshot from
current state, and a bare unauthenticated failure, were both rejected. Core's delivery path
accepts an ordered cross-boot proof for completion; an invalid chain never reaches
`proof_observed`.

### Specialized receipts: dedicated permanent journal, priority-tier snapshot

Each publication writes one specialized receipt — exactly `operation_key`, `request_sha256`,
`snapshot_normalized_sha256`, `snapshot_event_id`, `snapshot_content_sha256`, with no sequence
field — to a dedicated journal `<state>/spool/pcc-receipts.agf` (schema
`agmind.pcc-publication-receipt-record.v1`; bounds 4,096 records, 16 MiB verified bytes, 128 KiB
frame). The code is deliberately independent of the generic `ControlReceiptJournal` (a test
asserts PCC receipts cannot use it): the receipt is the exact-retry and ACK-authorization
authority and must bind the request bytes, the produced envelope's normalized content, and the
spool item identity — nothing else. Request and normalized hashes are independently recomputed on
recovery, and receipt reserve/append happens under the publication mutex atomically with snapshot
publication; ambiguous durability persists `mutation_read_only`.

Receipts are permanent append-only audit history. ACK never removes or compacts them (compacting
receipts with their spool items was rejected): startup accepts an anchored historical receipt
whose spool item is gone, revalidates every receipt for a still-live snapshot, and rejects any
live snapshot lacking its exact receipt. Conversely, history never authorizes publication — new
appends, exact-retry lookups, and ACK authorization all require an exact live unacknowledged
spool binding, or replayed history could mint new signed evidence. Before ACK cleanup may delete
any `pcc_correlation_snapshot` frame, a unique specialized receipt must match the spool item's
event/content hashes and the envelope's normalized hash. The 4,096-receipt cap is therefore a
lifetime cap on PCC publications per state lineage; hitting it is a hard stop, not a rotation.

Relatedly, `pcc_correlation_snapshot` is in the priority event-type set: appended at
`PriorityTier`, immune to routine quota and cleanup, removable only by receipted ACK. The proof is
the product of the whole pipeline; routine spool pressure must never evict it before Core has
durably accepted and acknowledged it.

### One publication mutex, one fixed order, one clock sample

Same-boot production runs entirely under the existing publication mutex in a fixed order:
validate/canonicalize the request and hash it; receipt retry/conflict check; state snapshot
(hard-fence check); exact trigger lookup; one inventory lock and clone; one pin snapshot; one UTC
sample truncated to microseconds and used identically for event, ingest, and decision times;
choose `S = LastSequence+1`; prove coverage through `S-1`; reserve exactly `S`; sign with the
sampled timestamp via a private externally-sampled signing path (ordinary `EnvelopeSigner.Wrap`
timestamp behavior unchanged); append snapshot and receipt; anchor state; release. Any ambiguous
durability persists `mutation_read_only`. The complete snapshot enforces the 24 KiB bound without
truncation.

One mutex plus one clock sample plus one pre-proved sequence makes the snapshot describe a single
consistent instant with a gap-free evidence prefix; proving coverage through `S-1` means the
proof's position in the stream is itself evidenced. Multiple clock samples and post-hoc sequence
assignment were rejected. PCC publication contends with all other publications on one mutex — a
throughput ceiling accepted for correctness — and a crash after reserve but before anchor is
ambiguous durability that fences the observer.

### Transport: Core-only UDS route with exact status semantics, exact-byte client

`POST /v1/events/pcc-correlation-snapshot` is registered only in the Core-only API under
`RequirePeer(coreMutationPeerAuthorized)`; the peer is authenticated before the (possibly
blocking) body is read, and there is no public-socket exposure. Only Core may request proofs; UDS
peer-credential checks bound the trust boundary to the local Core UID, and authenticating before
the body read prevents an unauthenticated peer from tying up the handler with a slow body. The
handler strictly reads one bounded canonical request and maps outcomes exactly: created to 201,
exact retry to 200, conflict to 409, hard-fence unavailable to 503 with a fixed code, returning
the exact `CoreEventV1` JSON.

On the Core side, `publish_correlation_snapshot` POSTs the exact canonical bytes — no mutation,
no redirects, no content-encoding — with the request bounded to 4 KiB and the response to
`MAX_CORE_EVENT_RESPONSE_BYTES`. Only 200/201 with exact JSON succeed; a typed 503 maps to
`DeliveryRetryableError` and 409 to `DeliveryFatalError`. The tight request bound reflects the
frozen five-field request: any schema change that grows past 4 KiB breaks transport by design.

### Core persists a three-phase correlation request journal in the evidence root

Core records each PCC request in `correlation-requests.agf` inside the evidence root's exact
artifact allowlist (schema `agmind.correlation-request-state.v1`), with a monotone phase machine
`selected -> proof_observed -> completed`: no skips, no rollback, no post-completion mutation;
exact repeated transitions are idempotent and write no new frame. The journal has its own
acquire/seal/append-uncertain/release lifecycle patterned on ACK-journal ownership and
deliberately does **not** reuse ACK commitment or SQLite state (rejected: independent failure
domains). `select()` fsyncs before returning and requires TTL 120 plus trigger-ref triple
equality; `mark_proof_observed` requires a protected PCC `EvidenceRef` after the trigger;
snapshot fields are an all-or-none pair valid only in `proof_observed`/`completed`. Startup
records the file identity and rejects substitution, disappearance, or unknown root artifacts; the
controller requires the journal's `SegmentStore` identity to equal the acceptance coordinator's
(same evidence root).

The request must be durable before the POST so a crash cannot produce two different requests for
one trigger; keeping it in the evidence root binds request state to the same integrity domain as
the evidence it governs. Recovery replays the legal phase union per operation, re-canonicalizes
the nested request, recomputes hash and operation key, and refuses an unproven tail.

**Superseded detail — record cap.** The original design fixed this journal at 4,096 records.
Current code supersedes that with `_MAX_RECORDS = 12_291` (3 × 4,097): the planned cap counted
operations, but each operation writes up to three frames (`selected`, `proof_observed`,
`completed`), so the cap was re-based on frames to fit a full three-phase lifecycle for the
intended operation count. Tests assert the 12,291st record is inclusive and the next fails. The
current bounds are 12,291 records, 16 MiB verified bytes, 64 KiB frame payload.

### Delivery ordering: proof durably accepted before any source ACK

A candidate-capable trigger (`falco_connect`, `successful_connect=True`,
`investigation_only=False`) is intercepted after durable acceptance and coverage application but
before any ACK. Core then: selects (fsyncs) the request; POSTs the exact canonical bytes; treats
the response only as a target identity — never permission to skip source order; fetches from the
trigger sequence onward, generically accepting every intervening event under strict increasing
contiguous authenticated stream semantics; accepts the snapshot via `accept_pcc` only for the
exact returned event/content pair under the persisted request authority; persists
`proof_observed`; and only then drives the ACK journal over trigger, intervening refs, and
snapshot in exact source order, marking `completed` after observer ACK confirms through the
snapshot.

If the trigger were ACKed before its proof was durably in Core, a crash or fenced observer could
permanently orphan the trigger with no proof and no evidence; preserving source order prevents
the direct POST response from becoming a side channel that skips intervening evidence. ACKing the
trigger generically and fetching the proof out of band was rejected — the ordered trace (trigger
accept, selected, post, intervening accepts, pcc accept, proof_observed, ack, completed) is
asserted exactly in tests.

Consequences: a recovered `proof_observed` skips the POST and resumes only ACK; `completed` is
terminal and idempotent; a 503 leaves the phase `selected`, the ACK journal empty, and the
trigger unacknowledged. On startup, recovered `selected` requests are resumed before any
unrelated later trigger is fetched, so a pending proof obligation is always driven to completion
ahead of new work. Existing uncovered-gap ceilings still block ACK, and non-candidate and
investigation-only events keep the unchanged generic loop. Restart at any crash point converges
with a byte-identical POST body.

## Current state (2026-08-11)

Verified in code:

- TTL 120 as a Core constant: `core/agmind_immune/ingest/service.py:89`; journal rejection of any
  other TTL: `core/agmind_immune/ingest/correlation_journal.py:135` and `:982`; policy clamp:
  `core/agmind_immune/proof.py:898`. Note the wire contract field itself admits 30–300
  (`core/agmind_immune/contracts.py:701`); the pin lives in the producers/consumers, not the
  schema.
- Five-field request and unprefixed request hash: `internal/contracts/pcc_correlation_proof.go:14`
  and `:66-73`; construction at `core/agmind_immune/ingest/service.py:3170-3175`; record shape at
  `core/agmind_immune/ingest/correlation_journal.py:111`.
- Operation key and conflict fencing: `host/observerd/pcc_publish.go:743`;
  `observer_pcc_request_conflict` persistence at `host/observerd/pcc_receipts.go:454,551,655,785`;
  409 mapping at `host/observerd/pcc_api.go:72`; fatal classification at
  `core/agmind_immune/ingest/service.py:347`.
- Hard fence: `host/observerd/pcc_publish.go:21,227,488-495`; 503 mapping at
  `host/observerd/pcc_api.go:78-87`; retryable classification at
  `core/agmind_immune/ingest/service.py:339`.
- Trigger triple lookup: `host/observerd/pcc_receipts.go:913` (`Spool.LookupUnacknowledged`) and
  `:965` (`LookupUnacknowledgedEvent`); validation flow in `host/observerd/pcc_publish.go`.
- Docker surface and inventory: six-method interface at `host/observerd/docker.go:52-60` with the
  reflection test at `host/observerd/inventory_test.go:458-475`; snapshot bounds at
  `internal/contracts/validation.go:541-542,561,578,585,893`; atomic generation and snapshot at
  `host/observerd/inventory.go:96,1014-1023`.
- Pins: constant paths and all-or-nothing load at `host/observerd/pcc_pins.go:17-20,127-187`;
  registry digest constants at `host/observerd/pcc_pins.go:23` and
  `internal/contracts/pcc_correlation_proof.go:21`; denylist bound at
  `internal/contracts/validation.go:597-598` and domain constants at
  `internal/contracts/pcc_correlation_proof.go:24-25`.
- State V5 and migration gating: `host/observerd/envelope.go:31,91-96,615-627,631-644`;
  anchor-consistency recovery at `host/observerd/pcc_receipts.go:180-207`.
- Boundary archive shape and bounds: `host/observerd/pcc_boundary_archive.go:19-21,63,127-135`;
  chain domain constant at `internal/contracts/pcc_correlation_proof.go:26`. Key-epoch cap:
  `host/observerd/envelope.go:2347,3486`.
- Cross-boot failed snapshot: `host/observerd/pcc_publish.go:498`.
- Receipts journal: `host/observerd/pcc_receipts.go:19-21,32-36,91`; ACK gating on
  `pcc_correlation_snapshot` frames at `host/observerd/spool.go:1873,2145,2674,2827`; priority
  tier at `host/observerd/envelope.go:1909-1919` and `host/observerd/spool.go:651-652`.
- Ordered production under the mutex: `host/observerd/pcc_publish.go:227-495`.
- Transport route and client: `host/observerd/core_api.go:451,473-475`;
  `host/observerd/pcc_api.go:72-94`; Core client with the 4 KiB request bound at
  `core/agmind_immune/ingest/service.py:702-710`.
- Core journal: `core/agmind_immune/ingest/correlation_journal.py:66-69,111,135,669-685`; root
  allowlist entry at `core/agmind_immune/evidence/segments.py:141`.
- Delivery ordering: `core/agmind_immune/ingest/service.py:3170-3175,3316,3505,3570`;
  `accept_pcc` and `accept_pcc_for_correlation` at
  `core/agmind_immune/ingest/service.py:171,239-246`.

Unverified: the boundary-archive **commit-ordering** integration (archive append before boundary
state commit, anchor before ACK cleanup) has not been traced line-by-line; the append/anchor path
exists in `host/observerd/pcc_boundary_archive.go`, but the ordering claims above rest on the
design record, not on cited code.

Superseded: the 4,096-record Core journal cap, replaced in code by 12,291 records
(`core/agmind_immune/ingest/correlation_journal.py:67`, tests at
`core/tests/ingest/test_correlation_journal.py:679,715-723`). All observer-side bounds (boundary
archive 1,024 records / 64 MiB / 128 KiB; receipts 4,096 records / 16 MiB / 128 KiB) match the
original design.

## Notes

- Crash-point matrix the delivery state machine must converge across, with a byte-identical POST
  body after restart: `after_trigger_append`, `after_selected`, `after_post_response`,
  `after_intervening_append`, `after_proof_observed`, `after_ack_intent`, `after_observer_ack`.
- The frozen failed-reason union for locally producible failures includes `mutation_read_only` as
  a decodable value the local producer never emits from its own persistent fence;
  `observer_boot_changed` is the only failure reason emitted on the cross-boot branch.
- Two-sided permission contract: the four pin paths are read through the owner/mode-enforcing
  protected reader, so the installer-shipped modes for those files must be asserted against the
  reader's policy in code. The 2026-08-11 audit found exactly this class of mismatch elsewhere in
  the repo (installer 0444/0400 vs a reader requiring 0600).
- Coverage caveat: `core/tests/ingest/test_correlation_journal.py:841` declares a parameter with
  no `parametrize` decorator, so one negative security test for this journal has never executed;
  coverage claims for the correlation journal should be re-checked against executed-case counts.
- The focused acceptance gate for this work: in `./host/observerd`, the Go tests matching
  `Test(PCC|InventoryGlobalNetwork|CorrelationInventorySnapshot|ObserverStateV5|CoreAPIRoute.*PCC)`;
  the PCC test set in `./internal/contracts`; pytest over
  `core/tests/ingest/test_correlation_journal.py` and `test_correlation_delivery.py` plus the
  named service/snapshot/controller tests, and mypy over `correlation_journal.py`, `service.py`,
  `controller.py`. On this repo's hosts, Go runs only through the Makefile's containerised
  `GO_RUN`.
