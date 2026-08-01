# Task 6C Proof Production and Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce one protected PCC correlation snapshot for an exact unacknowledged candidate-capable trigger and transport it into Core durably before any source ACK advances.

**Architecture:** Observerd first extends its atomic Docker inventory and fixed root-owned pin inputs, then adds two separately anchored append-only journals for boot-boundary evidence and PCC publication receipts. The observer producer composes those substrates under the existing publication mutex, while Core persists one exact four-field request in its evidence-root operational namespace and resumes the `selected -> proof_observed -> completed` delivery state machine across crashes.

**Tech Stack:** Go 1.26.5 observerd, Moby client API v1.55, Python 3.14, Pydantic v2 strict contracts, AGF1 framed journals, Ed25519 envelopes, HTTPX over the existing Core-only Unix-domain socket, pytest.

## Global Constraints

- Scope is Task 6C only; do not add Task 6D retention/projection behavior, policy, model, approval, containment, actuator, detector-rule, or Docker mutation authority.
- Core owns `requested_ttl_seconds = 120`; it is not caller, model, policy, operator, environment, or configuration input.
- `PCCCorrelationSnapshotRequestV1` keeps exactly `schema_version`, `trigger_event_id`, `trigger_content_sha256`, `trigger_source_sequence`, and `requested_ttl_seconds`; add no deadline, selection-time, or canonical-bytes field.
- The operation key is exactly `pcc_correlation_snapshot:<trigger_event_id>`.
- Exact retry reuses byte-identical canonical request bytes; a different request hash for an existing operation key is a durable conflict and persists mutation-read-only.
- Persistent observer `mutation_read_only` is an absolute typed-unavailable/no-publication fence: no trigger lookup, sequence reservation, signing, spool append, receipt append, or ACK.
- The `mutation_read_only` failed-reason enum remains decodable, but the local producer never synthesizes it from its own persistent hard fence.
- The trigger authority is the exact still-unacknowledged spool item identified by `(source_sequence, event_id, content_sha256)`.
- Moby access is one unfiltered `NetworkList(context.Context, client.NetworkListOptions{})`, followed by one exact-ID `NetworkInspect` for every returned network; no filters or partial selection.
- Docker network bounds are 64 networks, 128 total subnets, 128 total gateways, 32 subnets or gateways per network, 16 KiB canonical network array, and 24 KiB complete normalized snapshot.
- Fixed paths are `/etc/falco/rules.d/agmind-pcc.yaml`, `/usr/share/agmind-sais/ipv4-special-use.csv`, `/etc/agmind-sais/operator-denylist.json`, and `/etc/agmind-sais/management-destinations.json`.
- Every pin is a root-owned, single-link regular file opened without symlink traversal; one same-boot attempt takes one immutable pin snapshot.
- Observer publication order is publication mutex, exact trigger lookup, one inventory lock/clone, one pin snapshot, one UTC sample, choose `S`, prove coverage through `S-1`, reserve/sign/append snapshot and receipt, then publish durable state.
- Cross-boot production emits only failed `observer_boot_changed`, derives the full authenticated A/B/C chain, and performs no Docker, pin, freshness, routine-drop, or same-boot readiness call.
- Existing `PublicKeyMetadata.Validate` remains capped at 16 epochs.
- Observer state V5 adds exactly `pcc_boundary_count`, `pcc_boundary_bytes`, `pcc_boundary_head_sha256`, `pcc_receipt_count`, `pcc_receipt_bytes`, and `pcc_receipt_head_sha256`.
- V4-to-V5 migration is legal only when both fixed PCC journal files are absent; a pre-existing unanchored file fails closed.
- Boundary archive path/schema/bounds are `<state>/spool/pcc-boundaries.agf`, `agmind.pcc-boundary-archive-record.v1`, 1,024 records, 64 MiB verified bytes, and 128 KiB frame payload.
- PCC receipt path/schema/bounds are `<state>/spool/pcc-receipts.agf`, `agmind.pcc-publication-receipt-record.v1`, 4,096 records, 16 MiB verified bytes, and 128 KiB frame payload.
- Core request journal path/schema/bounds are evidence-root `correlation-requests.agf`, `agmind.correlation-request-state.v1`, 4,096 records, 16 MiB verified bytes, and 64 KiB frame payload.
- Use focused commands only; do not run repository-wide, native-Linux, retention, or Task 6D suites.

## File Structure

- `host/observerd/docker.go`: add only the read-only Moby `NetworkList` capability and wrapper.
- `host/observerd/inventory.go`: normalize, bound, persist, and clone the global network snapshot in the same generation as `ContainerIdentityV1`.
- `host/observerd/pcc_pins.go`: fixed-path protected pin loader and immutable canonical denylist snapshot.
- `host/observerd/pcc_boundary_archive.go`: authenticated boundary-record AGF recovery, append, V5 anchoring, and A/B/C chain derivation.
- `host/observerd/pcc_receipts.go`: specialized five-field PCC receipt AGF recovery, append, lookup, and spool rebind.
- `host/observerd/pcc_publish.go`: exact retry/conflict/hard-fence logic and same-/cross-boot snapshot production.
- `host/observerd/pcc_api.go`: bounded strict Core-only POST handler and typed status mapping.
- `core/agmind_immune/ingest/correlation_journal.py`: exact request-state records, evidence-root-bound AGF lifecycle, phase validation, and recovery.
- `core/agmind_immune/ingest/service.py`: async transport method, candidate interception, ordered proof fetch/accept, and ACK resumption.
- `core/agmind_immune/controller.py`: compose the exact recovered correlation journal into `DeliveryCoordinator`.

---

### Task 1: 6C-1 Same-Generation Global Network Inventory

**Files:**
- Modify: `host/observerd/docker.go`
- Modify: `host/observerd/inventory.go`
- Modify: `host/observerd/inventory_test.go`
- Modify: `host/observerd/docker_test.go`

**Interfaces:**
- Consumes: existing `ContainerIdentityV1`, `contracts.PCCDockerNetworkV1`, `contracts.PCCDockerNetworkSnapshotSHA256`, and `client.NetworkListOptions`/`client.NetworkInspectOptions`.
- Produces: `DockerReader.NetworkList(context.Context, client.NetworkListOptions) (client.NetworkListResult, error)` and `Inventory.SnapshotForCorrelation(fullContainerID string) (CorrelationInventorySnapshot, error)`.

```go
type CorrelationInventorySnapshot struct {
    Generation     uint64
    Identity       ContainerIdentityV1
    DockerNetworks []contracts.PCCDockerNetworkV1
}

func (inventory *Inventory) SnapshotForCorrelation(
    fullContainerID string,
) (CorrelationInventorySnapshot, error)
```

- [ ] **Step 1: Extend the fake and exact allowlist RED test**

Add `networkListResult`, `networkListErr`, `networkListOptions`, and `networkInspectIDs` to `fakeDockerReader`; implement `NetworkList`; record every exact inspect ID; and change `TestPublicDockerReaderHasExactReadOnlyAllowlist` to expect:

```go
want := []string{
    "ContainerInspect",
    "ContainerList",
    "Events",
    "ImageInspect",
    "NetworkInspect",
    "NetworkList",
}
```

- [ ] **Step 2: Add global-walk RED tests**

Add these exact table/subtest names in `host/observerd/inventory_test.go`:

```go
func TestInventoryGlobalNetworksUseUnfilteredListAndExactIDInspect(t *testing.T)
func TestInventoryGlobalNetworkCanonicalizationAndBounds(t *testing.T)
func TestInventoryGlobalNetworkFailureRetainsPriorGeneration(t *testing.T)
func TestCorrelationInventorySnapshotIsOneReadLockedGeneration(t *testing.T)
func TestInventoryGlobalNetworksPersistAcrossRestart(t *testing.T)
```

Fixtures must cover empty/duplicate IDs, list/inspect ID disagreement, disappearance, malformed/IPv6/IPv4-mapped IPAM, unsorted duplicates, 33 per-network entries, 65 networks, 129 global subnets/gateways, 16 KiB + 1 canonical bytes, and a failing persistence hook. Assert `DockerReconcileGap=true` and prior records/networks remain paired after every failure.

- [ ] **Step 3: Run the RED inventory target**

Run:

```sh
go test ./host/observerd -run 'Test(PublicDockerReaderHasExactReadOnlyAllowlist|InventoryGlobalNetwork|CorrelationInventorySnapshot)' -count=1
```

Expected: compile failure because `fakeDockerReader` and `DockerReader` do not yet expose `NetworkList`, followed by behavioral failures for missing persisted networks/snapshot method.

- [ ] **Step 4: Add the narrow Moby method**

Implement exactly:

```go
type DockerReader interface {
    // existing methods remain unchanged
    NetworkList(
        context.Context,
        client.NetworkListOptions,
    ) (client.NetworkListResult, error)
}

func (reader *mobyDockerReader) NetworkList(
    ctx context.Context,
    options client.NetworkListOptions,
) (client.NetworkListResult, error) {
    return reader.client.NetworkList(ctx, options)
}
```

- [ ] **Step 5: Persist a canonical global network field**

Add `DockerNetworks []contracts.PCCDockerNetworkV1` to `inventoryDiskState`. Implement a private `globalDockerNetworks(ctx)` that calls `NetworkList(ctx, client.NetworkListOptions{})`, rejects empty/duplicate IDs, exact-inspects every ID once, rejects any invalid IPAM fact instead of skipping it, sorts/deduplicates set fields, sorts networks by ID, and calls `contracts.PCCDockerNetworkSnapshotSHA256(networks)` for full bound validation before returning.

- [ ] **Step 6: Adopt records and networks in one generation**

In `Inventory.Reconcile`, finish the container and global-network walks before acquiring `inventory.mutex`; under the final write lock, derive one `nextGeneration`, stamp every identity, construct one `inventoryDiskState`, persist it once, then adopt it once. Any walk or persistence error leaves the already-open reconcile gap and previous records/network bytes intact.

- [ ] **Step 7: Add the one-lock correlation clone**

Under one `mutex.RLock`, reject a reconcile gap, validate the full ID, find one running record, require `record.Identity.InventoryGeneration == state.Generation`, deep-clone the identity and every network slice, and return the state generation.

- [ ] **Step 8: Run focused verification**

Run:

```sh
go test ./host/observerd -run 'Test(PublicDockerReaderHasExactReadOnlyAllowlist|InventoryGlobalNetwork|CorrelationInventorySnapshot|InventoryPersistsGenerationRevisionAndRedactedSnapshot|InventoryFailurePersistsGapAndAtomicallyRetainsPriorSnapshot)' -count=1
go test ./internal/contracts -run 'TestTask6A.*DockerNetwork' -count=1
```

Expected: PASS; no Docker method beyond the six-method read-only allowlist.

- [ ] **Step 9: Commit Task 1**

```sh
git add host/observerd/docker.go host/observerd/inventory.go host/observerd/inventory_test.go host/observerd/docker_test.go
git commit -m "feat(observer): persist global network inventory"
```

---

### Task 2: 6C-2 Fixed Root-Owned Safety Pins

**Files:**
- Create: `host/observerd/pcc_pins.go`
- Create: `host/observerd/pcc_pins_test.go`
- Modify: `host/observerd/config.go` only if the existing package-private protected read needs a reusable injected seam

**Interfaces:**
- Consumes: `readSingleLinkRegular`, `contracts.PCCDetectorBundleSHA256`, `contracts.PCCOperatorDenylistSHA256`, and `contracts.PCCManagementDenylistSHA256`.
- Produces: one immutable `PCCSafetyPinSnapshot` from four compile-time paths.

```go
const (
    pccDetectorRulesPath          = "/etc/falco/rules.d/agmind-pcc.yaml"
    pccSpecialUseRegistryPath     = "/usr/share/agmind-sais/ipv4-special-use.csv"
    pccOperatorDenylistPath       = "/etc/agmind-sais/operator-denylist.json"
    pccManagementDestinationsPath = "/etc/agmind-sais/management-destinations.json"
)

type PCCSafetyPinSnapshot struct {
    DetectorBundleSHA256          string
    SpecialUseRegistrySHA256      string
    OperatorDeniedNetworks        []string
    OperatorDeniedAddresses       []string
    OperatorDenylistSHA256        string
    ManagementDeniedNetworks      []string
    ManagementDeniedAddresses     []string
    ManagementDenylistSHA256      string
}

func LoadPCCSafetyPinSnapshot() (PCCSafetyPinSnapshot, error)
```

- [ ] **Step 1: Write protected-path and immutability RED tests**

Add:

```go
func TestPCCSafetyPinSnapshotReadsEveryFixedPathOnce(t *testing.T)
func TestPCCSafetyPinSnapshotRejectsUnsafeOrMalformedInput(t *testing.T)
func TestPCCSafetyPinSnapshotCanonicalizesDenyLists(t *testing.T)
func TestPCCSafetyPinSnapshotRejectsWrongSpecialUseDigest(t *testing.T)
func TestPCCSafetyPinSnapshotIsDeeplyCloned(t *testing.T)
```

The injected reader records exact path order and returns copied bytes. The failure table covers symlink, non-regular, multi-link, non-root-owned, mode other than the protected-reader policy, missing/unreadable, empty, size overflow, invalid JSON shape, unknown property, duplicate/noncanonical/malformed/IPv6 CIDR or address, and 129 entries.

- [ ] **Step 2: Run the RED pin target**

Run:

```sh
go test ./host/observerd -run 'TestPCCSafetyPinSnapshot' -count=1
```

Expected: compile failure because `LoadPCCSafetyPinSnapshot` and the snapshot type do not exist.

- [ ] **Step 3: Implement strict canonical denylist decoding**

Use one strict internal shape:

```go
type pccDenylistDocument struct {
    DeniedAddresses []string `json:"denied_addresses"`
    DeniedNetworks  []string `json:"denied_networks"`
}
```

Decode with `contracts.DecodeStrict`, require both arrays present, canonicalize IPv4 addresses/prefixes to sorted unique values, reject IPv4-mapped IPv6 and any count above 128, then compute the existing domain-separated hashes. Do not add the paths to `Config`.

- [ ] **Step 4: Implement one all-or-nothing snapshot**

Read each fixed path once through `readSingleLinkRegular`; clone raw bytes before hashing; require the special-use raw-byte digest equals `e3e39e76d00b1677335db8e9a805c7b9480ea2f4dc9e33f0b93cd3a905128d73`; and return deep-cloned denylist slices. Any input error returns no partial snapshot.

- [ ] **Step 5: Run focused verification**

Run:

```sh
go test ./host/observerd -run 'TestPCCSafetyPinSnapshot' -count=1
go test ./internal/contracts -run '^TestTask6AHashParityAndCanonicalInputValidation$' -count=1
```

Expected: PASS with no configurable trust path.

- [ ] **Step 6: Commit Task 2**

```sh
git add host/observerd/pcc_pins.go host/observerd/pcc_pins_test.go host/observerd/config.go
git commit -m "feat(observer): load fixed PCC safety pins"
```

---

### Task 3: 6C-3 Authenticated Boot Boundary Archive

**Files:**
- Create: `host/observerd/pcc_boundary_archive.go`
- Create: `host/observerd/pcc_boundary_archive_test.go`
- Modify: `host/observerd/envelope.go`
- Modify: `host/observerd/spool.go`
- Modify: `host/observerd/service.go`
- Modify: `host/observerd/config.go`
- Modify: `host/observerd/boot_boundary_test.go`
- Modify: `host/observerd/rotation_test.go`
- Modify: `host/observerd/repair_test.go`
- Modify: `host/observerd/state_v3_receipt_boundary_test.go`

**Interfaces:**
- Consumes: exact signed `contracts.EventEnvelopeV1` boundary/rotation envelopes, `Keyring`, `durablefile.Journal`, `StateStore.publicationMutex`, and existing `BootBoundary` state.
- Produces: V5 boundary anchors, durable A/B/C records, and oldest-to-newest `[]contracts.PCCBootTransitionHopV1`.

```go
type PCCBoundaryArchiveRecord struct {
    SchemaVersion          string                     `json:"schema_version"`
    BoundaryEvent          contracts.EventEnvelopeV1 `json:"boundary_event"`
    RotationCompanionEvent *contracts.EventEnvelopeV1 `json:"rotation_companion_event,omitempty"`
}

type PCCBoundaryArchiveAnchor struct {
    Count    uint64
    Bytes    uint64
    HeadHash string
}

type PCCBoundaryArchive struct {
    mutex   sync.Mutex
    journal *durablefile.Journal
    state   *StateStore
    keyring *Keyring
    anchor  PCCBoundaryArchiveAnchor
    records []PCCBoundaryArchiveRecord
    failed  bool
    closed  bool
}

func OpenPCCBoundaryArchive(
    stateDirectory string,
    state *StateStore,
    keyring *Keyring,
) (*PCCBoundaryArchive, error)

func (archive *PCCBoundaryArchive) RecordCommittedBoundary(
    boundary contracts.EventEnvelopeV1,
    rotationCompanion *contracts.EventEnvelopeV1,
) error

func (archive *PCCBoundaryArchive) Chain(
    previousBootID string,
    currentBootID string,
) ([]contracts.PCCBootTransitionHopV1, error)
```

- [ ] **Step 1: Write V5 migration and anchor RED tests**

Add exact tests:

```go
func TestObserverStateV4MigratesToV5OnlyWithBothPCCJournalsAbsent(t *testing.T)
func TestObserverStateV5ValidatesBothPCCAnchors(t *testing.T)
func TestObserverStateRejectsUnanchoredPCCJournalBeforeMigration(t *testing.T)
```

Build a canonical V4 fixture by removing all six PCC anchors and setting `schema_version` to `agmind.observer-state.v4`. Assert either fixed journal’s presence leaves durable V4 bytes unchanged and returns corruption.

- [ ] **Step 2: Write archive recovery RED tests**

Add:

```go
func TestPCCBoundaryArchiveDedicatedBoundarySurvivesAckAndRestart(t *testing.T)
func TestPCCBoundaryArchiveDerivesRotationPathsBAndC(t *testing.T)
func TestPCCBoundaryArchiveBuildsMultipleConsecutiveHops(t *testing.T)
func TestPCCBoundaryArchiveRejectsInvalidAuthenticatedHistory(t *testing.T)
func TestPCCBoundaryArchiveRejectsTailAnchorAndQuotaViolations(t *testing.T)
func TestPCCBoundaryArchiveDoesNotExpandPublicKeyMetadata(t *testing.T)
```

The invalid-history table changes one property at a time: signature, event ID, content hash, boundary flags, key epoch/key ID, boot IDs, predecessor sequence, pair ordering/adjacency, duplicated event, missing companion, extra companion, archive order, count 1,025, verified bytes 64 MiB + 1, and payload 128 KiB + 1.

- [ ] **Step 3: Run the RED state/archive target**

Run:

```sh
go test ./host/observerd -run 'Test(ObserverStateV4|ObserverStateV5|ObserverStateRejectsUnanchoredPCC|PCCBoundaryArchive)' -count=1
```

Expected: compile failures for V5 anchors/archive symbols and migration behavioral failures.

- [ ] **Step 4: Advance state from V4 to V5 once**

Rename the current schema constant to `observerStateSchemaV4`, set `observerStateSchema = "agmind.observer-state.v5"`, preserve the current field set in `observerStateV4`, and add these exact fields to `ObserverState`:

```go
PCCBoundaryCount    uint64 `json:"pcc_boundary_count"`
PCCBoundaryBytes    uint64 `json:"pcc_boundary_bytes"`
PCCBoundaryHeadHash string `json:"pcc_boundary_head_sha256"`
PCCReceiptCount     uint64 `json:"pcc_receipt_count"`
PCCReceiptBytes     uint64 `json:"pcc_receipt_bytes"`
PCCReceiptHeadHash  string `json:"pcc_receipt_head_sha256"`
```

Initialize both empty head hashes to their journal zero hash. Validate the count/bytes/head all-zero equivalence and caps. Gate V4 migration with `lstat` absence checks for both exact PCC paths before writing V5.

- [ ] **Step 5: Implement boundary record validation and recovery**

Set constants:

```go
const (
    pccBoundaryArchiveSchema          = "agmind.pcc-boundary-archive-record.v1"
    pccBoundaryArchiveMaxCount uint64 = 1_024
    pccBoundaryArchiveMaxBytes uint64 = 64 * 1024 * 1024
    pccBoundaryArchiveMaxFrame uint32 = 128 * 1024
)
```

Open `<state>/spool/pcc-boundaries.agf` with the durable journal tail-intent primitive. Recompute every frame hash and V5 count/byte/head anchor; reject a complete or incomplete unanchored tail. Verify each envelope’s canonical bytes, content/event IDs, signature against `Keyring`, protected flags, stream order, key epoch, boot link, and exact A/B/C grammar. The record never stores an A/B/C discriminator.

- [ ] **Step 6: Integrate archive append with boundary commits**

For A, append the dedicated boundary record before marking its boundary state committed. For B/C, hold the existing publication mutex through both durable events and append one record only after the adjacent transition/epoch-start pair is fully present and revalidated. Anchor the archive in state before allowing ordinary ACK cleanup to remove those spool frames; an uncertain append/anchor persists mutation-read-only.

- [ ] **Step 7: Implement exact chain derivation**

`Chain(previousBootID, currentBootID)` walks archive records oldest-to-newest, selects the connected suffix beginning at `previousBootID`, derives `PCCBootTransitionHopV1` fields from signed envelopes, deep-clones pointer fields, calls `contracts.PCCBootTransitionChainSHA256` for full contract validation, and requires the final hop boot equals `currentBootID`.

- [ ] **Step 8: Wire startup and close ownership**

Open the archive after `StateStore` and `Keyring`, before spool exposure; store it on the daemon/spool owner that commits boundaries; close it in `Daemon.Close`; and fail daemon startup if archive/state/spool evidence cannot be reconciled.

- [ ] **Step 9: Run focused verification**

Run:

```sh
go test ./host/observerd -run 'Test(ObserverStateV4|ObserverStateV5|ObserverStateRejectsUnanchoredPCC|PCCBoundaryArchive|BootBoundary.*PCC|Rotation.*PCC|Repair.*BoundaryArchive)' -count=1
```

Expected: PASS; `PublicKeyMetadata.Validate` still rejects more than 16 entries.

- [ ] **Step 10: Commit Task 3**

```sh
git add host/observerd/pcc_boundary_archive.go host/observerd/pcc_boundary_archive_test.go host/observerd/envelope.go host/observerd/spool.go host/observerd/service.go host/observerd/config.go host/observerd/boot_boundary_test.go host/observerd/rotation_test.go host/observerd/repair_test.go host/observerd/state_v3_receipt_boundary_test.go
git commit -m "feat(observer): retain authenticated PCC boot boundaries"
```

---

### Task 4: 6C-4 Specialized PCC Publication Receipts

**Files:**
- Create: `host/observerd/pcc_receipts.go`
- Create: `host/observerd/pcc_receipts_test.go`
- Modify: `host/observerd/envelope.go`
- Modify: `host/observerd/spool.go`
- Modify: `host/observerd/service.go`
- Modify: `host/observerd/config.go`
- Modify: `host/observerd/repair_test.go`
- Modify: `host/observerd/control_receipt_state_test.go`

**Interfaces:**
- Consumes: V5 PCC receipt anchors, `durablefile.Journal`, `CoreEventV1.Validate`, and exact spool frames.
- Produces: one specialized receipt per PCC operation and exact unacknowledged spool lookup helpers.

```go
type PCCPublicationReceipt struct {
    OperationKey             string `json:"operation_key"`
    RequestSHA256            string `json:"request_sha256"`
    SnapshotNormalizedSHA256 string `json:"snapshot_normalized_sha256"`
    SnapshotEventID          string `json:"snapshot_event_id"`
    SnapshotContentSHA256    string `json:"snapshot_content_sha256"`
}

type PCCPublicationReceiptRecord struct {
    SchemaVersion string                `json:"schema_version"`
    Receipt       PCCPublicationReceipt `json:"receipt"`
}

func (receipts *PCCReceiptStore) Lookup(
    operationKey string,
    requestSHA256 string,
) (PCCPublicationReceipt, bool, error)

func (receipts *PCCReceiptStore) Append(
    receipt PCCPublicationReceipt,
) error

func (spool *Spool) LookupUnacknowledged(
    sourceSequence uint64,
    eventID string,
    contentSHA256 string,
) (SpoolItem, error)

func (spool *Spool) LookupUnacknowledgedEvent(
    eventID string,
    contentSHA256 string,
) (SpoolItem, error)
```

- [ ] **Step 1: Write receipt schema/retry/conflict RED tests**

Add:

```go
func TestPCCReceiptHasExactNestedFiveFieldSchema(t *testing.T)
func TestPCCReceiptExactRetryConflictQuotaAndRestart(t *testing.T)
func TestPCCReceiptRebindsIndependentRequestAndNormalizedHashes(t *testing.T)
func TestPCCReceiptCannotUseGenericControlReceiptJournal(t *testing.T)
```

Assert the nested receipt has exactly the five frozen keys and no sequence. Exact key/hash returns the same receipt; same key/different hash conflicts; request and normalized hashes are independently recomputed.

- [ ] **Step 2: Write corruption/ACK-gate RED tests**

Add:

```go
func TestPCCReceiptRecoveryRejectsCorruptionAndUnanchoredTail(t *testing.T)
func TestPCCReceiptRequiresExactLiveSpoolBinding(t *testing.T)
func TestPCCSnapshotAckRequiresValidSpecializedReceipt(t *testing.T)
func TestSpoolLookupUnacknowledgedRequiresExactTriple(t *testing.T)
```

Cover forged receipt, wrong schema, duplicate conflict, receipt without spool event, snapshot without receipt, changed event/content/normalized hash, acknowledged/missing item, torn/interior frame, count 4,097, bytes 16 MiB + 1, and payload 128 KiB + 1.

- [ ] **Step 3: Run the RED receipt target**

Run:

```sh
go test ./host/observerd -run 'Test(PCCReceipt|PCCSnapshotAck|SpoolLookupUnacknowledged)' -count=1
```

Expected: compile failures for the new store and lookup helpers.

- [ ] **Step 4: Implement the specialized journal**

Use:

```go
const (
    pccReceiptRecordSchema          = "agmind.pcc-publication-receipt-record.v1"
    pccReceiptMaxCount       uint64 = 4_096
    pccReceiptMaxBytes       uint64 = 16 * 1024 * 1024
    pccReceiptMaxFrame       uint32 = 128 * 1024
)
```

Open `<state>/spool/pcc-receipts.agf`; strictly decode and canonicalize every record; validate operation key/request/snapshot hashes; rebuild count/byte/head; reject all unanchored tails; and reconcile only exact V5 anchors. Keep this code independent of `ControlReceiptJournal`.

- [ ] **Step 5: Implement exact unacknowledged lookup**

Under `spool.mutex`, require the requested sequence is above `AckSequence`, load and validate the standalone frame/publication binding, compare all three identities, and return a cloned `SpoolItem`. Event/hash lookup must return exactly one unacknowledged match or fail closed.

- [ ] **Step 6: Bind receipt cleanup and conflict fencing**

Before deleting any `pcc_correlation_snapshot`, require a unique specialized receipt whose event/content hashes match the exact spool item and whose normalized hash equals the envelope. On same operation key with different request hash, call `StateStore.PersistReadOnly("observer_pcc_request_conflict")` before returning the conflict.

Clarification: V5-anchored PCC receipts are permanent append-only audit
history. ACK does not remove or compact them. Startup accepts an exact anchored
historical receipt after its spool item is gone, but revalidates every receipt
for a still-live snapshot and rejects every live snapshot without its exact
receipt. New append, exact retry lookup, and ACK authorization still require an
exact live unacknowledged spool binding; historical receipt presence is never a
publication retry authority.

- [ ] **Step 7: Wire startup and close ownership**

Open/recover the receipt store after V5 state and before spool publication; attach it to `Spool`; close it with the spool; and reject missing or substituted expected artifacts at startup.

- [ ] **Step 8: Run focused verification**

Run:

```sh
go test ./host/observerd -run 'Test(PCCReceipt|PCCSnapshotAck|SpoolLookupUnacknowledged|Repair.*PCCReceipt|ObserverStateV5)' -count=1
```

Expected: PASS; generic control receipt tests remain unaffected.

- [ ] **Step 9: Commit Task 4**

```sh
git add host/observerd/pcc_receipts.go host/observerd/pcc_receipts_test.go host/observerd/envelope.go host/observerd/spool.go host/observerd/service.go host/observerd/config.go host/observerd/repair_test.go host/observerd/control_receipt_state_test.go
git commit -m "feat(observer): persist specialized PCC receipts"
```

---

### Task 5: 6C-5 Observer PCC Producer and Core Route

**Files:**
- Create: `host/observerd/pcc_publish.go`
- Create: `host/observerd/pcc_publish_test.go`
- Create: `host/observerd/pcc_api.go`
- Create: `host/observerd/pcc_api_test.go`
- Create: `host/observerd/pcc_restart_test.go`
- Modify: `host/observerd/core_api.go`
- Modify: `host/observerd/envelope.go`
- Modify: `host/observerd/spool.go`
- Modify: `host/observerd/service.go`
- Modify: `host/observerd/core_api_route_linux_test.go`

**Interfaces:**
- Consumes: `contracts.PCCCorrelationSnapshotRequestV1`, `PCCSafetyPinSnapshot`, `CorrelationInventorySnapshot`, `PCCBoundaryArchive`, `PCCReceiptStore`, exact trigger spool lookup, coverage state, and `StateStore.publicationMutex`.
- Produces: one created/retried `CoreEventV1` through the Core-only route.

```go
type PCCCorrelationPublication struct {
    Item    CoreEventV1
    Created bool
}

type pccCorrelationPublisher interface {
    PublishPCCCorrelationSnapshot(
        context.Context,
        contracts.PCCCorrelationSnapshotRequestV1,
    ) (PCCCorrelationPublication, error)
}
```

- [ ] **Step 1: Write route and trigger-authority RED tests**

Add:

```go
func TestPCCAPIIsCoreOnlyAndAuthenticatesBeforeBodyRead(t *testing.T)
func TestPCCAPIRequiresOneBoundedCanonicalRequest(t *testing.T)
func TestPCCPublishRequiresExactUnacknowledgedCandidateTrigger(t *testing.T)
```

Cover public-socket absence; group-only mutation denial; non-Core peer rejection before reading a blocking body; extra/missing/null field; noncanonical body; over-bound body; missing/ACKed/mismatched triple; investigation-only trigger; and caller-forged normalized trigger facts.

- [ ] **Step 2: Write complete/failed/cross-boot RED tests**

Add:

```go
func TestPCCPublishCompleteBindsOneGenerationPinsTimestampAndCoverage(t *testing.T)
func TestPCCPublishEmitsExactLocallyProducibleFailedUnions(t *testing.T)
func TestPCCPublishHardFenceReturnsUnavailableWithoutPublication(t *testing.T)
func TestPCCPublishExactRetryAndDurableConflict(t *testing.T)
func TestPCCRestartPublishesAuthenticatedCrossBootPathsABC(t *testing.T)
func TestPCCRestartRejectsMissingReorderedOrForgedBoundary(t *testing.T)
```

Instrument trigger lookup, inventory, pins, clock, reserve, sign, append, receipt, and state calls. Assert hard-fence call list is empty after the state snapshot, cross-boot calls no same-boot substrate, and complete publication uses one microsecond-truncated UTC value for event/ingest/decision.

- [ ] **Step 3: Run the RED producer/API target**

Run:

```sh
go test ./host/observerd -run 'Test(PCCPublish|PCCAPI|PCCRestart|CoreAPIRoute.*PCC)' -count=1
```

Expected: compile failures for producer/API symbols.

- [ ] **Step 4: Add an externally sampled signing path**

Add a private signer method that accepts one already-truncated UTC timestamp and an already-chosen expected sequence while preserving the existing signing, canonical-hash, reservation, publication, and boundary rules. Do not change ordinary `EnvelopeSigner.Wrap` timestamp behavior.

- [ ] **Step 5: Implement retry/conflict/hard-fence ordering**

Under `publicationMutex`: validate/canonicalize the exact request and hash; check receipt retry/conflict; snapshot state; if `MutationReadOnly`, return `ErrPCCPublicationUnavailable` immediately; then exact-lookup and validate the trigger. A conflict persists `observer_pcc_request_conflict`. An exact retry revalidates receipt, spool event, envelope, request hash, and normalized hash before returning `Created:false`.

- [ ] **Step 6: Implement trigger projection and cross-boot branch**

Strictly decode the trigger envelope’s `contracts.FalcoConnectV1`; require `event_type="falco_connect"`, successful connect, `InvestigationOnly=false`, and complete authoritative fields; construct `PCCFalcoTriggerProjectionV1` only from signed envelope/normalized data. If trigger boot differs from current state boot, call `archive.Chain`, emit only `failure_reasons=["observer_boot_changed"]`, set count/hash, and skip inventory/pins/readiness calls.

- [ ] **Step 7: Implement same-boot snapshot assembly**

Clone one `CorrelationInventorySnapshot`; load one `PCCSafetyPinSnapshot`; sample UTC once and truncate to microseconds; choose `S=LastSequence+1`; require coverage through `S-1`; evaluate the frozen failure reasons; populate exactly one complete or failed union; validate `contracts.PCCCorrelationSnapshotV1`; and enforce the 24 KiB complete bound without truncation.

- [ ] **Step 8: Atomically publish snapshot and receipt**

Reserve exactly `S`, sign with the sampled timestamp, append at `PriorityTier`, append:

```go
PCCPublicationReceipt{
    OperationKey:             "pcc_correlation_snapshot:" + request.TriggerEventID,
    RequestSHA256:            requestSHA256,
    SnapshotNormalizedSHA256: event.Envelope.NormalizedFieldsSHA256,
    SnapshotEventID:          event.EventID,
    SnapshotContentSHA256:    item.ContentSHA256,
}
```

and anchor publication/receipt state before releasing the mutex. Any ambiguous durability persists mutation-read-only.

- [ ] **Step 9: Register exact Core-only route**

Register `POST /v1/events/pcc-correlation-snapshot` in `newCoreAPI` under `uds.RequirePeer(coreMutationPeerAuthorized)`. Strictly read one bounded request, map conflict to 409, hard-fence unavailable to 503 with a fixed code, created to 201, retry to 200, and return exact JSON `CoreEventV1`.

- [ ] **Step 10: Mark PCC evidence protected**

Add `pcc_correlation_snapshot` to `priorityEventType`; assert routine quota/cleanup cannot discard it and ACK cleanup requires its specialized receipt.

- [ ] **Step 11: Run focused verification**

Run:

```sh
go test ./host/observerd -run 'Test(PCCPublish|PCCAPI|PCCRestart|CoreAPIRoute.*PCC|PCCSnapshotAck)' -count=1
go test ./internal/contracts -run 'TestTask6A.*PCCCorrelationSnapshot' -count=1
```

Expected: PASS with no public route and no local hard-fence snapshot.

- [ ] **Step 12: Commit Task 5**

```sh
git add host/observerd/pcc_publish.go host/observerd/pcc_publish_test.go host/observerd/pcc_api.go host/observerd/pcc_api_test.go host/observerd/pcc_restart_test.go host/observerd/core_api.go host/observerd/envelope.go host/observerd/spool.go host/observerd/service.go host/observerd/core_api_route_linux_test.go
git commit -m "feat(observer): publish protected PCC snapshots"
```

---

### Task 6: 6C-6 Core Correlation Request Journal

**Files:**
- Create: `core/agmind_immune/ingest/correlation_journal.py`
- Create: `core/tests/ingest/test_correlation_journal.py`
- Modify: `core/agmind_immune/evidence/segments.py`
- Modify: `core/agmind_immune/ingest/service.py`
- Modify: `core/agmind_immune/controller.py`
- Modify: `core/tests/test_controller.py`

**Interfaces:**
- Consumes: `SegmentStore`, `EvidenceRef`, `PCCCorrelationSnapshotRequestV1`, `canonical_json`, `pcc_correlation_request_sha256`, and AGF1 frame helpers.
- Produces: exact recovered phase state and one journal instance bound to the same evidence-root lifecycle as delivery.

```python
class _CorrelationRequestStateV1(ContractModel):
    schema_version: Literal["agmind.correlation-request-state.v1"]
    operation_key: str
    request_sha256: str
    request: PCCCorrelationSnapshotRequestV1
    phase: Literal["selected", "proof_observed", "completed"]
    snapshot_event_id: str | None = None
    snapshot_content_sha256: str | None = None
```

`CorrelationRequestJournal` exposes exact class methods
`create_new(store: SegmentStore) -> CorrelationRequestJournal` and
`open_and_recover(store: SegmentStore) -> CorrelationRequestJournal`, plus
`select(trigger_ref: EvidenceRef, canonical_request: bytes) ->
_CorrelationRequestStateV1`,
`mark_proof_observed(request_sha256: str, snapshot_ref: EvidenceRef) ->
_CorrelationRequestStateV1`, `mark_completed(request_sha256: str) ->
_CorrelationRequestStateV1`, and
`pending() -> tuple[_CorrelationRequestStateV1, ...]`.

- [ ] **Step 1: Write exact record and 120-second RED tests**

Add module-private `seeded_correlation_store(tmp_path)` and
`read_correlation_frame_payloads(path)` fixtures using the existing signed
event/AGF helpers. The first test's core is:

```python
def test_correlation_journal_selected_record_has_exact_schema_and_ttl_120(
    tmp_path: Path,
) -> None:
    store, trigger_ref = seeded_correlation_store(tmp_path)
    journal = CorrelationRequestJournal.create_new(store)
    request = PCCCorrelationSnapshotRequestV1(
        schema_version="agmind.pcc-correlation-snapshot-request.v1",
        trigger_event_id=trigger_ref.event_id,
        trigger_content_sha256=trigger_ref.content_sha256,
        trigger_source_sequence=trigger_ref.source_sequence,
        requested_ttl_seconds=120,
    )
    selected = journal.select(trigger_ref, canonical_json(request))
    payload = json.loads(
        read_correlation_frame_payloads(
            tmp_path / "correlation-requests.agf"
        )[0]
    )
    assert selected.phase == "selected"
    assert set(payload) == {
        "operation_key", "phase", "request", "request_sha256", "schema_version"
    }
    assert payload["request"] == request.model_dump(mode="json")
```

Also add
`test_correlation_journal_rederives_identical_canonical_request`; close and
reopen the journal, assert `canonical_json(recovered.request)` equals the
original bytes and its SHA-256 equals `request_sha256`. Assert the record has
only schema, operation key, request hash, nested request, phase, and
phase-appropriate optional snapshot fields; nested request has the exact five
JSON properties including `requested_ttl_seconds == 120`; there is no bytes,
deadline, or selected-time property.

- [ ] **Step 2: Write transition/recovery/corruption RED tests**

Add exact tests
`test_correlation_journal_allows_only_selected_proof_observed_completed`,
`test_correlation_journal_exact_phase_retries_are_idempotent`,
`test_correlation_journal_rejects_conflicting_request_or_proof`,
`test_correlation_journal_recovers_each_phase_and_quota_boundary`,
`test_correlation_journal_fails_closed_on_unsafe_or_unbound_artifact`, and
`test_controller_requires_correlation_journal_from_the_same_evidence_root`.
The legal transition assertion is:

```python
selected = journal.select(trigger_ref, canonical_request)
observed = journal.mark_proof_observed(selected.request_sha256, snapshot_ref)
completed = journal.mark_completed(selected.request_sha256)
assert (selected.phase, observed.phase, completed.phase) == (
    "selected",
    "proof_observed",
    "completed",
)
assert journal.pending() == ()
```

Cover skip/rollback/post-completion mutation, wrong operation key/hash/trigger/snapshot, noncanonical nested request, record 4,097, verified byte 16 MiB + 1, payload 64 KiB + 1, interior/torn frame, symlink/hardlink/mode/owner replacement, root mismatch, disappearance, and unexpected root artifact.

- [ ] **Step 3: Run the RED journal target**

Run:

```sh
python -m pytest core/tests/ingest/test_correlation_journal.py core/tests/test_controller.py::test_controller_requires_correlation_journal_from_the_same_evidence_root -q
```

Expected: import failure because `correlation_journal.py` does not exist.

- [ ] **Step 4: Add evidence-root operational binding**

Add `correlation-requests.agf` to the exact `SegmentStore` root allowlist and implement a dedicated acquire/seal/append-uncertain/release lifecycle patterned on ACK-journal ownership. Startup records the file identity and rejects substitution, disappearance, or any unknown root artifact. Do not reuse ACK commitment or SQLite state.

- [ ] **Step 5: Implement exact AGF recovery**

Set:

```python
_JOURNAL_NAME = "correlation-requests.agf"
_MAX_RECORDS = 4_096
_MAX_VERIFIED_BYTES = 16 * 1024 * 1024
_MAX_FRAME_PAYLOAD = 64 * 1024
```

Strictly decode each record, require canonical frame payload, re-canonicalize the nested request, recompute SHA-256 and operation key, validate optional snapshot fields as an all-or-none pair only for `proof_observed`/`completed`, and replay the legal phase union per operation. Refuse an unproven tail.

- [ ] **Step 6: Implement append and idempotent transitions**

`select` strictly decodes `canonical_request`, proves it equals `canonical_json(request)`, requires TTL 120 and trigger-ref triple equality, then fsyncs before returning. `mark_proof_observed` requires a protected PCC `EvidenceRef` after the trigger. `mark_completed` requires proof observed. Exact repeated calls return the existing state without a new frame.

- [ ] **Step 7: Compose the journal into delivery/controller**

Add an exact `CorrelationRequestJournal` parameter to `DeliveryCoordinator.create/_compose` and `CoreController.create`; require its `SegmentStore` identity equals `AcceptanceCoordinator.segment_store`; store it on delivery; include it in `_is_bound_to` checks; and close/release it in controller shutdown ownership without changing repair-mode authority.

- [ ] **Step 8: Run focused verification**

Run:

```sh
python -m pytest core/tests/ingest/test_correlation_journal.py core/tests/test_controller.py::test_controller_requires_correlation_journal_from_the_same_evidence_root -q
uv run --frozen mypy core/agmind_immune/ingest/correlation_journal.py core/agmind_immune/ingest/service.py core/agmind_immune/controller.py
```

Expected: PASS; the evidence root accepts exactly one bound correlation journal.

- [ ] **Step 9: Commit Task 6**

```sh
git add core/agmind_immune/ingest/correlation_journal.py core/agmind_immune/evidence/segments.py core/agmind_immune/ingest/service.py core/agmind_immune/controller.py core/tests/ingest/test_correlation_journal.py core/tests/test_controller.py
git commit -m "feat(core): persist correlation request phases"
```

---

### Task 7: 6C-7 Transport Before ACK and Restart Recovery

**Files:**
- Create: `core/tests/ingest/test_correlation_delivery.py`
- Modify: `core/agmind_immune/ingest/service.py`
- Modify: `core/tests/ingest/test_service.py`
- Modify: `core/tests/ingest/test_pcc_correlation_snapshot.py`
- Modify: `core/tests/test_controller.py`

**Interfaces:**
- Consumes: recovered `CorrelationRequestJournal`, `AcceptanceCoordinator.accept`/`accept_pcc`, authenticated `EvidenceRef`, existing ACK journal/barrier, and observer `CoreEventV1`.
- Produces: async PCC POST transport and one source-ordered `selected -> proof_observed -> completed` poll path.

```python
PCC_CORRELATION_TTL_SECONDS = 120
```

The new `ObserverCoreTransport` method is exactly
`async def publish_correlation_snapshot(canonical_body: bytes) -> bytes`;
all existing transport methods remain async.

- [ ] **Step 1: Extend transport fakes and add HTTP RED tests**

Add `publish_correlation_snapshot` to `_ScriptedTransport` and controller
`_Transport`, recording exact request bytes:

```python
async def publish_correlation_snapshot(self, canonical_body: bytes) -> bytes:
    self.actions.append(("pcc", bytes(canonical_body), None))
    if not self.publications:
        raise AssertionError("unexpected PCC publication")
    result = self.publications.pop(0)
    if isinstance(result, BaseException):
        raise result
    return result
```

Add exact test
`test_pcc_transport_uses_exact_route_body_bounds_and_statuses`. Assert
`POST /v1/events/pcc-correlation-snapshot`, exact `application/json`, no
redirects/encoding, response capped at `MAX_CORE_EVENT_RESPONSE_BYTES`,
200/201 success, 503 typed unavailable as retryable, 409 as fatal conflict,
and no body mutation.

- [ ] **Step 2: Write ordering and intervening-event RED tests**

In `test_correlation_delivery.py`, add exact tests
`test_candidate_trigger_is_selected_after_accept_before_any_ack`,
`test_intervening_events_are_accepted_before_bound_pcc_and_contiguous_ack`,
`test_snapshot_response_with_source_gap_forces_fetch_not_ack`, and
`test_non_candidate_and_investigation_only_keep_generic_delivery`. Add
`test_delivery_accepts_pcc_with_the_persisted_request_authority` to
`test_pcc_correlation_snapshot.py`.

Trace `evidence_trigger`, `journal_selected`, `post`, `evidence_intervening`, `evidence_pcc`, `journal_proof_observed`, `ack_pending`, `ack_post`, `journal_completed` and assert that exact order.

- [ ] **Step 3: Write crash/restart/hard-fence RED matrix**

Add exact test
`test_correlation_delivery_restart_converges_with_identical_request`,
parameterized by:

```python
CORRELATION_CRASH_POINTS = (
    "after_trigger_append",
    "after_selected",
    "after_post_response",
    "after_intervening_append",
    "after_proof_observed",
    "after_ack_intent",
    "after_observer_ack",
)
```

Also add exact tests
`test_mutation_read_only_unavailable_keeps_selected_and_unacknowledged`,
`test_cross_boot_abc_proof_allows_ordered_completion`, and
`test_invalid_cross_boot_chain_never_reaches_proof_observed`. Persist/reopen
all authorities at every crash point. Compare the POST body byte-for-byte
across restart and assert TTL 120. A 503 leaves phase `selected`, ACK journal
empty, and trigger unacknowledged until an externally recovered retry succeeds.

- [ ] **Step 4: Run the RED delivery target**

Run:

```sh
python -m pytest core/tests/ingest/test_correlation_delivery.py core/tests/ingest/test_service.py::test_delivery_transport_bounds_routes_and_statuses core/tests/ingest/test_pcc_correlation_snapshot.py::test_delivery_accepts_pcc_with_the_persisted_request_authority -q
```

Expected: protocol/fake compile failures for the missing async method, then ordering failures because `poll_once` still generically ACKs the trigger.

- [ ] **Step 5: Implement bounded async POST**

Add:

```python
async def publish_correlation_snapshot(
    self,
    canonical_body: bytes,
) -> bytes:
    return await self._publish_control(
        "/v1/events/pcc-correlation-snapshot",
        canonical_body,
        operation="PCC correlation snapshot",
        request_limit=4 * 1024,
        request_limit_label="4 KiB",
    )
```

The existing `_publish_control` helper must preserve exact bytes, accept only
200/201 exact JSON, bound the request to 4 KiB and the response to
`MAX_CORE_EVENT_RESPONSE_BYTES`, map typed 503 to `DeliveryRetryableError`,
and map 409 to `DeliveryFatalError`.

- [ ] **Step 6: Detect candidate-capable triggers after durable acceptance**

After `ref = self._acceptance.accept(item)` and coverage application, strictly validate `FalcoConnectV1` from `item.envelope.normalized_fields`. Branch only for `event_type=="falco_connect"` with `successful_connect=True` and `investigation_only=False`; do not add the trigger ref to generic ACK work.

- [ ] **Step 7: Build and fsync the exact Core-owned request**

Construct:

```python
request = PCCCorrelationSnapshotRequestV1(
    schema_version="agmind.pcc-correlation-snapshot-request.v1",
    trigger_event_id=ref.event_id,
    trigger_content_sha256=ref.content_sha256,
    trigger_source_sequence=ref.source_sequence,
    requested_ttl_seconds=PCC_CORRELATION_TTL_SECONDS,
)
canonical_request = canonical_json(request)
selected = self._correlation_requests.select(ref, canonical_request)
```

POST `canonical_json(selected.request)`, never a regenerated object after recovery. On startup, process existing `selected` before fetching unrelated later triggers.

- [ ] **Step 8: Fetch and accept the exact path through snapshot**

Treat the direct POST response as a target identity, not permission to skip source order. Fetch from the trigger sequence, accept every intervening event generically, require strict increasing contiguous authenticated stream semantics, and call `accept_pcc(item, selected.request)` only for the exact returned event/content pair. Continue bounded pages until the target is accepted or return retryable without ACK.

- [ ] **Step 9: Persist proof before contiguous ACK**

After PCC acceptance, call `mark_proof_observed(request_sha256, snapshot_ref)`. Then drive the existing ACK journal over trigger, every intervening ref, and snapshot in exact source order. After observer ACK confirms through snapshot, call `mark_completed`. A recovered `proof_observed` skips POST and resumes only ACK; a recovered `completed` is terminal and idempotent.

- [ ] **Step 10: Preserve barriers and generic behavior**

Apply coverage state to every accepted intervening/proof record before any ACK. Existing uncovered-gap ceilings still block ACK. Non-candidate and investigation-only Falco events use the unchanged generic loop.

- [ ] **Step 11: Run focused verification**

Run:

```sh
python -m pytest core/tests/ingest/test_correlation_delivery.py core/tests/ingest/test_service.py::test_delivery_transport_bounds_routes_and_statuses core/tests/ingest/test_service.py::test_delivery_commit_timeline_and_exact_pending_replay core/tests/ingest/test_service.py::test_delivery_cursor_divergence_and_network_order core/tests/ingest/test_pcc_correlation_snapshot.py::test_delivery_accepts_pcc_with_the_persisted_request_authority core/tests/test_controller.py::test_controller_requires_correlation_journal_from_the_same_evidence_root -q
uv run --frozen mypy core/agmind_immune/ingest/service.py core/agmind_immune/controller.py
```

Expected: PASS; every retry body is byte-identical and no trigger ACK precedes `proof_observed`.

- [ ] **Step 12: Commit Task 7**

```sh
git add core/agmind_immune/ingest/service.py core/tests/ingest/test_correlation_delivery.py core/tests/ingest/test_service.py core/tests/ingest/test_pcc_correlation_snapshot.py core/tests/test_controller.py
git commit -m "feat(core): deliver PCC proof before trigger ACK"
```

## Dependency Order

```text
6C-1 ─┐
6C-2 ─┼──────────────> 6C-5 ───────┐
6C-3 ─┤                              ├──> 6C-7
6C-4 ─┘                              │
6C-6 ────────────────────────────────┘
```

Implement 6C-1 and 6C-2 first, then serialize 6C-3 and 6C-4 because both advance observer state/spool startup, then 6C-6, 6C-5, and 6C-7. Each task ends at its stated commit boundary and focused gate.

## Final Focused Gate

After all seven task commits are individually reviewed, run only:

```sh
go test ./host/observerd -run 'Test(PCC|InventoryGlobalNetwork|CorrelationInventorySnapshot|ObserverStateV5|CoreAPIRoute.*PCC)' -count=1
go test ./internal/contracts -run 'TestTask6A(HashParityAndCanonicalInputValidation|RequestIsExactStrictAndBounded|RetainedTriggerRequiresCandidateCapableFacts|DockerNetworksEnforceCanonicalCompleteBounds|BootTransitionHopEnforcesClosedBoundaryUnion|SnapshotCompleteAndFailedFormsAreExclusive)' -count=1
python -m pytest core/tests/ingest/test_correlation_journal.py core/tests/ingest/test_correlation_delivery.py core/tests/ingest/test_service.py::test_delivery_transport_bounds_routes_and_statuses core/tests/ingest/test_service.py::test_delivery_commit_timeline_and_exact_pending_replay core/tests/ingest/test_service.py::test_delivery_cursor_divergence_and_network_order core/tests/ingest/test_pcc_correlation_snapshot.py::test_delivery_accepts_pcc_with_the_persisted_request_authority core/tests/test_controller.py::test_controller_requires_correlation_journal_from_the_same_evidence_root -q
uv run --frozen mypy core/agmind_immune/ingest/correlation_journal.py core/agmind_immune/ingest/service.py core/agmind_immune/controller.py
```

Expected: all focused gates pass; no repository-wide or native-Linux suite is part of Task 6C.
