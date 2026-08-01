package observerd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

const (
	pccReceiptRecordSchema        = "agmind.pcc-publication-receipt-record.v1"
	pccReceiptMaxCount     uint64 = 4_096
	pccReceiptMaxBytes     uint64 = 16 * 1024 * 1024
	pccReceiptMaxFrame     uint32 = 128 * 1024
)

var (
	ErrPCCReceiptConflict = errors.New("PCC publication receipt conflict")
	ErrPCCReceiptQuota    = errors.New("PCC publication receipt quota exhausted")
	ErrPCCReceiptCorrupt  = errors.New("PCC publication receipt journal corrupt")
	errPCCReceiptBinding  = errors.New("PCC publication receipt binding invalid")
)

type PCCPublicationReceipt struct {
	OperationKey             string `json:"operation_key"`
	RequestSHA256            string `json:"request_sha256"`
	SnapshotNormalizedSHA256 string `json:"snapshot_normalized_sha256"`
	SnapshotEventID          string `json:"snapshot_event_id"`
	SnapshotContentSHA256    string `json:"snapshot_content_sha256"`
}

func (receipt PCCPublicationReceipt) validateShape() error {
	const prefix = "pcc_correlation_snapshot:"
	if !strings.HasPrefix(receipt.OperationKey, prefix) ||
		!eventPattern.MatchString(strings.TrimPrefix(receipt.OperationKey, prefix)) ||
		!hex64Pattern.MatchString(receipt.RequestSHA256) ||
		!hex64Pattern.MatchString(receipt.SnapshotNormalizedSHA256) ||
		!eventPattern.MatchString(receipt.SnapshotEventID) ||
		!hex64Pattern.MatchString(receipt.SnapshotContentSHA256) {
		return ErrPCCReceiptCorrupt
	}
	return nil
}

type PCCPublicationReceiptRecord struct {
	SchemaVersion string                `json:"schema_version"`
	Receipt       PCCPublicationReceipt `json:"receipt"`
}

func (record PCCPublicationReceiptRecord) Validate() error {
	if record.SchemaVersion != pccReceiptRecordSchema ||
		record.Receipt.validateShape() != nil {
		return ErrPCCReceiptCorrupt
	}
	return nil
}

type PCCReceiptAnchor struct {
	Count    uint64
	Bytes    uint64
	HeadHash string
}

func pccReceiptAnchorFromState(state ObserverState) PCCReceiptAnchor {
	return PCCReceiptAnchor{
		Count:    state.PCCReceiptCount,
		Bytes:    state.PCCReceiptBytes,
		HeadHash: state.PCCReceiptHeadHash,
	}
}

func (anchor PCCReceiptAnchor) validate() error {
	if anchor.Count > pccReceiptMaxCount ||
		anchor.Bytes > pccReceiptMaxBytes ||
		!hex64Pattern.MatchString(anchor.HeadHash) ||
		(anchor.Count == 0) != (anchor.Bytes == 0) ||
		(anchor.Count == 0) != (anchor.HeadHash == zeroPCCJournalHash) {
		return ErrPCCReceiptCorrupt
	}
	return nil
}

func pccReceiptJournalPath(stateDirectory string) string {
	return filepath.Join(stateDirectory, "spool", "pcc-receipts.agf")
}

type PCCReceiptStore struct {
	mutex    sync.Mutex
	journal  *durablefile.Journal
	state    *StateStore
	spool    *Spool
	anchor   PCCReceiptAnchor
	receipts map[string]PCCPublicationReceipt
	failed   bool
	closed   bool
}

func pccReceiptCorrupt(err error) error {
	if err == nil {
		return ErrPCCReceiptCorrupt
	}
	return errors.Join(ErrPCCReceiptCorrupt, err)
}

func pccReceiptFailState(state *StateStore, reason string) {
	if state != nil {
		_ = state.PersistReadOnly(reason)
	}
}

func OpenPCCReceiptStore(
	stateDirectory string,
	state *StateStore,
) (*PCCReceiptStore, error) {
	return openPCCReceiptStore(stateDirectory, state)
}

func openPCCReceiptStore(
	stateDirectory string,
	state *StateStore,
	options ...durablefile.Option,
) (*PCCReceiptStore, error) {
	if state == nil {
		return nil, ErrPCCReceiptCorrupt
	}
	if err := durablefile.EnsurePrivateDirectory(
		filepath.Join(stateDirectory, "spool"),
	); err != nil {
		pccReceiptFailState(state, "observer_pcc_receipt_unsafe")
		return nil, pccReceiptCorrupt(err)
	}
	stateAnchor := pccReceiptAnchorFromState(state.Snapshot())
	if stateAnchor.validate() != nil {
		pccReceiptFailState(state, "observer_pcc_receipt_corrupt")
		return nil, ErrPCCReceiptCorrupt
	}
	if _, err := os.Lstat(pccReceiptJournalPath(stateDirectory)); errors.Is(
		err,
		os.ErrNotExist,
	) {
		if stateAnchor.Count != 0 {
			pccReceiptFailState(state, "observer_pcc_receipt_corrupt")
			return nil, ErrPCCReceiptCorrupt
		}
		// Keep an empty V5 receipt store logical until its first append. This
		// preserves the pre-existing rule that a path appearing before the
		// store has data is unowned; the first append creates, locks, and
		// re-verifies the fixed journal before writing.
		return &PCCReceiptStore{
			state:    state,
			anchor:   stateAnchor,
			receipts: make(map[string]PCCPublicationReceipt),
		}, nil
	} else if err != nil {
		pccReceiptFailState(state, "observer_pcc_receipt_unsafe")
		return nil, pccReceiptCorrupt(err)
	}
	journal, recovery, err := durablefile.NewJournalWithTailIntent(
		pccReceiptJournalPath(stateDirectory),
		func(durablefile.TornTailIntent) error {
			// A receipt exists only when its exact count/bytes/head V5 anchor
			// exists. Never truncate or adopt an unanchored suffix.
			return ErrPCCReceiptCorrupt
		},
		append(
			[]durablefile.Option{durablefile.WithMaxFrame(pccReceiptMaxFrame)},
			options...,
		)...,
	)
	if err != nil {
		pccReceiptFailState(state, "observer_pcc_receipt_corrupt")
		return nil, pccReceiptCorrupt(err)
	}
	fail := func(result error) (*PCCReceiptStore, error) {
		_ = journal.Close()
		pccReceiptFailState(state, "observer_pcc_receipt_corrupt")
		return nil, pccReceiptCorrupt(result)
	}
	if recovery.TailRepaired || recovery.VerifiedBytes < 0 ||
		uint64(recovery.VerifiedBytes) > pccReceiptMaxBytes ||
		uint64(len(recovery.Records)) > pccReceiptMaxCount {
		return fail(nil)
	}
	receipts := make(map[string]PCCPublicationReceipt, len(recovery.Records))
	seenSnapshotEvents := make(map[string]struct{}, len(recovery.Records))
	seenSnapshotContents := make(map[string]struct{}, len(recovery.Records))
	for _, frame := range recovery.Records {
		record, decodeErr := contracts.DecodeStrict[PCCPublicationReceiptRecord](
			bytes.NewReader(frame.Payload),
			int64(pccReceiptMaxFrame),
		)
		if decodeErr != nil {
			return fail(decodeErr)
		}
		canonical, canonicalErr := contracts.CanonicalJSON(record)
		if canonicalErr != nil || !bytes.Equal(canonical, frame.Payload) {
			return fail(canonicalErr)
		}
		if _, duplicate := receipts[record.Receipt.OperationKey]; duplicate {
			return fail(nil)
		}
		if _, duplicate := seenSnapshotEvents[record.Receipt.SnapshotEventID]; duplicate {
			return fail(nil)
		}
		if _, duplicate := seenSnapshotContents[record.Receipt.SnapshotContentSHA256]; duplicate {
			return fail(nil)
		}
		receipts[record.Receipt.OperationKey] = record.Receipt
		seenSnapshotEvents[record.Receipt.SnapshotEventID] = struct{}{}
		seenSnapshotContents[record.Receipt.SnapshotContentSHA256] = struct{}{}
	}
	headHash := zeroPCCJournalHash
	if len(recovery.Records) > 0 {
		headHash = hex.EncodeToString(
			recovery.Records[len(recovery.Records)-1].Hash[:],
		)
	}
	anchor := PCCReceiptAnchor{
		Count:    uint64(len(recovery.Records)),
		Bytes:    uint64(recovery.VerifiedBytes),
		HeadHash: headHash,
	}
	if anchor.validate() != nil || anchor != stateAnchor {
		return fail(nil)
	}
	return &PCCReceiptStore{
		journal:  journal,
		state:    state,
		anchor:   anchor,
		receipts: receipts,
	}, nil
}

func (receipts *PCCReceiptStore) ensureJournalLocked() error {
	if receipts.journal != nil {
		return nil
	}
	if receipts.anchor.Count != 0 || receipts.anchor.Bytes != 0 ||
		receipts.anchor.HeadHash != zeroPCCJournalHash {
		return ErrPCCReceiptCorrupt
	}
	journal, recovery, err := durablefile.NewJournalWithTailIntent(
		pccReceiptJournalPath(filepath.Dir(receipts.state.path)),
		func(durablefile.TornTailIntent) error { return ErrPCCReceiptCorrupt },
		durablefile.WithMaxFrame(pccReceiptMaxFrame),
	)
	if err != nil {
		receipts.failed = true
		pccReceiptFailState(receipts.state, "observer_pcc_receipt_append_failed")
		return pccReceiptCorrupt(err)
	}
	if recovery.TailRepaired || recovery.VerifiedBytes != 0 ||
		len(recovery.Records) != 0 {
		_ = journal.Close()
		receipts.failed = true
		pccReceiptFailState(receipts.state, "observer_pcc_receipt_append_invalid")
		return ErrPCCReceiptCorrupt
	}
	receipts.journal = journal
	return nil
}

func clonePCCPublicationReceipt(
	receipt PCCPublicationReceipt,
) (PCCPublicationReceipt, error) {
	record := PCCPublicationReceiptRecord{
		SchemaVersion: pccReceiptRecordSchema,
		Receipt:       receipt,
	}
	canonical, err := contracts.CanonicalJSON(record)
	if err != nil {
		return PCCPublicationReceipt{}, pccReceiptCorrupt(err)
	}
	cloned, err := contracts.DecodeStrict[PCCPublicationReceiptRecord](
		bytes.NewReader(canonical),
		int64(pccReceiptMaxFrame),
	)
	if err != nil {
		return PCCPublicationReceipt{}, pccReceiptCorrupt(err)
	}
	return cloned.Receipt, nil
}

func pccSnapshotFromExactItem(
	item SpoolItem,
) (contracts.PCCCorrelationSnapshotV1, contracts.EventEnvelopeV1, error) {
	coreEvent, err := coreEventFromSpoolItem(item)
	if err != nil {
		return contracts.PCCCorrelationSnapshotV1{}, contracts.EventEnvelopeV1{},
			pccReceiptCorrupt(err)
	}
	event := coreEvent.Envelope
	if event.EventType != "pcc_correlation_snapshot" ||
		event.SourceID != "agmind-observerd" ||
		event.SourceVersion != "0.1.0" ||
		event.ClockUncertaintyMS != 0 ||
		len(event.RedactionFlags) != 0 ||
		len(event.CoverageFlags) != 0 ||
		event.SourcePayloadHash != event.NormalizedFieldsSHA256 {
		return contracts.PCCCorrelationSnapshotV1{}, contracts.EventEnvelopeV1{},
			ErrPCCReceiptCorrupt
	}
	normalized, err := contracts.CanonicalJSON(event.NormalizedFields)
	if err != nil {
		return contracts.PCCCorrelationSnapshotV1{}, contracts.EventEnvelopeV1{},
			pccReceiptCorrupt(err)
	}
	digest := sha256.Sum256(normalized)
	if hex.EncodeToString(digest[:]) != event.NormalizedFieldsSHA256 {
		return contracts.PCCCorrelationSnapshotV1{}, contracts.EventEnvelopeV1{},
			ErrPCCReceiptCorrupt
	}
	snapshot, err := contracts.DecodeStrict[contracts.PCCCorrelationSnapshotV1](
		bytes.NewReader(normalized),
		65_536,
	)
	if err != nil || snapshot.Trigger.SourceSequence >= event.SourceSequence ||
		snapshot.CoverageThroughSequence != event.SourceSequence-1 ||
		snapshot.Trigger.HostID != event.HostID {
		return contracts.PCCCorrelationSnapshotV1{}, contracts.EventEnvelopeV1{},
			pccReceiptCorrupt(err)
	}
	return snapshot, event, nil
}

func validatePCCReceiptBinding(
	receipt PCCPublicationReceipt,
	item SpoolItem,
) error {
	if receipt.validateShape() != nil ||
		receipt.SnapshotEventID != item.EventID ||
		receipt.SnapshotContentSHA256 != item.ContentSHA256 ||
		item.Tier != PriorityTier {
		return ErrPCCReceiptCorrupt
	}
	snapshot, event, err := pccSnapshotFromExactItem(item)
	if err != nil {
		return err
	}
	request := contracts.PCCCorrelationSnapshotRequestV1{
		SchemaVersion:         "agmind.pcc-correlation-snapshot-request.v1",
		TriggerEventID:        snapshot.Trigger.EventID,
		TriggerContentSHA256:  snapshot.Trigger.ContentSHA256,
		TriggerSourceSequence: snapshot.Trigger.SourceSequence,
		RequestedTTLSeconds:   snapshot.RequestedTTLSeconds,
	}
	requestSHA256, err := contracts.PCCCorrelationRequestSHA256(request)
	if err != nil ||
		receipt.OperationKey != "pcc_correlation_snapshot:"+snapshot.Trigger.EventID ||
		receipt.RequestSHA256 != requestSHA256 ||
		snapshot.RequestSHA256 != requestSHA256 ||
		receipt.SnapshotNormalizedSHA256 != event.NormalizedFieldsSHA256 {
		return pccReceiptCorrupt(err)
	}
	return nil
}

func (receipts *PCCReceiptStore) Lookup(
	operationKey string,
	requestSHA256 string,
) (PCCPublicationReceipt, bool, error) {
	if receipts == nil || receipts.spool == nil {
		return PCCPublicationReceipt{}, false, ErrPCCReceiptCorrupt
	}
	spool := receipts.spool
	spool.state.publicationMutex.Lock()
	defer spool.state.publicationMutex.Unlock()
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	receipt, found, err := receipts.lookupLocked(operationKey, requestSHA256)
	if errors.Is(err, errPCCReceiptBinding) {
		pccReceiptFailState(receipts.state, "observer_pcc_receipt_binding_invalid")
	}
	return receipt, found, err
}

func (receipts *PCCReceiptStore) lookupLocked(
	operationKey string,
	requestSHA256 string,
) (PCCPublicationReceipt, bool, error) {
	receipts.mutex.Lock()
	defer receipts.mutex.Unlock()
	if receipts.closed || receipts.failed || receipts.spool == nil ||
		!hex64Pattern.MatchString(requestSHA256) {
		return PCCPublicationReceipt{}, false, ErrPCCReceiptCorrupt
	}
	receipt, found := receipts.receipts[operationKey]
	if found && receipt.RequestSHA256 != requestSHA256 {
		pccReceiptFailState(receipts.state, "observer_pcc_request_conflict")
		return PCCPublicationReceipt{}, false, ErrPCCReceiptConflict
	}
	if receipts.state.Snapshot().MutationReadOnly {
		return PCCPublicationReceipt{}, false, ErrPCCReceiptCorrupt
	}
	if !found {
		return PCCPublicationReceipt{}, false, nil
	}
	item, err := receipts.spool.lookupUnacknowledgedEventLocked(
		receipt.SnapshotEventID,
		receipt.SnapshotContentSHA256,
	)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return PCCPublicationReceipt{}, false, pccReceiptCorrupt(err)
		}
		return PCCPublicationReceipt{}, false,
			errors.Join(ErrPCCReceiptCorrupt, errPCCReceiptBinding, err)
	}
	if err := validatePCCReceiptBinding(receipt, item); err != nil {
		return PCCPublicationReceipt{}, false,
			errors.Join(ErrPCCReceiptCorrupt, errPCCReceiptBinding, err)
	}
	cloned, err := clonePCCPublicationReceipt(receipt)
	if err != nil {
		receipts.failed = true
		return PCCPublicationReceipt{}, false, err
	}
	return cloned, true, nil
}

func (receipts *PCCReceiptStore) Append(
	receipt PCCPublicationReceipt,
) error {
	if receipts == nil || receipts.spool == nil {
		return ErrPCCReceiptCorrupt
	}
	spool := receipts.spool
	spool.state.publicationMutex.Lock()
	defer spool.state.publicationMutex.Unlock()
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	return spool.appendPCCReceiptLocked(receipt)
}

func (receipts *PCCReceiptStore) previewAppendLocked(
	receipt PCCPublicationReceipt,
) ([]byte, durablefile.RecordMeta, PCCReceiptAnchor, error) {
	owned, err := clonePCCPublicationReceipt(receipt)
	if err != nil {
		return nil, durablefile.RecordMeta{}, PCCReceiptAnchor{}, err
	}
	record := PCCPublicationReceiptRecord{
		SchemaVersion: pccReceiptRecordSchema,
		Receipt:       owned,
	}
	canonical, err := contracts.CanonicalJSON(record)
	if err != nil {
		return nil, durablefile.RecordMeta{}, PCCReceiptAnchor{},
			pccReceiptCorrupt(err)
	}
	if receipts.anchor.validate() != nil ||
		receipts.anchor.Count >= pccReceiptMaxCount {
		return nil, durablefile.RecordMeta{}, PCCReceiptAnchor{},
			ErrPCCReceiptQuota
	}
	var previous [sha256.Size]byte
	if receipts.anchor.Count > 0 {
		decoded, err := hex.DecodeString(receipts.anchor.HeadHash)
		if err != nil {
			return nil, durablefile.RecordMeta{}, PCCReceiptAnchor{},
				ErrPCCReceiptCorrupt
		}
		copy(previous[:], decoded)
	}
	_, meta, err := durablefile.EncodeFrame(
		canonical,
		previous,
		pccReceiptMaxFrame,
	)
	if err != nil || meta.Size > pccReceiptMaxBytes-receipts.anchor.Bytes {
		return nil, durablefile.RecordMeta{}, PCCReceiptAnchor{},
			ErrPCCReceiptQuota
	}
	next := PCCReceiptAnchor{
		Count:    receipts.anchor.Count + 1,
		Bytes:    receipts.anchor.Bytes + meta.Size,
		HeadHash: hex.EncodeToString(meta.Hash[:]),
	}
	return canonical, meta, next, nil
}

func (receipts *PCCReceiptStore) appendBoundLocked(
	receipt PCCPublicationReceipt,
	item SpoolItem,
) (uint64, error) {
	receipts.mutex.Lock()
	defer receipts.mutex.Unlock()
	if receipts.closed || receipts.failed {
		return 0, ErrPCCReceiptCorrupt
	}
	if existing, found := receipts.receipts[receipt.OperationKey]; found {
		if existing.RequestSHA256 != receipt.RequestSHA256 {
			pccReceiptFailState(receipts.state, "observer_pcc_request_conflict")
			return 0, ErrPCCReceiptConflict
		}
		if existing != receipt || validatePCCReceiptBinding(existing, item) != nil {
			return 0, ErrPCCReceiptCorrupt
		}
		return 0, nil
	}
	if err := validatePCCReceiptBinding(receipt, item); err != nil {
		return 0, err
	}
	for _, existing := range receipts.receipts {
		if existing.SnapshotEventID == receipt.SnapshotEventID ||
			existing.SnapshotContentSHA256 == receipt.SnapshotContentSHA256 {
			return 0, ErrPCCReceiptCorrupt
		}
	}
	canonical, expectedMeta, next, err := receipts.previewAppendLocked(receipt)
	if err != nil {
		return 0, err
	}
	if err := receipts.ensureJournalLocked(); err != nil {
		return 0, err
	}
	meta, err := receipts.journal.Append(canonical, true)
	if err != nil {
		receipts.failed = true
		pccReceiptFailState(receipts.state, "observer_pcc_receipt_append_failed")
		return 0, err
	}
	if meta.Size != expectedMeta.Size || meta.Hash != expectedMeta.Hash ||
		meta.PreviousHash != expectedMeta.PreviousHash {
		receipts.failed = true
		pccReceiptFailState(receipts.state, "observer_pcc_receipt_append_invalid")
		return 0, ErrPCCReceiptCorrupt
	}
	if err := receipts.state.anchorPCCReceipt(receipts.anchor, next); err != nil {
		receipts.failed = true
		pccReceiptFailState(receipts.state, "observer_pcc_receipt_anchor_failed")
		return 0, err
	}
	owned, err := clonePCCPublicationReceipt(receipt)
	if err != nil {
		receipts.failed = true
		pccReceiptFailState(receipts.state, "observer_pcc_receipt_append_invalid")
		return 0, err
	}
	receipts.anchor = next
	receipts.receipts[receipt.OperationKey] = owned
	return meta.Size, nil
}

func (receipts *PCCReceiptStore) requireItemLocked(item SpoolItem) error {
	receipts.mutex.Lock()
	defer receipts.mutex.Unlock()
	if receipts.closed || receipts.failed {
		return ErrPCCReceiptCorrupt
	}
	return receipts.requireItemOwned(item)
}

func (receipts *PCCReceiptStore) requireItemOwned(item SpoolItem) error {
	coreEvent, err := coreEventFromSpoolItem(item)
	if err != nil {
		return ErrPCCReceiptCorrupt
	}
	if coreEvent.Envelope.EventType != "pcc_correlation_snapshot" {
		return nil
	}
	snapshot, _, err := pccSnapshotFromExactItem(item)
	if err != nil {
		return ErrPCCReceiptCorrupt
	}
	operationKey := "pcc_correlation_snapshot:" + snapshot.Trigger.EventID
	receipt, found := receipts.receipts[operationKey]
	if !found || validatePCCReceiptBinding(receipt, item) != nil {
		return ErrPCCReceiptCorrupt
	}
	return nil
}

func (receipts *PCCReceiptStore) validateLiveItems(
	items map[uint64]SpoolItem,
) error {
	receipts.mutex.Lock()
	defer receipts.mutex.Unlock()
	if receipts.closed || receipts.failed {
		return ErrPCCReceiptCorrupt
	}
	for _, item := range items {
		if err := receipts.requireItemOwned(item); err != nil {
			return err
		}
	}
	return nil
}

func (receipts *PCCReceiptStore) Close() error {
	if receipts == nil {
		return nil
	}
	receipts.mutex.Lock()
	defer receipts.mutex.Unlock()
	if receipts.closed {
		return nil
	}
	receipts.closed = true
	if receipts.journal == nil {
		return nil
	}
	err := receipts.journal.Close()
	receipts.journal = nil
	return err
}

func (spool *Spool) appendPCCReceiptLocked(
	receipt PCCPublicationReceipt,
) error {
	if spool.closed || spool.pccReceipts == nil ||
		spool.pccReceipts.spool != spool {
		return ErrPCCReceiptCorrupt
	}
	spool.pccReceipts.mutex.Lock()
	if spool.pccReceipts.closed || spool.pccReceipts.failed {
		spool.pccReceipts.mutex.Unlock()
		return ErrPCCReceiptCorrupt
	}
	if existing, found := spool.pccReceipts.receipts[receipt.OperationKey]; found && existing.RequestSHA256 != receipt.RequestSHA256 {
		pccReceiptFailState(
			spool.pccReceipts.state,
			"observer_pcc_request_conflict",
		)
		spool.pccReceipts.mutex.Unlock()
		return ErrPCCReceiptConflict
	}
	anchor := spool.pccReceipts.anchor
	spool.pccReceipts.mutex.Unlock()
	snapshot := spool.state.Snapshot()
	if snapshot.MutationReadOnly {
		return ErrPCCReceiptCorrupt
	}
	if pccReceiptAnchorFromState(snapshot) != anchor {
		pccReceiptFailState(
			spool.pccReceipts.state,
			"observer_pcc_receipt_preanchor_invalid",
		)
		return ErrPCCReceiptCorrupt
	}
	item, err := spool.lookupUnacknowledgedEventLocked(
		receipt.SnapshotEventID,
		receipt.SnapshotContentSHA256,
	)
	if err != nil {
		pccReceiptFailState(
			spool.pccReceipts.state,
			"observer_pcc_receipt_append_invalid",
		)
		return pccReceiptCorrupt(err)
	}
	spool.pccReceipts.mutex.Lock()
	if existing, found := spool.pccReceipts.receipts[receipt.OperationKey]; found {
		valid := existing == receipt &&
			validatePCCReceiptBinding(existing, item) == nil
		spool.pccReceipts.mutex.Unlock()
		if !valid {
			pccReceiptFailState(
				spool.pccReceipts.state,
				"observer_pcc_receipt_binding_invalid",
			)
			return ErrPCCReceiptCorrupt
		}
		return nil
	}
	spool.pccReceipts.mutex.Unlock()
	spool.pccReceipts.mutex.Lock()
	_, expectedMeta, _, previewErr := spool.pccReceipts.previewAppendLocked(receipt)
	spool.pccReceipts.mutex.Unlock()
	if previewErr != nil {
		reason := "observer_pcc_receipt_append_invalid"
		if errors.Is(previewErr, ErrPCCReceiptQuota) {
			reason = "observer_pcc_receipt_quota_exhausted"
		}
		pccReceiptFailState(spool.pccReceipts.state, reason)
		return previewErr
	}
	if spool.totalBytes > spool.config.MaxBytes ||
		ackJournalMaxFrameBytes > spool.config.MaxBytes-spool.totalBytes ||
		expectedMeta.Size >
			spool.config.MaxBytes-spool.totalBytes-ackJournalMaxFrameBytes {
		pccReceiptFailState(
			spool.pccReceipts.state,
			"observer_pcc_receipt_quota_exhausted",
		)
		return ErrPCCReceiptQuota
	}
	added, err := spool.pccReceipts.appendBoundLocked(receipt, item)
	if err != nil {
		if !spool.state.Snapshot().MutationReadOnly {
			reason := "observer_pcc_receipt_append_invalid"
			if errors.Is(err, ErrPCCReceiptQuota) {
				reason = "observer_pcc_receipt_quota_exhausted"
			}
			pccReceiptFailState(spool.pccReceipts.state, reason)
		}
		return err
	}
	if added > 0 {
		spool.pccReceiptBytes += added
		spool.totalBytes += added
	}
	return nil
}

func (spool *Spool) requirePCCReceiptLocked(item SpoolItem) error {
	if spool.pccReceipts == nil {
		return ErrPCCReceiptCorrupt
	}
	if err := spool.pccReceipts.requireItemLocked(item); err != nil {
		_ = spool.state.PersistReadOnly("observer_pcc_receipt_missing")
		return err
	}
	return nil
}

func (spool *Spool) lookupUnacknowledgedLocked(
	sourceSequence uint64,
	eventID string,
	contentSHA256 string,
) (SpoolItem, error) {
	snapshot := spool.state.Snapshot()
	if snapshot.MutationReadOnly {
		return SpoolItem{}, errors.Join(ErrSpoolCorrupt, errSpoolReadOnly)
	}
	if spool.closed || sourceSequence == 0 ||
		sourceSequence <= snapshot.AckSequence ||
		!eventPattern.MatchString(eventID) ||
		!hex64Pattern.MatchString(contentSHA256) {
		return SpoolItem{}, os.ErrNotExist
	}
	item, found := spool.items[sourceSequence]
	if !found || item.EventID != eventID || item.ContentSHA256 != contentSHA256 {
		return SpoolItem{}, os.ErrNotExist
	}
	event, canonical, contentHash, frameBytes, identity, err :=
		readStandaloneFrame(item.path, spool.keys)
	if err != nil || event.SourceSequence != item.Sequence ||
		event.EventID != item.EventID || contentHash != item.ContentSHA256 ||
		tierForEvent(event) != item.Tier || frameBytes != item.frameBytes ||
		identity != item.identity || !bytes.Equal(canonical, item.Canonical) ||
		validatePublicationItem(item) != nil {
		return SpoolItem{}, ErrSpoolCorrupt
	}
	item.Canonical = canonical
	return cloneSpoolItem(item), nil
}

func (spool *Spool) LookupUnacknowledged(
	sourceSequence uint64,
	eventID string,
	contentSHA256 string,
) (SpoolItem, error) {
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	item, err := spool.lookupUnacknowledgedLocked(
		sourceSequence,
		eventID,
		contentSHA256,
	)
	if errors.Is(err, ErrSpoolCorrupt) &&
		!errors.Is(err, errSpoolReadOnly) {
		_ = spool.state.PersistReadOnly("observer_spool_lookup_corrupt")
	}
	return item, err
}

func (spool *Spool) lookupUnacknowledgedEventLocked(
	eventID string,
	contentSHA256 string,
) (SpoolItem, error) {
	if spool.state.Snapshot().MutationReadOnly {
		return SpoolItem{}, errors.Join(ErrSpoolCorrupt, errSpoolReadOnly)
	}
	if !eventPattern.MatchString(eventID) ||
		!hex64Pattern.MatchString(contentSHA256) {
		return SpoolItem{}, os.ErrNotExist
	}
	acked := spool.state.Snapshot().AckSequence
	var sequence uint64
	for itemSequence, item := range spool.items {
		if itemSequence <= acked || item.EventID != eventID ||
			item.ContentSHA256 != contentSHA256 {
			continue
		}
		if sequence != 0 {
			return SpoolItem{}, ErrSpoolCorrupt
		}
		sequence = itemSequence
	}
	if sequence == 0 {
		return SpoolItem{}, os.ErrNotExist
	}
	return spool.lookupUnacknowledgedLocked(
		sequence,
		eventID,
		contentSHA256,
	)
}

func (spool *Spool) LookupUnacknowledgedEvent(
	eventID string,
	contentSHA256 string,
) (SpoolItem, error) {
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	item, err := spool.lookupUnacknowledgedEventLocked(eventID, contentSHA256)
	if errors.Is(err, ErrSpoolCorrupt) &&
		!errors.Is(err, errSpoolReadOnly) {
		_ = spool.state.PersistReadOnly("observer_spool_lookup_corrupt")
	}
	return item, err
}
