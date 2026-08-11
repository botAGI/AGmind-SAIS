package observerd

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

const (
	controlReceiptMaxFramePayload uint32 = 128 * 1024
	controlReceiptFrameOverhead          = 76
)

var (
	ErrControlReceiptConflict               = errors.New("control operation receipt conflict")
	ErrControlReceiptQuota                  = errors.New("control operation receipt quota exhausted")
	ErrControlReceiptCorrupt                = errors.New("control operation receipt journal corrupt")
	ErrControlReceiptReconciliationRequired = errors.New(
		"control operation receipt reconciliation required",
	)
)

type ControlReceiptAnchor struct {
	Count    uint64
	Bytes    uint64
	HeadHash string
}

func EmptyControlReceiptAnchor() ControlReceiptAnchor {
	return ControlReceiptAnchor{HeadHash: zeroControlReceiptHash}
}

func (anchor ControlReceiptAnchor) validate() error {
	if anchor.Count > controlReceiptMaxCount ||
		anchor.Bytes > controlReceiptMaxBytes ||
		!hex64Pattern.MatchString(anchor.HeadHash) ||
		(anchor.Count == 0) != (anchor.Bytes == 0) ||
		(anchor.Count == 0) !=
			(anchor.HeadHash == zeroControlReceiptHash) {
		return ErrControlReceiptCorrupt
	}
	return nil
}

func advanceControlReceiptAnchor(
	anchor ControlReceiptAnchor,
	meta durablefile.RecordMeta,
) (ControlReceiptAnchor, error) {
	if err := anchor.validate(); err != nil {
		return ControlReceiptAnchor{}, err
	}
	if anchor.Count >= controlReceiptMaxCount ||
		meta.Size > controlReceiptMaxBytes-anchor.Bytes {
		return ControlReceiptAnchor{}, ErrControlReceiptQuota
	}
	var expectedPrevious [sha256.Size]byte
	if anchor.Count > 0 {
		decoded, err := hex.DecodeString(anchor.HeadHash)
		if err != nil {
			return ControlReceiptAnchor{}, ErrControlReceiptCorrupt
		}
		copy(expectedPrevious[:], decoded)
	}
	if meta.PreviousHash != expectedPrevious {
		return ControlReceiptAnchor{}, ErrControlReceiptCorrupt
	}
	return ControlReceiptAnchor{
		Count:    anchor.Count + 1,
		Bytes:    anchor.Bytes + meta.Size,
		HeadHash: hex.EncodeToString(meta.Hash[:]),
	}, nil
}

type ControlReceipt struct {
	SchemaVersion string      `json:"schema_version"`
	Key           string      `json:"key"`
	RequestSHA256 string      `json:"request_sha256"`
	Item          CoreEventV1 `json:"item"`
}

func (receipt ControlReceipt) Validate() error {
	if receipt.SchemaVersion != "agmind.control-receipt.v1" ||
		!hex64Pattern.MatchString(receipt.RequestSHA256) ||
		receipt.Item.Validate() != nil {
		return ErrControlReceiptCorrupt
	}
	request, err := coreControlRequestFromEnvelope(receipt.Item.Envelope)
	if err != nil || request == nil ||
		request.OperationKey() != receipt.Key ||
		request.EventType() != receipt.Item.Envelope.EventType {
		return ErrControlReceiptCorrupt
	}
	requestSHA256, err := CoreControlRequestSHA256(request)
	if err != nil ||
		requestSHA256 != receipt.RequestSHA256 ||
		receipt.Item.Envelope.NormalizedFieldsSHA256 != requestSHA256 ||
		receipt.Item.Envelope.SourcePayloadHash != requestSHA256 ||
		receipt.Item.Envelope.SourceID != "agmind-observerd" ||
		receipt.Item.Envelope.ClockUncertaintyMS != 0 ||
		receipt.Item.Envelope.ContainerID != nil ||
		receipt.Item.Envelope.ContainerStartTime != nil ||
		receipt.Item.Envelope.ReleaseID != nil ||
		receipt.Item.Envelope.InventoryGeneration != 0 ||
		receipt.Item.Envelope.InventoryRevision != nil ||
		len(receipt.Item.Envelope.RedactionFlags) != 0 ||
		len(receipt.Item.Envelope.CoverageFlags) != 0 ||
		!priorityEventType(receipt.Item.Envelope.EventType) {
		return ErrControlReceiptCorrupt
	}
	return nil
}

func validateControlReceiptCausality(
	receipt ControlReceipt,
	receipts map[string]ControlReceipt,
) error {
	request, err := coreControlRequestFromEnvelope(receipt.Item.Envelope)
	if err != nil || request == nil {
		return ErrControlReceiptCorrupt
	}
	completion, isCompletion := request.(EvidenceRepairCompleteV1)
	if !isCompletion {
		return nil
	}
	authorizationKey := EvidenceRepairAuthorizeV1{
		RepairID: completion.RepairID,
	}.OperationKey()
	authorizationReceipt, found := receipts[authorizationKey]
	if !found ||
		authorizationReceipt.Validate() != nil ||
		authorizationReceipt.Item.Sequence >= receipt.Item.Sequence ||
		authorizationReceipt.Item.EventID != completion.AuthorizationEventID ||
		authorizationReceipt.Item.ContentSHA256 !=
			completion.AuthorizationContentSHA256 {
		return ErrControlReceiptCorrupt
	}
	authorizationRequest, err := coreControlRequestFromEnvelope(
		authorizationReceipt.Item.Envelope,
	)
	if err != nil {
		return ErrControlReceiptCorrupt
	}
	authorization, ok := authorizationRequest.(EvidenceRepairAuthorizeV1)
	if !ok {
		return ErrControlReceiptCorrupt
	}
	authorizationSHA256, err := CoreControlRequestSHA256(authorization)
	if err != nil ||
		authorizationReceipt.RequestSHA256 != authorizationSHA256 ||
		authorization.RepairID != completion.RepairID ||
		authorization.SegmentID != completion.SegmentID ||
		authorization.VerifiedBytes != completion.VerifiedBytes ||
		authorization.LastVerifiedFrameSHA256 !=
			completion.LastVerifiedFrameSHA256 ||
		authorization.CurrentChainHeadSHA256 !=
			completion.CurrentChainHeadSHA256 {
		return ErrControlReceiptCorrupt
	}
	return nil
}

func validateControlReceiptCandidateForAppend(
	receipt ControlReceipt,
	receipts map[string]ControlReceipt,
) error {
	if receipt.Validate() != nil {
		return ErrControlReceiptCorrupt
	}
	if _, duplicate := receipts[receipt.Key]; duplicate {
		return ErrControlReceiptCorrupt
	}
	var previousReceiptSequence uint64
	for _, existing := range receipts {
		if existing.Item.Sequence == receipt.Item.Sequence ||
			existing.Item.EventID == receipt.Item.EventID {
			return ErrControlReceiptCorrupt
		}
		if existing.Item.Sequence > previousReceiptSequence {
			previousReceiptSequence = existing.Item.Sequence
		}
	}
	if receipt.Item.Sequence <= previousReceiptSequence {
		return ErrControlReceiptCorrupt
	}
	return validateControlReceiptCausality(receipt, receipts)
}

func cloneCoreControlEvent(item CoreEventV1) (CoreEventV1, error) {
	canonical, err := contracts.CanonicalJSON(item)
	if err != nil {
		return CoreEventV1{}, ErrControlReceiptCorrupt
	}
	cloned, err := contracts.DecodeStrict[CoreEventV1](
		bytes.NewReader(canonical),
		int64(controlReceiptMaxFramePayload),
	)
	if err != nil || cloned.Validate() != nil {
		return CoreEventV1{}, ErrControlReceiptCorrupt
	}
	return cloned, nil
}

func cloneControlReceipt(receipt ControlReceipt) (ControlReceipt, error) {
	canonical, err := contracts.CanonicalJSON(receipt)
	if err != nil {
		return ControlReceipt{}, ErrControlReceiptCorrupt
	}
	cloned, err := contracts.DecodeStrict[ControlReceipt](
		bytes.NewReader(canonical),
		int64(controlReceiptMaxFramePayload),
	)
	if err != nil || cloned.Validate() != nil {
		return ControlReceipt{}, ErrControlReceiptCorrupt
	}
	return cloned, nil
}

func controlReceiptJournalPath(stateDir string) string {
	return filepath.Join(stateDir, "spool", "control-receipts.agf")
}

type ControlReceiptRecoveryKind string

const (
	ControlReceiptRecoveryExact          ControlReceiptRecoveryKind = "exact"
	ControlReceiptRecoveryCompleteTail   ControlReceiptRecoveryKind = "complete_tail"
	ControlReceiptRecoveryIncompleteTail ControlReceiptRecoveryKind = "incomplete_tail"
)

type ControlReceiptRecovery struct {
	Kind            ControlReceiptRecoveryKind
	JournalAnchor   ControlReceiptAnchor
	Candidate       *ControlReceipt
	UnanchoredBytes uint64
	receipts        map[string]ControlReceipt
}

func anchorHashBytes(anchor ControlReceiptAnchor) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if err := anchor.validate(); err != nil {
		return result, err
	}
	if anchor.Count == 0 {
		return result, nil
	}
	raw, err := hex.DecodeString(anchor.HeadHash)
	if err != nil {
		return result, ErrControlReceiptCorrupt
	}
	copy(result[:], raw)
	return result, nil
}

func inspectControlReceiptBytes(
	raw []byte,
	stateAnchor ControlReceiptAnchor,
) (ControlReceiptRecovery, error) {
	if err := stateAnchor.validate(); err != nil {
		return ControlReceiptRecovery{}, err
	}
	anchor := EmptyControlReceiptAnchor()
	anchoredPrefixMatches := stateAnchor.Count == 0
	receipts := make(map[string]ControlReceipt)
	sequences := make(map[uint64]struct{})
	eventIDs := make(map[string]struct{})
	var previousReceiptSequence uint64
	var candidate *ControlReceipt
	var expectedPrevious [sha256.Size]byte
	offset := 0
	for offset < len(raw) {
		remaining := len(raw) - offset
		if remaining < 8 {
			if uint64(offset) != stateAnchor.Bytes || !anchoredPrefixMatches {
				return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
			}
			return ControlReceiptRecovery{
				Kind:            ControlReceiptRecoveryIncompleteTail,
				JournalAnchor:   anchor,
				UnanchoredBytes: uint64(remaining),
				receipts:        receipts,
			}, nil
		}
		if string(raw[offset:offset+4]) != "AGF1" {
			return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
		}
		payloadBytes := binary.BigEndian.Uint32(raw[offset+4 : offset+8])
		if payloadBytes > controlReceiptMaxFramePayload {
			return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
		}
		frameBytes := uint64(controlReceiptFrameOverhead) + uint64(payloadBytes)
		if frameBytes > uint64(remaining) {
			if uint64(offset) != stateAnchor.Bytes || !anchoredPrefixMatches {
				return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
			}
			return ControlReceiptRecovery{
				Kind:            ControlReceiptRecoveryIncompleteTail,
				JournalAnchor:   anchor,
				UnanchoredBytes: uint64(remaining),
				receipts:        receipts,
			}, nil
		}
		frame, err := durablefile.DecodeFrame(
			raw[offset:offset+int(frameBytes)],
			controlReceiptMaxFramePayload,
			expectedPrevious,
		)
		if err != nil {
			return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
		}
		var receipt ControlReceipt
		receipt, err = contracts.DecodeStrict[ControlReceipt](
			bytes.NewReader(frame.Payload),
			int64(controlReceiptMaxFramePayload),
		)
		if err != nil || receipt.Validate() != nil {
			return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
		}
		canonical, err := contracts.CanonicalJSON(receipt)
		if err != nil || !bytes.Equal(canonical, frame.Payload) {
			return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
		}
		if _, duplicate := receipts[receipt.Key]; duplicate {
			return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
		}
		if receipt.Item.Sequence <= previousReceiptSequence {
			return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
		}
		if _, duplicate := sequences[receipt.Item.Sequence]; duplicate {
			return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
		}
		if _, duplicate := eventIDs[receipt.Item.EventID]; duplicate {
			return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
		}
		receipts[receipt.Key] = receipt
		if err := validateControlReceiptCausality(
			receipt,
			receipts,
		); err != nil {
			return ControlReceiptRecovery{}, err
		}
		sequences[receipt.Item.Sequence] = struct{}{}
		eventIDs[receipt.Item.EventID] = struct{}{}
		previousReceiptSequence = receipt.Item.Sequence
		anchor, err = advanceControlReceiptAnchor(anchor, frame.RecordMeta)
		if err != nil {
			return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
		}
		offset += int(frameBytes)
		expectedPrevious = frame.Hash
		if anchor.Count == stateAnchor.Count {
			anchoredPrefixMatches = anchor == stateAnchor
		}
		if anchor.Count > stateAnchor.Count {
			if anchor.Count != stateAnchor.Count+1 {
				return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
			}
			copied := receipt
			candidate = &copied
		}
	}
	if anchor == stateAnchor {
		return ControlReceiptRecovery{
			Kind:          ControlReceiptRecoveryExact,
			JournalAnchor: anchor,
			receipts:      receipts,
		}, nil
	}
	if !anchoredPrefixMatches ||
		anchor.Count != stateAnchor.Count+1 ||
		candidate == nil {
		return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
	}
	return ControlReceiptRecovery{
		Kind:          ControlReceiptRecoveryCompleteTail,
		JournalAnchor: anchor,
		Candidate:     candidate,
		receipts:      receipts,
	}, nil
}

func InspectControlReceiptJournal(
	stateDir string,
	stateAnchor ControlReceiptAnchor,
) (ControlReceiptRecovery, error) {
	path := controlReceiptJournalPath(stateDir)
	raw, err := durablefile.ReadRegular(
		path,
		int64(controlReceiptMaxBytes)+
			int64(controlReceiptMaxFramePayload)+
			controlReceiptFrameOverhead,
	)
	if errors.Is(err, os.ErrNotExist) {
		if stateAnchor != EmptyControlReceiptAnchor() {
			return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
		}
		return ControlReceiptRecovery{
			Kind:          ControlReceiptRecoveryExact,
			JournalAnchor: stateAnchor,
			receipts:      make(map[string]ControlReceipt),
		}, nil
	}
	if err != nil {
		return ControlReceiptRecovery{}, errors.Join(
			ErrControlReceiptCorrupt,
			err,
		)
	}
	return inspectControlReceiptBytes(raw, stateAnchor)
}

func inspectLockedControlReceiptRecovery(
	recovery durablefile.Recovery,
	stateAnchor ControlReceiptAnchor,
) (ControlReceiptRecovery, error) {
	if err := stateAnchor.validate(); err != nil ||
		recovery.VerifiedBytes < 0 {
		return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
	}
	anchor := EmptyControlReceiptAnchor()
	anchoredPrefixMatches := stateAnchor.Count == 0
	receipts := make(map[string]ControlReceipt, len(recovery.Records))
	sequences := make(map[uint64]struct{}, len(recovery.Records))
	eventIDs := make(map[string]struct{}, len(recovery.Records))
	var previousReceiptSequence uint64
	var candidate *ControlReceipt
	for _, record := range recovery.Records {
		receipt, err := contracts.DecodeStrict[ControlReceipt](
			bytes.NewReader(record.Payload),
			int64(controlReceiptMaxFramePayload),
		)
		if err != nil || receipt.Validate() != nil {
			return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
		}
		canonical, err := contracts.CanonicalJSON(receipt)
		if err != nil || !bytes.Equal(canonical, record.Payload) {
			return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
		}
		if _, duplicate := receipts[receipt.Key]; duplicate {
			return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
		}
		if receipt.Item.Sequence <= previousReceiptSequence {
			return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
		}
		if _, duplicate := sequences[receipt.Item.Sequence]; duplicate {
			return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
		}
		if _, duplicate := eventIDs[receipt.Item.EventID]; duplicate {
			return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
		}
		receipts[receipt.Key] = receipt
		if err := validateControlReceiptCausality(
			receipt,
			receipts,
		); err != nil {
			return ControlReceiptRecovery{}, err
		}
		sequences[receipt.Item.Sequence] = struct{}{}
		eventIDs[receipt.Item.EventID] = struct{}{}
		previousReceiptSequence = receipt.Item.Sequence
		anchor, err = advanceControlReceiptAnchor(anchor, record.RecordMeta)
		if err != nil {
			return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
		}
		if anchor.Count == stateAnchor.Count {
			anchoredPrefixMatches = anchor == stateAnchor
		}
		if anchor.Count > stateAnchor.Count {
			if anchor.Count != stateAnchor.Count+1 {
				return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
			}
			cloned, cloneErr := cloneControlReceipt(receipt)
			if cloneErr != nil {
				return ControlReceiptRecovery{}, cloneErr
			}
			candidate = &cloned
		}
	}
	if uint64(recovery.VerifiedBytes) != anchor.Bytes {
		return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
	}
	if anchor == stateAnchor {
		return ControlReceiptRecovery{
			Kind:          ControlReceiptRecoveryExact,
			JournalAnchor: anchor,
			receipts:      receipts,
		}, nil
	}
	if !anchoredPrefixMatches ||
		anchor.Count != stateAnchor.Count+1 ||
		candidate == nil {
		return ControlReceiptRecovery{}, ErrControlReceiptCorrupt
	}
	return ControlReceiptRecovery{
		Kind:          ControlReceiptRecoveryCompleteTail,
		JournalAnchor: anchor,
		Candidate:     candidate,
		receipts:      receipts,
	}, nil
}

// ControlReceiptLiveProof can only be sealed by re-reading an immutable,
// signed priority spool frame and its publication binding.
type ControlReceiptLiveProof struct {
	key           string
	requestSHA256 string
	item          CoreEventV1
	sealed        bool
}

func receiptFromProof(proof ControlReceiptLiveProof) (ControlReceipt, error) {
	if !proof.sealed {
		return ControlReceipt{}, ErrControlReceiptCorrupt
	}
	receipt := ControlReceipt{
		SchemaVersion: "agmind.control-receipt.v1",
		Key:           proof.key,
		RequestSHA256: proof.requestSHA256,
		Item:          proof.item,
	}
	return cloneControlReceipt(receipt)
}

func controlReceiptProofFromLiveSpoolItem(
	item SpoolItem,
	keys *Keyring,
) (ControlReceiptLiveProof, bool, error) {
	if keys == nil {
		return ControlReceiptLiveProof{}, false, ErrControlReceiptCorrupt
	}
	event, canonical, contentHash, frameBytes, identity, err :=
		readStandaloneFrame(item.path, keys)
	if err != nil ||
		event.SourceSequence != item.Sequence ||
		event.EventID != item.EventID ||
		contentHash != item.ContentSHA256 ||
		frameBytes != item.frameBytes ||
		!identity.Same(item.identity) ||
		tierForEvent(event) != item.Tier ||
		!bytes.Equal(canonical, item.Canonical) ||
		validatePublicationItem(item) != nil {
		return ControlReceiptLiveProof{}, false, ErrControlReceiptCorrupt
	}
	exactItem, err := coreEventFromSpoolItem(SpoolItem{
		Sequence:      item.Sequence,
		EventID:       item.EventID,
		ContentSHA256: item.ContentSHA256,
		Canonical:     canonical,
	})
	if err != nil {
		return ControlReceiptLiveProof{}, false, ErrControlReceiptCorrupt
	}
	request, err := coreControlRequestFromEnvelope(exactItem.Envelope)
	if err != nil {
		return ControlReceiptLiveProof{}, false, ErrControlReceiptCorrupt
	}
	if request == nil {
		return ControlReceiptLiveProof{}, false, nil
	}
	if item.Tier != PriorityTier {
		return ControlReceiptLiveProof{}, false, ErrControlReceiptCorrupt
	}
	requestSHA256, err := CoreControlRequestSHA256(request)
	if err != nil {
		return ControlReceiptLiveProof{}, false, ErrControlReceiptCorrupt
	}
	proof := ControlReceiptLiveProof{
		key:           request.OperationKey(),
		requestSHA256: requestSHA256,
		item:          exactItem,
		sealed:        true,
	}
	if _, err := receiptFromProof(proof); err != nil {
		return ControlReceiptLiveProof{}, false, err
	}
	return proof, true, nil
}

func ReconcileControlReceiptJournal(
	stateDir string,
	stateAnchor ControlReceiptAnchor,
	proof ControlReceiptLiveProof,
	commit func(ControlReceiptAnchor, ControlReceiptAnchor) error,
) (ControlReceiptAnchor, error) {
	return reconcileControlReceiptJournal(
		stateDir,
		stateAnchor,
		proof,
		nil,
		commit,
	)
}

func reconcileControlReceiptJournal(
	stateDir string,
	stateAnchor ControlReceiptAnchor,
	proof ControlReceiptLiveProof,
	validateLocked func(map[string]ControlReceipt) error,
	commit func(ControlReceiptAnchor, ControlReceiptAnchor) error,
) (ControlReceiptAnchor, error) {
	if commit == nil {
		return ControlReceiptAnchor{}, fmt.Errorf("nil receipt recovery commit")
	}
	receipt, err := receiptFromProof(proof)
	if err != nil {
		return ControlReceiptAnchor{}, err
	}
	canonical, err := contracts.CanonicalJSON(receipt)
	if err != nil {
		return ControlReceiptAnchor{}, err
	}
	previous, err := anchorHashBytes(stateAnchor)
	if err != nil {
		return ControlReceiptAnchor{}, err
	}
	frame, meta, err := durablefile.EncodeFrame(
		canonical,
		previous,
		controlReceiptMaxFramePayload,
	)
	if err != nil {
		return ControlReceiptAnchor{}, err
	}
	next, err := advanceControlReceiptAnchor(stateAnchor, meta)
	if err != nil {
		return ControlReceiptAnchor{}, err
	}
	path := controlReceiptJournalPath(stateDir)
	var acceptedTornTail bool
	journal, lockedRecovery, err := durablefile.NewJournalWithTailIntent(
		path,
		func(intent durablefile.TornTailIntent) error {
			if intent.VerifiedBytes < 0 ||
				uint64(intent.VerifiedBytes) != stateAnchor.Bytes ||
				len(intent.Tail) == 0 ||
				len(intent.Tail) >= len(frame) ||
				!bytes.Equal(intent.Tail, frame[:len(intent.Tail)]) {
				return ErrControlReceiptCorrupt
			}
			lockedPrefix, err := inspectLockedControlReceiptRecovery(
				durablefile.Recovery{
					Records:       intent.Records,
					VerifiedBytes: intent.VerifiedBytes,
				},
				stateAnchor,
			)
			if err != nil ||
				lockedPrefix.Kind != ControlReceiptRecoveryExact ||
				validateControlReceiptCandidateForAppend(
					receipt,
					lockedPrefix.receipts,
				) != nil {
				return ErrControlReceiptCorrupt
			}
			if validateLocked != nil {
				withCandidate := make(
					map[string]ControlReceipt,
					len(lockedPrefix.receipts)+1,
				)
				for key, existing := range lockedPrefix.receipts {
					withCandidate[key] = existing
				}
				withCandidate[receipt.Key] = receipt
				if err := validateLocked(withCandidate); err != nil {
					return err
				}
			}
			acceptedTornTail = true
			return nil
		},
		durablefile.WithMaxFrame(controlReceiptMaxFramePayload),
	)
	if err != nil {
		return ControlReceiptAnchor{}, err
	}
	defer journal.Close()
	lockedState, err := inspectLockedControlReceiptRecovery(
		lockedRecovery,
		stateAnchor,
	)
	if err != nil {
		return ControlReceiptAnchor{}, err
	}
	if err := validateControlReceiptCausality(
		receipt,
		lockedState.receipts,
	); err != nil {
		return ControlReceiptAnchor{}, err
	}
	if !acceptedTornTail && validateLocked != nil {
		if err := validateLocked(lockedState.receipts); err != nil {
			return ControlReceiptAnchor{}, err
		}
	}
	switch {
	case acceptedTornTail:
		if !lockedRecovery.TailRepaired ||
			lockedState.Kind != ControlReceiptRecoveryExact ||
			lockedState.JournalAnchor != stateAnchor {
			return ControlReceiptAnchor{}, ErrControlReceiptCorrupt
		}
		appended, appendErr := journal.Append(canonical, true)
		if appendErr != nil {
			return ControlReceiptAnchor{}, appendErr
		}
		actual, advanceErr := advanceControlReceiptAnchor(stateAnchor, appended)
		if advanceErr != nil || actual != next {
			return ControlReceiptAnchor{}, ErrControlReceiptCorrupt
		}
	case lockedRecovery.TailRepaired:
		return ControlReceiptAnchor{}, ErrControlReceiptCorrupt
	default:
		if lockedState.Kind != ControlReceiptRecoveryCompleteTail ||
			lockedState.Candidate == nil ||
			!controlReceiptsEqual(*lockedState.Candidate, receipt) ||
			lockedState.JournalAnchor != next {
			return ControlReceiptAnchor{}, ErrControlReceiptCorrupt
		}
	}
	if err := commit(stateAnchor, next); err != nil {
		return ControlReceiptAnchor{}, err
	}
	return next, nil
}

func controlReceiptsEqual(left, right ControlReceipt) bool {
	leftRaw, leftErr := contracts.CanonicalJSON(left)
	rightRaw, rightErr := contracts.CanonicalJSON(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

func coreControlEventsEqual(left, right CoreEventV1) bool {
	leftRaw, leftErr := contracts.CanonicalJSON(left)
	rightRaw, rightErr := contracts.CanonicalJSON(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

func controlReceiptAnchorFromState(state ObserverState) ControlReceiptAnchor {
	return ControlReceiptAnchor{
		Count:    state.ControlReceiptCount,
		Bytes:    state.ControlReceiptBytes,
		HeadHash: state.ControlReceiptHeadHash,
	}
}

func controlReceiptProofsMissingFrom(
	items map[uint64]SpoolItem,
	receipts map[string]ControlReceipt,
	keys *Keyring,
) ([]ControlReceiptLiveProof, error) {
	missing := make([]ControlReceiptLiveProof, 0, 1)
	for _, spoolItem := range items {
		proof, control, err := controlReceiptProofFromLiveSpoolItem(
			spoolItem,
			keys,
		)
		if err != nil {
			return nil, err
		}
		if !control {
			continue
		}
		if receipt, exists := receipts[proof.key]; exists {
			if receipt.RequestSHA256 != proof.requestSHA256 ||
				!coreControlEventsEqual(receipt.Item, proof.item) {
				return nil, ErrControlReceiptCorrupt
			}
			continue
		}
		missing = append(missing, proof)
	}
	return missing, nil
}

func controlReceiptEventAllowedByIdentityHistory(
	event contracts.EventEnvelopeV1,
	state ObserverState,
	keys *Keyring,
) bool {
	if keys == nil ||
		keys.Verify(event) != nil ||
		!eventAllowedByState(event, state, nil) {
		return false
	}
	keys.mutex.RLock()
	hostID := keys.hostID
	metadataEpoch := keys.metadataEpoch
	epochKeys := make(map[uint64]string, len(keys.keys))
	for keyID, entry := range keys.keys {
		if existing, duplicate := epochKeys[entry.epoch]; duplicate &&
			existing != keyID {
			keys.mutex.RUnlock()
			return false
		}
		epochKeys[entry.epoch] = keyID
	}
	transitionSequences := make(
		map[uint64]uint64,
		len(keys.boundaries),
	)
	for epoch, boundary := range keys.boundaries {
		if boundary.epoch != epoch {
			keys.mutex.RUnlock()
			return false
		}
		transitionSequences[epoch] = boundary.transition.SourceSequence
	}
	keys.mutex.RUnlock()

	if metadataEpoch == 0 {
		return state.KeyEpoch == 1 &&
			event.KeyEpoch == 1 &&
			event.KeyID == state.KeyID &&
			epochKeys[1] == event.KeyID
	}
	if hostID != state.HostID ||
		event.KeyEpoch > metadataEpoch ||
		epochKeys[event.KeyEpoch] != event.KeyID {
		return false
	}
	expectedEpoch := uint64(1)
	for epoch := uint64(2); epoch <= metadataEpoch; epoch++ {
		transitionSequence, ok := transitionSequences[epoch]
		if !ok || transitionSequence == 0 {
			return false
		}
		if event.SourceSequence > transitionSequence {
			expectedEpoch = epoch
			continue
		}
		break
	}
	return event.KeyEpoch == expectedEpoch &&
		epochKeys[expectedEpoch] == event.KeyID
}

func validateRecoveredControlReceiptSet(
	receipts map[string]ControlReceipt,
	items map[uint64]SpoolItem,
	state ObserverState,
	keys *Keyring,
) error {
	for _, receipt := range receipts {
		if receipt.Validate() != nil ||
			receipt.Item.Sequence > state.LastSequence ||
			!controlReceiptEventAllowedByIdentityHistory(
				receipt.Item.Envelope,
				state,
				keys,
			) ||
			validateControlReceiptCausality(
				receipt,
				receipts,
			) != nil {
			return ErrControlReceiptCorrupt
		}
		if receipt.Item.Sequence <= state.AckSequence {
			continue
		}
		item, exists := items[receipt.Item.Sequence]
		if !exists {
			return ErrControlReceiptCorrupt
		}
		event, err := coreEventFromSpoolItem(item)
		if err != nil || item.Tier != PriorityTier ||
			!coreControlEventsEqual(event, receipt.Item) {
			return ErrControlReceiptCorrupt
		}
	}
	return nil
}

func validateRecoveredControlReceipts(
	journal *ControlReceiptJournal,
	items map[uint64]SpoolItem,
	state ObserverState,
	keys *Keyring,
) error {
	journal.mutex.Lock()
	defer journal.mutex.Unlock()
	return validateRecoveredControlReceiptSet(
		journal.receipts,
		items,
		state,
		keys,
	)
}

func recoverControlReceiptJournal(
	stateDir string,
	state *StateStore,
	items map[uint64]SpoolItem,
	keys *Keyring,
	maxReceiptBytes uint64,
) (*ControlReceiptJournal, error) {
	snapshot := state.Snapshot()
	anchor := controlReceiptAnchorFromState(snapshot)
	if anchor.Bytes > maxReceiptBytes {
		return nil, ErrControlReceiptQuota
	}
	recovery, err := InspectControlReceiptJournal(stateDir, anchor)
	if err != nil {
		return nil, err
	}
	missing, err := controlReceiptProofsMissingFrom(
		items,
		recovery.receipts,
		keys,
	)
	if err != nil {
		return nil, err
	}
	if recovery.JournalAnchor.Bytes > maxReceiptBytes {
		return nil, ErrControlReceiptQuota
	}
	validateLocked := func(receipts map[string]ControlReceipt) error {
		return validateRecoveredControlReceiptSet(
			receipts,
			items,
			snapshot,
			keys,
		)
	}
	if err := validateLocked(recovery.receipts); err != nil {
		return nil, err
	}
	commitRecovery := func(
		previous ControlReceiptAnchor,
		next ControlReceiptAnchor,
	) error {
		return state.recoverControlReceipt(
			previous.Count,
			previous.Bytes,
			previous.HeadHash,
			next.Count,
			next.Bytes,
			next.HeadHash,
		)
	}
	switch recovery.Kind {
	case ControlReceiptRecoveryCompleteTail:
		if recovery.Candidate == nil || len(missing) != 0 {
			return nil, ErrControlReceiptCorrupt
		}
		item, exists := items[recovery.Candidate.Item.Sequence]
		if !exists {
			return nil, ErrControlReceiptCorrupt
		}
		proof, control, proofErr := controlReceiptProofFromLiveSpoolItem(
			item,
			keys,
		)
		if proofErr != nil || !control {
			return nil, ErrControlReceiptCorrupt
		}
		candidate, candidateErr := receiptFromProof(proof)
		if candidateErr != nil ||
			!controlReceiptsEqual(*recovery.Candidate, candidate) {
			return nil, ErrControlReceiptCorrupt
		}
		if _, err := reconcileControlReceiptJournal(
			stateDir,
			anchor,
			proof,
			validateLocked,
			commitRecovery,
		); err != nil {
			return nil, err
		}
		return recoverControlReceiptJournal(
			stateDir,
			state,
			items,
			keys,
			maxReceiptBytes,
		)
	case ControlReceiptRecoveryIncompleteTail:
		if len(missing) != 1 {
			return nil, ErrControlReceiptCorrupt
		}
		receipt, receiptErr := receiptFromProof(missing[0])
		if receiptErr != nil {
			return nil, receiptErr
		}
		if err := validateControlReceiptCandidateForAppend(
			receipt,
			recovery.receipts,
		); err != nil {
			return nil, err
		}
		_, next, previewErr := previewControlReceipt(anchor, receipt)
		if previewErr != nil || next.Bytes > maxReceiptBytes {
			return nil, ErrControlReceiptQuota
		}
		if _, err := reconcileControlReceiptJournal(
			stateDir,
			anchor,
			missing[0],
			validateLocked,
			commitRecovery,
		); err != nil {
			return nil, err
		}
		return recoverControlReceiptJournal(
			stateDir,
			state,
			items,
			keys,
			maxReceiptBytes,
		)
	case ControlReceiptRecoveryExact:
		if len(missing) != 0 {
			return nil, ErrControlReceiptCorrupt
		}
	default:
		return nil, ErrControlReceiptCorrupt
	}
	journal, err := OpenControlReceiptJournal(stateDir, anchor)
	if err != nil {
		return nil, err
	}
	if err := validateRecoveredControlReceipts(
		journal,
		items,
		snapshot,
		keys,
	); err != nil {
		_ = journal.Close()
		return nil, err
	}
	return journal, nil
}

func (spool *Spool) requireControlReceiptLocked(item SpoolItem) error {
	event, err := coreEventFromSpoolItem(item)
	if err != nil {
		return err
	}
	request, err := coreControlRequestFromEnvelope(event.Envelope)
	if err != nil {
		return err
	}
	if request == nil {
		return nil
	}
	if spool.controlReceipts == nil {
		_ = spool.state.PersistReadOnly("observer_control_receipt_missing")
		return ErrControlReceiptCorrupt
	}
	requestSHA256, err := CoreControlRequestSHA256(request)
	if err != nil {
		return err
	}
	receipt, found, err := spool.controlReceipts.Find(
		request.OperationKey(),
	)
	if err != nil ||
		!found ||
		receipt.RequestSHA256 != requestSHA256 ||
		!coreControlEventsEqual(receipt.Item, event) {
		_ = spool.state.PersistReadOnly("observer_control_receipt_missing")
		if err != nil {
			return errors.Join(ErrControlReceiptCorrupt, err)
		}
		return ErrControlReceiptCorrupt
	}
	return nil
}

type ControlReceiptJournal struct {
	mutex    sync.Mutex
	journal  *durablefile.Journal
	anchor   ControlReceiptAnchor
	receipts map[string]ControlReceipt
	failed   bool
	closed   bool
}

func OpenControlReceiptJournal(
	stateDir string,
	stateAnchor ControlReceiptAnchor,
) (*ControlReceiptJournal, error) {
	if err := durablefile.EnsurePrivateDirectory(
		filepath.Join(stateDir, "spool"),
	); err != nil {
		return nil, err
	}
	journal, lockedRecovery, err := durablefile.NewJournalWithTailIntent(
		controlReceiptJournalPath(stateDir),
		func(durablefile.TornTailIntent) error {
			return ErrControlReceiptReconciliationRequired
		},
		durablefile.WithMaxFrame(controlReceiptMaxFramePayload),
	)
	if err != nil {
		return nil, err
	}
	recovery, err := inspectLockedControlReceiptRecovery(
		lockedRecovery,
		stateAnchor,
	)
	if err != nil {
		_ = journal.Close()
		return nil, err
	}
	if lockedRecovery.TailRepaired ||
		recovery.Kind != ControlReceiptRecoveryExact {
		_ = journal.Close()
		return nil, ErrControlReceiptReconciliationRequired
	}
	return &ControlReceiptJournal{
		journal:  journal,
		anchor:   stateAnchor,
		receipts: recovery.receipts,
	}, nil
}

func (journal *ControlReceiptJournal) Anchor() ControlReceiptAnchor {
	journal.mutex.Lock()
	defer journal.mutex.Unlock()
	return journal.anchor
}

func (journal *ControlReceiptJournal) Find(
	key string,
) (ControlReceipt, bool, error) {
	journal.mutex.Lock()
	defer journal.mutex.Unlock()
	if journal.closed || journal.failed {
		return ControlReceipt{}, false, ErrControlReceiptCorrupt
	}
	receipt, found := journal.receipts[key]
	if !found {
		return ControlReceipt{}, false, nil
	}
	cloned, err := cloneControlReceipt(receipt)
	if err != nil {
		journal.failed = true
		return ControlReceipt{}, false, err
	}
	return cloned, true, nil
}

func (journal *ControlReceiptJournal) Lookup(
	key string,
	requestSHA256 string,
) (CoreEventV1, error) {
	receipt, found, err := journal.Find(key)
	if err != nil {
		return CoreEventV1{}, err
	}
	if !found {
		return CoreEventV1{}, os.ErrNotExist
	}
	if receipt.RequestSHA256 != requestSHA256 {
		return CoreEventV1{}, ErrControlReceiptConflict
	}
	return receipt.Item, nil
}

func previewControlReceipt(
	anchor ControlReceiptAnchor,
	receipt ControlReceipt,
) (durablefile.RecordMeta, ControlReceiptAnchor, error) {
	if err := receipt.Validate(); err != nil {
		return durablefile.RecordMeta{}, ControlReceiptAnchor{}, err
	}
	canonical, err := contracts.CanonicalJSON(receipt)
	if err != nil {
		return durablefile.RecordMeta{}, ControlReceiptAnchor{}, err
	}
	previous, err := anchorHashBytes(anchor)
	if err != nil {
		return durablefile.RecordMeta{}, ControlReceiptAnchor{}, err
	}
	_, meta, err := durablefile.EncodeFrame(
		canonical,
		previous,
		controlReceiptMaxFramePayload,
	)
	if err != nil {
		return durablefile.RecordMeta{}, ControlReceiptAnchor{}, err
	}
	next, err := advanceControlReceiptAnchor(anchor, meta)
	return meta, next, err
}

func (journal *ControlReceiptJournal) Preview(
	key string,
	requestSHA256 string,
	item CoreEventV1,
) (CoreEventV1, bool, uint64, error) {
	journal.mutex.Lock()
	defer journal.mutex.Unlock()
	if journal.closed || journal.failed {
		return CoreEventV1{}, false, 0, ErrControlReceiptCorrupt
	}
	if existing, found := journal.receipts[key]; found {
		if existing.RequestSHA256 != requestSHA256 {
			return CoreEventV1{}, false, 0, ErrControlReceiptConflict
		}
		cloned, err := cloneCoreControlEvent(existing.Item)
		return cloned, false, 0, err
	}
	ownedItem, err := cloneCoreControlEvent(item)
	if err != nil {
		return CoreEventV1{}, false, 0, err
	}
	receipt := ControlReceipt{
		SchemaVersion: "agmind.control-receipt.v1",
		Key:           key,
		RequestSHA256: requestSHA256,
		Item:          ownedItem,
	}
	if err := validateControlReceiptCandidateForAppend(
		receipt,
		journal.receipts,
	); err != nil {
		return CoreEventV1{}, false, 0, err
	}
	meta, _, err := previewControlReceipt(journal.anchor, receipt)
	if err != nil {
		return CoreEventV1{}, false, 0, err
	}
	return ownedItem, true, meta.Size, nil
}

func (journal *ControlReceiptJournal) Store(
	key string,
	requestSHA256 string,
	item CoreEventV1,
	commit func(ControlReceiptAnchor, ControlReceiptAnchor) error,
) (CoreEventV1, bool, error) {
	journal.mutex.Lock()
	defer journal.mutex.Unlock()
	if journal.closed || journal.failed {
		return CoreEventV1{}, false, ErrControlReceiptCorrupt
	}
	if existing, found := journal.receipts[key]; found {
		if existing.RequestSHA256 != requestSHA256 {
			return CoreEventV1{}, false, ErrControlReceiptConflict
		}
		cloned, err := cloneCoreControlEvent(existing.Item)
		return cloned, false, err
	}
	if commit == nil {
		return CoreEventV1{}, false, fmt.Errorf("nil receipt anchor commit")
	}
	ownedItem, err := cloneCoreControlEvent(item)
	if err != nil {
		return CoreEventV1{}, false, err
	}
	receipt := ControlReceipt{
		SchemaVersion: "agmind.control-receipt.v1",
		Key:           key,
		RequestSHA256: requestSHA256,
		Item:          ownedItem,
	}
	ownedReceipt, err := cloneControlReceipt(receipt)
	if err != nil {
		return CoreEventV1{}, false, err
	}
	if err := validateControlReceiptCandidateForAppend(
		ownedReceipt,
		journal.receipts,
	); err != nil {
		return CoreEventV1{}, false, err
	}
	canonical, err := contracts.CanonicalJSON(ownedReceipt)
	if err != nil || ownedReceipt.Validate() != nil {
		return CoreEventV1{}, false, ErrControlReceiptCorrupt
	}
	_, next, err := previewControlReceipt(journal.anchor, ownedReceipt)
	if err != nil {
		return CoreEventV1{}, false, err
	}
	meta, err := journal.journal.Append(canonical, true)
	if err != nil {
		journal.failed = true
		return CoreEventV1{}, false, err
	}
	actual, err := advanceControlReceiptAnchor(journal.anchor, meta)
	if err != nil || actual != next {
		journal.failed = true
		return CoreEventV1{}, false, ErrControlReceiptCorrupt
	}
	previous := journal.anchor
	if err := commit(previous, next); err != nil {
		journal.failed = true
		return CoreEventV1{}, false, err
	}
	journal.anchor = next
	journal.receipts[key] = ownedReceipt
	result, err := cloneCoreControlEvent(ownedReceipt.Item)
	if err != nil {
		journal.failed = true
		return CoreEventV1{}, false, err
	}
	return result, true, nil
}

func (journal *ControlReceiptJournal) Close() error {
	journal.mutex.Lock()
	defer journal.mutex.Unlock()
	if journal.closed {
		return nil
	}
	journal.closed = true
	if journal.journal == nil {
		return nil
	}
	return journal.journal.Close()
}

func receiptBytesFitGlobal(
	current uint64,
	itemBytes uint64,
	receiptBytes uint64,
	maxBytes uint64,
) bool {
	if current > maxBytes ||
		itemBytes > maxBytes-current ||
		receiptBytes > maxBytes-current-itemBytes {
		return false
	}
	return current+itemBytes+receiptBytes <= maxBytes
}

func addReceiptBytes(current, added uint64) (uint64, error) {
	if current > math.MaxUint64-added {
		return 0, ErrControlReceiptCorrupt
	}
	return current + added, nil
}
