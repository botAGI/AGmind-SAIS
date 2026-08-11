package observerd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"path/filepath"
	"sync"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

const (
	pccBoundaryArchiveSchema          = "agmind.pcc-boundary-archive-record.v1"
	pccBoundaryArchiveMaxCount uint64 = 1_024
	pccBoundaryArchiveMaxBytes uint64 = 64 * 1024 * 1024
	pccBoundaryArchiveMaxFrame uint32 = 128 * 1024
)

type PCCBoundaryArchiveRecord struct {
	SchemaVersion          string                     `json:"schema_version"`
	BoundaryEvent          contracts.EventEnvelopeV1  `json:"boundary_event"`
	RotationCompanionEvent *contracts.EventEnvelopeV1 `json:"rotation_companion_event,omitempty"`
}

func (record PCCBoundaryArchiveRecord) Validate() error {
	if record.SchemaVersion != pccBoundaryArchiveSchema {
		return ErrPCCJournalCorrupt
	}
	if err := record.BoundaryEvent.Validate(); err != nil {
		return errors.Join(ErrPCCJournalCorrupt, err)
	}
	if record.RotationCompanionEvent != nil {
		if err := record.RotationCompanionEvent.Validate(); err != nil {
			return errors.Join(ErrPCCJournalCorrupt, err)
		}
	}
	return nil
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

func pccBoundaryArchivePath(stateDirectory string) string {
	return filepath.Join(stateDirectory, "spool", "pcc-boundaries.agf")
}

func pccArchiveCorrupt(err error) error {
	if err == nil {
		return ErrPCCJournalCorrupt
	}
	return errors.Join(ErrPCCJournalCorrupt, err)
}

func pccArchiveFailState(state *StateStore, reason string) {
	if state != nil {
		_ = state.PersistReadOnly(reason)
	}
}

func OpenPCCBoundaryArchive(
	stateDirectory string,
	state *StateStore,
	keyring *Keyring,
) (*PCCBoundaryArchive, error) {
	return openPCCBoundaryArchive(stateDirectory, state, keyring)
}

func openPCCBoundaryArchive(
	stateDirectory string,
	state *StateStore,
	keyring *Keyring,
	options ...durablefile.Option,
) (*PCCBoundaryArchive, error) {
	if state == nil || keyring == nil {
		return nil, ErrPCCJournalCorrupt
	}
	spoolRoot := filepath.Join(stateDirectory, "spool")
	if err := durablefile.EnsurePrivateDirectory(spoolRoot); err != nil {
		pccArchiveFailState(state, "observer_pcc_boundary_archive_unsafe")
		return nil, pccArchiveCorrupt(err)
	}
	journal, recovery, err := durablefile.NewJournalWithTailIntent(
		pccBoundaryArchivePath(stateDirectory),
		func(durablefile.TornTailIntent) error {
			// A boundary frame is authoritative only with the exact V5 state
			// anchor. No incomplete suffix can have such an anchor, so repair
			// would silently adopt unauthenticated history.
			return ErrPCCJournalCorrupt
		},
		append(
			[]durablefile.Option{
				durablefile.WithMaxFrame(pccBoundaryArchiveMaxFrame),
			},
			options...,
		)...,
	)
	if err != nil {
		pccArchiveFailState(state, "observer_pcc_boundary_archive_corrupt")
		return nil, pccArchiveCorrupt(err)
	}
	fail := func(result error) (*PCCBoundaryArchive, error) {
		_ = journal.Close()
		pccArchiveFailState(state, "observer_pcc_boundary_archive_corrupt")
		return nil, pccArchiveCorrupt(result)
	}
	if recovery.TailRepaired ||
		recovery.VerifiedBytes < 0 ||
		uint64(recovery.VerifiedBytes) > pccBoundaryArchiveMaxBytes ||
		uint64(len(recovery.Records)) > pccBoundaryArchiveMaxCount {
		return fail(nil)
	}
	records := make([]PCCBoundaryArchiveRecord, 0, len(recovery.Records))
	for _, frame := range recovery.Records {
		record, decodeErr := contracts.DecodeStrict[PCCBoundaryArchiveRecord](
			bytes.NewReader(frame.Payload),
			int64(pccBoundaryArchiveMaxFrame),
		)
		if decodeErr != nil {
			return fail(decodeErr)
		}
		canonical, canonicalErr := contracts.CanonicalJSON(record)
		if canonicalErr != nil || !bytes.Equal(canonical, frame.Payload) {
			return fail(canonicalErr)
		}
		records = append(records, record)
	}
	headHash := zeroPCCJournalHash
	if len(recovery.Records) > 0 {
		headHash = hex.EncodeToString(
			recovery.Records[len(recovery.Records)-1].Hash[:],
		)
	}
	anchor := PCCBoundaryArchiveAnchor{
		Count:    uint64(len(recovery.Records)),
		Bytes:    uint64(recovery.VerifiedBytes),
		HeadHash: headHash,
	}
	snapshot := state.Snapshot()
	if snapshot.PCCBoundaryCount != anchor.Count ||
		snapshot.PCCBoundaryBytes != anchor.Bytes ||
		snapshot.PCCBoundaryHeadHash != anchor.HeadHash {
		return fail(nil)
	}
	if _, err := validatePCCArchiveRecords(records, snapshot, keyring); err != nil {
		return fail(err)
	}
	return &PCCBoundaryArchive{
		journal: journal,
		state:   state,
		keyring: keyring,
		anchor:  anchor,
		records: records,
	}, nil
}

func pccEnvelopeCanonicalAndHash(
	event contracts.EventEnvelopeV1,
) ([]byte, string, error) {
	raw, err := contracts.CanonicalJSON(event)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), nil
}

func pccProtectedEnvelopeShape(event contracts.EventEnvelopeV1) bool {
	return event.SourceID == "agmind-observerd" &&
		event.SourceVersion == "0.1.0" &&
		event.ContainerID == nil &&
		event.ContainerStartTime == nil &&
		event.ReleaseID == nil &&
		event.InventoryGeneration == 0 &&
		event.InventoryRevision == nil &&
		len(event.RedactionFlags) == 0 &&
		event.SourcePayloadHash == event.NormalizedFieldsSHA256
}

func pccVerifyArchiveEnvelope(
	event contracts.EventEnvelopeV1,
	keyring *Keyring,
) error {
	if !pccProtectedEnvelopeShape(event) ||
		keyring.hostID != "" && event.HostID != keyring.hostID {
		return ErrPCCJournalCorrupt
	}
	if err := keyring.Verify(event); err != nil {
		return pccArchiveCorrupt(err)
	}
	raw, _, err := pccEnvelopeCanonicalAndHash(event)
	if err != nil {
		return pccArchiveCorrupt(err)
	}
	decoded, err := contracts.DecodeStrict[contracts.EventEnvelopeV1](
		bytes.NewReader(raw),
		int64(pccBoundaryArchiveMaxFrame),
	)
	if err != nil || decoded.EventID != event.EventID {
		return pccArchiveCorrupt(err)
	}
	return nil
}

func pccDecodeBootBoundary(
	event contracts.EventEnvelopeV1,
) (contracts.ObserverBootBoundaryV1, error) {
	raw, err := contracts.CanonicalJSON(event.NormalizedFields)
	if err != nil {
		return contracts.ObserverBootBoundaryV1{}, err
	}
	return contracts.DecodeStrict[contracts.ObserverBootBoundaryV1](
		bytes.NewReader(raw),
		65_536,
	)
}

func pccDecodeTransition(
	event contracts.EventEnvelopeV1,
) (contracts.KeyTransitionV1, error) {
	raw, err := contracts.CanonicalJSON(event.NormalizedFields)
	if err != nil {
		return contracts.KeyTransitionV1{}, err
	}
	return contracts.DecodeStrict[contracts.KeyTransitionV1](
		bytes.NewReader(raw),
		65_536,
	)
}

func pccKeyringPublic(
	keyring *Keyring,
	keyID string,
	epoch uint64,
) (ed25519.PublicKey, bool) {
	keyring.mutex.RLock()
	defer keyring.mutex.RUnlock()
	entry, ok := keyring.keys[keyID]
	if !ok || entry.epoch != epoch {
		return nil, false
	}
	return append(ed25519.PublicKey(nil), entry.key...), true
}

func pccValidateRotationPair(
	boundary contracts.EventEnvelopeV1,
	companion contracts.EventEnvelopeV1,
	keyring *Keyring,
) (contracts.EventEnvelopeV1, contracts.EventEnvelopeV1, error) {
	var transition contracts.EventEnvelopeV1
	var start contracts.EventEnvelopeV1
	switch boundary.EventType {
	case "observer_key_transition":
		if companion.EventType != "observer_key_epoch_start" ||
			boundary.BootID != companion.BootID ||
			!exactFlags(
				boundary.CoverageFlags,
				"boot_transition",
				"key_rotation",
			) ||
			!exactFlags(companion.CoverageFlags, "key_rotation") {
			return transition, start, ErrPCCJournalCorrupt
		}
		transition, start = boundary, companion
	case "observer_key_epoch_start":
		if companion.EventType != "observer_key_transition" ||
			boundary.BootID == companion.BootID ||
			!exactFlags(
				boundary.CoverageFlags,
				"boot_transition",
				"key_rotation",
			) ||
			!exactFlags(companion.CoverageFlags, "key_rotation") {
			return transition, start, ErrPCCJournalCorrupt
		}
		transition, start = companion, boundary
	default:
		return transition, start, ErrPCCJournalCorrupt
	}
	if transition.SourceSequence == math.MaxUint64 ||
		start.SourceSequence != transition.SourceSequence+1 ||
		transition.HostID != start.HostID ||
		transition.KeyEpoch == math.MaxUint64 ||
		start.KeyEpoch != transition.KeyEpoch+1 {
		return transition, start, ErrPCCJournalCorrupt
	}
	transitionFields, err := pccDecodeTransition(transition)
	if err != nil ||
		transitionFields.HostID != transition.HostID ||
		transitionFields.OldKeyID != transition.KeyID ||
		transitionFields.OldEpoch != transition.KeyEpoch ||
		transitionFields.NewKeyID != start.KeyID ||
		transitionFields.NewEpoch != start.KeyEpoch {
		return transition, start, pccArchiveCorrupt(err)
	}
	startFields := map[string]any{
		"kind":      "observer_key_epoch_start",
		"key_id":    transitionFields.NewKeyID,
		"key_epoch": transitionFields.NewEpoch,
	}
	if !eventHasExactFields(start, startFields) {
		return transition, start, ErrPCCJournalCorrupt
	}
	oldPublic, ok := pccKeyringPublic(
		keyring,
		transitionFields.OldKeyID,
		transitionFields.OldEpoch,
	)
	if !ok {
		return transition, start, ErrPCCJournalCorrupt
	}
	newPublic, ok := pccKeyringPublic(
		keyring,
		transitionFields.NewKeyID,
		transitionFields.NewEpoch,
	)
	if !ok ||
		hex.EncodeToString(newPublic) != transitionFields.NewPublicKey ||
		contracts.VerifyKeyTransition(transitionFields, oldPublic) != nil {
		return transition, start, ErrPCCJournalCorrupt
	}
	return transition, start, nil
}

func pccBoundaryPredecessor(
	event contracts.EventEnvelopeV1,
	snapshot ObserverState,
) (string, uint64, error) {
	for index, boundary := range snapshot.BootHistory {
		if boundary.BoundaryEventID != event.EventID {
			continue
		}
		if index == 0 ||
			boundary.BoundaryEventType != event.EventType ||
			boundary.BootID != event.BootID ||
			boundary.FirstSequence != event.SourceSequence {
			return "", 0, ErrPCCJournalCorrupt
		}
		return snapshot.BootHistory[index-1].BootID,
			boundary.FirstSequence - 1,
			nil
	}
	if snapshot.BootBoundaryState == bootBoundaryPending &&
		snapshot.PendingBootBoundary != nil &&
		snapshot.PendingBootBoundary.PreviousBootID != nil &&
		len(snapshot.BootHistory) > 1 {
		last := snapshot.BootHistory[len(snapshot.BootHistory)-1]
		pending := snapshot.PendingBootBoundary
		if last.BootID == event.BootID &&
			last.FirstSequence == event.SourceSequence &&
			pending.PreviousSourceSequence+1 == last.FirstSequence {
			return *pending.PreviousBootID,
				pending.PreviousSourceSequence,
				nil
		}
	}
	return "", 0, ErrPCCJournalCorrupt
}

func pccRecordToHop(
	record PCCBoundaryArchiveRecord,
	snapshot ObserverState,
	keyring *Keyring,
) (contracts.PCCBootTransitionHopV1, error) {
	if err := pccVerifyArchiveEnvelope(record.BoundaryEvent, keyring); err != nil {
		return contracts.PCCBootTransitionHopV1{}, err
	}
	previousBootID, previousSequence, err := pccBoundaryPredecessor(
		record.BoundaryEvent,
		snapshot,
	)
	if err != nil {
		return contracts.PCCBootTransitionHopV1{}, err
	}
	boundary := record.BoundaryEvent
	hop := contracts.PCCBootTransitionHopV1{
		BoundaryEventType:      boundary.EventType,
		EventID:                boundary.EventID,
		SourceSequence:         boundary.SourceSequence,
		BootID:                 boundary.BootID,
		PreviousBootID:         previousBootID,
		PreviousSourceSequence: previousSequence,
	}
	_, contentHash, err := pccEnvelopeCanonicalAndHash(boundary)
	if err != nil {
		return contracts.PCCBootTransitionHopV1{}, err
	}
	hop.ContentSHA256 = contentHash
	switch boundary.EventType {
	case "observer_boot_boundary":
		if record.RotationCompanionEvent != nil ||
			!exactFlags(
				boundary.CoverageFlags,
				"boot_transition",
				"reconcile_required",
			) {
			return contracts.PCCBootTransitionHopV1{}, ErrPCCJournalCorrupt
		}
		fields, err := pccDecodeBootBoundary(boundary)
		if err != nil ||
			fields.ReasonCode != "kernel_boot_id_changed" ||
			fields.PreviousBootID == nil ||
			*fields.PreviousBootID != previousBootID ||
			fields.PreviousSourceSequence != previousSequence ||
			boundary.SourceSequence != previousSequence+1 {
			return contracts.PCCBootTransitionHopV1{}, pccArchiveCorrupt(err)
		}
	case "observer_key_transition", "observer_key_epoch_start":
		if record.RotationCompanionEvent == nil {
			return contracts.PCCBootTransitionHopV1{}, ErrPCCJournalCorrupt
		}
		companion := *record.RotationCompanionEvent
		if err := pccVerifyArchiveEnvelope(companion, keyring); err != nil {
			return contracts.PCCBootTransitionHopV1{}, err
		}
		if _, _, err := pccValidateRotationPair(
			boundary,
			companion,
			keyring,
		); err != nil {
			return contracts.PCCBootTransitionHopV1{}, err
		}
		_, companionHash, err := pccEnvelopeCanonicalAndHash(companion)
		if err != nil {
			return contracts.PCCBootTransitionHopV1{}, err
		}
		companionType := companion.EventType
		companionID := companion.EventID
		companionSequence := companion.SourceSequence
		companionBootID := companion.BootID
		hop.RotationCompanionEventType = &companionType
		hop.RotationCompanionEventID = &companionID
		hop.RotationCompanionContentSHA256 = &companionHash
		hop.RotationCompanionSourceSequence = &companionSequence
		hop.RotationCompanionBootID = &companionBootID
	default:
		return contracts.PCCBootTransitionHopV1{}, ErrPCCJournalCorrupt
	}
	if err := hop.Validate(); err != nil {
		return contracts.PCCBootTransitionHopV1{}, pccArchiveCorrupt(err)
	}
	return hop, nil
}

func validatePCCArchiveRecords(
	records []PCCBoundaryArchiveRecord,
	snapshot ObserverState,
	keyring *Keyring,
) ([]contracts.PCCBootTransitionHopV1, error) {
	if len(records) == 0 {
		return []contracts.PCCBootTransitionHopV1{}, nil
	}
	hops := make([]contracts.PCCBootTransitionHopV1, 0, len(records))
	for _, record := range records {
		hop, err := pccRecordToHop(record, snapshot, keyring)
		if err != nil {
			return nil, err
		}
		hops = append(hops, hop)
	}
	if _, err := contracts.PCCBootTransitionChainSHA256(hops); err != nil {
		return nil, pccArchiveCorrupt(err)
	}
	return hops, nil
}

func pccValidateGenesis(
	event contracts.EventEnvelopeV1,
	companion *contracts.EventEnvelopeV1,
	keyring *Keyring,
) (bool, error) {
	if event.EventType != "observer_boot_boundary" {
		return false, nil
	}
	fields, err := pccDecodeBootBoundary(event)
	if err != nil || fields.ReasonCode != "observer_genesis" {
		return false, nil
	}
	if companion != nil ||
		event.SourceSequence != 1 ||
		!exactFlags(
			event.CoverageFlags,
			"boot_transition",
			"reconcile_required",
		) {
		return true, ErrPCCJournalCorrupt
	}
	return true, pccVerifyArchiveEnvelope(event, keyring)
}

// pccValidateGenesisRotation identifies the genesis-B origin shape: on a
// fresh state, offline rotation makes the key-transition envelope itself
// BootHistory[0], so it has no predecessor and PCCBootTransitionHopV1 makes
// a predecessor-less hop unrepresentable. Like observer_genesis it stays
// outside the transition archive, but only after the full rotation-pair
// validation (envelope signatures, keyring, epoch adjacency, exact flags)
// passes and only while the archive is still empty; rotations chained at
// BootHistory index >= 1 keep taking the record path unchanged.
func pccValidateGenesisRotation(
	boundary contracts.EventEnvelopeV1,
	companion *contracts.EventEnvelopeV1,
	snapshot ObserverState,
	anchor PCCBoundaryArchiveAnchor,
	recordCount int,
	keyring *Keyring,
) (bool, error) {
	if boundary.EventType != "observer_key_transition" ||
		companion == nil ||
		anchor.Count != 0 ||
		recordCount != 0 ||
		len(snapshot.BootHistory) == 0 {
		return false, nil
	}
	first := snapshot.BootHistory[0]
	if first.BoundaryEventID != boundary.EventID ||
		first.BoundaryEventType != boundary.EventType ||
		first.BootID != boundary.BootID ||
		first.FirstSequence != boundary.SourceSequence {
		return false, nil
	}
	if err := pccVerifyArchiveEnvelope(boundary, keyring); err != nil {
		return true, err
	}
	if err := pccVerifyArchiveEnvelope(*companion, keyring); err != nil {
		return true, err
	}
	if _, _, err := pccValidateRotationPair(
		boundary,
		*companion,
		keyring,
	); err != nil {
		return true, err
	}
	return true, nil
}

func clonePCCBoundaryRecord(
	record PCCBoundaryArchiveRecord,
) (PCCBoundaryArchiveRecord, error) {
	raw, err := contracts.CanonicalJSON(record)
	if err != nil {
		return PCCBoundaryArchiveRecord{}, err
	}
	return contracts.DecodeStrict[PCCBoundaryArchiveRecord](
		bytes.NewReader(raw),
		int64(pccBoundaryArchiveMaxFrame),
	)
}

// RetainsCommittedEvent proves that a protected boot-transition event is in
// the V5-anchored archive. Callers hold publication then spool locks before
// entering here; this method adds archive then state, preserving the global
// publication -> spool -> archive -> state lock order.
func (archive *PCCBoundaryArchive) RetainsCommittedEvent(
	event contracts.EventEnvelopeV1,
	following *contracts.EventEnvelopeV1,
) error {
	archive.mutex.Lock()
	defer archive.mutex.Unlock()
	if archive.closed || archive.journal == nil {
		return ErrPCCJournalCorrupt
	}
	retentionRequired, err := pccArchiveRetentionRequired(event, following)
	if err != nil {
		return err
	}
	if !retentionRequired {
		return nil
	}
	snapshot := archive.state.Snapshot()
	if snapshot.PCCBoundaryCount != archive.anchor.Count ||
		snapshot.PCCBoundaryBytes != archive.anchor.Bytes ||
		snapshot.PCCBoundaryHeadHash != archive.anchor.HeadHash ||
		archive.anchor.Count != uint64(len(archive.records)) {
		return ErrPCCJournalCorrupt
	}
	genesisRotation, err := pccValidateGenesisRotation(
		event,
		following,
		snapshot,
		archive.anchor,
		len(archive.records),
		archive.keyring,
	)
	if err != nil {
		return err
	}
	if genesisRotation {
		// The genesis-B transition IS BootHistory[0]; RecordCommittedBoundary
		// keeps it outside the transition archive because a predecessor-less
		// hop is unrepresentable, so retention is proven by the validated pair
		// plus the V5 boot history instead of an archive record.
		return nil
	}
	want, err := contracts.CanonicalJSON(event)
	if err != nil {
		return pccArchiveCorrupt(err)
	}
	for _, record := range archive.records {
		for _, archived := range []contracts.EventEnvelopeV1{
			record.BoundaryEvent,
		} {
			have, canonicalErr := contracts.CanonicalJSON(archived)
			if canonicalErr != nil {
				return pccArchiveCorrupt(canonicalErr)
			}
			if bytes.Equal(have, want) {
				return nil
			}
		}
		if record.RotationCompanionEvent != nil {
			have, canonicalErr := contracts.CanonicalJSON(
				*record.RotationCompanionEvent,
			)
			if canonicalErr != nil {
				return pccArchiveCorrupt(canonicalErr)
			}
			if bytes.Equal(have, want) {
				return nil
			}
		}
	}
	return ErrPCCJournalCorrupt
}

// pccArchiveRetentionRequired identifies every event that can be the
// boundary or companion of an A/B/C transition. The C transition itself is
// deliberately not boot_transition-flagged, so it must inspect its adjacent
// epoch-start event before ACK is allowed to discard it. A missing or
// malformed successor is treated as protected until the pair is complete.
func pccArchiveRetentionRequired(
	event contracts.EventEnvelopeV1,
	following *contracts.EventEnvelopeV1,
) (bool, error) {
	if !pccProtectedEnvelopeShape(event) {
		return false, nil
	}
	switch event.EventType {
	case "observer_boot_boundary":
		fields, err := pccDecodeBootBoundary(event)
		if err == nil &&
			fields.ReasonCode == "observer_genesis" &&
			fields.PreviousBootID == nil &&
			fields.PreviousSourceSequence == 0 &&
			event.SourceSequence == 1 &&
			exactFlags(
				event.CoverageFlags,
				"boot_transition",
				"reconcile_required",
			) {
			// Genesis has no predecessor and is intentionally outside the
			// transition archive; RecordCommittedBoundary validates it before
			// taking this no-record path.
			return false, nil
		}
		return true, nil
	case "observer_key_epoch_start":
		return exactFlags(
			event.CoverageFlags,
			"boot_transition",
			"key_rotation",
		), nil
	case "observer_key_transition":
		if exactFlags(
			event.CoverageFlags,
			"boot_transition",
			"key_rotation",
		) {
			return true, nil
		}
		if !exactFlags(event.CoverageFlags, "key_rotation") {
			return false, nil
		}
		if following == nil {
			return true, nil
		}
		if !pccProtectedEnvelopeShape(*following) ||
			following.EventType != "observer_key_epoch_start" ||
			!exactFlags(following.CoverageFlags, "key_rotation") {
			return true, nil
		}
		if following.BootID == event.BootID {
			// Same-boot key rotations are intentionally not PCC transitions.
			return false, nil
		}
		return true, nil
	default:
		return false, nil
	}
}

func (archive *PCCBoundaryArchive) failPreAnchor(err error) error {
	archive.failed = true
	pccArchiveFailState(
		archive.state,
		"observer_pcc_boundary_archive_preanchor_invalid",
	)
	return err
}

func (archive *PCCBoundaryArchive) RecordCommittedBoundary(
	boundary contracts.EventEnvelopeV1,
	rotationCompanion *contracts.EventEnvelopeV1,
) error {
	archive.mutex.Lock()
	defer archive.mutex.Unlock()
	if archive.closed || archive.failed || archive.journal == nil {
		return ErrPCCJournalCorrupt
	}
	genesis, err := pccValidateGenesis(
		boundary,
		rotationCompanion,
		archive.keyring,
	)
	if err != nil {
		return archive.failPreAnchor(err)
	}
	if genesis {
		return nil
	}
	genesisRotation, err := pccValidateGenesisRotation(
		boundary,
		rotationCompanion,
		archive.state.Snapshot(),
		archive.anchor,
		len(archive.records),
		archive.keyring,
	)
	if err != nil {
		return archive.failPreAnchor(err)
	}
	if genesisRotation {
		return nil
	}
	record := PCCBoundaryArchiveRecord{
		SchemaVersion:          pccBoundaryArchiveSchema,
		BoundaryEvent:          boundary,
		RotationCompanionEvent: rotationCompanion,
	}
	canonical, err := contracts.CanonicalJSON(record)
	if err != nil || len(canonical) > int(pccBoundaryArchiveMaxFrame) {
		return archive.failPreAnchor(pccArchiveCorrupt(err))
	}
	if len(archive.records) > 0 {
		lastCanonical, lastErr := contracts.CanonicalJSON(
			archive.records[len(archive.records)-1],
		)
		if lastErr != nil {
			return archive.failPreAnchor(pccArchiveCorrupt(lastErr))
		}
		if bytes.Equal(lastCanonical, canonical) {
			return nil
		}
	}
	cloned, err := clonePCCBoundaryRecord(record)
	if err != nil {
		return archive.failPreAnchor(pccArchiveCorrupt(err))
	}
	nextRecords := append(
		append([]PCCBoundaryArchiveRecord(nil), archive.records...),
		cloned,
	)
	if _, err := validatePCCArchiveRecords(
		nextRecords,
		archive.state.Snapshot(),
		archive.keyring,
	); err != nil {
		return archive.failPreAnchor(err)
	}
	frameBytes := uint64(len(canonical)) + 76
	if archive.anchor.Count >= pccBoundaryArchiveMaxCount ||
		frameBytes > pccBoundaryArchiveMaxBytes ||
		archive.anchor.Bytes > pccBoundaryArchiveMaxBytes-frameBytes {
		return archive.failPreAnchor(ErrPCCJournalCorrupt)
	}
	meta, err := archive.journal.Append(canonical, true)
	if err != nil {
		archive.failed = true
		pccArchiveFailState(
			archive.state,
			"observer_pcc_boundary_archive_append_failed",
		)
		return err
	}
	nextAnchor := PCCBoundaryArchiveAnchor{
		Count:    archive.anchor.Count + 1,
		Bytes:    archive.anchor.Bytes + meta.Size,
		HeadHash: hex.EncodeToString(meta.Hash[:]),
	}
	if meta.Size != frameBytes ||
		hex.EncodeToString(meta.PreviousHash[:]) != archive.anchor.HeadHash {
		archive.failed = true
		pccArchiveFailState(
			archive.state,
			"observer_pcc_boundary_archive_append_invalid",
		)
		return ErrPCCJournalCorrupt
	}
	if err := archive.state.anchorPCCBoundary(
		archive.anchor,
		nextAnchor,
	); err != nil {
		archive.failed = true
		pccArchiveFailState(
			archive.state,
			"observer_pcc_boundary_archive_anchor_failed",
		)
		return err
	}
	archive.anchor = nextAnchor
	archive.records = nextRecords
	return nil
}

func (archive *PCCBoundaryArchive) Chain(
	previousBootID string,
	currentBootID string,
) ([]contracts.PCCBootTransitionHopV1, error) {
	archive.mutex.Lock()
	defer archive.mutex.Unlock()
	if archive.closed || archive.failed ||
		!uuid4Pattern.MatchString(previousBootID) ||
		!uuid4Pattern.MatchString(currentBootID) ||
		previousBootID == currentBootID {
		return nil, ErrPCCJournalCorrupt
	}
	hops, err := validatePCCArchiveRecords(
		archive.records,
		archive.state.Snapshot(),
		archive.keyring,
	)
	if err != nil {
		return nil, err
	}
	start := -1
	for index := range hops {
		if hops[index].PreviousBootID == previousBootID {
			start = index
			break
		}
	}
	if start < 0 {
		return nil, ErrPCCJournalCorrupt
	}
	selected := make([]contracts.PCCBootTransitionHopV1, 0, len(hops)-start)
	for _, hop := range hops[start:] {
		selected = append(selected, clonePCCBootTransitionHop(hop))
		if hop.BootID == currentBootID {
			break
		}
	}
	if len(selected) == 0 ||
		selected[len(selected)-1].BootID != currentBootID {
		return nil, ErrPCCJournalCorrupt
	}
	if _, err := contracts.PCCBootTransitionChainSHA256(selected); err != nil {
		return nil, pccArchiveCorrupt(err)
	}
	return selected, nil
}

func clonePCCBootTransitionHop(
	hop contracts.PCCBootTransitionHopV1,
) contracts.PCCBootTransitionHopV1 {
	cloned := hop
	if hop.RotationCompanionEventType != nil {
		value := *hop.RotationCompanionEventType
		cloned.RotationCompanionEventType = &value
	}
	if hop.RotationCompanionEventID != nil {
		value := *hop.RotationCompanionEventID
		cloned.RotationCompanionEventID = &value
	}
	if hop.RotationCompanionContentSHA256 != nil {
		value := *hop.RotationCompanionContentSHA256
		cloned.RotationCompanionContentSHA256 = &value
	}
	if hop.RotationCompanionSourceSequence != nil {
		value := *hop.RotationCompanionSourceSequence
		cloned.RotationCompanionSourceSequence = &value
	}
	if hop.RotationCompanionBootID != nil {
		value := *hop.RotationCompanionBootID
		cloned.RotationCompanionBootID = &value
	}
	return cloned
}

func (archive *PCCBoundaryArchive) Close() error {
	if archive == nil {
		return nil
	}
	archive.mutex.Lock()
	defer archive.mutex.Unlock()
	if archive.closed {
		return nil
	}
	archive.closed = true
	if archive.journal == nil {
		return nil
	}
	err := archive.journal.Close()
	archive.journal = nil
	return err
}
