package observerd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

var (
	ErrSpoolCorrupt  = errors.New("observer spool corrupt")
	ErrRoutineQuota  = errors.New("routine spool quota exhausted")
	ErrPriorityQuota = errors.New("priority spool quota exhausted")
	ErrAckInvalid    = errors.New("invalid spool acknowledgement")
)

type Tier string

const (
	RoutineTier             Tier   = "routine"
	PriorityTier            Tier   = "priority"
	ackJournalMaxFrameBytes uint64 = 4_096 + 76
)

type SpoolConfig struct {
	StateDir             string
	MaxBytes             uint64
	PriorityReserveBytes uint64
	Now                  func() time.Time
}

type SpoolItem struct {
	Sequence      uint64
	EventID       string
	ContentSHA256 string
	Tier          Tier
	Canonical     []byte
	frameBytes    uint64
	path          string
}

type SequenceGap struct {
	Start uint64
	End   uint64
}

type Spool struct {
	mutex        sync.Mutex
	config       SpoolConfig
	state        *StateStore
	keys         *Keyring
	items        map[uint64]SpoolItem
	routineBytes uint64
	totalBytes   uint64
	ackBytes     uint64
	ackJournal   *durablefile.Journal
	closed       bool
	remove       func(string) error
	publish      func(string, []byte) error
}

type ackRecord struct {
	SchemaVersion string `json:"schema_version"`
	Sequence      uint64 `json:"sequence"`
	EventID       string `json:"event_id"`
	ContentSHA256 string `json:"content_sha256"`
	AckedAt       string `json:"acked_at"`
}

func (record ackRecord) Validate() error {
	if record.SchemaVersion != "agmind.spool-ack.v1" ||
		record.Sequence == 0 ||
		!eventPattern.MatchString(record.EventID) ||
		!hex64Pattern.MatchString(record.ContentSHA256) {
		return ErrAckInvalid
	}
	parsed, err := time.Parse(time.RFC3339Nano, record.AckedAt)
	if err != nil || parsed.Location() != time.UTC {
		return ErrAckInvalid
	}
	return nil
}

var spoolNamePattern = regexp.MustCompile(`^([0-9]{20})\.agf$`)

func ensurePrivateDirectory(path string) error {
	return durablefile.EnsurePrivateDirectory(path)
}

func validateSpoolPayload(
	raw []byte,
	keys *Keyring,
) (contracts.EventEnvelopeV1, string, error) {
	event, err := contracts.DecodeStrict[contracts.EventEnvelopeV1](
		bytes.NewReader(raw),
		65_536,
	)
	if err != nil {
		return contracts.EventEnvelopeV1{}, "", err
	}
	canonical, err := contracts.CanonicalJSON(event)
	if err != nil || !bytes.Equal(canonical, raw) {
		return contracts.EventEnvelopeV1{}, "", fmt.Errorf("non-canonical envelope")
	}
	if err := keys.Verify(event); err != nil {
		return contracts.EventEnvelopeV1{}, "", err
	}
	sum := sha256.Sum256(canonical)
	return event, hex.EncodeToString(sum[:]), nil
}

func readStandaloneFrame(
	path string,
	keys *Keyring,
) (contracts.EventEnvelopeV1, []byte, string, uint64, error) {
	raw, err := durablefile.ReadRegular(path, 65_536+76)
	if err != nil {
		return contracts.EventEnvelopeV1{}, nil, "", 0, err
	}
	record, err := durablefile.DecodeFrame(raw, 65_536, [32]byte{})
	if err != nil {
		// Standalone published frames are never repaired or truncated.
		return contracts.EventEnvelopeV1{}, nil, "", 0, ErrSpoolCorrupt
	}
	event, contentHash, err := validateSpoolPayload(record.Payload, keys)
	if err != nil {
		return contracts.EventEnvelopeV1{}, nil, "", 0, ErrSpoolCorrupt
	}
	return event, record.Payload, contentHash, uint64(len(raw)), nil
}

func scanTier(
	directory string,
	tier Tier,
	keys *Keyring,
	items map[uint64]SpoolItem,
) (uint64, error) {
	entries, err := durablefile.ReadDirectoryNames(directory)
	if err != nil {
		return 0, err
	}
	var used uint64
	for _, entry := range entries {
		match := spoolNamePattern.FindStringSubmatch(entry)
		if match == nil {
			return 0, ErrSpoolCorrupt
		}
		sequence, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil || fmt.Sprintf("%020d.agf", sequence) != entry {
			return 0, ErrSpoolCorrupt
		}
		if _, exists := items[sequence]; exists {
			return 0, ErrSpoolCorrupt
		}
		path := filepath.Join(directory, entry)
		event, canonical, contentHash, frameBytes, err := readStandaloneFrame(path, keys)
		if err != nil || event.SourceSequence != sequence {
			return 0, ErrSpoolCorrupt
		}
		if ^uint64(0)-used < frameBytes {
			return 0, ErrSpoolCorrupt
		}
		used += frameBytes
		items[sequence] = SpoolItem{
			Sequence:      sequence,
			EventID:       event.EventID,
			ContentSHA256: contentHash,
			Tier:          tier,
			Canonical:     canonical,
			frameBytes:    frameBytes,
			path:          path,
		}
	}
	return used, nil
}

func NewSpool(
	config SpoolConfig,
	state *StateStore,
	keys *Keyring,
) (*Spool, error) {
	if state == nil || keys == nil ||
		config.MaxBytes == 0 ||
		config.PriorityReserveBytes == 0 ||
		config.PriorityReserveBytes >= config.MaxBytes ||
		config.MaxBytes <= ackJournalMaxFrameBytes {
		return nil, fmt.Errorf("invalid spool configuration")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	spoolRoot := filepath.Join(config.StateDir, "spool")
	routineDir := filepath.Join(spoolRoot, string(RoutineTier))
	priorityDir := filepath.Join(spoolRoot, string(PriorityTier))
	for _, directory := range []string{spoolRoot, routineDir, priorityDir} {
		if err := ensurePrivateDirectory(directory); err != nil {
			_ = state.PersistReadOnly("observer_spool_path_unsafe")
			return nil, err
		}
	}
	items := make(map[uint64]SpoolItem)
	routineBytes, err := scanTier(routineDir, RoutineTier, keys, items)
	if err != nil {
		_ = state.PersistReadOnly("observer_spool_corrupt")
		return nil, err
	}
	priorityBytes, err := scanTier(priorityDir, PriorityTier, keys, items)
	if err != nil || ^uint64(0)-routineBytes < priorityBytes {
		_ = state.PersistReadOnly("observer_spool_corrupt")
		return nil, ErrSpoolCorrupt
	}
	eventBytes := routineBytes + priorityBytes
	snapshot := state.Snapshot()
	var highest uint64
	for sequence := range items {
		if sequence > highest {
			highest = sequence
		}
	}
	if highest > snapshot.LastSequence {
		_ = state.PersistReadOnly("observer_sequence_rollback")
		return nil, ErrSpoolCorrupt
	}
	ackPath := filepath.Join(spoolRoot, "acked.agf")
	ackRecovery, err := durablefile.Recover(ackPath, 4_096)
	if errors.Is(err, os.ErrNotExist) {
		ackRecovery = durablefile.Recovery{}
	} else if err != nil {
		_ = state.PersistReadOnly("observer_ack_journal_unsafe")
		return nil, err
	}
	if ackRecovery.VerifiedBytes < 0 ||
		uint64(ackRecovery.VerifiedBytes) > config.MaxBytes ||
		eventBytes > config.MaxBytes-uint64(ackRecovery.VerifiedBytes) ||
		routineBytes > config.MaxBytes-config.PriorityReserveBytes {
		_ = state.PersistReadOnly("observer_spool_quota_invalid")
		return nil, ErrSpoolCorrupt
	}
	ackBytes := uint64(ackRecovery.VerifiedBytes)
	totalBytes := eventBytes + ackBytes
	ackRecords := make([]ackRecord, 0, len(ackRecovery.Records))
	var previousSequence uint64
	for _, framed := range ackRecovery.Records {
		record, decodeErr := contracts.DecodeStrict[ackRecord](
			bytes.NewReader(framed.Payload),
			4_096,
		)
		if decodeErr != nil || record.Sequence <= previousSequence {
			_ = state.PersistReadOnly("observer_ack_journal_corrupt")
			return nil, ErrSpoolCorrupt
		}
		canonical, canonicalErr := contracts.CanonicalJSON(record)
		if canonicalErr != nil || !bytes.Equal(canonical, framed.Payload) {
			_ = state.PersistReadOnly("observer_ack_journal_corrupt")
			return nil, ErrSpoolCorrupt
		}
		previousSequence = record.Sequence
		ackRecords = append(ackRecords, record)
	}
	if err := reconcileAckAnchor(state, ackRecovery.Records, ackRecords); err != nil {
		_ = state.PersistReadOnly("observer_ack_journal_regression")
		return nil, err
	}
	ackJournal, err := durablefile.NewJournal(
		ackPath,
		durablefile.WithMaxFrame(4_096),
	)
	if err != nil {
		_ = state.PersistReadOnly("observer_ack_journal_corrupt")
		return nil, err
	}
	spool := &Spool{
		config:       config,
		state:        state,
		keys:         keys,
		items:        items,
		routineBytes: routineBytes,
		totalBytes:   totalBytes,
		ackBytes:     ackBytes,
		ackJournal:   ackJournal,
		remove:       durablefile.Remove,
		publish:      durablefile.CreateOnly,
	}
	if err := spool.cleanupAckedLocked(state.Snapshot().AckSequence); err != nil {
		// The durable ack is authoritative; cleanup can be retried and Fetch
		// suppresses these items meanwhile.
	}
	return spool, nil
}

func reconcileAckAnchor(
	state *StateStore,
	framed []durablefile.Record,
	records []ackRecord,
) error {
	snapshot := state.Snapshot()
	for _, record := range records {
		if record.Sequence > snapshot.LastSequence {
			return ErrSpoolCorrupt
		}
	}
	if len(records) == 0 {
		if snapshot.AckSequence != 0 || snapshot.AckRecordHash != "" {
			return ErrSpoolCorrupt
		}
		return nil
	}
	anchorIndex := -1
	if snapshot.AckSequence != 0 {
		for index, frame := range framed {
			if hex.EncodeToString(frame.Hash[:]) == snapshot.AckRecordHash {
				anchorIndex = index
				break
			}
		}
		if anchorIndex < 0 {
			lastIndex := len(records) - 1
			last := records[lastIndex]
			payloadHash := sha256.Sum256(framed[lastIndex].Payload)
			if len(records) == 1 &&
				last.Sequence == snapshot.AckSequence &&
				last.EventID == snapshot.AckEventID &&
				last.ContentSHA256 == snapshot.AckContentSHA256 &&
				hex.EncodeToString(payloadHash[:]) == snapshot.AckPayloadSHA256 {
				return state.applyAck(
					last.Sequence,
					last.EventID,
					last.ContentSHA256,
					hex.EncodeToString(framed[lastIndex].Hash[:]),
					hex.EncodeToString(payloadHash[:]),
				)
			}
			return ErrSpoolCorrupt
		}
		anchorPayloadHash := sha256.Sum256(framed[anchorIndex].Payload)
		if records[anchorIndex].Sequence != snapshot.AckSequence ||
			records[anchorIndex].EventID != snapshot.AckEventID ||
			records[anchorIndex].ContentSHA256 != snapshot.AckContentSHA256 ||
			hex.EncodeToString(anchorPayloadHash[:]) != snapshot.AckPayloadSHA256 {
			return ErrSpoolCorrupt
		}
	}
	lastIndex := len(records) - 1
	if snapshot.AckSequence == 0 || anchorIndex < lastIndex {
		last := records[lastIndex]
		payloadHash := sha256.Sum256(framed[lastIndex].Payload)
		if err := state.applyAck(
			last.Sequence,
			last.EventID,
			last.ContentSHA256,
			hex.EncodeToString(framed[lastIndex].Hash[:]),
			hex.EncodeToString(payloadHash[:]),
		); err != nil {
			return err
		}
	}
	return nil
}

func (spool *Spool) directory(tier Tier) string {
	return filepath.Join(spool.config.StateDir, "spool", string(tier))
}

func (spool *Spool) Append(
	event contracts.EventEnvelopeV1,
	tier Tier,
) (SpoolItem, error) {
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	if spool.closed {
		return SpoolItem{}, fmt.Errorf("spool closed")
	}
	if tier != RoutineTier && tier != PriorityTier {
		return SpoolItem{}, fmt.Errorf("invalid spool tier")
	}
	canonical, err := contracts.CanonicalJSON(event)
	if err != nil {
		return SpoolItem{}, err
	}
	validated, contentHash, err := validateSpoolPayload(canonical, spool.keys)
	if err != nil || validated.SourceSequence != event.SourceSequence {
		return SpoolItem{}, ErrSpoolCorrupt
	}
	frame, _, err := durablefile.EncodeFrame(canonical, [32]byte{}, 65_536)
	if err != nil {
		return SpoolItem{}, err
	}
	if existing, ok := spool.items[event.SourceSequence]; ok {
		if existing.ContentSHA256 == contentHash &&
			bytes.Equal(existing.Canonical, canonical) {
			return existing, nil
		}
		_ = spool.state.PersistReadOnly("observer_spool_sequence_conflict")
		return SpoolItem{}, ErrSpoolCorrupt
	}
	frameBytes := uint64(len(frame))
	if ^uint64(0)-spool.totalBytes < frameBytes {
		_ = spool.state.PersistReadOnly("observer_spool_size_overflow")
		return SpoolItem{}, ErrSpoolCorrupt
	}
	if tier == RoutineTier &&
		spool.routineBytes+frameBytes >
			spool.config.MaxBytes-spool.config.PriorityReserveBytes {
		return SpoolItem{}, ErrRoutineQuota
	}
	if spool.config.MaxBytes <= ackJournalMaxFrameBytes ||
		spool.totalBytes+frameBytes >
			spool.config.MaxBytes-ackJournalMaxFrameBytes {
		_ = spool.state.PersistReadOnly("observer_priority_spool_exhausted")
		return SpoolItem{}, ErrPriorityQuota
	}
	path := filepath.Join(
		spool.directory(tier),
		fmt.Sprintf("%020d.agf", event.SourceSequence),
	)
	if err := spool.publish(path, frame); err != nil {
		if errors.Is(err, os.ErrExist) {
			existingEvent, existingCanonical, existingHash, existingSize, readErr :=
				readStandaloneFrame(path, spool.keys)
			if readErr == nil &&
				existingEvent.SourceSequence == event.SourceSequence &&
				existingHash == contentHash &&
				bytes.Equal(existingCanonical, canonical) {
				item := SpoolItem{
					Sequence:      event.SourceSequence,
					EventID:       event.EventID,
					ContentSHA256: contentHash,
					Tier:          tier,
					Canonical:     canonical,
					frameBytes:    existingSize,
					path:          path,
				}
				spool.items[event.SourceSequence] = item
				return item, nil
			}
		}
		_ = spool.state.PersistReadOnly("observer_spool_write_uncertain")
		return SpoolItem{}, err
	}
	item := SpoolItem{
		Sequence:      event.SourceSequence,
		EventID:       event.EventID,
		ContentSHA256: contentHash,
		Tier:          tier,
		Canonical:     canonical,
		frameBytes:    frameBytes,
		path:          path,
	}
	spool.items[event.SourceSequence] = item
	spool.totalBytes += frameBytes
	if tier == RoutineTier {
		spool.routineBytes += frameBytes
	}
	return item, nil
}

func (spool *Spool) Fetch(
	after uint64,
	limit int,
	maxBytes uint64,
) ([]SpoolItem, error) {
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	if limit < 1 || limit > 100 || maxBytes == 0 || maxBytes > 4*1024*1024 {
		return nil, fmt.Errorf("invalid fetch bound")
	}
	acked := spool.state.Snapshot().AckSequence
	sequences := make([]uint64, 0, len(spool.items))
	for sequence := range spool.items {
		if sequence > after && sequence > acked {
			sequences = append(sequences, sequence)
		}
	}
	sort.Slice(sequences, func(left, right int) bool {
		return sequences[left] < sequences[right]
	})
	result := make([]SpoolItem, 0, min(limit, len(sequences)))
	var used uint64
	for _, sequence := range sequences {
		if len(result) == limit {
			break
		}
		item := spool.items[sequence]
		event, canonical, contentHash, _, err := readStandaloneFrame(item.path, spool.keys)
		if err != nil ||
			event.SourceSequence != item.Sequence ||
			event.EventID != item.EventID ||
			contentHash != item.ContentSHA256 {
			_ = spool.state.PersistReadOnly("observer_spool_fetch_corrupt")
			return nil, ErrSpoolCorrupt
		}
		if used+uint64(len(canonical)) > maxBytes {
			break
		}
		item.Canonical = canonical
		result = append(result, item)
		used += uint64(len(canonical))
	}
	return result, nil
}

func (spool *Spool) UncoveredGaps(after uint64) []SequenceGap {
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	snapshot := spool.state.Snapshot()
	if snapshot.AckSequence == ^uint64(0) {
		_ = spool.state.PersistReadOnly("observer_sequence_exhausted")
		return nil
	}
	start := snapshot.AckSequence + 1
	if after >= start {
		if after == ^uint64(0) {
			return nil
		}
		start = after + 1
	}
	if start > snapshot.LastSequence {
		return nil
	}
	sequences := make([]uint64, 0, len(spool.items))
	for sequence := range spool.items {
		if sequence >= start && sequence <= snapshot.LastSequence {
			sequences = append(sequences, sequence)
		}
	}
	sort.Slice(sequences, func(left, right int) bool {
		return sequences[left] < sequences[right]
	})
	cursor := start
	gaps := make([]SequenceGap, 0)
	for _, sequence := range sequences {
		if sequence > cursor {
			gaps = append(gaps, SequenceGap{Start: cursor, End: sequence - 1})
		}
		if sequence == ^uint64(0) {
			return gaps
		}
		cursor = sequence + 1
	}
	if cursor <= snapshot.LastSequence {
		gaps = append(gaps, SequenceGap{Start: cursor, End: snapshot.LastSequence})
	}
	return gaps
}

func (spool *Spool) cleanupAckedLocked(sequence uint64) error {
	sequences := make([]uint64, 0)
	for itemSequence := range spool.items {
		if itemSequence <= sequence {
			sequences = append(sequences, itemSequence)
		}
	}
	sort.Slice(sequences, func(left, right int) bool {
		return sequences[left] < sequences[right]
	})
	for _, itemSequence := range sequences {
		item := spool.items[itemSequence]
		err := spool.remove(item.path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := durablefile.SyncDirectory(filepath.Dir(item.path)); err != nil {
			return err
		}
		delete(spool.items, itemSequence)
		spool.totalBytes -= item.frameBytes
		if item.Tier == RoutineTier {
			spool.routineBytes -= item.frameBytes
		}
	}
	return nil
}

// Ack durably binds sequence, event ID, and canonical-content SHA-256 before
// deleting any standalone spool file.
func (spool *Spool) Ack(
	sequence uint64,
	eventID string,
	contentSHA256 string,
) error {
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	if spool.closed {
		return fmt.Errorf("spool closed")
	}
	snapshot := spool.state.Snapshot()
	if sequence < snapshot.AckSequence {
		return ErrAckInvalid
	}
	if sequence == snapshot.AckSequence {
		if sequence == 0 ||
			eventID != snapshot.AckEventID ||
			contentSHA256 != snapshot.AckContentSHA256 {
			_ = spool.state.PersistReadOnly("observer_ack_identity_conflict")
			return ErrSpoolCorrupt
		}
		return spool.cleanupAckedLocked(sequence)
	}
	sequences := make([]uint64, 0, len(spool.items))
	for itemSequence := range spool.items {
		if itemSequence > snapshot.AckSequence {
			sequences = append(sequences, itemSequence)
		}
	}
	if len(sequences) == 0 {
		return ErrAckInvalid
	}
	sort.Slice(sequences, func(left, right int) bool {
		return sequences[left] < sequences[right]
	})
	if sequence != sequences[0] {
		return ErrAckInvalid
	}
	item := spool.items[sequence]
	if item.EventID != eventID || item.ContentSHA256 != contentSHA256 {
		_ = spool.state.PersistReadOnly("observer_ack_identity_conflict")
		return ErrSpoolCorrupt
	}
	record := ackRecord{
		SchemaVersion: "agmind.spool-ack.v1",
		Sequence:      sequence,
		EventID:       eventID,
		ContentSHA256: contentSHA256,
		AckedAt:       spool.config.Now().UTC().Format(time.RFC3339Nano),
	}
	canonical, err := contracts.CanonicalJSON(record)
	if err != nil {
		return err
	}
	frameBytes := uint64(len(canonical)) + 76
	if ^uint64(0)-spool.totalBytes < frameBytes ||
		spool.totalBytes+frameBytes > spool.config.MaxBytes {
		_ = spool.state.PersistReadOnly("observer_ack_journal_quota_exhausted")
		return ErrPriorityQuota
	}
	meta, err := spool.ackJournal.Append(canonical, true)
	if err != nil {
		_ = spool.state.PersistReadOnly("observer_ack_journal_failed")
		return err
	}
	spool.ackBytes += uint64(meta.Size)
	spool.totalBytes += uint64(meta.Size)
	payloadHash := sha256.Sum256(canonical)
	if err := spool.state.applyAck(
		sequence,
		eventID,
		contentSHA256,
		hex.EncodeToString(meta.Hash[:]),
		hex.EncodeToString(payloadHash[:]),
	); err != nil {
		return err
	}
	checkpoint, err := spool.ackJournal.Checkpoint(canonical)
	if err != nil {
		_ = spool.state.PersistReadOnly("observer_ack_journal_checkpoint_failed")
		return err
	}
	oldAckBytes := spool.ackBytes
	spool.ackBytes = uint64(checkpoint.Size)
	spool.totalBytes = spool.totalBytes - oldAckBytes + spool.ackBytes
	if err := spool.state.applyAck(
		sequence,
		eventID,
		contentSHA256,
		hex.EncodeToString(checkpoint.Hash[:]),
		hex.EncodeToString(payloadHash[:]),
	); err != nil {
		return err
	}
	return spool.cleanupAckedLocked(sequence)
}

func (spool *Spool) Close() error {
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	if spool.closed {
		return nil
	}
	spool.closed = true
	return spool.ackJournal.Close()
}
