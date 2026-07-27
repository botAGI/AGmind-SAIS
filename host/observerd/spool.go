package observerd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
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
	rotation             *rotationMarker
}

type SpoolItem struct {
	Sequence            uint64
	EventID             string
	ContentSHA256       string
	Tier                Tier
	Canonical           []byte
	frameBytes          uint64
	path                string
	identity            durablefile.FileIdentity
	publication         publicationRecord
	publicationRaw      []byte
	publicationBytes    uint64
	publicationPath     string
	publicationIdentity durablefile.FileIdentity
	publicationHash     string
}

type SequenceGap struct {
	Start uint64
	End   uint64
}

type Spool struct {
	mutex             sync.Mutex
	config            SpoolConfig
	state             *StateStore
	keys              *Keyring
	items             map[uint64]SpoolItem
	routineBytes      uint64
	totalBytes        uint64
	ackBytes          uint64
	ackJournal        *durablefile.Journal
	closed            bool
	remove            func(string, durablefile.FileIdentity) error
	removePublication func(string, durablefile.FileIdentity) error
	syncDirectory     func(string) error
	publish           func(string, []byte) error
	beforeRemove      func(SpoolItem)
}

type ackRecord struct {
	SchemaVersion string `json:"schema_version"`
	Sequence      uint64 `json:"sequence"`
	EventID       string `json:"event_id"`
	ContentSHA256 string `json:"content_sha256"`
	AckedAt       string `json:"acked_at"`
}

type publicationRecord struct {
	SchemaVersion           string `json:"schema_version"`
	Sequence                uint64 `json:"sequence"`
	EventID                 string `json:"event_id"`
	ContentSHA256           string `json:"content_sha256"`
	Tier                    Tier   `json:"tier"`
	HostID                  string `json:"host_id"`
	BootID                  string `json:"boot_id"`
	KeyID                   string `json:"key_id"`
	KeyEpoch                uint64 `json:"key_epoch"`
	PreviousPublicationHash string `json:"previous_publication_hash"`
}

func (record publicationRecord) Validate() error {
	if record.SchemaVersion != "agmind.spool-publication.v1" ||
		record.Sequence == 0 ||
		!eventPattern.MatchString(record.EventID) ||
		!hex64Pattern.MatchString(record.ContentSHA256) ||
		record.Tier != RoutineTier && record.Tier != PriorityTier ||
		!uuid4Pattern.MatchString(record.HostID) ||
		!uuid4Pattern.MatchString(record.BootID) ||
		!hex32Pattern.MatchString(record.KeyID) ||
		record.KeyEpoch == 0 ||
		!hex64Pattern.MatchString(record.PreviousPublicationHash) {
		return ErrSpoolCorrupt
	}
	return nil
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

var (
	spoolNamePattern       = regexp.MustCompile(`^([0-9]{20})\.agf$`)
	publicationNamePattern = regexp.MustCompile(
		`^([0-9]{20})\.(prepared|published)$`,
	)
	spoolFrameTempNamePattern = regexp.MustCompile(
		`^\.([0-9]{20})\.agf\.tmp-[0-9a-f]{32}$`,
	)
	publicationTempNamePattern = regexp.MustCompile(
		`^\.([0-9]{20})\.prepared\.tmp-[0-9a-f]{32}$`,
	)
	ackTempNamePattern = regexp.MustCompile(
		`^\.acked\.agf\.tmp-[0-9a-f]{32}$`,
	)
)

type spoolRecoveryArtifact struct {
	path     string
	identity durablefile.FileIdentity
	bytes    uint64
	sequence uint64
	tier     Tier
	kind     string
}

type publicationRecovery struct {
	sequence uint64
	prepared bool
}

func recoveryArtifactBytes(identity durablefile.FileIdentity) uint64 {
	if identity.Size == 0 {
		// Even an empty temporary file consumes a physical inode and must not
		// disappear from startup quota accounting.
		return 1
	}
	return identity.Size
}

func collectCreateOnlyTemp(
	path string,
	match []string,
	maxBytes int64,
	tier Tier,
	kind string,
	snapshot ObserverState,
	artifacts *[]spoolRecoveryArtifact,
) error {
	if len(match) != 2 || len(*artifacts) != 0 {
		return ErrSpoolCorrupt
	}
	sequence, err := strconv.ParseUint(match[1], 10, 64)
	if err != nil ||
		sequence == 0 ||
		sequence != snapshot.LastSequence ||
		sequence <= snapshot.PublicationHeadSequence {
		return ErrSpoolCorrupt
	}
	_, identity, err := durablefile.ReadRegularIdentity(path, maxBytes)
	if err != nil {
		return ErrSpoolCorrupt
	}
	*artifacts = append(*artifacts, spoolRecoveryArtifact{
		path:     path,
		identity: identity,
		bytes:    recoveryArtifactBytes(identity),
		sequence: sequence,
		tier:     tier,
		kind:     kind,
	})
	return nil
}

func publicationDirectory(stateDir string) string {
	return filepath.Join(stateDir, "spool", "publications")
}

func publicationPreparedPath(stateDir string, sequence uint64) string {
	return filepath.Join(
		publicationDirectory(stateDir),
		fmt.Sprintf("%020d.prepared", sequence),
	)
}

func publicationPublishedPath(stateDir string, sequence uint64) string {
	return filepath.Join(
		publicationDirectory(stateDir),
		fmt.Sprintf("%020d.published", sequence),
	)
}

func publicationFor(
	event contracts.EventEnvelopeV1,
	tier Tier,
	contentHash string,
	previousPublicationHash string,
) publicationRecord {
	return publicationRecord{
		SchemaVersion:           "agmind.spool-publication.v1",
		Sequence:                event.SourceSequence,
		EventID:                 event.EventID,
		ContentSHA256:           contentHash,
		Tier:                    tier,
		HostID:                  event.HostID,
		BootID:                  event.BootID,
		KeyID:                   event.KeyID,
		KeyEpoch:                event.KeyEpoch,
		PreviousPublicationHash: previousPublicationHash,
	}
}

func publicationNodeHash(
	record publicationRecord,
) ([]byte, string, error) {
	if err := record.Validate(); err != nil {
		return nil, "", err
	}
	raw, err := contracts.CanonicalJSON(record)
	if err != nil {
		return nil, "", err
	}
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("AGMIND_SPOOL_PUBLICATION_NODE_V1\x00"))
	_, _ = hasher.Write(raw)
	return raw, hex.EncodeToString(hasher.Sum(nil)), nil
}

func readPublication(
	path string,
) (publicationRecord, []byte, durablefile.FileIdentity, error) {
	raw, identity, err := durablefile.ReadRegularIdentity(path, 4_096)
	if err != nil {
		return publicationRecord{}, nil, durablefile.FileIdentity{}, err
	}
	record, err := contracts.DecodeStrict[publicationRecord](
		bytes.NewReader(raw),
		4_096,
	)
	if err != nil {
		return publicationRecord{}, nil, durablefile.FileIdentity{}, ErrSpoolCorrupt
	}
	if err := record.Validate(); err != nil {
		return publicationRecord{}, nil, durablefile.FileIdentity{}, ErrSpoolCorrupt
	}
	canonical, err := contracts.CanonicalJSON(record)
	if err != nil || !bytes.Equal(canonical, raw) {
		return publicationRecord{}, nil, durablefile.FileIdentity{}, ErrSpoolCorrupt
	}
	return record, raw, identity, nil
}

func publicationMatchesItem(
	record publicationRecord,
	item SpoolItem,
) bool {
	return record.Sequence == item.Sequence &&
		record.EventID == item.EventID &&
		record.ContentSHA256 == item.ContentSHA256 &&
		record.Tier == item.Tier &&
		record.HostID == item.publication.HostID &&
		record.BootID == item.publication.BootID &&
		record.KeyID == item.publication.KeyID &&
		record.KeyEpoch == item.publication.KeyEpoch &&
		record.PreviousPublicationHash ==
			item.publication.PreviousPublicationHash
}

func bootAllowed(
	snapshot ObserverState,
	bootID string,
	sequence uint64,
) bool {
	if len(snapshot.BootHistory) == 0 {
		return snapshot.BootID == bootID
	}
	for index, boundary := range snapshot.BootHistory {
		if boundary.BootID != bootID ||
			sequence < boundary.FirstSequence {
			continue
		}
		if index+1 == len(snapshot.BootHistory) ||
			sequence < snapshot.BootHistory[index+1].FirstSequence {
			return true
		}
		return false
	}
	return false
}

func eventAllowedByState(
	event contracts.EventEnvelopeV1,
	snapshot ObserverState,
) bool {
	return event.HostID == snapshot.HostID &&
		bootAllowed(snapshot, event.BootID, event.SourceSequence) &&
		event.KeyEpoch <= snapshot.KeyEpoch
}

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
) (
	contracts.EventEnvelopeV1,
	[]byte,
	string,
	uint64,
	durablefile.FileIdentity,
	error,
) {
	raw, identity, err := durablefile.ReadRegularIdentity(path, 65_536+76)
	if err != nil {
		return contracts.EventEnvelopeV1{}, nil, "", 0, durablefile.FileIdentity{}, err
	}
	record, err := durablefile.DecodeFrame(raw, 65_536, [32]byte{})
	if err != nil {
		// Standalone published frames are never repaired or truncated.
		return contracts.EventEnvelopeV1{}, nil, "", 0, durablefile.FileIdentity{}, ErrSpoolCorrupt
	}
	event, contentHash, err := validateSpoolPayload(record.Payload, keys)
	if err != nil {
		return contracts.EventEnvelopeV1{}, nil, "", 0, durablefile.FileIdentity{}, ErrSpoolCorrupt
	}
	return event, record.Payload, contentHash, uint64(len(raw)), identity, nil
}

func tierForEvent(event contracts.EventEnvelopeV1) Tier {
	if priorityEventType(event.EventType) {
		return PriorityTier
	}
	return RoutineTier
}

func scanTier(
	directory string,
	tier Tier,
	keys *Keyring,
	snapshot ObserverState,
	items map[uint64]SpoolItem,
	tempArtifacts *[]spoolRecoveryArtifact,
) (uint64, error) {
	entries, err := durablefile.ReadDirectoryNames(directory)
	if err != nil {
		return 0, err
	}
	var used uint64
	for _, entry := range entries {
		match := spoolNamePattern.FindStringSubmatch(entry)
		if match == nil {
			tempMatch := spoolFrameTempNamePattern.FindStringSubmatch(entry)
			if tempMatch == nil ||
				collectCreateOnlyTemp(
					filepath.Join(directory, entry),
					tempMatch,
					65_536+76,
					tier,
					"frame_temp",
					snapshot,
					tempArtifacts,
				) != nil {
				return 0, ErrSpoolCorrupt
			}
			continue
		}
		sequence, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil || fmt.Sprintf("%020d.agf", sequence) != entry {
			return 0, ErrSpoolCorrupt
		}
		if _, exists := items[sequence]; exists {
			return 0, ErrSpoolCorrupt
		}
		path := filepath.Join(directory, entry)
		event, canonical, contentHash, frameBytes, identity, err :=
			readStandaloneFrame(path, keys)
		if err != nil ||
			event.SourceSequence != sequence ||
			tierForEvent(event) != tier ||
			!eventAllowedByState(event, snapshot) {
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
			identity:      identity,
			publication: publicationFor(
				event,
				tier,
				contentHash,
				zeroPublicationHash,
			),
		}
	}
	return used, nil
}

func publicationAllowedByState(
	record publicationRecord,
	snapshot ObserverState,
) bool {
	return record.HostID == snapshot.HostID &&
		bootAllowed(snapshot, record.BootID, record.Sequence) &&
		record.KeyEpoch <= snapshot.KeyEpoch
}

func scanPublications(
	stateDir string,
	state *StateStore,
	items map[uint64]SpoolItem,
	tempArtifacts *[]spoolRecoveryArtifact,
	cleanupArtifacts *[]spoolRecoveryArtifact,
	recovery **publicationRecovery,
) (uint64, uint64, error) {
	directory := publicationDirectory(stateDir)
	entries, err := durablefile.ReadDirectoryNames(directory)
	if err != nil {
		return 0, 0, err
	}
	sort.Strings(entries)
	seen := make(map[uint64]struct{}, len(entries))
	snapshot := state.Snapshot()
	var routineBytes uint64
	var priorityBytes uint64
	for _, entry := range entries {
		match := publicationNamePattern.FindStringSubmatch(entry)
		if match == nil {
			tempMatch := publicationTempNamePattern.FindStringSubmatch(entry)
			if tempMatch == nil ||
				collectCreateOnlyTemp(
					filepath.Join(directory, entry),
					tempMatch,
					4_096,
					Tier(""),
					"publication_temp",
					snapshot,
					tempArtifacts,
				) != nil {
				return 0, 0, ErrSpoolCorrupt
			}
			continue
		}
		sequence, parseErr := strconv.ParseUint(match[1], 10, 64)
		if parseErr != nil ||
			sequence == 0 ||
			fmt.Sprintf("%020d.%s", sequence, match[2]) != entry {
			return 0, 0, ErrSpoolCorrupt
		}
		if _, duplicate := seen[sequence]; duplicate {
			return 0, 0, ErrSpoolCorrupt
		}
		seen[sequence] = struct{}{}
		path := filepath.Join(directory, entry)
		record, raw, identity, readErr := readPublication(path)
		if readErr != nil ||
			record.Sequence != sequence ||
			record.Sequence > snapshot.LastSequence ||
			!publicationAllowedByState(record, snapshot) {
			return 0, 0, ErrSpoolCorrupt
		}
		nodeRaw, nodeHash, hashErr := publicationNodeHash(record)
		if hashErr != nil || !bytes.Equal(nodeRaw, raw) {
			return 0, 0, ErrSpoolCorrupt
		}
		item, frameExists := items[sequence]
		if !frameExists {
			if match[2] == "prepared" &&
				sequence == snapshot.LastSequence &&
				sequence > snapshot.PublicationHeadSequence &&
				record.PreviousPublicationHash ==
					snapshot.PublicationHeadHash &&
				len(*cleanupArtifacts) == 0 {
				*cleanupArtifacts = append(
					*cleanupArtifacts,
					spoolRecoveryArtifact{
						path:     path,
						identity: identity,
						bytes:    recoveryArtifactBytes(identity),
						sequence: sequence,
						tier:     record.Tier,
						kind:     "prepared_without_frame",
					},
				)
				continue
			}
			if match[2] == "published" &&
				sequence <= snapshot.PublicationBaseSequence &&
				(sequence != snapshot.PublicationBaseSequence ||
					nodeHash == snapshot.PublicationBaseHash) {
				item = SpoolItem{
					Sequence:      sequence,
					EventID:       record.EventID,
					ContentSHA256: record.ContentSHA256,
					Tier:          record.Tier,
					path: filepath.Join(
						stateDir,
						"spool",
						string(record.Tier),
						fmt.Sprintf("%020d.agf", sequence),
					),
					publication: record,
				}
			} else {
				return 0, 0, ErrSpoolCorrupt
			}
		}
		expectedItem := item
		expectedItem.publication.PreviousPublicationHash =
			record.PreviousPublicationHash
		if !publicationMatchesItem(record, expectedItem) {
			return 0, 0, ErrSpoolCorrupt
		}
		item.publication = record
		if match[2] == "prepared" &&
			sequence <= snapshot.PublicationHeadSequence {
			return 0, 0, ErrSpoolCorrupt
		}
		publicationBytes := uint64(len(raw))
		if record.Tier == RoutineTier {
			if ^uint64(0)-routineBytes < publicationBytes {
				return 0, 0, ErrSpoolCorrupt
			}
			routineBytes += publicationBytes
		} else {
			if ^uint64(0)-priorityBytes < publicationBytes {
				return 0, 0, ErrSpoolCorrupt
			}
			priorityBytes += publicationBytes
		}
		item.publication = record
		item.publicationRaw = raw
		item.publicationBytes = publicationBytes
		item.publicationPath = path
		item.publicationIdentity = identity
		item.publicationHash = nodeHash
		items[sequence] = item
	}
	if len(*tempArtifacts) == 1 {
		temp := (*tempArtifacts)[0]
		_, frameExists := items[temp.sequence]
		_, publicationExists := seen[temp.sequence]
		switch temp.kind {
		case "publication_temp":
			if frameExists || publicationExists ||
				len(*cleanupArtifacts) != 0 {
				return 0, 0, ErrSpoolCorrupt
			}
		case "frame_temp":
			if frameExists ||
				!publicationExists ||
				len(*cleanupArtifacts) != 1 ||
				(*cleanupArtifacts)[0].sequence != temp.sequence ||
				(*cleanupArtifacts)[0].tier != temp.tier {
				return 0, 0, ErrSpoolCorrupt
			}
		default:
			return 0, 0, ErrSpoolCorrupt
		}
	}
	for _, item := range items {
		if item.publicationPath == "" {
			return 0, 0, ErrSpoolCorrupt
		}
	}
	sequences := make([]uint64, 0, len(items))
	for sequence := range items {
		if sequence > snapshot.PublicationBaseSequence {
			sequences = append(sequences, sequence)
			continue
		}
		if sequence < snapshot.PublicationBaseSequence {
			continue
		}
		item := items[sequence]
		if sequence == 0 ||
			item.publicationHash != snapshot.PublicationBaseHash {
			return 0, 0, ErrSpoolCorrupt
		}
	}
	sort.Slice(sequences, func(left, right int) bool {
		return sequences[left] < sequences[right]
	})
	currentSequence := snapshot.PublicationBaseSequence
	currentHash := snapshot.PublicationBaseHash
	reachedStoredHead := currentSequence == snapshot.PublicationHeadSequence &&
		currentHash == snapshot.PublicationHeadHash
	tailCount := 0
	for _, sequence := range sequences {
		item := items[sequence]
		if sequence <= currentSequence ||
			item.publication.PreviousPublicationHash != currentHash {
			return 0, 0, ErrSpoolCorrupt
		}
		currentSequence = sequence
		currentHash = item.publicationHash
		if sequence == snapshot.PublicationHeadSequence {
			if currentHash != snapshot.PublicationHeadHash {
				return 0, 0, ErrSpoolCorrupt
			}
			reachedStoredHead = true
		} else if sequence > snapshot.PublicationHeadSequence &&
			!reachedStoredHead {
			return 0, 0, ErrSpoolCorrupt
		} else if sequence > snapshot.PublicationHeadSequence {
			tailCount++
			if tailCount > 1 {
				return 0, 0, ErrSpoolCorrupt
			}
		}
	}
	if !reachedStoredHead {
		return 0, 0, ErrSpoolCorrupt
	}
	if currentSequence > snapshot.PublicationHeadSequence {
		if currentSequence != snapshot.LastSequence {
			return 0, 0, ErrSpoolCorrupt
		}
		if *recovery != nil {
			return 0, 0, ErrSpoolCorrupt
		}
		item := items[currentSequence]
		*recovery = &publicationRecovery{
			sequence: currentSequence,
			prepared: item.publicationPath ==
				publicationPreparedPath(stateDir, currentSequence),
		}
	}
	return routineBytes, priorityBytes, nil
}

func finalizePublicationRecovery(
	stateDir string,
	state *StateStore,
	items map[uint64]SpoolItem,
	recovery *publicationRecovery,
) error {
	if recovery == nil {
		return nil
	}
	item, ok := items[recovery.sequence]
	if !ok ||
		item.publicationHash == "" ||
		item.publication.PreviousPublicationHash == "" {
		return ErrSpoolCorrupt
	}
	if recovery.prepared {
		publishedPath := publicationPublishedPath(
			stateDir,
			recovery.sequence,
		)
		promoteErr := durablefile.PromoteNoReplace(
			item.publicationPath,
			publishedPath,
		)
		if errors.Is(promoteErr, durablefile.ErrCommitUncertain) {
			promoteErr = durablefile.SyncDirectory(
				publicationDirectory(stateDir),
			)
		}
		if promoteErr != nil {
			return promoteErr
		}
		item.publicationPath = publishedPath
		record, raw, identity, err := readPublication(publishedPath)
		_, nodeHash, hashErr := publicationNodeHash(record)
		if err != nil ||
			hashErr != nil ||
			!publicationMatchesItem(record, item) ||
			!bytes.Equal(raw, item.publicationRaw) ||
			uint64(len(raw)) != item.publicationBytes ||
			nodeHash != item.publicationHash {
			return ErrSpoolCorrupt
		}
		item.publicationIdentity = identity
		items[recovery.sequence] = item
	} else if err := validatePublicationItem(item); err != nil {
		return err
	}
	return state.recoverPublicationHead(
		item.publication.PreviousPublicationHash,
		item.Sequence,
		item.publicationHash,
	)
}

func validateIdentityHistory(
	items map[uint64]SpoolItem,
	snapshot ObserverState,
	keys *Keyring,
	rotation *rotationMarker,
) error {
	keys.mutex.RLock()
	hostID := keys.hostID
	metadataEpoch := keys.metadataEpoch
	boundaries := make(map[uint64]epochBoundary, len(keys.boundaries))
	for epoch, boundary := range keys.boundaries {
		boundaries[epoch] = boundary
	}
	epochKeys := make(map[uint64]string, len(keys.keys))
	for keyID, entry := range keys.keys {
		if existing, duplicate := epochKeys[entry.epoch]; duplicate &&
			existing != keyID {
			keys.mutex.RUnlock()
			return ErrSpoolCorrupt
		}
		epochKeys[entry.epoch] = keyID
	}
	keys.mutex.RUnlock()

	if metadataEpoch == 0 {
		if snapshot.KeyEpoch > 1 || rotation != nil {
			return ErrSpoolCorrupt
		}
		return nil
	}
	if hostID != snapshot.HostID {
		return ErrSpoolCorrupt
	}
	if rotation == nil {
		if metadataEpoch != snapshot.KeyEpoch {
			return ErrSpoolCorrupt
		}
	} else {
		if err := rotation.Validate(); err != nil ||
			rotation.HostID != snapshot.HostID ||
			metadataEpoch != rotation.Transition.OldEpoch &&
				metadataEpoch != rotation.Transition.NewEpoch {
			return ErrSpoolCorrupt
		}
		stateOld := snapshot.KeyEpoch == rotation.Transition.OldEpoch &&
			snapshot.KeyID == rotation.Transition.OldKeyID
		stateNew := snapshot.KeyEpoch == rotation.Transition.NewEpoch &&
			snapshot.KeyID == rotation.Transition.NewKeyID
		if !stateOld && !stateNew ||
			metadataEpoch == rotation.Transition.NewEpoch && !stateNew {
			return ErrSpoolCorrupt
		}
	}
	for epoch := uint64(1); epoch <= metadataEpoch; epoch++ {
		if _, ok := epochKeys[epoch]; !ok {
			return ErrSpoolCorrupt
		}
		if epoch == 1 {
			continue
		}
		boundary, ok := boundaries[epoch]
		if !ok ||
			boundary.epoch != epoch ||
			boundary.keyID != epochKeys[epoch] ||
			boundary.transition.SourceSequence > snapshot.LastSequence ||
			boundary.start.SourceSequence > snapshot.LastSequence ||
			!bootAllowed(
				snapshot,
				boundary.transition.BootID,
				boundary.transition.SourceSequence,
			) ||
			!bootAllowed(
				snapshot,
				boundary.start.BootID,
				boundary.start.SourceSequence,
			) {
			return ErrSpoolCorrupt
		}
		for _, proof := range []contracts.EventEnvelopeV1{
			boundary.transition,
			boundary.start,
		} {
			item, exists := items[proof.SourceSequence]
			if !exists {
				if proof.SourceSequence > snapshot.AckSequence {
					return ErrSpoolCorrupt
				}
				continue
			}
			if len(item.Canonical) == 0 &&
				proof.SourceSequence <= snapshot.AckSequence {
				continue
			}
			canonical, err := contracts.CanonicalJSON(proof)
			if err != nil || !bytes.Equal(canonical, item.Canonical) {
				return ErrSpoolCorrupt
			}
		}
	}
	for sequence, item := range items {
		expectedEpoch := uint64(1)
		for epoch := uint64(2); epoch <= metadataEpoch; epoch++ {
			if sequence > boundaries[epoch].transition.SourceSequence {
				expectedEpoch = epoch
				continue
			}
			break
		}
		if item.publication.KeyEpoch != expectedEpoch ||
			item.publication.KeyID != epochKeys[expectedEpoch] {
			if rotation != nil &&
				metadataEpoch == rotation.Transition.OldEpoch &&
				sequence == rotation.StartSequence &&
				item.publication.KeyEpoch == rotation.Transition.NewEpoch &&
				item.publication.KeyID == rotation.Transition.NewKeyID {
				continue
			}
			return ErrSpoolCorrupt
		}
	}
	if rotation == nil {
		return nil
	}
	if snapshot.LastSequence < rotation.TransitionSequence-1 ||
		snapshot.LastSequence > rotation.StartSequence {
		return ErrSpoolCorrupt
	}
	transitionFields, err := transitionMap(rotation.Transition)
	if err != nil {
		return ErrSpoolCorrupt
	}
	startFields := map[string]any{
		"kind":      "observer_key_epoch_start",
		"key_id":    rotation.Transition.NewKeyID,
		"key_epoch": rotation.Transition.NewEpoch,
	}
	transitionItem, transitionExists := items[rotation.TransitionSequence]
	startItem, startExists := items[rotation.StartSequence]
	if transitionExists {
		event, decodeErr := contracts.DecodeStrict[contracts.EventEnvelopeV1](
			bytes.NewReader(transitionItem.Canonical),
			65_536,
		)
		if decodeErr != nil ||
			event.EventType != "observer_key_transition" ||
			event.KeyID != rotation.Transition.OldKeyID ||
			event.KeyEpoch != rotation.Transition.OldEpoch ||
			event.HostID != rotation.HostID ||
			!eventHasExactFields(event, transitionFields) ||
			event.SourcePayloadHash != event.NormalizedFieldsSHA256 {
			return ErrSpoolCorrupt
		}
	}
	if startExists {
		event, decodeErr := contracts.DecodeStrict[contracts.EventEnvelopeV1](
			bytes.NewReader(startItem.Canonical),
			65_536,
		)
		if decodeErr != nil ||
			event.EventType != "observer_key_epoch_start" ||
			event.KeyID != rotation.Transition.NewKeyID ||
			event.KeyEpoch != rotation.Transition.NewEpoch ||
			event.HostID != rotation.HostID ||
			!eventHasExactFields(event, startFields) ||
			event.SourcePayloadHash != event.NormalizedFieldsSHA256 {
			return ErrSpoolCorrupt
		}
	}
	if transitionExists !=
		(snapshot.LastSequence >= rotation.TransitionSequence) ||
		startExists != (snapshot.LastSequence >= rotation.StartSequence) ||
		startExists && !transitionExists {
		return ErrSpoolCorrupt
	}
	stateIsOld := snapshot.KeyEpoch == rotation.Transition.OldEpoch
	if stateIsOld && startExists {
		return ErrSpoolCorrupt
	}
	switch rotation.Stage {
	case "prepared":
		if !stateIsOld ||
			metadataEpoch != rotation.Transition.OldEpoch ||
			startExists {
			return ErrSpoolCorrupt
		}
	case "transition_spooled":
		if !transitionExists ||
			metadataEpoch != rotation.Transition.OldEpoch ||
			startExists {
			return ErrSpoolCorrupt
		}
	case "key_switched":
		if !transitionExists || stateIsOld ||
			metadataEpoch == rotation.Transition.NewEpoch && !startExists {
			return ErrSpoolCorrupt
		}
	case "start_spooled":
		if !transitionExists || !startExists ||
			metadataEpoch != rotation.Transition.NewEpoch {
			return ErrSpoolCorrupt
		}
	}
	return nil
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
	publicationDir := publicationDirectory(config.StateDir)
	for _, directory := range []string{
		spoolRoot,
		routineDir,
		priorityDir,
		publicationDir,
	} {
		if err := ensurePrivateDirectory(directory); err != nil {
			_ = state.PersistReadOnly("observer_spool_path_unsafe")
			return nil, err
		}
	}
	rootEntries, err := durablefile.ReadDirectoryNames(spoolRoot)
	if err != nil {
		_ = state.PersistReadOnly("observer_spool_path_unsafe")
		return nil, err
	}
	ackPath := filepath.Join(spoolRoot, "acked.agf")
	ackExists := false
	tempPaths := make([]string, 0)
	for _, entry := range rootEntries {
		switch entry {
		case string(RoutineTier), string(PriorityTier), "publications":
		case "acked.agf":
			ackExists = true
		default:
			if ackTempNamePattern.MatchString(entry) {
				tempPaths = append(tempPaths, filepath.Join(spoolRoot, entry))
			} else {
				_ = state.PersistReadOnly("observer_spool_root_unknown")
				return nil, ErrSpoolCorrupt
			}
		}
	}
	if len(tempPaths) > 0 && !ackExists {
		_ = state.PersistReadOnly("observer_ack_checkpoint_temp_without_journal")
		return nil, ErrSpoolCorrupt
	}
	if len(tempPaths) > 1 {
		_ = state.PersistReadOnly("observer_multiple_transaction_temps")
		return nil, ErrSpoolCorrupt
	}
	sort.Strings(tempPaths)
	type tempArtifact struct {
		path     string
		identity durablefile.FileIdentity
	}
	temps := make([]tempArtifact, 0, len(tempPaths))
	var tempBytes uint64
	for _, path := range tempPaths {
		_, identity, readErr := durablefile.ReadRegularIdentity(
			path,
			int64(ackJournalMaxFrameBytes),
		)
		artifactBytes := recoveryArtifactBytes(identity)
		if readErr != nil ||
			^uint64(0)-tempBytes < artifactBytes {
			_ = state.PersistReadOnly("observer_ack_checkpoint_temp_unsafe")
			return nil, ErrSpoolCorrupt
		}
		tempBytes += artifactBytes
		temps = append(temps, tempArtifact{path: path, identity: identity})
	}
	if tempBytes > config.MaxBytes {
		_ = state.PersistReadOnly("observer_spool_quota_invalid")
		return nil, ErrSpoolCorrupt
	}
	items := make(map[uint64]SpoolItem)
	createOnlyTemps := make([]spoolRecoveryArtifact, 0, 1)
	publicationCleanup := make([]spoolRecoveryArtifact, 0, 1)
	snapshot := state.Snapshot()
	routineFrameBytes, err := scanTier(
		routineDir,
		RoutineTier,
		keys,
		snapshot,
		items,
		&createOnlyTemps,
	)
	if err != nil {
		_ = state.PersistReadOnly("observer_spool_corrupt")
		return nil, err
	}
	priorityFrameBytes, err := scanTier(
		priorityDir,
		PriorityTier,
		keys,
		snapshot,
		items,
		&createOnlyTemps,
	)
	if err != nil || ^uint64(0)-routineFrameBytes < priorityFrameBytes {
		_ = state.PersistReadOnly("observer_spool_corrupt")
		return nil, ErrSpoolCorrupt
	}
	eventBytes := routineFrameBytes + priorityFrameBytes
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
	var pendingPublication *publicationRecovery
	routinePublicationBytes, priorityPublicationBytes, err :=
		scanPublications(
			config.StateDir,
			state,
			items,
			&createOnlyTemps,
			&publicationCleanup,
			&pendingPublication,
		)
	if err != nil {
		_ = state.PersistReadOnly("observer_publication_ledger_corrupt")
		return nil, err
	}
	if len(temps) > 0 &&
		(len(createOnlyTemps) > 0 ||
			len(publicationCleanup) > 0 ||
			pendingPublication != nil) {
		_ = state.PersistReadOnly("observer_multiple_transaction_temps")
		return nil, ErrSpoolCorrupt
	}
	hasUnresolvedPublication := len(createOnlyTemps) > 0 ||
		len(publicationCleanup) > 0 ||
		pendingPublication != nil
	ackRecovery, err := durablefile.RecoverWithTailIntent(
		ackPath,
		4_096,
		func() error {
			if hasUnresolvedPublication || len(temps) > 0 {
				return ErrSpoolCorrupt
			}
			return state.markAckRepair(
				"observer_ack_torn_tail_repaired",
			)
		},
	)
	if errors.Is(err, os.ErrNotExist) {
		ackRecovery = durablefile.Recovery{}
	} else if err != nil {
		_ = state.PersistReadOnly("observer_ack_journal_unsafe")
		return nil, err
	}
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
	if err := reconcileAckAnchor(
		state,
		ackRecovery.Records,
		ackRecords,
		items,
	); err != nil {
		_ = state.PersistReadOnly("observer_ack_journal_regression")
		return nil, err
	}
	if len(temps) > 0 {
		if err := state.markAckRepair(
			"observer_ack_checkpoint_temp_removed",
		); err != nil {
			return nil, err
		}
	}
	if err := validateIdentityHistory(
		items,
		state.Snapshot(),
		keys,
		config.rotation,
	); err != nil {
		_ = state.PersistReadOnly("observer_identity_history_corrupt")
		return nil, err
	}
	if ^uint64(0)-routineFrameBytes < routinePublicationBytes ||
		^uint64(0)-priorityFrameBytes < priorityPublicationBytes {
		_ = state.PersistReadOnly("observer_spool_quota_invalid")
		return nil, ErrSpoolCorrupt
	}
	routineBytes := routineFrameBytes + routinePublicationBytes
	priorityBytes := priorityFrameBytes + priorityPublicationBytes
	if ^uint64(0)-routineBytes < priorityBytes {
		_ = state.PersistReadOnly("observer_spool_quota_invalid")
		return nil, ErrSpoolCorrupt
	}
	eventBytes = routineBytes + priorityBytes
	var recoveryRoutineBytes uint64
	var recoveryPriorityBytes uint64
	var recoveryUnknownBytes uint64
	for _, artifacts := range [][]spoolRecoveryArtifact{
		createOnlyTemps,
		publicationCleanup,
	} {
		for _, artifact := range artifacts {
			switch artifact.tier {
			case RoutineTier:
				if ^uint64(0)-recoveryRoutineBytes < artifact.bytes {
					_ = state.PersistReadOnly(
						"observer_spool_quota_invalid",
					)
					return nil, ErrSpoolCorrupt
				}
				recoveryRoutineBytes += artifact.bytes
			case PriorityTier:
				if ^uint64(0)-recoveryPriorityBytes < artifact.bytes {
					_ = state.PersistReadOnly(
						"observer_spool_quota_invalid",
					)
					return nil, ErrSpoolCorrupt
				}
				recoveryPriorityBytes += artifact.bytes
			case Tier(""):
				if ^uint64(0)-recoveryUnknownBytes < artifact.bytes {
					_ = state.PersistReadOnly(
						"observer_spool_quota_invalid",
					)
					return nil, ErrSpoolCorrupt
				}
				recoveryUnknownBytes += artifact.bytes
			default:
				_ = state.PersistReadOnly("observer_spool_quota_invalid")
				return nil, ErrSpoolCorrupt
			}
		}
	}
	if ^uint64(0)-routineBytes < recoveryRoutineBytes ||
		^uint64(0)-priorityBytes < recoveryPriorityBytes {
		_ = state.PersistReadOnly("observer_spool_quota_invalid")
		return nil, ErrSpoolCorrupt
	}
	physicalRoutineBytes := routineBytes + recoveryRoutineBytes
	physicalPriorityBytes := priorityBytes + recoveryPriorityBytes
	if ^uint64(0)-physicalRoutineBytes < physicalPriorityBytes {
		_ = state.PersistReadOnly("observer_spool_quota_invalid")
		return nil, ErrSpoolCorrupt
	}
	physicalEventBytes := physicalRoutineBytes + physicalPriorityBytes
	if ^uint64(0)-physicalEventBytes < recoveryUnknownBytes {
		_ = state.PersistReadOnly("observer_spool_quota_invalid")
		return nil, ErrSpoolCorrupt
	}
	physicalEventBytes += recoveryUnknownBytes
	if ackRecovery.VerifiedBytes < 0 ||
		uint64(ackRecovery.VerifiedBytes) > config.MaxBytes ||
		tempBytes > config.MaxBytes-uint64(ackRecovery.VerifiedBytes) ||
		physicalEventBytes >
			config.MaxBytes-uint64(ackRecovery.VerifiedBytes)-tempBytes ||
		physicalRoutineBytes >
			config.MaxBytes-config.PriorityReserveBytes {
		_ = state.PersistReadOnly("observer_spool_quota_invalid")
		return nil, ErrSpoolCorrupt
	}
	if err := finalizePublicationRecovery(
		config.StateDir,
		state,
		items,
		pendingPublication,
	); err != nil {
		_ = state.PersistReadOnly("observer_publication_recovery_failed")
		return nil, err
	}
	ackBytes := uint64(ackRecovery.VerifiedBytes)
	totalBytes := eventBytes + ackBytes
	for _, artifacts := range [][]spoolRecoveryArtifact{
		createOnlyTemps,
		publicationCleanup,
	} {
		for _, artifact := range artifacts {
			if err := removeIdentityDurably(
				artifact.path,
				artifact.identity,
				durablefile.RemoveIfIdentity,
			); err != nil {
				_ = state.PersistReadOnly(
					"observer_spool_create_temp_cleanup_failed",
				)
				return nil, err
			}
		}
	}
	for _, temp := range temps {
		if err := removeIdentityDurably(
			temp.path,
			temp.identity,
			durablefile.RemoveIfIdentity,
		); err != nil {
			_ = state.PersistReadOnly(
				"observer_ack_checkpoint_temp_cleanup_failed",
			)
			return nil, err
		}
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
		config:            config,
		state:             state,
		keys:              keys,
		items:             items,
		routineBytes:      routineBytes,
		totalBytes:        totalBytes,
		ackBytes:          ackBytes,
		ackJournal:        ackJournal,
		remove:            durablefile.RemoveIfIdentity,
		removePublication: durablefile.RemoveIfIdentity,
		syncDirectory:     durablefile.SyncDirectory,
		publish: func(path string, payload []byte) error {
			return durablefile.CreateOnly(path, payload)
		},
	}
	if err := spool.cleanupAckedLocked(state.Snapshot().AckSequence); err != nil {
		_ = ackJournal.Close()
		_ = state.PersistReadOnly("observer_spool_acked_cleanup_failed")
		return nil, err
	}
	return spool, nil
}

func reconcileAckAnchor(
	state *StateStore,
	framed []durablefile.Record,
	records []ackRecord,
	items map[uint64]SpoolItem,
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
					snapshot.PublicationBaseSequence,
					snapshot.PublicationBaseHash,
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
		cursor := snapshot.AckSequence
		first := anchorIndex + 1
		for _, record := range records[first:] {
			if record.Sequence <= cursor ||
				ackCrossesUncoveredGap(
					cursor,
					record.Sequence,
					snapshot.LastCoveredGapEnd,
				) ||
				!ackRecordMatchesOutstanding(record, cursor, items) {
				return ErrSpoolCorrupt
			}
			cursor = record.Sequence
		}
		last := records[lastIndex]
		publicationItem, ok := items[last.Sequence]
		if !ok || publicationItem.publicationHash == "" {
			return ErrSpoolCorrupt
		}
		payloadHash := sha256.Sum256(framed[lastIndex].Payload)
		if err := state.applyAck(
			last.Sequence,
			last.EventID,
			last.ContentSHA256,
			hex.EncodeToString(framed[lastIndex].Hash[:]),
			hex.EncodeToString(payloadHash[:]),
			publicationItem.Sequence,
			publicationItem.publicationHash,
		); err != nil {
			return err
		}
	}
	return nil
}

func ackCrossesUncoveredGap(
	after uint64,
	sequence uint64,
	lastCoveredGapEnd uint64,
) bool {
	return sequence > after &&
		sequence-after > 1 &&
		lastCoveredGapEnd < sequence-1
}

func ackRecordMatchesOutstanding(
	record ackRecord,
	after uint64,
	items map[uint64]SpoolItem,
) bool {
	var next uint64
	for sequence := range items {
		if sequence <= after || next != 0 && sequence >= next {
			continue
		}
		next = sequence
	}
	if next == 0 || record.Sequence != next {
		return false
	}
	item := items[next]
	return record.EventID == item.EventID &&
		record.ContentSHA256 == item.ContentSHA256 &&
		validatePublicationItem(item) == nil
}

func (spool *Spool) directory(tier Tier) string {
	return filepath.Join(spool.config.StateDir, "spool", string(tier))
}

func validatePublicationItem(item SpoolItem) error {
	record, raw, identity, err := readPublication(item.publicationPath)
	if errors.Is(err, os.ErrNotExist) {
		return os.ErrNotExist
	}
	nodeRaw, nodeHash, hashErr := publicationNodeHash(record)
	if err != nil ||
		hashErr != nil ||
		!publicationMatchesItem(record, item) ||
		!bytes.Equal(nodeRaw, raw) ||
		nodeHash != item.publicationHash ||
		!bytes.Equal(raw, item.publicationRaw) ||
		uint64(len(raw)) != item.publicationBytes ||
		identity != item.publicationIdentity {
		return ErrSpoolCorrupt
	}
	return nil
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
	if tierForEvent(event) != tier {
		_ = spool.state.PersistReadOnly("observer_spool_tier_mismatch")
		return SpoolItem{}, ErrSpoolCorrupt
	}
	canonical, err := contracts.CanonicalJSON(event)
	if err != nil {
		return SpoolItem{}, err
	}
	validated, contentHash, err := validateSpoolPayload(canonical, spool.keys)
	if err != nil || validated.SourceSequence != event.SourceSequence {
		return SpoolItem{}, ErrSpoolCorrupt
	}
	snapshot := spool.state.Snapshot()
	if snapshot.MutationReadOnly ||
		validated.HostID != snapshot.HostID ||
		validated.BootID != snapshot.BootID ||
		validated.KeyID != snapshot.KeyID ||
		validated.KeyEpoch != snapshot.KeyEpoch ||
		validated.SourceSequence > snapshot.LastSequence {
		_ = spool.state.PersistReadOnly("observer_spool_identity_history_invalid")
		return SpoolItem{}, ErrSpoolCorrupt
	}
	frame, _, err := durablefile.EncodeFrame(canonical, [32]byte{}, 65_536)
	if err != nil {
		return SpoolItem{}, err
	}
	if existing, ok := spool.items[event.SourceSequence]; ok {
		if existing.ContentSHA256 == contentHash &&
			bytes.Equal(existing.Canonical, canonical) {
			diskEvent, diskCanonical, diskHash, diskBytes, diskIdentity, diskErr :=
				readStandaloneFrame(existing.path, spool.keys)
			if diskErr != nil ||
				diskEvent.SourceSequence != existing.Sequence ||
				diskEvent.EventID != existing.EventID ||
				diskHash != existing.ContentSHA256 ||
				tierForEvent(diskEvent) != existing.Tier ||
				diskBytes != existing.frameBytes ||
				diskIdentity != existing.identity ||
				!bytes.Equal(diskCanonical, existing.Canonical) ||
				validatePublicationItem(existing) != nil {
				_ = spool.state.PersistReadOnly(
					"observer_spool_idempotent_disk_changed",
				)
				return SpoolItem{}, ErrSpoolCorrupt
			}
			return existing, nil
		}
		_ = spool.state.PersistReadOnly("observer_spool_sequence_conflict")
		return SpoolItem{}, ErrSpoolCorrupt
	}
	if validated.SourceSequence <= snapshot.PublicationHeadSequence {
		if validated.SourceSequence != snapshot.PublicationHeadSequence {
			_ = spool.state.PersistReadOnly(
				"observer_publication_sequence_rollback",
			)
			return SpoolItem{}, ErrSpoolCorrupt
		}
		path := filepath.Join(
			spool.directory(tier),
			fmt.Sprintf("%020d.agf", event.SourceSequence),
		)
		diskEvent, diskCanonical, diskHash, diskBytes, diskIdentity, diskErr :=
			readStandaloneFrame(path, spool.keys)
		record, raw, publicationIdentity, publicationErr := readPublication(
			publicationPublishedPath(
				spool.config.StateDir,
				event.SourceSequence,
			),
		)
		expected := SpoolItem{
			Sequence:      event.SourceSequence,
			EventID:       event.EventID,
			ContentSHA256: contentHash,
			Tier:          tier,
			publication: publicationFor(
				event,
				tier,
				contentHash,
				record.PreviousPublicationHash,
			),
		}
		_, nodeHash, hashErr := publicationNodeHash(record)
		if diskErr != nil ||
			publicationErr != nil ||
			hashErr != nil ||
			nodeHash != snapshot.PublicationHeadHash ||
			diskEvent.SourceSequence != event.SourceSequence ||
			diskHash != contentHash ||
			diskBytes != uint64(len(frame)) ||
			!bytes.Equal(diskCanonical, canonical) ||
			!publicationMatchesItem(record, expected) {
			_ = spool.state.PersistReadOnly(
				"observer_spool_existing_unbound",
			)
			return SpoolItem{}, ErrSpoolCorrupt
		}
		item := SpoolItem{
			Sequence:         event.SourceSequence,
			EventID:          event.EventID,
			ContentSHA256:    contentHash,
			Tier:             tier,
			Canonical:        canonical,
			frameBytes:       diskBytes,
			path:             path,
			identity:         diskIdentity,
			publication:      record,
			publicationRaw:   raw,
			publicationBytes: uint64(len(raw)),
			publicationPath: publicationPublishedPath(
				spool.config.StateDir,
				event.SourceSequence,
			),
			publicationIdentity: publicationIdentity,
			publicationHash:     nodeHash,
		}
		itemBytes := item.frameBytes + item.publicationBytes
		if spool.totalBytes > math.MaxUint64-itemBytes ||
			tier == RoutineTier &&
				spool.routineBytes > math.MaxUint64-itemBytes {
			_ = spool.state.PersistReadOnly(
				"observer_spool_size_overflow",
			)
			return SpoolItem{}, ErrSpoolCorrupt
		}
		if spool.totalBytes+itemBytes >
			spool.config.MaxBytes-ackJournalMaxFrameBytes {
			return SpoolItem{}, ErrPriorityQuota
		}
		if tier == RoutineTier &&
			spool.routineBytes+itemBytes >
				spool.config.MaxBytes-
					spool.config.PriorityReserveBytes {
			return SpoolItem{}, ErrRoutineQuota
		}
		spool.items[event.SourceSequence] = item
		spool.totalBytes += itemBytes
		if tier == RoutineTier {
			spool.routineBytes += itemBytes
		}
		return item, nil
	}
	publication := publicationFor(
		event,
		tier,
		contentHash,
		snapshot.PublicationHeadHash,
	)
	publicationRaw, publicationHash, err := publicationNodeHash(publication)
	if err != nil {
		return SpoolItem{}, err
	}
	frameBytes := uint64(len(frame))
	publicationBytes := uint64(len(publicationRaw))
	if ^uint64(0)-frameBytes < publicationBytes {
		_ = spool.state.PersistReadOnly("observer_spool_size_overflow")
		return SpoolItem{}, ErrSpoolCorrupt
	}
	itemBytes := frameBytes + publicationBytes
	if ^uint64(0)-spool.totalBytes < itemBytes {
		_ = spool.state.PersistReadOnly("observer_spool_size_overflow")
		return SpoolItem{}, ErrSpoolCorrupt
	}
	nextTotal := spool.totalBytes + itemBytes
	nextRoutine := spool.routineBytes
	if tier == RoutineTier {
		if ^uint64(0)-spool.routineBytes < itemBytes {
			_ = spool.state.PersistReadOnly("observer_spool_size_overflow")
			return SpoolItem{}, ErrSpoolCorrupt
		}
		nextRoutine += itemBytes
		if nextRoutine >
			spool.config.MaxBytes-spool.config.PriorityReserveBytes {
			return SpoolItem{}, ErrRoutineQuota
		}
	}
	if spool.config.MaxBytes <= ackJournalMaxFrameBytes ||
		nextTotal >
			spool.config.MaxBytes-ackJournalMaxFrameBytes {
		_ = spool.state.PersistReadOnly("observer_priority_spool_exhausted")
		return SpoolItem{}, ErrPriorityQuota
	}
	path := filepath.Join(
		spool.directory(tier),
		fmt.Sprintf("%020d.agf", event.SourceSequence),
	)
	preparedPath := publicationPreparedPath(
		spool.config.StateDir,
		event.SourceSequence,
	)
	publishedPath := publicationPublishedPath(
		spool.config.StateDir,
		event.SourceSequence,
	)
	if existingEvent, existingCanonical, existingHash, existingSize,
		existingIdentity, readErr := readStandaloneFrame(path, spool.keys); readErr == nil {
		record, raw, publicationIdentity, publicationErr :=
			readPublication(publishedPath)
		if errors.Is(publicationErr, os.ErrNotExist) {
			record, raw, publicationIdentity, publicationErr =
				readPublication(preparedPath)
			if publicationErr == nil {
				promoteErr := durablefile.PromoteNoReplace(
					preparedPath,
					publishedPath,
				)
				if errors.Is(promoteErr, durablefile.ErrCommitUncertain) {
					promoteErr = durablefile.SyncDirectory(
						publicationDirectory(spool.config.StateDir),
					)
				}
				if promoteErr == nil {
					record, raw, publicationIdentity, publicationErr =
						readPublication(publishedPath)
				} else {
					publicationErr = promoteErr
				}
			}
		}
		expected := SpoolItem{
			Sequence:      event.SourceSequence,
			EventID:       event.EventID,
			ContentSHA256: contentHash,
			Tier:          tier,
			publication:   publication,
		}
		if publicationErr != nil ||
			existingEvent.SourceSequence != event.SourceSequence ||
			tierForEvent(existingEvent) != tier ||
			existingHash != contentHash ||
			existingSize != frameBytes ||
			!bytes.Equal(existingCanonical, canonical) ||
			!publicationMatchesItem(record, expected) ||
			!bytes.Equal(raw, publicationRaw) {
			_ = spool.state.PersistReadOnly("observer_spool_existing_unbound")
			return SpoolItem{}, ErrSpoolCorrupt
		}
		item := SpoolItem{
			Sequence:            event.SourceSequence,
			EventID:             event.EventID,
			ContentSHA256:       contentHash,
			Tier:                tier,
			Canonical:           canonical,
			frameBytes:          existingSize,
			path:                path,
			identity:            existingIdentity,
			publication:         record,
			publicationRaw:      raw,
			publicationBytes:    uint64(len(raw)),
			publicationPath:     publishedPath,
			publicationIdentity: publicationIdentity,
			publicationHash:     publicationHash,
		}
		if err := spool.state.anchorPublication(
			publication.PreviousPublicationHash,
			item.Sequence,
			publicationHash,
		); err != nil {
			_ = spool.state.PersistReadOnly(
				"observer_publication_head_commit_failed",
			)
			return SpoolItem{}, err
		}
		spool.items[event.SourceSequence] = item
		spool.totalBytes = nextTotal
		spool.routineBytes = nextRoutine
		return item, nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		_ = spool.state.PersistReadOnly("observer_spool_existing_unsafe")
		return SpoolItem{}, ErrSpoolCorrupt
	}
	for _, ledgerPath := range []string{preparedPath, publishedPath} {
		if _, _, _, ledgerErr := readPublication(ledgerPath); ledgerErr == nil ||
			!errors.Is(ledgerErr, os.ErrNotExist) {
			_ = spool.state.PersistReadOnly("observer_spool_publication_without_frame")
			return SpoolItem{}, ErrSpoolCorrupt
		}
	}
	if err := durablefile.CreateOnly(preparedPath, publicationRaw); err != nil {
		_ = spool.state.PersistReadOnly("observer_spool_publication_prepare_failed")
		return SpoolItem{}, err
	}
	preparedRecord, preparedRaw, _, preparedErr := readPublication(preparedPath)
	expected := SpoolItem{
		Sequence:      event.SourceSequence,
		EventID:       event.EventID,
		ContentSHA256: contentHash,
		Tier:          tier,
		publication:   publication,
	}
	if preparedErr != nil ||
		!publicationMatchesItem(preparedRecord, expected) ||
		!bytes.Equal(preparedRaw, publicationRaw) {
		_ = spool.state.PersistReadOnly("observer_spool_publication_prepare_invalid")
		return SpoolItem{}, ErrSpoolCorrupt
	}
	if err := spool.publish(path, frame); err != nil {
		if errors.Is(err, durablefile.ErrCommitUncertain) {
			if syncErr := durablefile.SyncDirectory(spool.directory(tier)); syncErr == nil {
				err = nil
			}
		}
		if err != nil {
			_ = spool.state.PersistReadOnly("observer_spool_write_uncertain")
			return SpoolItem{}, err
		}
	}
	publishedEvent, publishedCanonical, publishedHash, publishedSize,
		publishedIdentity, readErr := readStandaloneFrame(path, spool.keys)
	if readErr != nil ||
		publishedEvent.SourceSequence != event.SourceSequence ||
		tierForEvent(publishedEvent) != tier ||
		publishedHash != contentHash ||
		publishedSize != frameBytes ||
		!bytes.Equal(publishedCanonical, canonical) {
		_ = spool.state.PersistReadOnly("observer_spool_write_uncertain")
		return SpoolItem{}, ErrSpoolCorrupt
	}
	promoteErr := durablefile.PromoteNoReplace(preparedPath, publishedPath)
	if errors.Is(promoteErr, durablefile.ErrCommitUncertain) {
		promoteErr = durablefile.SyncDirectory(
			publicationDirectory(spool.config.StateDir),
		)
	}
	if promoteErr != nil {
		_ = spool.state.PersistReadOnly("observer_spool_publication_promote_failed")
		return SpoolItem{}, promoteErr
	}
	publishedRecord, publishedRaw, publicationIdentity, publicationErr :=
		readPublication(publishedPath)
	if publicationErr != nil ||
		!publicationMatchesItem(publishedRecord, expected) ||
		!bytes.Equal(publishedRaw, publicationRaw) {
		_ = spool.state.PersistReadOnly("observer_spool_publication_promote_invalid")
		return SpoolItem{}, ErrSpoolCorrupt
	}
	item := SpoolItem{
		Sequence:            event.SourceSequence,
		EventID:             event.EventID,
		ContentSHA256:       contentHash,
		Tier:                tier,
		Canonical:           canonical,
		frameBytes:          frameBytes,
		path:                path,
		identity:            publishedIdentity,
		publication:         publishedRecord,
		publicationRaw:      publishedRaw,
		publicationBytes:    uint64(len(publishedRaw)),
		publicationPath:     publishedPath,
		publicationIdentity: publicationIdentity,
		publicationHash:     publicationHash,
	}
	if err := spool.state.anchorPublication(
		publication.PreviousPublicationHash,
		item.Sequence,
		publicationHash,
	); err != nil {
		_ = spool.state.PersistReadOnly(
			"observer_publication_head_commit_failed",
		)
		return SpoolItem{}, err
	}
	spool.items[event.SourceSequence] = item
	spool.totalBytes = nextTotal
	spool.routineBytes = nextRoutine
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
		event, canonical, contentHash, frameBytes, identity, err :=
			readStandaloneFrame(item.path, spool.keys)
		if err != nil ||
			event.SourceSequence != item.Sequence ||
			event.EventID != item.EventID ||
			contentHash != item.ContentSHA256 ||
			tierForEvent(event) != item.Tier ||
			frameBytes != item.frameBytes ||
			identity != item.identity {
			_ = spool.state.PersistReadOnly("observer_spool_fetch_corrupt")
			return nil, ErrSpoolCorrupt
		}
		if err := validatePublicationItem(item); err != nil {
			_ = spool.state.PersistReadOnly("observer_spool_publication_fetch_corrupt")
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
		publicationErr := validatePublicationItem(item)
		if errors.Is(publicationErr, os.ErrNotExist) {
			_, _, frameErr := durablefile.ReadRegularIdentity(
				item.path,
				65_536+76,
			)
			if !errors.Is(frameErr, os.ErrNotExist) ||
				item.Sequence >
					spool.state.Snapshot().PublicationBaseSequence {
				_ = spool.state.PersistReadOnly(
					"observer_spool_cleanup_publication_changed",
				)
				return ErrSpoolCorrupt
			}
			if err := spool.syncDirectory(
				filepath.Dir(item.path),
			); err != nil {
				return errors.Join(durablefile.ErrCommitUncertain, err)
			}
			if err := spool.syncDirectory(
				filepath.Dir(item.publicationPath),
			); err != nil {
				return errors.Join(durablefile.ErrCommitUncertain, err)
			}
			if err := spool.forgetItemLocked(itemSequence, item); err != nil {
				return err
			}
			continue
		}
		if publicationErr != nil {
			_ = spool.state.PersistReadOnly(
				"observer_spool_cleanup_publication_changed",
			)
			return ErrSpoolCorrupt
		}
		if spool.beforeRemove != nil {
			spool.beforeRemove(item)
		}
		event, canonical, contentHash, frameBytes, identity, readErr :=
			readStandaloneFrame(item.path, spool.keys)
		if errors.Is(readErr, os.ErrNotExist) {
			// A durable acknowledgement permits the event name to have been
			// removed by a prior cleanup attempt. The immutable publication
			// binding must still be present until this retry removes it.
			readErr = nil
		}
		if readErr != nil ||
			event.SourceSequence != 0 &&
				(event.SourceSequence != item.Sequence ||
					event.EventID != item.EventID ||
					contentHash != item.ContentSHA256 ||
					tierForEvent(event) != item.Tier ||
					frameBytes != item.frameBytes ||
					identity != item.identity ||
					!bytes.Equal(canonical, item.Canonical)) {
			_ = spool.state.PersistReadOnly("observer_spool_cleanup_identity_changed")
			return ErrSpoolCorrupt
		}
		if event.SourceSequence != 0 {
			err := removeIdentityDurably(
				item.path,
				item.identity,
				spool.remove,
				spool.syncDirectory,
			)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				if errors.Is(err, durablefile.ErrUnsafePath) {
					_ = spool.state.PersistReadOnly(
						"observer_spool_cleanup_identity_changed",
					)
				}
				return err
			}
		}
		if err := validatePublicationItem(item); err != nil {
			_ = spool.state.PersistReadOnly(
				"observer_spool_cleanup_publication_changed",
			)
			return ErrSpoolCorrupt
		}
		if err := removeIdentityDurably(
			item.publicationPath,
			item.publicationIdentity,
			spool.removePublication,
			spool.syncDirectory,
		); err != nil && !errors.Is(err, os.ErrNotExist) {
			if errors.Is(err, durablefile.ErrUnsafePath) {
				_ = spool.state.PersistReadOnly(
					"observer_spool_cleanup_publication_changed",
				)
			}
			return err
		}
		if err := spool.forgetItemLocked(itemSequence, item); err != nil {
			return err
		}
	}
	return nil
}

func (spool *Spool) forgetItemLocked(
	sequence uint64,
	item SpoolItem,
) error {
	itemBytes := item.frameBytes + item.publicationBytes
	if spool.totalBytes < itemBytes ||
		item.Tier == RoutineTier && spool.routineBytes < itemBytes {
		_ = spool.state.PersistReadOnly("observer_spool_counter_underflow")
		return ErrSpoolCorrupt
	}
	delete(spool.items, sequence)
	spool.totalBytes -= itemBytes
	if item.Tier == RoutineTier {
		spool.routineBytes -= itemBytes
	}
	return nil
}

func removeIdentityDurably(
	path string,
	identity durablefile.FileIdentity,
	remove func(string, durablefile.FileIdentity) error,
	syncFunctions ...func(string) error,
) error {
	syncDirectory := durablefile.SyncDirectory
	if len(syncFunctions) > 1 {
		return fmt.Errorf("invalid directory sync override")
	}
	if len(syncFunctions) == 1 {
		if syncFunctions[0] == nil {
			return fmt.Errorf("nil directory sync override")
		}
		syncDirectory = syncFunctions[0]
	}
	err := remove(path, identity)
	if !errors.Is(err, durablefile.ErrCommitUncertain) {
		return err
	}
	if syncErr := syncDirectory(filepath.Dir(path)); syncErr != nil {
		return errors.Join(err, syncErr)
	}
	retryErr := remove(path, identity)
	if errors.Is(retryErr, os.ErrNotExist) {
		return nil
	}
	return retryErr
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
		// The first anchor write may have failed after the synced journal
		// append while advancing only the live in-memory state. Re-persist the
		// exact durable anchor before an idempotent retry is allowed to delete
		// either the frame or its publication binding.
		if err := spool.state.applyAck(
			snapshot.AckSequence,
			snapshot.AckEventID,
			snapshot.AckContentSHA256,
			snapshot.AckRecordHash,
			snapshot.AckPayloadSHA256,
			snapshot.PublicationBaseSequence,
			snapshot.PublicationBaseHash,
		); err != nil {
			return err
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
	if ackCrossesUncoveredGap(
		snapshot.AckSequence,
		sequence,
		snapshot.LastCoveredGapEnd,
	) {
		return ErrAckInvalid
	}
	item := spool.items[sequence]
	if item.EventID != eventID || item.ContentSHA256 != contentSHA256 {
		_ = spool.state.PersistReadOnly("observer_ack_identity_conflict")
		return ErrSpoolCorrupt
	}
	diskEvent, diskCanonical, diskHash, diskBytes, diskIdentity, diskErr :=
		readStandaloneFrame(item.path, spool.keys)
	if diskErr != nil ||
		diskEvent.SourceSequence != item.Sequence ||
		diskEvent.EventID != item.EventID ||
		diskHash != item.ContentSHA256 ||
		tierForEvent(diskEvent) != item.Tier ||
		diskBytes != item.frameBytes ||
		diskIdentity != item.identity ||
		!bytes.Equal(diskCanonical, item.Canonical) {
		_ = spool.state.PersistReadOnly("observer_ack_disk_identity_changed")
		return ErrSpoolCorrupt
	}
	if err := validatePublicationItem(item); err != nil {
		_ = spool.state.PersistReadOnly("observer_ack_publication_changed")
		return ErrSpoolCorrupt
	}
	record := ackRecord{
		SchemaVersion: "agmind.spool-ack.v1",
		Sequence:      sequence,
		EventID:       eventID,
		ContentSHA256: contentSHA256,
		AckedAt:       spool.config.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := record.Validate(); err != nil {
		return err
	}
	canonical, err := contracts.CanonicalJSON(record)
	if err != nil {
		return err
	}
	frameBytes := uint64(len(canonical)) + 76
	if frameBytes > math.MaxUint64/2 ||
		spool.totalBytes > spool.config.MaxBytes ||
		2*frameBytes > spool.config.MaxBytes-spool.totalBytes {
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
		item.Sequence,
		item.publicationHash,
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
		item.Sequence,
		item.publicationHash,
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
