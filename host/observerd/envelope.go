package observerd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

const observerStateSchema = "agmind.observer-state.v1"
const zeroPublicationHash = "0000000000000000000000000000000000000000000000000000000000000000"

type BootBoundary struct {
	BootID        string `json:"boot_id"`
	FirstSequence uint64 `json:"first_sequence"`
}

type ObserverState struct {
	SchemaVersion           string         `json:"schema_version"`
	HostID                  string         `json:"host_id"`
	BootID                  string         `json:"boot_id"`
	KeyID                   string         `json:"key_id"`
	KeyEpoch                uint64         `json:"key_epoch"`
	LastSequence            uint64         `json:"last_sequence"`
	MutationReadOnly        bool           `json:"mutation_read_only"`
	ReadOnlyReason          string         `json:"read_only_reason"`
	ReconcileRequired       bool           `json:"reconcile_required"`
	RoutineDropped          uint64         `json:"routine_dropped"`
	DropEventPending        bool           `json:"drop_event_pending"`
	AckSequence             uint64         `json:"ack_sequence"`
	AckEventID              string         `json:"ack_event_id"`
	AckContentSHA256        string         `json:"ack_content_sha256"`
	AckRecordHash           string         `json:"ack_record_hash"`
	AckPayloadSHA256        string         `json:"ack_payload_sha256"`
	LastCoveredGapEnd       uint64         `json:"last_covered_gap_end"`
	BootHistory             []BootBoundary `json:"boot_history,omitempty"`
	AckRepairPending        bool           `json:"ack_repair_pending"`
	AckRepairReason         string         `json:"ack_repair_reason"`
	PublicationBaseSequence uint64         `json:"publication_base_sequence"`
	PublicationBaseHash     string         `json:"publication_base_hash"`
	PublicationHeadSequence uint64         `json:"publication_head_sequence"`
	PublicationHeadHash     string         `json:"publication_head_hash"`
}

var (
	uuid4Pattern = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
	)
	hex32Pattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex64Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	eventPattern = regexp.MustCompile(`^evt_[0-9a-f]{64}$`)
)

func (state ObserverState) Validate() error {
	if state.SchemaVersion != observerStateSchema ||
		!uuid4Pattern.MatchString(state.HostID) ||
		!uuid4Pattern.MatchString(state.BootID) ||
		!hex32Pattern.MatchString(state.KeyID) ||
		state.KeyEpoch == 0 {
		return fmt.Errorf("invalid observer state identity")
	}
	if state.MutationReadOnly && state.ReadOnlyReason == "" {
		return fmt.Errorf("read-only state requires a reason")
	}
	if !state.MutationReadOnly && state.ReadOnlyReason != "" {
		return fmt.Errorf("healthy state cannot retain read-only reason")
	}
	if state.AckSequence == 0 {
		if state.AckEventID != "" ||
			state.AckContentSHA256 != "" ||
			state.AckRecordHash != "" ||
			state.AckPayloadSHA256 != "" {
			return fmt.Errorf("empty ack anchor must have empty identity")
		}
	} else if !eventPattern.MatchString(state.AckEventID) ||
		!hex64Pattern.MatchString(state.AckContentSHA256) ||
		!hex64Pattern.MatchString(state.AckRecordHash) ||
		!hex64Pattern.MatchString(state.AckPayloadSHA256) {
		return fmt.Errorf("invalid ack anchor")
	}
	if state.LastCoveredGapEnd > state.LastSequence {
		return fmt.Errorf("covered gap exceeds reserved sequence")
	}
	if state.AckSequence > state.LastSequence {
		return fmt.Errorf("acknowledgement exceeds reserved sequence")
	}
	if state.AckRepairPending != (state.AckRepairReason != "") {
		return fmt.Errorf("ack repair state is inconsistent")
	}
	if !hex64Pattern.MatchString(state.PublicationBaseHash) ||
		!hex64Pattern.MatchString(state.PublicationHeadHash) ||
		state.PublicationBaseSequence > state.PublicationHeadSequence ||
		state.PublicationHeadSequence > state.LastSequence ||
		state.PublicationBaseSequence != state.AckSequence ||
		(state.PublicationBaseSequence == 0) !=
			(state.PublicationBaseHash == zeroPublicationHash) ||
		(state.PublicationHeadSequence == 0) !=
			(state.PublicationHeadHash == zeroPublicationHash) ||
		state.PublicationBaseSequence == state.PublicationHeadSequence &&
			state.PublicationBaseHash != state.PublicationHeadHash {
		return fmt.Errorf("invalid observer publication anchor")
	}
	if len(state.BootHistory) == 0 ||
		len(state.BootHistory) > 1_024 ||
		state.BootHistory[0].FirstSequence != 1 ||
		state.BootHistory[len(state.BootHistory)-1].BootID != state.BootID {
		return fmt.Errorf("invalid observer boot history")
	}
	{
		seen := make(map[string]struct{}, len(state.BootHistory))
		var priorFirst uint64
		for index, boundary := range state.BootHistory {
			if !uuid4Pattern.MatchString(boundary.BootID) ||
				index > 0 && boundary.FirstSequence <= priorFirst ||
				boundary.FirstSequence > state.LastSequence &&
					(state.LastSequence == math.MaxUint64 ||
						boundary.FirstSequence != state.LastSequence+1) {
				return fmt.Errorf("invalid observer boot history")
			}
			if _, exists := seen[boundary.BootID]; exists {
				return fmt.Errorf("duplicate observer boot history")
			}
			seen[boundary.BootID] = struct{}{}
			priorFirst = boundary.FirstSequence
		}
	}
	return nil
}

type StateIdentity struct {
	HostID   string
	BootID   string
	KeyID    string
	KeyEpoch uint64
}

type StateStore struct {
	mutex            sync.Mutex
	publicationMutex sync.Mutex
	path             string
	state            ObserverState
	persist          func(string, ObserverState) error
}

func cloneObserverState(state ObserverState) ObserverState {
	cloned := state
	cloned.BootHistory = append(
		[]BootBoundary(nil),
		state.BootHistory...,
	)
	return cloned
}

func persistState(path string, state ObserverState) error {
	if err := state.Validate(); err != nil {
		return err
	}
	raw, err := contracts.CanonicalJSON(state)
	if err != nil {
		return err
	}
	if len(raw) > 65_536 {
		return fmt.Errorf("observer state exceeds 64 KiB")
	}
	return durablefile.AtomicWrite(path, raw)
}

func OpenStateStore(path string, identity StateIdentity) (*StateStore, error) {
	if err := durablefile.EnsurePrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	initial := ObserverState{
		SchemaVersion:       observerStateSchema,
		HostID:              identity.HostID,
		BootID:              identity.BootID,
		KeyID:               identity.KeyID,
		KeyEpoch:            identity.KeyEpoch,
		ReconcileRequired:   true,
		PublicationBaseHash: zeroPublicationHash,
		PublicationHeadHash: zeroPublicationHash,
		BootHistory: []BootBoundary{{
			BootID:        identity.BootID,
			FirstSequence: 1,
		}},
	}
	raw, err := readSingleLinkRegular(path, 65_536)
	if errors.Is(err, os.ErrNotExist) {
		if err := persistState(path, initial); err != nil {
			return nil, err
		}
		return &StateStore{
			path:    path,
			state:   cloneObserverState(initial),
			persist: persistState,
		}, nil
	}
	if err != nil {
		return nil, err
	}
	state, err := contracts.DecodeStrict[ObserverState](bytes.NewReader(raw), 65_536)
	if err != nil {
		return nil, err
	}
	if state.HostID != identity.HostID ||
		state.KeyID != identity.KeyID ||
		state.KeyEpoch != identity.KeyEpoch {
		return nil, fmt.Errorf("observer state identity mismatch")
	}
	needsPersist := false
	if state.BootID != identity.BootID {
		for _, boundary := range state.BootHistory {
			if boundary.BootID == identity.BootID {
				state.MutationReadOnly = true
				state.ReadOnlyReason = "observer_boot_id_rollback"
				state.ReconcileRequired = true
				_ = persistState(path, state)
				return nil, fmt.Errorf("observer boot ID rollback")
			}
		}
		if state.LastSequence == math.MaxUint64 {
			state.MutationReadOnly = true
			state.ReadOnlyReason = "observer_sequence_exhausted"
			state.ReconcileRequired = true
			_ = persistState(path, state)
			return nil, fmt.Errorf("observer sequence exhausted")
		}
		lastIndex := len(state.BootHistory) - 1
		if state.BootHistory[lastIndex].FirstSequence ==
			state.LastSequence+1 {
			state.BootID = identity.BootID
			state.BootHistory[lastIndex].BootID = identity.BootID
		} else {
			if len(state.BootHistory) >= 1_024 {
				state.MutationReadOnly = true
				state.ReadOnlyReason = "observer_boot_history_exhausted"
				state.ReconcileRequired = true
				_ = persistState(path, state)
				return nil, fmt.Errorf("observer boot history exhausted")
			}
			state.BootID = identity.BootID
			state.BootHistory = append(state.BootHistory, BootBoundary{
				BootID:        identity.BootID,
				FirstSequence: state.LastSequence + 1,
			})
		}
		state.ReconcileRequired = true
		needsPersist = true
	}
	if needsPersist {
		if err := persistState(path, state); err != nil {
			return nil, err
		}
	}
	return &StateStore{
		path:    path,
		state:   cloneObserverState(state),
		persist: persistState,
	}, nil
}

func (store *StateStore) Snapshot() ObserverState {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	return cloneObserverState(store.state)
}

func (store *StateStore) replaceLocked(next ObserverState) error {
	next = cloneObserverState(next)
	if err := store.persistLocked(next); err != nil {
		if errors.Is(err, durablefile.ErrCommitUncertain) {
			// The rename may already have made next authoritative on disk.
			// Adopt the reserved state and fence further reservations so the
			// live process can never reuse a possibly committed sequence.
			next.MutationReadOnly = true
			if next.ReadOnlyReason == "" {
				next.ReadOnlyReason = "observer_state_commit_uncertain"
			}
			next.ReconcileRequired = true
			store.state = cloneObserverState(next)
			fenceErr := store.persistLocked(next)
			return errors.Join(err, fenceErr)
		}
		return err
	}
	store.state = cloneObserverState(next)
	return nil
}

func (store *StateStore) persistLocked(next ObserverState) error {
	persist := store.persist
	if persist == nil {
		persist = persistState
	}
	return persist(store.path, cloneObserverState(next))
}

func (store *StateStore) PersistReadOnly(reason string) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	next := cloneObserverState(store.state)
	next.MutationReadOnly = true
	next.ReadOnlyReason = reason
	next.ReconcileRequired = true
	// Fail closed in the live process before attempting persistence. A disk
	// failure is returned but can never leave readiness true in memory.
	store.state = cloneObserverState(next)
	return store.persistLocked(next)
}

func (store *StateStore) persistRotationIncomplete() error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.state.MutationReadOnly {
		if store.state.ReadOnlyReason == "observer_rotation_incomplete" {
			return nil
		}
		return fmt.Errorf(
			"refusing to replace unrelated mutation read-only reason: %s",
			store.state.ReadOnlyReason,
		)
	}
	next := cloneObserverState(store.state)
	next.MutationReadOnly = true
	next.ReadOnlyReason = "observer_rotation_incomplete"
	next.ReconcileRequired = true
	store.state = cloneObserverState(next)
	return store.persistLocked(next)
}

func (store *StateStore) reserve(identity StateIdentity) (uint64, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.state.MutationReadOnly {
		return 0, fmt.Errorf("observer state is mutation read-only")
	}
	if store.state.HostID != identity.HostID ||
		store.state.BootID != identity.BootID ||
		store.state.KeyID != identity.KeyID ||
		store.state.KeyEpoch != identity.KeyEpoch {
		return 0, fmt.Errorf("observer signing identity mismatch")
	}
	if store.state.LastSequence == math.MaxUint64 {
		next := cloneObserverState(store.state)
		next.MutationReadOnly = true
		next.ReadOnlyReason = "observer_sequence_exhausted"
		next.ReconcileRequired = true
		store.state = cloneObserverState(next)
		persistErr := store.persistLocked(next)
		return 0, errors.Join(fmt.Errorf("observer sequence exhausted"), persistErr)
	}
	next := cloneObserverState(store.state)
	next.BootID = identity.BootID
	next.LastSequence++
	if err := store.replaceLocked(next); err != nil {
		return 0, err
	}
	return next.LastSequence, nil
}

func (store *StateStore) applyAck(
	sequence uint64,
	eventID string,
	contentSHA256 string,
	recordHash string,
	payloadSHA256 string,
	publicationSequence uint64,
	publicationHash string,
) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	next := cloneObserverState(store.state)
	next.AckSequence = sequence
	next.AckEventID = eventID
	next.AckContentSHA256 = contentSHA256
	next.AckRecordHash = recordHash
	next.AckPayloadSHA256 = payloadSHA256
	if publicationSequence != sequence ||
		!hex64Pattern.MatchString(publicationHash) ||
		publicationSequence < next.PublicationBaseSequence ||
		publicationSequence > next.PublicationHeadSequence {
		return fmt.Errorf("invalid publication acknowledgement anchor")
	}
	next.PublicationBaseSequence = publicationSequence
	next.PublicationBaseHash = publicationHash
	// A synced journal record is authoritative even if the redundant
	// state-file anchor cannot be rewritten. Keep the live state forward so a
	// retry cannot append the same sequence twice.
	store.state = cloneObserverState(next)
	return store.persistLocked(next)
}

func (store *StateStore) anchorPublication(
	expectedPreviousHash string,
	sequence uint64,
	publicationHash string,
) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.state.MutationReadOnly ||
		store.state.PublicationHeadHash != expectedPreviousHash ||
		sequence <= store.state.PublicationHeadSequence ||
		sequence > store.state.LastSequence ||
		!hex64Pattern.MatchString(publicationHash) ||
		publicationHash == zeroPublicationHash {
		return fmt.Errorf("invalid publication head transition")
	}
	next := cloneObserverState(store.state)
	next.PublicationHeadSequence = sequence
	next.PublicationHeadHash = publicationHash
	return store.replaceLocked(next)
}

func (store *StateStore) recoverPublicationHead(
	expectedPreviousHash string,
	sequence uint64,
	publicationHash string,
) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.state.PublicationHeadHash != expectedPreviousHash ||
		sequence <= store.state.PublicationHeadSequence ||
		sequence != store.state.LastSequence ||
		!hex64Pattern.MatchString(publicationHash) ||
		publicationHash == zeroPublicationHash {
		return fmt.Errorf("invalid publication recovery transition")
	}
	next := cloneObserverState(store.state)
	next.PublicationHeadSequence = sequence
	next.PublicationHeadHash = publicationHash
	// Startup recovery may make the immutable publication anchor more exact,
	// but it must never clear or replace an existing mutation fence.
	return store.replaceLocked(next)
}

func (store *StateStore) switchKey(newKeyID string, newEpoch uint64) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if !hex32Pattern.MatchString(newKeyID) ||
		store.state.KeyEpoch == math.MaxUint64 ||
		newEpoch != store.state.KeyEpoch+1 {
		return fmt.Errorf("key epochs must be consecutive")
	}
	next := cloneObserverState(store.state)
	next.KeyID = newKeyID
	next.KeyEpoch = newEpoch
	next.ReconcileRequired = true
	return store.replaceLocked(next)
}

func (store *StateStore) incrementRoutineDrop() (bool, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.state.RoutineDropped == math.MaxUint64 {
		return false, fmt.Errorf("routine drop counter exhausted")
	}
	next := cloneObserverState(store.state)
	next.RoutineDropped++
	emit := !next.DropEventPending
	next.DropEventPending = true
	return emit, store.replaceLocked(next)
}

func (store *StateStore) markGapCovered(sequence uint64) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if sequence > store.state.LastSequence ||
		sequence < store.state.LastCoveredGapEnd {
		return fmt.Errorf("invalid covered gap sequence")
	}
	next := cloneObserverState(store.state)
	next.LastCoveredGapEnd = sequence
	return store.replaceLocked(next)
}

func (store *StateStore) markAckRepair(reason string) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	next := cloneObserverState(store.state)
	next.AckRepairPending = true
	next.AckRepairReason = reason
	next.ReconcileRequired = true
	return store.replaceLocked(next)
}

func (store *StateStore) clearRotationFence() error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if !store.state.MutationReadOnly {
		return nil
	}
	if store.state.ReadOnlyReason != "observer_rotation_incomplete" {
		return fmt.Errorf("observer remains mutation read-only")
	}
	next := cloneObserverState(store.state)
	next.MutationReadOnly = false
	next.ReadOnlyReason = ""
	next.ReconcileRequired = true
	return store.replaceLocked(next)
}

type keyEntry struct {
	epoch uint64
	key   ed25519.PublicKey
}

type epochBoundary struct {
	epoch      uint64
	keyID      string
	transition contracts.EventEnvelopeV1
	start      contracts.EventEnvelopeV1
}

type Keyring struct {
	mutex         sync.RWMutex
	keys          map[string]keyEntry
	hostID        string
	boundaries    map[uint64]epochBoundary
	metadataEpoch uint64
}

func NewKeyring() *Keyring {
	return &Keyring{
		keys:       make(map[string]keyEntry),
		boundaries: make(map[uint64]epochBoundary),
	}
}

func (keyring *Keyring) Add(epoch uint64, publicKey ed25519.PublicKey) error {
	if epoch == 0 || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid observer public key")
	}
	keyID, err := contracts.KeyID(publicKey)
	if err != nil {
		return err
	}
	keyring.mutex.Lock()
	defer keyring.mutex.Unlock()
	if existing, ok := keyring.keys[keyID]; ok &&
		(existing.epoch != epoch || !bytes.Equal(existing.key, publicKey)) {
		return fmt.Errorf("conflicting observer public key")
	}
	keyring.keys[keyID] = keyEntry{
		epoch: epoch,
		key:   append(ed25519.PublicKey(nil), publicKey...),
	}
	return nil
}

func (keyring *Keyring) Verify(event contracts.EventEnvelopeV1) error {
	keyring.mutex.RLock()
	entry, ok := keyring.keys[event.KeyID]
	keyring.mutex.RUnlock()
	if !ok || entry.epoch != event.KeyEpoch {
		return fmt.Errorf("untrusted observer key epoch")
	}
	return contracts.VerifyEventSignature(event, entry.key)
}

type SignerConfig struct {
	HostID        string
	BootID        string
	KeyEpoch      uint64
	SourceID      string
	SourceVersion string
	Now           func() time.Time
}

type EventMetadata struct {
	EventTime           time.Time
	ClockUncertaintyMS  uint64
	ContainerID         *string
	ContainerStartTime  *string
	ReleaseID           *string
	InventoryGeneration uint64
	InventoryRevision   *uint64
	RedactionFlags      []string
	CoverageFlags       []string
	SourcePayloadHash   string
}

type EnvelopeSigner struct {
	config     SignerConfig
	state      *StateStore
	spool      *Spool
	privateKey ed25519.PrivateKey
	keyID      string
}

func NewEnvelopeSigner(
	config SignerConfig,
	state *StateStore,
	spool *Spool,
	privateKey ed25519.PrivateKey,
) (*EnvelopeSigner, error) {
	if state == nil || spool == nil || config.Now == nil ||
		len(privateKey) != ed25519.PrivateKeySize {
		if state != nil {
			_ = state.PersistReadOnly("observer_private_key_unavailable")
		}
		return nil, fmt.Errorf("observer private key unavailable")
	}
	if !validPrivateKey(privateKey) {
		_ = state.PersistReadOnly("observer_private_key_invalid")
		return nil, fmt.Errorf("observer private key seed/public mismatch")
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, err := contracts.KeyID(publicKey)
	if err != nil {
		_ = state.PersistReadOnly("observer_private_key_invalid")
		return nil, err
	}
	snapshot := state.Snapshot()
	if keyID != snapshot.KeyID ||
		config.KeyEpoch != snapshot.KeyEpoch ||
		config.HostID != snapshot.HostID ||
		config.BootID != snapshot.BootID {
		return nil, fmt.Errorf("observer signer identity does not match state")
	}
	return &EnvelopeSigner{
		config:     config,
		state:      state,
		spool:      spool,
		privateKey: append(ed25519.PrivateKey(nil), privateKey...),
		keyID:      keyID,
	}, nil
}

func cloneNormalized(fields map[string]any) (map[string]any, []byte, error) {
	canonical, err := contracts.CanonicalJSON(fields)
	if err != nil {
		return nil, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	var copied map[string]any
	if err := decoder.Decode(&copied); err != nil {
		return nil, nil, err
	}
	reencoded, err := contracts.CanonicalJSON(copied)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(canonical, reencoded) {
		return nil, nil, fmt.Errorf("normalized fields are not canonical")
	}
	return copied, canonical, nil
}

func priorityEventType(eventType string) bool {
	switch eventType {
	case "coverage",
		"observer_start",
		"observer_key_transition",
		"observer_key_epoch_start",
		"retention_tombstone",
		"incident_action_mirror",
		"corruption":
		return true
	default:
		return false
	}
}

func (signer *EnvelopeSigner) Wrap(
	ctx context.Context,
	eventType string,
	normalizedFields map[string]any,
	metadata EventMetadata,
) (contracts.EventEnvelopeV1, error) {
	select {
	case <-ctx.Done():
		return contracts.EventEnvelopeV1{}, ctx.Err()
	default:
	}
	signer.state.publicationMutex.Lock()
	locked := true
	defer func() {
		if locked {
			signer.state.publicationMutex.Unlock()
		}
	}()
	select {
	case <-ctx.Done():
		return contracts.EventEnvelopeV1{}, ctx.Err()
	default:
	}
	sequence, err := signer.state.reserve(StateIdentity{
		HostID:   signer.config.HostID,
		BootID:   signer.config.BootID,
		KeyID:    signer.keyID,
		KeyEpoch: signer.config.KeyEpoch,
	})
	if err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	copied, normalizedCanonical, err := cloneNormalized(normalizedFields)
	if err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	copyString := func(value *string) *string {
		if value == nil {
			return nil
		}
		copiedValue := *value
		return &copiedValue
	}
	copyUint64 := func(value *uint64) *uint64 {
		if value == nil {
			return nil
		}
		copiedValue := *value
		return &copiedValue
	}
	normalizedDigest := sha256.Sum256(normalizedCanonical)
	event := contracts.EventEnvelopeV1{
		SchemaVersion:          "agmind.event-envelope.v1",
		EventType:              eventType,
		SourceID:               signer.config.SourceID,
		SourceVersion:          signer.config.SourceVersion,
		KeyID:                  signer.keyID,
		KeyEpoch:               signer.config.KeyEpoch,
		HostID:                 signer.config.HostID,
		BootID:                 signer.config.BootID,
		SourceSequence:         sequence,
		EventTime:              metadata.EventTime.UTC().Format(time.RFC3339Nano),
		IngestTime:             signer.config.Now().UTC().Format(time.RFC3339Nano),
		ClockUncertaintyMS:     metadata.ClockUncertaintyMS,
		ContainerID:            copyString(metadata.ContainerID),
		ContainerStartTime:     copyString(metadata.ContainerStartTime),
		ReleaseID:              copyString(metadata.ReleaseID),
		InventoryGeneration:    metadata.InventoryGeneration,
		InventoryRevision:      copyUint64(metadata.InventoryRevision),
		NormalizedFields:       copied,
		NormalizedFieldsSHA256: hex.EncodeToString(normalizedDigest[:]),
		RedactionFlags:         append([]string{}, metadata.RedactionFlags...),
		CoverageFlags:          append([]string{}, metadata.CoverageFlags...),
		SourcePayloadHash:      metadata.SourcePayloadHash,
	}
	event.EventID, err = contracts.DeriveEventID(event)
	if err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	message, err := contracts.EventSigningMessage(event)
	if err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	event.SourceSignature = hex.EncodeToString(ed25519.Sign(signer.privateKey, message))
	if err := event.Validate(); err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	tier := RoutineTier
	if priorityEventType(eventType) {
		tier = PriorityTier
	}
	if _, err := signer.spool.Append(event, tier); err != nil {
		if errors.Is(err, ErrRoutineQuota) {
			locked = false
			signer.state.publicationMutex.Unlock()
			return contracts.EventEnvelopeV1{}, routineQuotaError(
				err,
				signer.recordRoutineDrop(),
			)
		}
		return contracts.EventEnvelopeV1{}, err
	}
	return event, nil
}

var (
	ErrRootRequired         = errors.New("root privileges required")
	ErrStateLocked          = errors.New("observer state is locked")
	ErrInjectedRotationStop = errors.New("injected rotation stop")
)

type StateLock struct {
	journal *durablefile.Journal
}

func AcquireStateLock(stateDir string) (*StateLock, error) {
	if err := durablefile.EnsurePrivateDirectory(stateDir); err != nil {
		return nil, err
	}
	journal, err := durablefile.NewJournal(
		filepath.Join(stateDir, ".observer.lock"),
		durablefile.WithMaxFrame(1),
	)
	if errors.Is(err, durablefile.ErrJournalLocked) {
		return nil, ErrStateLocked
	}
	if err != nil {
		return nil, err
	}
	return &StateLock{journal: journal}, nil
}

func (lock *StateLock) Close() error {
	if lock == nil || lock.journal == nil {
		return nil
	}
	err := lock.journal.Close()
	lock.journal = nil
	return err
}

type PublicKeyEpoch struct {
	KeyID              string                     `json:"key_id"`
	Epoch              uint64                     `json:"epoch"`
	PublicKey          string                     `json:"public_key"`
	Transition         *contracts.KeyTransitionV1 `json:"transition,omitempty"`
	TransitionEnvelope *contracts.EventEnvelopeV1 `json:"transition_envelope,omitempty"`
	EpochStartEnvelope *contracts.EventEnvelopeV1 `json:"epoch_start_envelope,omitempty"`
}

type PublicKeyMetadata struct {
	SchemaVersion string           `json:"schema_version"`
	HostID        string           `json:"host_id"`
	CurrentKeyID  string           `json:"current_key_id"`
	CurrentEpoch  uint64           `json:"current_epoch"`
	Keys          []PublicKeyEpoch `json:"keys"`
}

func (metadata PublicKeyMetadata) Validate() error {
	if metadata.SchemaVersion != "agmind.observer-public-keys.v1" ||
		!uuid4Pattern.MatchString(metadata.HostID) ||
		!hex32Pattern.MatchString(metadata.CurrentKeyID) ||
		metadata.CurrentEpoch == 0 ||
		metadata.Keys == nil ||
		len(metadata.Keys) == 0 ||
		len(metadata.Keys) > 16 {
		return fmt.Errorf("invalid observer public-key metadata")
	}
	var prior uint64
	currentFound := false
	var priorPublic ed25519.PublicKey
	var priorEntry PublicKeyEpoch
	var priorStartSequence uint64
	for index, entry := range metadata.Keys {
		if entry.Epoch != prior+1 ||
			!hex32Pattern.MatchString(entry.KeyID) ||
			!hex64Pattern.MatchString(entry.PublicKey) {
			return fmt.Errorf("invalid observer public-key epoch")
		}
		publicKey, err := hex.DecodeString(entry.PublicKey)
		if err != nil {
			return err
		}
		derived, err := contracts.KeyID(publicKey)
		if err != nil || derived != entry.KeyID {
			return fmt.Errorf("observer key ID mismatch")
		}
		if index == 0 {
			if entry.Transition != nil ||
				entry.TransitionEnvelope != nil ||
				entry.EpochStartEnvelope != nil {
				return fmt.Errorf("initial observer key cannot have transition proof")
			}
		} else {
			if entry.Transition == nil ||
				entry.TransitionEnvelope == nil ||
				entry.EpochStartEnvelope == nil {
				return fmt.Errorf("observer key epoch lacks transition proof")
			}
			transition := *entry.Transition
			if transition.HostID != metadata.HostID ||
				transition.OldKeyID != priorEntry.KeyID ||
				transition.NewKeyID != entry.KeyID ||
				transition.OldEpoch != priorEntry.Epoch ||
				transition.NewEpoch != entry.Epoch ||
				transition.NewPublicKey != entry.PublicKey {
				return fmt.Errorf("observer key transition identity mismatch")
			}
			if err := contracts.VerifyKeyTransition(
				transition,
				priorPublic,
			); err != nil {
				return fmt.Errorf("invalid observer key transition: %w", err)
			}
			transitionFields, err := transitionMap(transition)
			if err != nil || !eventHasExactFields(
				*entry.TransitionEnvelope,
				transitionFields,
			) {
				return fmt.Errorf("observer transition envelope fields mismatch")
			}
			transitionEnvelope := *entry.TransitionEnvelope
			if transitionEnvelope.HostID != metadata.HostID ||
				transitionEnvelope.EventType != "observer_key_transition" ||
				transitionEnvelope.KeyID != priorEntry.KeyID ||
				transitionEnvelope.KeyEpoch != priorEntry.Epoch ||
				transitionEnvelope.SourceID != "agmind-observerd" ||
				transitionEnvelope.SourceSequence == 0 ||
				transitionEnvelope.SourcePayloadHash !=
					transitionEnvelope.NormalizedFieldsSHA256 {
				return fmt.Errorf("observer transition envelope identity mismatch")
			}
			if err := contracts.VerifyEventSignature(
				transitionEnvelope,
				priorPublic,
			); err != nil {
				return fmt.Errorf("invalid observer transition envelope: %w", err)
			}
			startFields := map[string]any{
				"kind":      "observer_key_epoch_start",
				"key_id":    entry.KeyID,
				"key_epoch": entry.Epoch,
			}
			startEnvelope := *entry.EpochStartEnvelope
			if !eventHasExactFields(startEnvelope, startFields) ||
				startEnvelope.HostID != metadata.HostID ||
				startEnvelope.EventType != "observer_key_epoch_start" ||
				startEnvelope.KeyID != entry.KeyID ||
				startEnvelope.KeyEpoch != entry.Epoch ||
				startEnvelope.SourceID != "agmind-observerd" ||
				startEnvelope.SourcePayloadHash !=
					startEnvelope.NormalizedFieldsSHA256 ||
				transitionEnvelope.SourceSequence == math.MaxUint64 ||
				startEnvelope.SourceSequence !=
					transitionEnvelope.SourceSequence+1 {
				return fmt.Errorf("observer epoch-start envelope identity mismatch")
			}
			if err := contracts.VerifyEventSignature(
				startEnvelope,
				ed25519.PublicKey(publicKey),
			); err != nil {
				return fmt.Errorf("invalid observer epoch-start envelope: %w", err)
			}
			if priorStartSequence != 0 &&
				transitionEnvelope.SourceSequence <= priorStartSequence {
				return fmt.Errorf("observer key transition sequence rollback")
			}
			priorStartSequence = startEnvelope.SourceSequence
		}
		if entry.Epoch == metadata.CurrentEpoch &&
			entry.KeyID == metadata.CurrentKeyID {
			currentFound = true
		}
		prior = entry.Epoch
		priorPublic = append(ed25519.PublicKey(nil), publicKey...)
		priorEntry = entry
	}
	if !currentFound {
		return fmt.Errorf("current observer key missing")
	}
	last := metadata.Keys[len(metadata.Keys)-1]
	if metadata.CurrentEpoch != prior ||
		metadata.CurrentEpoch != last.Epoch ||
		metadata.CurrentKeyID != last.KeyID {
		return fmt.Errorf("current observer key is not the final epoch")
	}
	canonical, err := contracts.CanonicalJSON(metadata)
	if err != nil || len(canonical) > 65_536 {
		return fmt.Errorf("observer public-key metadata exceeds 64 KiB")
	}
	return nil
}

func eventHasExactFields(
	event contracts.EventEnvelopeV1,
	expected map[string]any,
) bool {
	actualCanonical, actualErr := contracts.CanonicalJSON(
		event.NormalizedFields,
	)
	expectedCanonical, expectedErr := contracts.CanonicalJSON(expected)
	return actualErr == nil &&
		expectedErr == nil &&
		bytes.Equal(actualCanonical, expectedCanonical)
}

func (metadata PublicKeyMetadata) Keyring() (*Keyring, error) {
	if err := metadata.Validate(); err != nil {
		return nil, err
	}
	keyring := NewKeyring()
	for _, entry := range metadata.Keys {
		publicKey, _ := hex.DecodeString(entry.PublicKey)
		if err := keyring.Add(entry.Epoch, ed25519.PublicKey(publicKey)); err != nil {
			return nil, err
		}
		if entry.Epoch > 1 {
			keyring.boundaries[entry.Epoch] = epochBoundary{
				epoch:      entry.Epoch,
				keyID:      entry.KeyID,
				transition: *entry.TransitionEnvelope,
				start:      *entry.EpochStartEnvelope,
			}
		}
	}
	keyring.hostID = metadata.HostID
	keyring.metadataEpoch = metadata.CurrentEpoch
	return keyring, nil
}

func publicMetadataPath(stateDir string) string {
	return filepath.Join(stateDir, "observer-public-keys.json")
}

func LoadPublicKeyMetadata(stateDir string) (PublicKeyMetadata, error) {
	raw, err := readSingleLinkRegular(publicMetadataPath(stateDir), 65_536)
	if err != nil {
		return PublicKeyMetadata{}, err
	}
	return contracts.DecodeStrict[PublicKeyMetadata](bytes.NewReader(raw), 65_536)
}

func savePublicKeyMetadata(stateDir string, metadata PublicKeyMetadata) error {
	if err := metadata.Validate(); err != nil {
		return err
	}
	raw, err := contracts.CanonicalJSON(metadata)
	if err != nil {
		return err
	}
	if len(raw) > 65_536 {
		return fmt.Errorf("observer public-key metadata exceeds 64 KiB")
	}
	return durablefile.AtomicWrite(publicMetadataPath(stateDir), raw)
}

type rotationMarker struct {
	SchemaVersion      string                    `json:"schema_version"`
	HostID             string                    `json:"host_id"`
	Stage              string                    `json:"stage"`
	NewPrivateSHA256   string                    `json:"new_private_sha256"`
	TransitionSequence uint64                    `json:"transition_sequence"`
	StartSequence      uint64                    `json:"start_sequence"`
	Transition         contracts.KeyTransitionV1 `json:"transition"`
}

func (marker rotationMarker) Validate() error {
	if marker.SchemaVersion != "agmind.observer-key-rotation.v1" ||
		!uuid4Pattern.MatchString(marker.HostID) ||
		!hex64Pattern.MatchString(marker.NewPrivateSHA256) ||
		marker.TransitionSequence == 0 ||
		marker.TransitionSequence == math.MaxUint64 ||
		marker.StartSequence != marker.TransitionSequence+1 {
		return fmt.Errorf("invalid rotation marker")
	}
	switch marker.Stage {
	case "prepared", "transition_spooled", "key_switched", "start_spooled":
	default:
		return fmt.Errorf("invalid rotation stage")
	}
	if marker.Transition.HostID != marker.HostID {
		return fmt.Errorf("rotation host mismatch")
	}
	return marker.Transition.Validate()
}

type rotationOptions struct {
	euid                  func() int
	bootID                func() (string, error)
	now                   func() time.Time
	generate              func() (ed25519.PublicKey, ed25519.PrivateKey, error)
	saveMetadata          func(string, PublicKeyMetadata) error
	syncMetadataDirectory func(string) error
	stopAfter             string
}

type RotationOption func(*rotationOptions)

func WithRotationEUID(value func() int) RotationOption {
	return func(options *rotationOptions) { options.euid = value }
}

func WithRotationBootID(value func() (string, error)) RotationOption {
	return func(options *rotationOptions) { options.bootID = value }
}

func WithRotationNow(value func() time.Time) RotationOption {
	return func(options *rotationOptions) { options.now = value }
}

func WithRotationKeyGenerator(
	value func() (ed25519.PublicKey, ed25519.PrivateKey, error),
) RotationOption {
	return func(options *rotationOptions) { options.generate = value }
}

func WithRotationStopAfter(stage string) RotationOption {
	return func(options *rotationOptions) { options.stopAfter = stage }
}

func readKernelBootID() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	value := strings.TrimSuffix(string(raw), "\n")
	if !uuid4Pattern.MatchString(value) {
		return "", fmt.Errorf("invalid kernel boot ID")
	}
	return value, nil
}

func readHostID(path string) (string, error) {
	raw, err := readSingleLinkRegular(path, 128)
	if err != nil {
		return "", err
	}
	value := strings.TrimSuffix(string(raw), "\n")
	if !uuid4Pattern.MatchString(value) {
		return "", fmt.Errorf("invalid host ID")
	}
	return value, nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := readSingleLinkRegular(path, ed25519.PrivateKeySize)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key must be raw 64-byte Ed25519")
	}
	if !validPrivateKey(ed25519.PrivateKey(raw)) {
		return nil, fmt.Errorf("private key seed/public mismatch")
	}
	return append(ed25519.PrivateKey(nil), raw...), nil
}

func validPrivateKey(privateKey ed25519.PrivateKey) bool {
	if len(privateKey) != ed25519.PrivateKeySize {
		return false
	}
	derived := ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])
	return subtle.ConstantTimeCompare(privateKey, derived) == 1
}

func markerPath(stateDir string) string {
	return filepath.Join(stateDir, "key-rotation.json")
}

func rotationKeyPath(stateDir string) string {
	return filepath.Join(stateDir, "key-rotation-new.key")
}

func saveRotationMarker(stateDir string, marker rotationMarker) error {
	if err := marker.Validate(); err != nil {
		return err
	}
	raw, err := contracts.CanonicalJSON(marker)
	if err != nil {
		return err
	}
	return durablefile.AtomicWrite(markerPath(stateDir), raw)
}

func loadRotationMarker(stateDir string) (rotationMarker, error) {
	raw, err := readSingleLinkRegular(markerPath(stateDir), 65_536)
	if err != nil {
		return rotationMarker{}, err
	}
	return contracts.DecodeStrict[rotationMarker](bytes.NewReader(raw), 65_536)
}

func removeExactRotationArtifact(
	path string,
	expected []byte,
	maxBytes int64,
) error {
	raw, identity, err := durablefile.ReadRegularIdentity(path, maxBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !bytes.Equal(raw, expected) {
		return fmt.Errorf("rotation artifact identity mismatch")
	}
	return removeIdentityDurably(
		path,
		identity,
		durablefile.RemoveIfIdentity,
	)
}

func loadObserverState(path string) (ObserverState, error) {
	raw, err := readSingleLinkRegular(path, 65_536)
	if err != nil {
		return ObserverState{}, err
	}
	return contracts.DecodeStrict[ObserverState](bytes.NewReader(raw), 65_536)
}

func markExistingStateReadOnly(path, reason string) {
	state, err := loadObserverState(path)
	if err != nil {
		return
	}
	store := &StateStore{
		path:    path,
		state:   cloneObserverState(state),
		persist: persistState,
	}
	_ = store.PersistReadOnly(reason)
}

func rotationMetadata(
	now time.Time,
	fields map[string]any,
) (EventMetadata, error) {
	canonical, err := contracts.CanonicalJSON(fields)
	if err != nil {
		return EventMetadata{}, err
	}
	sum := sha256.Sum256(canonical)
	return EventMetadata{
		EventTime:         now.UTC(),
		RedactionFlags:    []string{},
		CoverageFlags:     []string{"key_rotation"},
		SourcePayloadHash: hex.EncodeToString(sum[:]),
	}, nil
}

func (spool *Spool) findRotationEvent(
	eventType string,
	keyID string,
	sequence uint64,
	expectedFields map[string]any,
) (contracts.EventEnvelopeV1, bool, error) {
	expectedCanonical, err := contracts.CanonicalJSON(expectedFields)
	if err != nil {
		return contracts.EventEnvelopeV1{}, false, err
	}
	expectedHash := sha256.Sum256(expectedCanonical)
	expectedHashHex := hex.EncodeToString(expectedHash[:])
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	item, exists := spool.items[sequence]
	if !exists {
		return contracts.EventEnvelopeV1{}, false, nil
	}
	{
		event, _, _, _, _, readErr := readStandaloneFrame(item.path, spool.keys)
		if readErr != nil ||
			event.EventType != eventType ||
			event.KeyID != keyID ||
			event.SourceSequence != sequence ||
			event.NormalizedFieldsSHA256 != expectedHashHex ||
			event.SourcePayloadHash != expectedHashHex {
			return contracts.EventEnvelopeV1{}, false, ErrSpoolCorrupt
		}
		actualCanonical, canonicalErr := contracts.CanonicalJSON(
			event.NormalizedFields,
		)
		if canonicalErr == nil && bytes.Equal(actualCanonical, expectedCanonical) {
			return event, true, nil
		}
	}
	return contracts.EventEnvelopeV1{}, false, ErrSpoolCorrupt
}

func (spool *Spool) containsRotationEvent(
	eventType string,
	keyID string,
	expectedFields map[string]any,
) bool {
	spool.mutex.Lock()
	sequences := make([]uint64, 0, len(spool.items))
	for sequence := range spool.items {
		sequences = append(sequences, sequence)
	}
	spool.mutex.Unlock()
	for _, sequence := range sequences {
		_, found, err := spool.findRotationEvent(
			eventType,
			keyID,
			sequence,
			expectedFields,
		)
		if err == nil && found {
			return true
		}
	}
	return false
}

func transitionMap(transition contracts.KeyTransitionV1) (map[string]any, error) {
	raw, err := contracts.CanonicalJSON(transition)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var result map[string]any
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func canonicalEqual(left, right any) bool {
	leftRaw, leftErr := contracts.CanonicalJSON(left)
	rightRaw, rightErr := contracts.CanonicalJSON(right)
	return leftErr == nil &&
		rightErr == nil &&
		bytes.Equal(leftRaw, rightRaw)
}

func reconcileUncertainPublicMetadataCommit(
	stateDir string,
	expected PublicKeyMetadata,
	syncDirectory func(string) error,
) error {
	expectedRaw, err := contracts.CanonicalJSON(expected)
	if err != nil {
		return err
	}
	actualRaw, err := readSingleLinkRegular(
		publicMetadataPath(stateDir),
		65_536,
	)
	if err != nil {
		return err
	}
	if !bytes.Equal(actualRaw, expectedRaw) {
		return fmt.Errorf("uncertain observer public-key metadata mismatch")
	}
	if syncDirectory == nil {
		return fmt.Errorf("observer public-key metadata resync unavailable")
	}
	return syncDirectory(stateDir)
}

func defaultRotationOptions() rotationOptions {
	return rotationOptions{
		euid:                  os.Geteuid,
		bootID:                readKernelBootID,
		now:                   time.Now,
		saveMetadata:          savePublicKeyMetadata,
		syncMetadataDirectory: durablefile.SyncDirectory,
		generate: func() (ed25519.PublicKey, ed25519.PrivateKey, error) {
			return ed25519.GenerateKey(rand.Reader)
		},
	}
}

// RotateKeys performs root-only offline, resumable observer key rotation.
func RotateKeys(configPath string, supplied ...RotationOption) error {
	if err := requireLinuxPlatform(runtime.GOOS); err != nil {
		return err
	}
	options := defaultRotationOptions()
	for _, option := range supplied {
		option(&options)
	}
	if options.euid == nil || options.euid() != 0 {
		return ErrRootRequired
	}
	config, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	lock, err := AcquireStateLock(config.StateDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	hostID, err := readHostID(config.HostIDFile)
	if err != nil {
		return err
	}
	bootID, err := options.bootID()
	if err != nil {
		return err
	}
	statePath := filepath.Join(config.StateDir, "observer-state.json")
	preflightState, preflightErr := loadObserverState(statePath)
	stateExists := preflightErr == nil
	if preflightErr != nil && !errors.Is(preflightErr, os.ErrNotExist) {
		return preflightErr
	}
	artifactsPresent := rotationArtifactsPresent(config.StateDir)
	if stateExists &&
		preflightState.MutationReadOnly &&
		(preflightState.ReadOnlyReason != "observer_rotation_incomplete" ||
			!artifactsPresent) {
		return fmt.Errorf(
			"observer key rotation blocked by mutation read-only state: %s",
			preflightState.ReadOnlyReason,
		)
	}
	activeKey, keyErr := readPrivateKey(config.PrivateKeyFile)
	if keyErr != nil {
		markExistingStateReadOnly(statePath, "observer_private_key_unavailable")
		return keyErr
	}
	activeKeyID, err := contracts.KeyID(activeKey.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}

	var marker rotationMarker
	marker, err = loadRotationMarker(config.StateDir)
	if errors.Is(err, os.ErrNotExist) {
		identity := StateIdentity{
			HostID:   hostID,
			BootID:   bootID,
			KeyID:    activeKeyID,
			KeyEpoch: 1,
		}
		existingState, loadErr := preflightState, preflightErr
		if stateExists {
			if existingState.HostID != hostID ||
				existingState.KeyID != activeKeyID {
				markExistingStateReadOnly(
					statePath,
					"observer_rotation_active_identity_mismatch",
				)
				return fmt.Errorf("observer rotation active identity mismatch")
			}
			identity.KeyEpoch = existingState.KeyEpoch
		} else if !errors.Is(loadErr, os.ErrNotExist) {
			return loadErr
		}
		state, stateErr := OpenStateStore(
			statePath,
			identity,
		)
		if stateErr != nil {
			return stateErr
		}
		snapshot := state.Snapshot()
		if snapshot.KeyEpoch == math.MaxUint64 ||
			snapshot.LastSequence >= math.MaxUint64-1 {
			_ = state.PersistReadOnly("observer_key_epoch_exhausted")
			return fmt.Errorf("observer key rotation sequence exhausted")
		}
		preflightMetadata, metadataErr := LoadPublicKeyMetadata(config.StateDir)
		if errors.Is(metadataErr, os.ErrNotExist) {
			if snapshot.KeyEpoch != 1 || snapshot.LastSequence != 0 {
				_ = state.PersistReadOnly(
					"observer_public_key_metadata_missing",
				)
				return fmt.Errorf("observer public key metadata missing")
			}
			preflightMetadata = initialPublicMetadata(
				hostID,
				activeKeyID,
				snapshot.KeyEpoch,
				activeKey.Public().(ed25519.PublicKey),
			)
			if err := options.saveMetadata(
				config.StateDir,
				preflightMetadata,
			); err != nil {
				return err
			}
		} else if metadataErr != nil {
			_ = state.PersistReadOnly(
				"observer_public_key_metadata_invalid",
			)
			return metadataErr
		}
		if preflightMetadata.HostID != hostID ||
			preflightMetadata.CurrentKeyID != snapshot.KeyID ||
			preflightMetadata.CurrentEpoch != snapshot.KeyEpoch {
			_ = state.PersistReadOnly(
				"observer_public_key_metadata_mismatch",
			)
			return fmt.Errorf("observer public key metadata mismatch")
		}
		if len(preflightMetadata.Keys) >= 16 {
			_ = state.PersistReadOnly(
				"observer_key_history_exhausted",
			)
			return fmt.Errorf("observer key history exhausted")
		}
		var publicKey ed25519.PublicKey
		var newPrivate ed25519.PrivateKey
		newPrivate, orphanErr := readPrivateKey(
			rotationKeyPath(config.StateDir),
		)
		if errors.Is(orphanErr, os.ErrNotExist) {
			var generateErr error
			publicKey, newPrivate, generateErr = options.generate()
			if generateErr != nil {
				return generateErr
			}
			if len(newPrivate) != ed25519.PrivateKeySize ||
				!bytes.Equal(
					publicKey,
					newPrivate.Public().(ed25519.PublicKey),
				) {
				return fmt.Errorf("invalid generated observer key")
			}
			if err := durablefile.CreateOnly(
				rotationKeyPath(config.StateDir),
				newPrivate,
			); err != nil {
				return err
			}
			if options.stopAfter == "new_key_written" {
				return ErrInjectedRotationStop
			}
		} else if orphanErr != nil {
			_ = state.PersistReadOnly("observer_rotation_orphan_key_invalid")
			return orphanErr
		} else {
			publicKey = newPrivate.Public().(ed25519.PublicKey)
		}
		newKeyID, keyIDErr := contracts.KeyID(publicKey)
		if keyIDErr != nil {
			return fmt.Errorf("invalid generated observer key")
		}
		transition := contracts.KeyTransitionV1{
			SchemaVersion: "agmind.key-transition.v1",
			OldKeyID:      snapshot.KeyID,
			NewKeyID:      newKeyID,
			OldEpoch:      snapshot.KeyEpoch,
			NewEpoch:      snapshot.KeyEpoch + 1,
			NewPublicKey:  hex.EncodeToString(publicKey),
			HostID:        hostID,
			OccurredAt:    options.now().UTC().Format(time.RFC3339Nano),
			OldSignature:  strings.Repeat("0", ed25519.SignatureSize*2),
			NewSignature:  strings.Repeat("0", ed25519.SignatureSize*2),
		}
		message, messageErr := contracts.KeyTransitionSigningMessage(transition)
		if messageErr != nil {
			return messageErr
		}
		transition.OldSignature = hex.EncodeToString(ed25519.Sign(activeKey, message))
		transition.NewSignature = hex.EncodeToString(ed25519.Sign(newPrivate, message))
		sum := sha256.Sum256(newPrivate)
		marker = rotationMarker{
			SchemaVersion:      "agmind.observer-key-rotation.v1",
			HostID:             hostID,
			Stage:              "prepared",
			NewPrivateSHA256:   hex.EncodeToString(sum[:]),
			TransitionSequence: snapshot.LastSequence + 1,
			StartSequence:      snapshot.LastSequence + 2,
			Transition:         transition,
		}
		if err := saveRotationMarker(config.StateDir, marker); err != nil {
			return err
		}
		if options.stopAfter == "prepared" {
			return ErrInjectedRotationStop
		}
	} else if err != nil {
		markExistingStateReadOnly(statePath, "observer_rotation_marker_invalid")
		return err
	}
	if marker.HostID != hostID {
		markExistingStateReadOnly(statePath, "observer_rotation_host_mismatch")
		return fmt.Errorf("rotation host mismatch")
	}
	newPrivate, err := readPrivateKey(rotationKeyPath(config.StateDir))
	if errors.Is(err, os.ErrNotExist) &&
		marker.Stage == "start_spooled" &&
		activeKeyID == marker.Transition.NewKeyID {
		// Cleanup durably removes the temporary key before removing the marker.
		// At that boundary the active key is the same verified key material.
		newPrivate = append(ed25519.PrivateKey(nil), activeKey...)
		err = nil
	}
	if err != nil {
		markExistingStateReadOnly(statePath, "observer_rotation_key_missing")
		return err
	}
	newPrivateHash := sha256.Sum256(newPrivate)
	if hex.EncodeToString(newPrivateHash[:]) != marker.NewPrivateSHA256 {
		markExistingStateReadOnly(statePath, "observer_rotation_key_mismatch")
		return fmt.Errorf("rotation key mismatch")
	}
	oldPublic := activeKey.Public().(ed25519.PublicKey)
	if activeKeyID == marker.Transition.NewKeyID {
		oldPublicBytes, decodeErr := hex.DecodeString(marker.Transition.NewPublicKey)
		if decodeErr != nil || bytes.Equal(oldPublic, oldPublicBytes) == false {
			return fmt.Errorf("active new key mismatch")
		}
		metadata, metadataErr := LoadPublicKeyMetadata(config.StateDir)
		if metadataErr != nil {
			return metadataErr
		}
		for _, entry := range metadata.Keys {
			if entry.KeyID == marker.Transition.OldKeyID {
				decoded, _ := hex.DecodeString(entry.PublicKey)
				oldPublic = ed25519.PublicKey(decoded)
			}
		}
	}
	if err := contracts.VerifyKeyTransition(marker.Transition, oldPublic); err != nil {
		markExistingStateReadOnly(statePath, "observer_rotation_transition_invalid")
		return err
	}
	currentState, err := loadObserverState(statePath)
	if err != nil {
		return err
	}
	stateIsOld := currentState.HostID == hostID &&
		currentState.KeyID == marker.Transition.OldKeyID &&
		currentState.KeyEpoch == marker.Transition.OldEpoch
	stateIsNew := currentState.HostID == hostID &&
		currentState.KeyID == marker.Transition.NewKeyID &&
		currentState.KeyEpoch == marker.Transition.NewEpoch
	if !stateIsOld && !stateIsNew {
		markExistingStateReadOnly(
			statePath,
			"observer_rotation_state_identity_invalid",
		)
		return fmt.Errorf("observer rotation state identity invalid")
	}
	state, err := OpenStateStore(
		statePath,
		StateIdentity{
			HostID:   hostID,
			BootID:   bootID,
			KeyID:    currentState.KeyID,
			KeyEpoch: currentState.KeyEpoch,
		},
	)
	if err != nil {
		return err
	}
	if err := state.clearRotationFence(); err != nil {
		return err
	}
	metadata, err := LoadPublicKeyMetadata(config.StateDir)
	if errors.Is(err, os.ErrNotExist) {
		_ = state.PersistReadOnly("observer_public_key_metadata_missing")
		return fmt.Errorf("observer public key metadata missing")
	} else if err != nil {
		_ = state.PersistReadOnly("observer_public_key_metadata_invalid")
		return err
	}
	if metadata.HostID != hostID {
		_ = state.PersistReadOnly(
			"observer_public_key_metadata_host_mismatch",
		)
		return fmt.Errorf("observer public key metadata host mismatch")
	}
	keyring, err := metadata.Keyring()
	if err != nil {
		return err
	}
	newPublic, _ := hex.DecodeString(marker.Transition.NewPublicKey)
	if err := keyring.Add(
		marker.Transition.NewEpoch,
		ed25519.PublicKey(newPublic),
	); err != nil {
		return err
	}
	spool, err := NewSpool(
		SpoolConfig{
			StateDir:             config.StateDir,
			MaxBytes:             config.SpoolMaxBytes,
			PriorityReserveBytes: config.SpoolPriorityReserveBytes,
			Now:                  options.now,
			rotation:             &marker,
		},
		state,
		keyring,
	)
	if err != nil {
		return err
	}
	defer spool.Close()
	transitionFields, err := transitionMap(marker.Transition)
	if err != nil {
		return err
	}
	transitionEvent, transitionFound, err := spool.findRotationEvent(
		"observer_key_transition",
		marker.Transition.OldKeyID,
		marker.TransitionSequence,
		transitionFields,
	)
	if err != nil {
		_ = state.PersistReadOnly("observer_rotation_transition_invalid")
		return err
	}
	if !transitionFound {
		if state.Snapshot().LastSequence != marker.TransitionSequence-1 {
			_ = state.PersistReadOnly("observer_rotation_transition_sequence_lost")
			return fmt.Errorf("observer rotation transition sequence lost")
		}
		if state.Snapshot().KeyID != marker.Transition.OldKeyID ||
			activeKeyID != marker.Transition.OldKeyID {
			_ = state.PersistReadOnly("observer_rotation_transition_missing")
			return fmt.Errorf("cannot reconstruct missing old-epoch transition")
		}
		signer, err := NewEnvelopeSigner(
			SignerConfig{
				HostID:        hostID,
				BootID:        bootID,
				KeyEpoch:      marker.Transition.OldEpoch,
				SourceID:      "agmind-observerd",
				SourceVersion: "0.1.0",
				Now:           options.now,
			},
			state,
			spool,
			activeKey,
		)
		if err != nil {
			return err
		}
		eventMetadata, err := rotationMetadata(options.now(), transitionFields)
		if err != nil {
			return err
		}
		transitionEvent, err = signer.Wrap(
			context.Background(),
			"observer_key_transition",
			transitionFields,
			eventMetadata,
		)
		if err != nil {
			return err
		}
		if transitionEvent.SourceSequence != marker.TransitionSequence {
			_ = state.PersistReadOnly(
				"observer_rotation_transition_sequence_lost",
			)
			return fmt.Errorf("observer rotation transition sequence mismatch")
		}
	}
	marker.Stage = "transition_spooled"
	if err := saveRotationMarker(config.StateDir, marker); err != nil {
		return err
	}
	if options.stopAfter == marker.Stage {
		return ErrInjectedRotationStop
	}
	if state.Snapshot().KeyID == marker.Transition.OldKeyID {
		if err := state.switchKey(
			marker.Transition.NewKeyID,
			marker.Transition.NewEpoch,
		); err != nil {
			return err
		}
	}
	if err := durablefile.AtomicWrite(config.PrivateKeyFile, newPrivate); err != nil {
		return err
	}
	marker.Stage = "key_switched"
	if err := saveRotationMarker(config.StateDir, marker); err != nil {
		return err
	}
	if options.stopAfter == marker.Stage {
		return ErrInjectedRotationStop
	}
	startFields := map[string]any{
		"kind":      "observer_key_epoch_start",
		"key_id":    marker.Transition.NewKeyID,
		"key_epoch": marker.Transition.NewEpoch,
	}
	startEvent, startFound, err := spool.findRotationEvent(
		"observer_key_epoch_start",
		marker.Transition.NewKeyID,
		marker.StartSequence,
		startFields,
	)
	if err != nil {
		_ = state.PersistReadOnly("observer_rotation_epoch_start_invalid")
		return err
	}
	if !startFound {
		if state.Snapshot().LastSequence != marker.StartSequence-1 {
			_ = state.PersistReadOnly(
				"observer_rotation_epoch_start_sequence_lost",
			)
			return fmt.Errorf("observer rotation epoch-start sequence lost")
		}
		signer, err := NewEnvelopeSigner(
			SignerConfig{
				HostID:        hostID,
				BootID:        bootID,
				KeyEpoch:      marker.Transition.NewEpoch,
				SourceID:      "agmind-observerd",
				SourceVersion: "0.1.0",
				Now:           options.now,
			},
			state,
			spool,
			newPrivate,
		)
		if err != nil {
			return err
		}
		eventMetadata, err := rotationMetadata(options.now(), startFields)
		if err != nil {
			return err
		}
		startEvent, err = signer.Wrap(
			context.Background(),
			"observer_key_epoch_start",
			startFields,
			eventMetadata,
		)
		if err != nil {
			return err
		}
		if startEvent.SourceSequence != marker.StartSequence {
			_ = state.PersistReadOnly(
				"observer_rotation_epoch_start_sequence_lost",
			)
			return fmt.Errorf("observer rotation epoch-start sequence mismatch")
		}
	}
	if options.stopAfter == "start_durable" ||
		options.stopAfter == "start_spooled_metadata_old" {
		return ErrInjectedRotationStop
	}
	newEntry := PublicKeyEpoch{
		KeyID:              marker.Transition.NewKeyID,
		Epoch:              marker.Transition.NewEpoch,
		PublicKey:          marker.Transition.NewPublicKey,
		Transition:         &marker.Transition,
		TransitionEnvelope: &transitionEvent,
		EpochStartEnvelope: &startEvent,
	}
	switch metadata.CurrentEpoch {
	case marker.Transition.OldEpoch:
		if metadata.CurrentKeyID != marker.Transition.OldKeyID ||
			len(metadata.Keys) != int(marker.Transition.OldEpoch) {
			_ = state.PersistReadOnly(
				"observer_public_key_metadata_mismatch",
			)
			return fmt.Errorf("observer public key metadata mismatch")
		}
		metadata.Keys = append(metadata.Keys, newEntry)
		metadata.CurrentKeyID = marker.Transition.NewKeyID
		metadata.CurrentEpoch = marker.Transition.NewEpoch
	case marker.Transition.NewEpoch:
		if metadata.CurrentKeyID != marker.Transition.NewKeyID ||
			len(metadata.Keys) != int(marker.Transition.NewEpoch) ||
			!canonicalEqual(
				metadata.Keys[len(metadata.Keys)-1],
				newEntry,
			) {
			_ = state.PersistReadOnly(
				"observer_public_key_metadata_mismatch",
			)
			return fmt.Errorf("observer public key metadata mismatch")
		}
	default:
		_ = state.PersistReadOnly("observer_public_key_metadata_mismatch")
		return fmt.Errorf("observer public key metadata mismatch")
	}
	metadataCommitErr := options.saveMetadata(config.StateDir, metadata)
	if metadataCommitErr != nil {
		if errors.Is(metadataCommitErr, durablefile.ErrCommitUncertain) {
			if reconcileErr := reconcileUncertainPublicMetadataCommit(
				config.StateDir,
				metadata,
				options.syncMetadataDirectory,
			); reconcileErr == nil {
				metadataCommitErr = nil
			} else {
				metadataCommitErr = errors.Join(
					metadataCommitErr,
					reconcileErr,
				)
			}
		}
		if metadataCommitErr != nil {
			return errors.Join(
				metadataCommitErr,
				state.persistRotationIncomplete(),
			)
		}
	}
	if options.stopAfter == "metadata_committed" {
		return ErrInjectedRotationStop
	}
	marker.Stage = "start_spooled"
	if err := saveRotationMarker(config.StateDir, marker); err != nil {
		return err
	}
	if options.stopAfter == marker.Stage {
		return ErrInjectedRotationStop
	}
	if err := removeExactRotationArtifact(
		rotationKeyPath(config.StateDir),
		newPrivate,
		ed25519.PrivateKeySize,
	); err != nil {
		return err
	}
	if options.stopAfter == "rotation_key_removed" {
		return ErrInjectedRotationStop
	}
	markerRaw, err := contracts.CanonicalJSON(marker)
	if err != nil {
		return err
	}
	if err := removeExactRotationArtifact(
		markerPath(config.StateDir),
		markerRaw,
		65_536,
	); err != nil {
		return err
	}
	if options.stopAfter == "marker_removed" {
		return ErrInjectedRotationStop
	}
	return nil
}
