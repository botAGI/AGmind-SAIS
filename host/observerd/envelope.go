package observerd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

const observerStateSchema = "agmind.observer-state.v1"

type ObserverState struct {
	SchemaVersion     string `json:"schema_version"`
	HostID            string `json:"host_id"`
	BootID            string `json:"boot_id"`
	KeyID             string `json:"key_id"`
	KeyEpoch          uint64 `json:"key_epoch"`
	LastSequence      uint64 `json:"last_sequence"`
	MutationReadOnly  bool   `json:"mutation_read_only"`
	ReadOnlyReason    string `json:"read_only_reason"`
	ReconcileRequired bool   `json:"reconcile_required"`
	RoutineDropped    uint64 `json:"routine_dropped"`
	DropEventPending  bool   `json:"drop_event_pending"`
	AckSequence       uint64 `json:"ack_sequence"`
	AckEventID        string `json:"ack_event_id"`
	AckContentSHA256  string `json:"ack_content_sha256"`
	AckRecordHash     string `json:"ack_record_hash"`
	AckPayloadSHA256  string `json:"ack_payload_sha256"`
	LastCoveredGapEnd uint64 `json:"last_covered_gap_end"`
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
	return nil
}

type StateIdentity struct {
	HostID   string
	BootID   string
	KeyID    string
	KeyEpoch uint64
}

type StateStore struct {
	mutex sync.Mutex
	path  string
	state ObserverState
}

func persistState(path string, state ObserverState) error {
	if err := state.Validate(); err != nil {
		return err
	}
	raw, err := contracts.CanonicalJSON(state)
	if err != nil {
		return err
	}
	return durablefile.AtomicWrite(path, raw)
}

func OpenStateStore(path string, identity StateIdentity) (*StateStore, error) {
	if err := durablefile.EnsurePrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	initial := ObserverState{
		SchemaVersion:     observerStateSchema,
		HostID:            identity.HostID,
		BootID:            identity.BootID,
		KeyID:             identity.KeyID,
		KeyEpoch:          identity.KeyEpoch,
		ReconcileRequired: true,
	}
	raw, err := readSingleLinkRegular(path, 65_536)
	if errors.Is(err, os.ErrNotExist) {
		if err := persistState(path, initial); err != nil {
			return nil, err
		}
		return &StateStore{path: path, state: initial}, nil
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
	if state.BootID != identity.BootID {
		state.BootID = identity.BootID
		state.ReconcileRequired = true
		if err := persistState(path, state); err != nil {
			return nil, err
		}
	}
	return &StateStore{path: path, state: state}, nil
}

func (store *StateStore) Snapshot() ObserverState {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	return store.state
}

func (store *StateStore) replaceLocked(next ObserverState) error {
	if err := persistState(store.path, next); err != nil {
		return err
	}
	store.state = next
	return nil
}

func (store *StateStore) PersistReadOnly(reason string) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	next := store.state
	next.MutationReadOnly = true
	next.ReadOnlyReason = reason
	next.ReconcileRequired = true
	// Fail closed in the live process before attempting persistence. A disk
	// failure is returned but can never leave readiness true in memory.
	store.state = next
	return persistState(store.path, next)
}

func (store *StateStore) reserve(identity StateIdentity) (uint64, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.state.HostID != identity.HostID ||
		store.state.KeyID != identity.KeyID ||
		store.state.KeyEpoch != identity.KeyEpoch {
		return 0, fmt.Errorf("observer signing identity mismatch")
	}
	if store.state.LastSequence == math.MaxUint64 {
		next := store.state
		next.MutationReadOnly = true
		next.ReadOnlyReason = "observer_sequence_exhausted"
		next.ReconcileRequired = true
		store.state = next
		persistErr := persistState(store.path, next)
		return 0, errors.Join(fmt.Errorf("observer sequence exhausted"), persistErr)
	}
	next := store.state
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
) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	next := store.state
	next.AckSequence = sequence
	next.AckEventID = eventID
	next.AckContentSHA256 = contentSHA256
	next.AckRecordHash = recordHash
	next.AckPayloadSHA256 = payloadSHA256
	// A synced journal record is authoritative even if the redundant
	// state-file anchor cannot be rewritten. Keep the live state forward so a
	// retry cannot append the same sequence twice.
	store.state = next
	return persistState(store.path, next)
}

func (store *StateStore) switchKey(newKeyID string, newEpoch uint64) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if !hex32Pattern.MatchString(newKeyID) ||
		store.state.KeyEpoch == math.MaxUint64 ||
		newEpoch != store.state.KeyEpoch+1 {
		return fmt.Errorf("key epochs must be consecutive")
	}
	next := store.state
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
	next := store.state
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
	next := store.state
	next.LastCoveredGapEnd = sequence
	return store.replaceLocked(next)
}

type keyEntry struct {
	epoch uint64
	key   ed25519.PublicKey
}

type Keyring struct {
	mutex sync.RWMutex
	keys  map[string]keyEntry
}

func NewKeyring() *Keyring {
	return &Keyring{keys: make(map[string]keyEntry)}
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
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, err := contracts.KeyID(publicKey)
	if err != nil {
		_ = state.PersistReadOnly("observer_private_key_invalid")
		return nil, err
	}
	snapshot := state.Snapshot()
	if keyID != snapshot.KeyID ||
		config.KeyEpoch != snapshot.KeyEpoch ||
		config.HostID != snapshot.HostID {
		_ = state.PersistReadOnly("observer_private_key_mismatch")
		return nil, fmt.Errorf("observer private key does not match state")
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
	KeyID     string `json:"key_id"`
	Epoch     uint64 `json:"epoch"`
	PublicKey string `json:"public_key"`
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
		len(metadata.Keys) == 0 {
		return fmt.Errorf("invalid observer public-key metadata")
	}
	var prior uint64
	currentFound := false
	for _, entry := range metadata.Keys {
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
		if entry.Epoch == metadata.CurrentEpoch &&
			entry.KeyID == metadata.CurrentKeyID {
			currentFound = true
		}
		prior = entry.Epoch
	}
	if !currentFound {
		return fmt.Errorf("current observer key missing")
	}
	return nil
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
	}
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
	return durablefile.AtomicWrite(publicMetadataPath(stateDir), raw)
}

type rotationMarker struct {
	SchemaVersion    string                    `json:"schema_version"`
	HostID           string                    `json:"host_id"`
	Stage            string                    `json:"stage"`
	NewPrivateSHA256 string                    `json:"new_private_sha256"`
	Transition       contracts.KeyTransitionV1 `json:"transition"`
}

func (marker rotationMarker) Validate() error {
	if marker.SchemaVersion != "agmind.observer-key-rotation.v1" ||
		!uuid4Pattern.MatchString(marker.HostID) ||
		!hex64Pattern.MatchString(marker.NewPrivateSHA256) {
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
	euid      func() int
	bootID    func() (string, error)
	now       func() time.Time
	generate  func() (ed25519.PublicKey, ed25519.PrivateKey, error)
	stopAfter string
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
	return append(ed25519.PrivateKey(nil), raw...), nil
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
	store := &StateStore{path: path, state: state}
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

func (spool *Spool) containsRotationEvent(
	eventType string,
	keyID string,
	expectedFields map[string]any,
) bool {
	expectedCanonical, err := contracts.CanonicalJSON(expectedFields)
	if err != nil {
		return false
	}
	expectedHash := sha256.Sum256(expectedCanonical)
	expectedHashHex := hex.EncodeToString(expectedHash[:])
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	for _, item := range spool.items {
		event, _, _, _, readErr := readStandaloneFrame(item.path, spool.keys)
		if readErr != nil ||
			event.EventType != eventType ||
			event.KeyID != keyID ||
			event.NormalizedFieldsSHA256 != expectedHashHex ||
			event.SourcePayloadHash != expectedHashHex {
			continue
		}
		actualCanonical, canonicalErr := contracts.CanonicalJSON(
			event.NormalizedFields,
		)
		if canonicalErr == nil && bytes.Equal(actualCanonical, expectedCanonical) {
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

func defaultRotationOptions() rotationOptions {
	return rotationOptions{
		euid:   os.Geteuid,
		bootID: readKernelBootID,
		now:    time.Now,
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
		existingState, loadErr := loadObserverState(statePath)
		if loadErr == nil {
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
		if snapshot.KeyEpoch == math.MaxUint64 {
			_ = state.PersistReadOnly("observer_key_epoch_exhausted")
			return fmt.Errorf("observer key epoch exhausted")
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
			SchemaVersion:    "agmind.observer-key-rotation.v1",
			HostID:           hostID,
			Stage:            "prepared",
			NewPrivateSHA256: hex.EncodeToString(sum[:]),
			Transition:       transition,
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
	metadata, err := LoadPublicKeyMetadata(config.StateDir)
	if errors.Is(err, os.ErrNotExist) {
		metadata = PublicKeyMetadata{
			SchemaVersion: "agmind.observer-public-keys.v1",
			HostID:        hostID,
			CurrentKeyID:  marker.Transition.OldKeyID,
			CurrentEpoch:  marker.Transition.OldEpoch,
			Keys: []PublicKeyEpoch{{
				KeyID:     marker.Transition.OldKeyID,
				Epoch:     marker.Transition.OldEpoch,
				PublicKey: hex.EncodeToString(oldPublic),
			}},
		}
		if err := savePublicKeyMetadata(config.StateDir, metadata); err != nil {
			return err
		}
	} else if err != nil {
		return err
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
	if !spool.containsRotationEvent(
		"observer_key_transition",
		marker.Transition.OldKeyID,
		transitionFields,
	) {
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
		if _, err := signer.Wrap(
			context.Background(),
			"observer_key_transition",
			transitionFields,
			eventMetadata,
		); err != nil {
			return err
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
	metadata.CurrentKeyID = marker.Transition.NewKeyID
	metadata.CurrentEpoch = marker.Transition.NewEpoch
	foundNew := false
	for _, entry := range metadata.Keys {
		foundNew = foundNew || entry.KeyID == marker.Transition.NewKeyID
	}
	if !foundNew {
		metadata.Keys = append(metadata.Keys, PublicKeyEpoch{
			KeyID:     marker.Transition.NewKeyID,
			Epoch:     marker.Transition.NewEpoch,
			PublicKey: marker.Transition.NewPublicKey,
		})
		sort.Slice(metadata.Keys, func(left, right int) bool {
			return metadata.Keys[left].Epoch < metadata.Keys[right].Epoch
		})
	}
	if err := savePublicKeyMetadata(config.StateDir, metadata); err != nil {
		return err
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
	if !spool.containsRotationEvent(
		"observer_key_epoch_start",
		marker.Transition.NewKeyID,
		startFields,
	) {
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
		if _, err := signer.Wrap(
			context.Background(),
			"observer_key_epoch_start",
			startFields,
			eventMetadata,
		); err != nil {
			return err
		}
	}
	marker.Stage = "start_spooled"
	if err := saveRotationMarker(config.StateDir, marker); err != nil {
		return err
	}
	if options.stopAfter == marker.Stage {
		return ErrInjectedRotationStop
	}
	if err := durablefile.Remove(
		rotationKeyPath(config.StateDir),
	); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if options.stopAfter == "rotation_key_removed" {
		return ErrInjectedRotationStop
	}
	if err := durablefile.Remove(markerPath(config.StateDir)); err != nil {
		return err
	}
	if options.stopAfter == "marker_removed" {
		return ErrInjectedRotationStop
	}
	return nil
}
