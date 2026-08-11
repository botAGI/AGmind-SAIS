package observerd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
	"agmind.local/sais/internal/uds"
)

const DefaultConfigPath = "/etc/agmind-sais/observer.json"

type Config struct {
	SchemaVersion             string `json:"schema_version"`
	HostIDFile                string `json:"host_id_file"`
	PrivateKeyFile            string `json:"private_key_file"`
	StateDir                  string `json:"state_dir"`
	RunDir                    string `json:"run_dir"`
	SpoolMaxBytes             uint64 `json:"spool_max_bytes"`
	SpoolPriorityReserveBytes uint64 `json:"spool_priority_reserve_bytes"`
}

func cleanAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func (config Config) Validate() error {
	if config.SchemaVersion != "agmind.observer-config.v1" {
		return fmt.Errorf("unsupported observer config schema")
	}
	for _, path := range []string{
		config.HostIDFile,
		config.PrivateKeyFile,
		config.StateDir,
		config.RunDir,
	} {
		if !cleanAbsolute(path) {
			return fmt.Errorf("observer config paths must be clean absolute paths")
		}
	}
	if config.SpoolMaxBytes == 0 ||
		config.SpoolPriorityReserveBytes == 0 ||
		config.SpoolPriorityReserveBytes >= config.SpoolMaxBytes {
		return fmt.Errorf("invalid observer spool capacity")
	}
	return nil
}

// Modes observerd accepts for the immutable artifacts scripts/install-linux.sh creates.
//
// These are NOT free choices — they are the modes the installer actually produces, plus 0600
// because durablefile.AtomicWrite chmods rotated files to 0600. Reading them with the
// hardcoded-0600 reader made observerd unable to load its own config on a real host, so the
// signed-evidence leg never started while every unit test stayed green against its own
// 0600 fixtures. host/observerd/installed_modes_test.go derives both sides from the installer so
// the two can no longer drift silently.
//
// Config and secrets are deliberately separate sets: the config is non-secret and is installed
// world-readable alongside the other service configs, while the host identity and the signing key
// must stay owner-only whatever the config does.
var (
	installedConfigModes = []fs.FileMode{0o444, 0o400, 0o600}
	installedSecretModes = []fs.FileMode{0o400, 0o600}
)

// readSingleLinkRegular reads runtime state that observerd itself wrote (spool, rotation
// markers), which durablefile.AtomicWrite always creates at 0600.
func readSingleLinkRegular(path string, maxBytes int64) ([]byte, error) {
	return durablefile.ReadRegular(path, maxBytes)
}

// readInstalledConfig reads a root-installed, non-secret artifact.
func readInstalledConfig(path string, maxBytes int64) ([]byte, error) {
	return durablefile.ReadRegularModes(path, maxBytes, installedConfigModes...)
}

// readInstalledSecret reads a root-installed owner-only artifact (identity, signing key).
func readInstalledSecret(path string, maxBytes int64) ([]byte, error) {
	return durablefile.ReadRegularModes(path, maxBytes, installedSecretModes...)
}

func LoadConfig(path string) (Config, error) {
	raw, err := readInstalledConfig(path, 65_536)
	if err != nil {
		return Config{}, err
	}
	config, err := contracts.DecodeStrict[Config](bytes.NewReader(raw), 65_536)
	if err != nil {
		return Config{}, err
	}
	return config, nil
}

type bootstrapOptions struct {
	bootID  func() (string, error)
	now     func() time.Time
	persist func(string, ObserverState) error
}

type BootstrapOption func(*bootstrapOptions)

func WithBootstrapBootID(value func() (string, error)) BootstrapOption {
	return func(options *bootstrapOptions) { options.bootID = value }
}

func WithBootstrapNow(value func() time.Time) BootstrapOption {
	return func(options *bootstrapOptions) { options.now = value }
}

func withBootstrapStatePersist(
	value func(string, ObserverState) error,
) BootstrapOption {
	return func(options *bootstrapOptions) { options.persist = value }
}

type Daemon struct {
	lock     *StateLock
	state    *StateStore
	spool    *Spool
	signer   *EnvelopeSigner
	coverage *Coverage
	degraded error
	config   Config
}

func requireLinuxPlatform(goos string) error {
	if goos != "linux" {
		return uds.ErrUnsupportedPlatform
	}
	return nil
}

func (daemon *Daemon) ReconcileRequired() bool {
	return daemon.state.Snapshot().ReconcileRequired
}

func (daemon *Daemon) MutationReadOnly() bool {
	return daemon.state.Snapshot().MutationReadOnly
}

func (daemon *Daemon) Close() error {
	if daemon == nil {
		return nil
	}
	var spoolErr error
	if daemon.spool != nil {
		spoolErr = daemon.spool.Close()
		daemon.spool = nil
	}
	var lockErr error
	if daemon.lock != nil {
		lockErr = daemon.lock.Close()
		daemon.lock = nil
	}
	return errors.Join(spoolErr, lockErr)
}

func initialPublicMetadata(
	hostID string,
	keyID string,
	epoch uint64,
	publicKey ed25519.PublicKey,
) PublicKeyMetadata {
	return PublicKeyMetadata{
		SchemaVersion: "agmind.observer-public-keys.v1",
		HostID:        hostID,
		CurrentKeyID:  keyID,
		CurrentEpoch:  epoch,
		Keys: []PublicKeyEpoch{{
			KeyID:     keyID,
			Epoch:     epoch,
			PublicKey: hex.EncodeToString(publicKey),
		}},
	}
}

func rotationArtifactsPresent(stateDir string) bool {
	for path, maxBytes := range map[string]int64{
		markerPath(stateDir):      65_536,
		rotationKeyPath(stateDir): ed25519.PrivateKeySize,
	} {
		if _, err := readSingleLinkRegular(path, maxBytes); err == nil {
			return true
		} else if !errors.Is(err, os.ErrNotExist) {
			// Unsafe, malformed, or unreadable rotation artifacts are still an
			// incomplete boundary. Ordinary startup must never route around
			// them.
			return true
		}
	}
	return false
}

func ensureDedicatedBootBoundary(
	ctx context.Context,
	state *StateStore,
	signer *EnvelopeSigner,
	now time.Time,
) error {
	snapshot := state.Snapshot()
	if snapshot.BootBoundaryState == bootBoundaryCommitted {
		return nil
	}
	if snapshot.BootBoundaryState != bootBoundaryPending ||
		snapshot.PendingBootBoundary == nil {
		return ErrBootBoundaryPending
	}
	pending := snapshot.PendingBootBoundary
	fields := map[string]any{
		"schema_version":           "agmind.observer-boot-boundary.v1",
		"kind":                     "observer_boot_boundary",
		"reason_code":              pending.ReasonCode,
		"previous_source_sequence": pending.PreviousSourceSequence,
	}
	if pending.PreviousBootID != nil {
		fields["previous_boot_id"] = *pending.PreviousBootID
	}
	canonical, err := contracts.CanonicalJSON(fields)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	_, err = signer.wrapAuthorizedBootBoundary(
		ctx,
		observerBootBoundaryPublication,
		"observer_boot_boundary",
		fields,
		EventMetadata{
			EventTime:         now.UTC(),
			RedactionFlags:    []string{},
			CoverageFlags:     []string{"boot_transition", "reconcile_required"},
			SourcePayloadHash: hex.EncodeToString(digest[:]),
		},
	)
	return err
}

// Bootstrap starts the Task 2 daemon state machine fenced in
// reconcile_required. It intentionally creates no Docker client or state.
func Bootstrap(
	ctx context.Context,
	configPath string,
	supplied ...BootstrapOption,
) (*Daemon, error) {
	if err := requireLinuxPlatform(runtime.GOOS); err != nil {
		return nil, err
	}
	options := bootstrapOptions{
		bootID:  readKernelBootID,
		now:     time.Now,
		persist: persistState,
	}
	for _, option := range supplied {
		option(&options)
	}
	config, err := LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	lock, err := AcquireStateLock(config.StateDir)
	if err != nil {
		return nil, err
	}
	fail := func(result error, spool *Spool) (*Daemon, error) {
		if spool != nil {
			_ = spool.Close()
		}
		_ = lock.Close()
		return nil, result
	}
	hostID, err := readHostID(config.HostIDFile)
	if err != nil {
		return fail(err, nil)
	}
	statePath := filepath.Join(config.StateDir, "observer-state.json")
	if rotationArtifactsPresent(config.StateDir) {
		existing, stateErr := loadObserverState(statePath)
		if stateErr != nil || existing.HostID != hostID {
			return fail(
				errors.Join(
					fmt.Errorf("incomplete observer key rotation"),
					stateErr,
				),
				nil,
			)
		}
		state := &StateStore{
			path:    statePath,
			state:   cloneObserverState(existing),
			persist: options.persist,
		}
		degraded := fmt.Errorf("incomplete observer key rotation")
		if !existing.MutationReadOnly {
			stateErr = state.PersistReadOnly(
				"observer_rotation_incomplete",
			)
			degraded = errors.Join(degraded, stateErr)
		} else if existing.ReadOnlyReason != "observer_rotation_incomplete" {
			degraded = errors.Join(
				degraded,
				fmt.Errorf(
					"observer state remains mutation read-only: %s",
					existing.ReadOnlyReason,
				),
			)
		}
		return &Daemon{
			lock:     lock,
			state:    state,
			degraded: degraded,
			config:   config,
		}, nil
	}
	bootID, err := options.bootID()
	if err != nil {
		return fail(err, nil)
	}
	privateKey, err := readPrivateKey(config.PrivateKeyFile)
	if err != nil {
		existing, stateErr := loadObserverState(statePath)
		if stateErr != nil ||
			existing.HostID != hostID {
			markExistingStateReadOnly(
				statePath,
				"observer_private_key_unavailable",
			)
			return fail(errors.Join(err, stateErr), nil)
		}
		state := &StateStore{
			path:    statePath,
			state:   cloneObserverState(existing),
			persist: options.persist,
		}
		persistErr := state.PersistReadOnly(
			"observer_private_key_unavailable",
		)
		return &Daemon{
			lock:     lock,
			state:    state,
			degraded: errors.Join(err, persistErr),
			config:   config,
		}, nil
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, err := contracts.KeyID(publicKey)
	if err != nil {
		return fail(err, nil)
	}
	epoch := uint64(1)
	if existing, stateErr := loadObserverState(
		statePath,
	); stateErr == nil {
		epoch = existing.KeyEpoch
		if existing.KeyID != keyID {
			state := &StateStore{
				path:    statePath,
				state:   cloneObserverState(existing),
				persist: options.persist,
			}
			persistErr := state.PersistReadOnly(
				"observer_private_key_mismatch",
			)
			return &Daemon{
				lock:   lock,
				state:  state,
				config: config,
				degraded: errors.Join(
					fmt.Errorf("observer private key mismatch"),
					persistErr,
				),
			}, nil
		}
	} else if !errors.Is(stateErr, os.ErrNotExist) {
		return fail(stateErr, nil)
	}
	if existing, stateErr := loadObserverState(statePath); stateErr == nil &&
		existing.BootID != bootID &&
		existing.BootBoundaryState == bootBoundaryPending &&
		len(existing.BootHistory) > 0 &&
		existing.PublicationHeadSequence >=
			existing.BootHistory[len(existing.BootHistory)-1].FirstSequence {
		metadata, metadataErr := LoadPublicKeyMetadata(config.StateDir)
		if metadataErr != nil {
			return fail(metadataErr, nil)
		}
		keyring, keyringErr := metadata.Keyring()
		if keyringErr != nil {
			return fail(keyringErr, nil)
		}
		if recoverErr := recoverPendingBootBoundaryBeforeBootChange(
			statePath,
			StateIdentity{
				HostID:   hostID,
				BootID:   bootID,
				KeyID:    keyID,
				KeyEpoch: epoch,
			},
			SpoolConfig{
				StateDir:             config.StateDir,
				MaxBytes:             config.SpoolMaxBytes,
				PriorityReserveBytes: config.SpoolPriorityReserveBytes,
				Now:                  options.now,
			},
			keyring,
		); recoverErr != nil {
			return fail(recoverErr, nil)
		}
	}
	state, err := OpenStateStore(
		statePath,
		StateIdentity{
			HostID:   hostID,
			BootID:   bootID,
			KeyID:    keyID,
			KeyEpoch: epoch,
		},
	)
	if err != nil {
		return fail(err, nil)
	}
	metadata, err := LoadPublicKeyMetadata(config.StateDir)
	if errors.Is(err, os.ErrNotExist) {
		snapshot := state.Snapshot()
		if snapshot.KeyEpoch != 1 ||
			snapshot.LastSequence != 0 ||
			snapshot.AckSequence != 0 {
			_ = state.PersistReadOnly(
				"observer_public_key_metadata_missing",
			)
			return fail(
				fmt.Errorf("observer public key metadata missing"),
				nil,
			)
		}
		metadata = initialPublicMetadata(hostID, keyID, epoch, publicKey)
		if err := savePublicKeyMetadata(config.StateDir, metadata); err != nil {
			return fail(err, nil)
		}
	} else if err != nil {
		_ = state.PersistReadOnly("observer_public_key_metadata_invalid")
		return fail(err, nil)
	}
	if metadata.HostID != hostID ||
		metadata.HostID != state.Snapshot().HostID {
		_ = state.PersistReadOnly("observer_public_key_metadata_host_mismatch")
		return fail(fmt.Errorf("observer public key metadata host mismatch"), nil)
	}
	if metadata.CurrentKeyID != keyID || metadata.CurrentEpoch != epoch {
		_ = state.PersistReadOnly("observer_public_key_metadata_mismatch")
		return fail(fmt.Errorf("observer public key metadata mismatch"), nil)
	}
	keyring, err := metadata.Keyring()
	if err != nil {
		_ = state.PersistReadOnly("observer_public_key_metadata_invalid")
		return fail(err, nil)
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
		return fail(err, nil)
	}
	if snapshot := state.Snapshot(); snapshot.MutationReadOnly {
		return &Daemon{
			lock:   lock,
			state:  state,
			spool:  spool,
			config: config,
			degraded: fmt.Errorf(
				"observer mutation is read-only: %s",
				snapshot.ReadOnlyReason,
			),
		}, nil
	}
	signer, err := NewEnvelopeSigner(
		SignerConfig{
			HostID:        hostID,
			BootID:        bootID,
			KeyEpoch:      epoch,
			SourceID:      "agmind-observerd",
			SourceVersion: "0.1.0",
			Now:           options.now,
		},
		state,
		spool,
		privateKey,
	)
	if err != nil {
		return fail(err, spool)
	}
	if err := ensureDedicatedBootBoundary(
		ctx,
		state,
		signer,
		options.now(),
	); err != nil {
		return fail(err, spool)
	}
	if err := spool.recoverSequenceGapMarkers(); err != nil {
		return fail(err, spool)
	}
	for _, gap := range spool.UncoveredGaps(state.Snapshot().LastCoveredGapEnd) {
		now := options.now().UTC()
		fields := map[string]any{
			"component":                      "observer",
			"kind":                           "observer_sequence_gap",
			"severity":                       "CRITICAL",
			"opened_at":                      now.Format(time.RFC3339Nano),
			"affected_source_sequence_start": gap.Start,
			"affected_source_sequence_end":   gap.End,
			"reason_code":                    "reserved_sequence_not_published",
		}
		canonical, canonicalErr := contracts.CanonicalJSON(fields)
		if canonicalErr != nil {
			return fail(canonicalErr, spool)
		}
		sum := sha256.Sum256(canonical)
		if _, wrapErr := signer.Wrap(
			ctx,
			"coverage",
			fields,
			EventMetadata{
				EventTime:         now,
				RedactionFlags:    []string{},
				CoverageFlags:     []string{"reconcile_required", "sequence_gap"},
				SourcePayloadHash: hex.EncodeToString(sum[:]),
			},
		); wrapErr != nil {
			return fail(wrapErr, spool)
		}
		if markErr := state.markGapCovered(gap.End); markErr != nil {
			return fail(markErr, spool)
		}
	}
	now := options.now().UTC()
	fields := map[string]any{
		"kind":               "observer_start",
		"reconcile_required": true,
	}
	canonical, err := contracts.CanonicalJSON(fields)
	if err != nil {
		return fail(err, spool)
	}
	sum := sha256.Sum256(canonical)
	if _, err := signer.Wrap(
		ctx,
		"observer_start",
		fields,
		EventMetadata{
			EventTime:         now,
			RedactionFlags:    []string{},
			CoverageFlags:     []string{"reconcile_required"},
			SourcePayloadHash: hex.EncodeToString(sum[:]),
		},
	); err != nil {
		return fail(err, spool)
	}
	return &Daemon{
		lock:     lock,
		state:    state,
		spool:    spool,
		signer:   signer,
		coverage: NewCoverage(state, signer),
		config:   config,
	}, nil
}
