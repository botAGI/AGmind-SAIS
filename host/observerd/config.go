package observerd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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

func readSingleLinkRegular(path string, maxBytes int64) ([]byte, error) {
	return durablefile.ReadRegular(path, maxBytes)
}

func LoadConfig(path string) (Config, error) {
	raw, err := readSingleLinkRegular(path, 65_536)
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
	bootID func() (string, error)
	now    func() time.Time
}

type BootstrapOption func(*bootstrapOptions)

func WithBootstrapBootID(value func() (string, error)) BootstrapOption {
	return func(options *bootstrapOptions) { options.bootID = value }
}

func WithBootstrapNow(value func() time.Time) BootstrapOption {
	return func(options *bootstrapOptions) { options.now = value }
}

type Daemon struct {
	lock     *StateLock
	state    *StateStore
	spool    *Spool
	signer   *EnvelopeSigner
	coverage *Coverage
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
	options := bootstrapOptions{bootID: readKernelBootID, now: time.Now}
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
	bootID, err := options.bootID()
	if err != nil {
		return fail(err, nil)
	}
	privateKey, err := readPrivateKey(config.PrivateKeyFile)
	if err != nil {
		statePath := filepath.Join(config.StateDir, "observer-state.json")
		existing, stateErr := loadObserverState(statePath)
		if stateErr != nil ||
			existing.HostID != hostID {
			markExistingStateReadOnly(
				statePath,
				"observer_private_key_unavailable",
			)
			return fail(errors.Join(err, stateErr), nil)
		}
		state, stateErr := OpenStateStore(
			statePath,
			StateIdentity{
				HostID:   hostID,
				BootID:   bootID,
				KeyID:    existing.KeyID,
				KeyEpoch: existing.KeyEpoch,
			},
		)
		if stateErr != nil {
			return fail(errors.Join(err, stateErr), nil)
		}
		if stateErr := state.PersistReadOnly(
			"observer_private_key_unavailable",
		); stateErr != nil {
			return fail(errors.Join(err, stateErr), nil)
		}
		return &Daemon{lock: lock, state: state}, nil
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, err := contracts.KeyID(publicKey)
	if err != nil {
		return fail(err, nil)
	}
	epoch := uint64(1)
	if existing, stateErr := loadObserverState(
		filepath.Join(config.StateDir, "observer-state.json"),
	); stateErr == nil {
		epoch = existing.KeyEpoch
		if existing.KeyID != keyID {
			markExistingStateReadOnly(
				filepath.Join(config.StateDir, "observer-state.json"),
				"observer_private_key_mismatch",
			)
			return fail(fmt.Errorf("observer private key mismatch"), nil)
		}
	}
	state, err := OpenStateStore(
		filepath.Join(config.StateDir, "observer-state.json"),
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
		metadata = initialPublicMetadata(hostID, keyID, epoch, publicKey)
		if err := savePublicKeyMetadata(config.StateDir, metadata); err != nil {
			return fail(err, nil)
		}
	} else if err != nil {
		_ = state.PersistReadOnly("observer_public_key_metadata_invalid")
		return fail(err, nil)
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
	}, nil
}
