package observerd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"agmind.local/sais/internal/contracts"
)

func rotationFixture(
	t *testing.T,
) (string, Config, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	root := t.TempDir()
	for _, directory := range []string{
		filepath.Join(root, "identity"),
		filepath.Join(root, "secrets"),
		filepath.Join(root, "state"),
		filepath.Join(root, "run"),
	} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	oldKey := testKey(t, 30)
	newKey := testKey(t, 31)
	hostPath := filepath.Join(root, "identity", "host-id")
	if err := os.WriteFile(hostPath, []byte(testHostID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "secrets", "observer.key")
	if err := os.WriteFile(keyPath, oldKey, 0o600); err != nil {
		t.Fatal(err)
	}
	config := Config{
		SchemaVersion:             "agmind.observer-config.v1",
		HostIDFile:                hostPath,
		PrivateKeyFile:            keyPath,
		StateDir:                  filepath.Join(root, "state"),
		RunDir:                    filepath.Join(root, "run"),
		SpoolMaxBytes:             4 * 1024 * 1024,
		SpoolPriorityReserveBytes: 1024 * 1024,
	}
	raw, err := contracts.CanonicalJSON(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "observer.json")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath, config, oldKey, newKey
}

func fixedRotationOptions(newKey ed25519.PrivateKey) []RotationOption {
	return []RotationOption{
		WithRotationEUID(func() int { return 0 }),
		WithRotationBootID(func() (string, error) { return testBootID, nil }),
		WithRotationNow(func() time.Time {
			return time.Date(2026, 7, 27, 13, 0, 0, 0, time.UTC)
		}),
		WithRotationKeyGenerator(func() (ed25519.PublicKey, ed25519.PrivateKey, error) {
			return newKey.Public().(ed25519.PublicKey), newKey, nil
		}),
	}
}

func TestOfflineRotationIsRootOnlyAndRefusesLiveDaemonLock(t *testing.T) {
	configPath, config, _, newKey := rotationFixture(t)
	options := fixedRotationOptions(newKey)
	nonroot := append([]RotationOption{}, options...)
	nonroot[0] = WithRotationEUID(func() int { return 1000 })
	if err := RotateKeys(configPath, nonroot...); !errors.Is(
		err,
		ErrRootRequired,
	) {
		t.Fatalf("got %v, want root required", err)
	}
	lock, err := AcquireStateLock(config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := RotateKeys(configPath, options...); !errors.Is(
		err,
		ErrStateLocked,
	) {
		t.Fatalf("got %v, want state locked", err)
	}
}

func TestOfflineRotationSpoolsOldEnvelopeThenOneNewEpochStart(t *testing.T) {
	configPath, config, oldKey, newKey := rotationFixture(t)
	if err := RotateKeys(configPath, fixedRotationOptions(newKey)...); err != nil {
		t.Fatal(err)
	}
	rawKey, err := os.ReadFile(config.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rawKey, newKey) {
		t.Fatal("active private key was not atomically switched")
	}
	publicMetadata, err := LoadPublicKeyMetadata(config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if publicMetadata.CurrentEpoch != 2 || len(publicMetadata.Keys) != 2 {
		t.Fatalf("metadata=%+v", publicMetadata)
	}
	state, err := OpenStateStore(
		filepath.Join(config.StateDir, "observer-state.json"),
		StateIdentity{
			HostID:   testHostID,
			BootID:   testBootID,
			KeyID:    publicMetadata.CurrentKeyID,
			KeyEpoch: 2,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := publicMetadata.Keyring()
	if err != nil {
		t.Fatal(err)
	}
	spool, err := NewSpool(
		SpoolConfig{
			StateDir:             config.StateDir,
			MaxBytes:             config.SpoolMaxBytes,
			PriorityReserveBytes: config.SpoolPriorityReserveBytes,
		},
		state,
		keyring,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	items, err := spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("items=%d want=2", len(items))
	}
	transitionEnvelope, err := contracts.DecodeStrict[contracts.EventEnvelopeV1](
		bytes.NewReader(items[0].Canonical),
		65_536,
	)
	if err != nil {
		t.Fatal(err)
	}
	startEnvelope, err := contracts.DecodeStrict[contracts.EventEnvelopeV1](
		bytes.NewReader(items[1].Canonical),
		65_536,
	)
	if err != nil {
		t.Fatal(err)
	}
	if transitionEnvelope.EventType != "observer_key_transition" ||
		transitionEnvelope.KeyEpoch != 1 ||
		startEnvelope.EventType != "observer_key_epoch_start" ||
		startEnvelope.KeyEpoch != 2 ||
		transitionEnvelope.SourceSequence != 1 ||
		startEnvelope.SourceSequence != 2 {
		t.Fatalf("transition=%+v start=%+v", transitionEnvelope, startEnvelope)
	}
	transitionRaw, err := contracts.CanonicalJSON(transitionEnvelope.NormalizedFields)
	if err != nil {
		t.Fatal(err)
	}
	transition, err := contracts.DecodeStrict[contracts.KeyTransitionV1](
		bytes.NewReader(transitionRaw),
		65_536,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.VerifyKeyTransition(
		transition,
		oldKey.Public().(ed25519.PublicKey),
	); err != nil {
		t.Fatal(err)
	}
	if err := contracts.VerifyEventSignature(
		startEnvelope,
		newKey.Public().(ed25519.PublicKey),
	); err != nil {
		t.Fatal(err)
	}
}

func TestRotationResumeDoesNotGenerateSecondKeyOrDuplicateTransition(t *testing.T) {
	configPath, config, _, newKey := rotationFixture(t)
	options := append(
		fixedRotationOptions(newKey),
		WithRotationStopAfter("transition_spooled"),
	)
	if err := RotateKeys(configPath, options...); !errors.Is(
		err,
		ErrInjectedRotationStop,
	) {
		t.Fatalf("got %v, want injected stop", err)
	}
	if err := RotateKeys(configPath, fixedRotationOptions(newKey)...); err != nil {
		t.Fatal(err)
	}
	metadata, err := LoadPublicKeyMetadata(config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := OpenStateStore(
		filepath.Join(config.StateDir, "observer-state.json"),
		StateIdentity{
			HostID:   testHostID,
			BootID:   testBootID,
			KeyID:    metadata.CurrentKeyID,
			KeyEpoch: 2,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := metadata.Keyring()
	if err != nil {
		t.Fatal(err)
	}
	spool, err := NewSpool(
		SpoolConfig{
			StateDir:             config.StateDir,
			MaxBytes:             config.SpoolMaxBytes,
			PriorityReserveBytes: config.SpoolPriorityReserveBytes,
		},
		state,
		keyring,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	items, err := spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("resumed rotation emitted %d events", len(items))
	}
}

func TestTwoConsecutiveRotationsPreserveGlobalSequenceAndEpochChain(t *testing.T) {
	configPath, config, _, secondKey := rotationFixture(t)
	thirdKey := testKey(t, 32)
	if err := RotateKeys(configPath, fixedRotationOptions(secondKey)...); err != nil {
		t.Fatal(err)
	}
	if err := RotateKeys(configPath, fixedRotationOptions(thirdKey)...); err != nil {
		t.Fatal(err)
	}
	metadata, err := LoadPublicKeyMetadata(config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.CurrentEpoch != 3 || len(metadata.Keys) != 3 {
		t.Fatalf("metadata=%+v", metadata)
	}
	state, err := OpenStateStore(
		filepath.Join(config.StateDir, "observer-state.json"),
		StateIdentity{
			HostID:   testHostID,
			BootID:   testBootID,
			KeyID:    metadata.CurrentKeyID,
			KeyEpoch: 3,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := metadata.Keyring()
	if err != nil {
		t.Fatal(err)
	}
	spool, err := NewSpool(
		SpoolConfig{
			StateDir:             config.StateDir,
			MaxBytes:             config.SpoolMaxBytes,
			PriorityReserveBytes: config.SpoolPriorityReserveBytes,
		},
		state,
		keyring,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	items, err := spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 4 {
		t.Fatalf("items=%d want=4", len(items))
	}
	for index, item := range items {
		event, err := contracts.DecodeStrict[contracts.EventEnvelopeV1](
			bytes.NewReader(item.Canonical),
			65_536,
		)
		if err != nil {
			t.Fatal(err)
		}
		wantSequence := uint64(index + 1)
		wantEpoch := uint64((index+1)/2 + 1)
		if event.SourceSequence != wantSequence || event.KeyEpoch != wantEpoch {
			t.Fatalf(
				"event[%d] sequence=%d epoch=%d",
				index,
				event.SourceSequence,
				event.KeyEpoch,
			)
		}
	}
}

func TestRotationResumesEveryDurableStageIncludingOrphanNewKey(t *testing.T) {
	for _, stage := range []string{
		"new_key_written",
		"prepared",
		"transition_spooled",
		"key_switched",
		"start_spooled",
		"rotation_key_removed",
	} {
		t.Run(stage, func(t *testing.T) {
			configPath, config, _, newKey := rotationFixture(t)
			options := append(
				fixedRotationOptions(newKey),
				WithRotationStopAfter(stage),
			)
			if err := RotateKeys(configPath, options...); !errors.Is(
				err,
				ErrInjectedRotationStop,
			) {
				t.Fatalf("got %v, want injected stop", err)
			}
			if stage == "rotation_key_removed" {
				if _, err := os.Lstat(rotationKeyPath(config.StateDir)); !errors.Is(
					err,
					os.ErrNotExist,
				) {
					t.Fatalf("temporary key still exists: %v", err)
				}
				if _, err := os.Lstat(markerPath(config.StateDir)); err != nil {
					t.Fatalf("marker was not retained through final cleanup: %v", err)
				}
			}
			generatorCalls := 0
			resume := fixedRotationOptions(newKey)
			resume[3] = WithRotationKeyGenerator(
				func() (ed25519.PublicKey, ed25519.PrivateKey, error) {
					generatorCalls++
					return newKey.Public().(ed25519.PublicKey), newKey, nil
				},
			)
			if err := RotateKeys(configPath, resume...); err != nil {
				t.Fatal(err)
			}
			if stage == "new_key_written" && generatorCalls != 0 {
				t.Fatalf("orphan resume generated %d replacement keys", generatorCalls)
			}
			if _, err := os.Lstat(markerPath(config.StateDir)); !errors.Is(
				err,
				os.ErrNotExist,
			) {
				t.Fatalf("marker cleanup: %v", err)
			}
			if _, err := os.Lstat(rotationKeyPath(config.StateDir)); !errors.Is(
				err,
				os.ErrNotExist,
			) {
				t.Fatalf("temporary key cleanup: %v", err)
			}
		})
	}
}

func TestRotationMarkerRemovalIsFinalAndDaemonCanRestart(t *testing.T) {
	configPath, config, _, newKey := rotationFixture(t)
	options := append(
		fixedRotationOptions(newKey),
		WithRotationStopAfter("marker_removed"),
	)
	if err := RotateKeys(configPath, options...); !errors.Is(
		err,
		ErrInjectedRotationStop,
	) {
		t.Fatalf("got %v, want injected stop", err)
	}
	for _, path := range []string{
		rotationKeyPath(config.StateDir),
		markerPath(config.StateDir),
	} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("completed cleanup retained %s: %v", path, err)
		}
	}
	daemon, err := Bootstrap(
		context.Background(),
		configPath,
		WithBootstrapBootID(func() (string, error) { return testBootID, nil }),
		WithBootstrapNow(func() time.Time {
			return time.Date(2026, 7, 27, 14, 0, 0, 0, time.UTC)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := daemon.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRotationEpochExhaustionFailsReadOnlyBeforeWritingOrphanKey(t *testing.T) {
	configPath, config, oldKey, newKey := rotationFixture(t)
	oldID, err := contracts.KeyID(oldKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	state, err := OpenStateStore(
		filepath.Join(config.StateDir, "observer-state.json"),
		StateIdentity{
			HostID:   testHostID,
			BootID:   testBootID,
			KeyID:    oldID,
			KeyEpoch: ^uint64(0),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := RotateKeys(
		configPath,
		fixedRotationOptions(newKey)...,
	); err == nil {
		t.Fatal("exhausted key epoch rotated")
	}
	if !state.Snapshot().MutationReadOnly {
		reloaded, loadErr := loadObserverState(
			filepath.Join(config.StateDir, "observer-state.json"),
		)
		if loadErr != nil || !reloaded.MutationReadOnly {
			t.Fatalf("epoch exhaustion did not persist read-only: %v", loadErr)
		}
	}
	if _, err := os.Lstat(rotationKeyPath(config.StateDir)); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf("epoch exhaustion wrote orphan key: %v", err)
	}
}

func TestContainsRotationEventRequiresExactNormalizedPayload(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 33)
	_, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	wrong := map[string]any{
		"kind":      "observer_key_epoch_start",
		"key_id":    signer.keyID,
		"key_epoch": uint64(999),
	}
	if _, err := signer.Wrap(
		context.Background(),
		"observer_key_epoch_start",
		wrong,
		metadata(),
	); err != nil {
		t.Fatal(err)
	}
	expected := map[string]any{
		"kind":      "observer_key_epoch_start",
		"key_id":    signer.keyID,
		"key_epoch": uint64(2),
	}
	if spool.containsRotationEvent(
		"observer_key_epoch_start",
		signer.keyID,
		expected,
	) {
		t.Fatal("same event type and key ID accepted with wrong payload")
	}
}

func TestMissingOldKeyCannotBeRotatedAway(t *testing.T) {
	configPath, config, oldKey, newKey := rotationFixture(t)
	oldID, err := contracts.KeyID(oldKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStateStore(
		filepath.Join(config.StateDir, "observer-state.json"),
		StateIdentity{
			HostID:   testHostID,
			BootID:   testBootID,
			KeyID:    oldID,
			KeyEpoch: 1,
		},
	); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(config.PrivateKeyFile); err != nil {
		t.Fatal(err)
	}
	if err := RotateKeys(
		configPath,
		fixedRotationOptions(newKey)...,
	); err == nil {
		t.Fatal("missing old key was rotated away")
	}
	raw, err := os.ReadFile(filepath.Join(config.StateDir, "observer-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	state, err := contracts.DecodeStrict[ObserverState](bytes.NewReader(raw), 65_536)
	if err != nil {
		t.Fatal(err)
	}
	if !state.MutationReadOnly {
		t.Fatal("missing old key did not persist read-only")
	}
}
