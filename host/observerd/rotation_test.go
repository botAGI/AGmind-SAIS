package observerd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func fixedRotationOptionsForBoot(
	newKey ed25519.PrivateKey,
	bootID string,
) []RotationOption {
	options := fixedRotationOptions(newKey)
	options[1] = WithRotationBootID(func() (string, error) { return bootID, nil })
	return options
}

func bootstrapRotationFixture(
	t *testing.T,
	configPath string,
	bootID string,
) {
	t.Helper()
	daemon, err := Bootstrap(
		context.Background(),
		configPath,
		WithBootstrapBootID(func() (string, error) { return bootID, nil }),
		WithBootstrapNow(func() time.Time {
			return time.Date(2026, 7, 27, 12, 30, 0, 0, time.UTC)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := daemon.Close(); err != nil {
		t.Fatal(err)
	}
}

func loadRotationFixtureEvents(
	t *testing.T,
	config Config,
	bootID string,
) ([]contracts.EventEnvelopeV1, ObserverState) {
	t.Helper()
	publicMetadata, err := LoadPublicKeyMetadata(config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := OpenStateStore(
		filepath.Join(config.StateDir, "observer-state.json"),
		StateIdentity{
			HostID:   testHostID,
			BootID:   bootID,
			KeyID:    publicMetadata.CurrentKeyID,
			KeyEpoch: publicMetadata.CurrentEpoch,
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
	events := fetchEnvelopeEvents(t, spool)
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	return events, state.Snapshot()
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

func TestOfflineRotationUsesFreshGenesisB(t *testing.T) {
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
		startEnvelope.SourceSequence != 2 ||
		transitionEnvelope.BootID != testBootID ||
		startEnvelope.BootID != testBootID ||
		!exactFlags(
			transitionEnvelope.CoverageFlags,
			"boot_transition",
			"key_rotation",
		) ||
		!exactFlags(startEnvelope.CoverageFlags, "key_rotation") {
		t.Fatalf("transition=%+v start=%+v", transitionEnvelope, startEnvelope)
	}
	snapshot := state.Snapshot()
	if snapshot.BootBoundaryState != bootBoundaryCommitted ||
		len(snapshot.BootHistory) != 1 ||
		snapshot.BootHistory[0].BoundaryEventID != transitionEnvelope.EventID ||
		snapshot.BootHistory[0].BoundaryEventType !=
			"observer_key_transition" {
		t.Fatalf("fresh B boundary state=%+v", snapshot)
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

func TestRotationBoundaryRoutesAndSameBootFlags(t *testing.T) {
	tests := []struct {
		name              string
		prepare           func(*testing.T, string, ed25519.PrivateKey)
		resumeBoot        string
		transitionBoot    string
		startBoot         string
		transitionFlags   []string
		startFlags        []string
		wantBoundaryEvent string
	}{
		{
			name: "same boot after committed A",
			prepare: func(
				t *testing.T,
				configPath string,
				_ ed25519.PrivateKey,
			) {
				bootstrapRotationFixture(t, configPath, testBootID)
			},
			resumeBoot:        testBootID,
			transitionBoot:    testBootID,
			startBoot:         testBootID,
			transitionFlags:   []string{"key_rotation"},
			startFlags:        []string{"key_rotation"},
			wantBoundaryEvent: "observer_boot_boundary",
		},
		{
			name: "B after reboot before transition durability",
			prepare: func(
				t *testing.T,
				configPath string,
				newKey ed25519.PrivateKey,
			) {
				bootstrapRotationFixture(t, configPath, testBootID)
				options := append(
					fixedRotationOptionsForBoot(newKey, testBootID),
					WithRotationStopAfter("prepared"),
				)
				if err := RotateKeys(configPath, options...); !errors.Is(
					err,
					ErrInjectedRotationStop,
				) {
					t.Fatalf("prepare B: %v", err)
				}
			},
			resumeBoot:        testBootID2,
			transitionBoot:    testBootID2,
			startBoot:         testBootID2,
			transitionFlags:   []string{"boot_transition", "key_rotation"},
			startFlags:        []string{"key_rotation"},
			wantBoundaryEvent: "observer_key_transition",
		},
		{
			name: "C after transition durability and reboot",
			prepare: func(
				t *testing.T,
				configPath string,
				newKey ed25519.PrivateKey,
			) {
				bootstrapRotationFixture(t, configPath, testBootID)
				options := append(
					fixedRotationOptionsForBoot(newKey, testBootID),
					WithRotationStopAfter("transition_spooled"),
				)
				if err := RotateKeys(configPath, options...); !errors.Is(
					err,
					ErrInjectedRotationStop,
				) {
					t.Fatalf("prepare C: %v", err)
				}
			},
			resumeBoot:        testBootID2,
			transitionBoot:    testBootID,
			startBoot:         testBootID2,
			transitionFlags:   []string{"key_rotation"},
			startFlags:        []string{"boot_transition", "key_rotation"},
			wantBoundaryEvent: "observer_key_epoch_start",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath, config, _, newKey := rotationFixture(t)
			test.prepare(t, configPath, newKey)
			if err := RotateKeys(
				configPath,
				fixedRotationOptionsForBoot(newKey, test.resumeBoot)...,
			); err != nil {
				t.Fatal(err)
			}
			events, snapshot := loadRotationFixtureEvents(
				t,
				config,
				test.resumeBoot,
			)
			var transition, start contracts.EventEnvelopeV1
			for _, event := range events {
				switch event.EventType {
				case "observer_key_transition":
					transition = event
				case "observer_key_epoch_start":
					start = event
				}
			}
			if transition.EventID == "" ||
				start.EventID == "" ||
				transition.SourceSequence+1 != start.SourceSequence ||
				transition.BootID != test.transitionBoot ||
				start.BootID != test.startBoot ||
				!exactFlags(
					transition.CoverageFlags,
					test.transitionFlags...,
				) ||
				!exactFlags(start.CoverageFlags, test.startFlags...) {
				t.Fatalf("transition=%+v start=%+v", transition, start)
			}
			lastBoundary := snapshot.BootHistory[len(snapshot.BootHistory)-1]
			if lastBoundary.BoundaryEventType != test.wantBoundaryEvent {
				t.Fatalf("boundary=%+v", lastBoundary)
			}
		})
	}
}

func TestRotationCandidateRemainsInactiveUntilExactStartIsDurable(
	t *testing.T,
) {
	configPath, config, oldKey, newKey := rotationFixture(t)
	bootstrapRotationFixture(t, configPath, testBootID)
	options := append(
		fixedRotationOptions(newKey),
		WithRotationStopAfter("key_switched"),
	)
	if err := RotateKeys(configPath, options...); !errors.Is(
		err,
		ErrInjectedRotationStop,
	) {
		t.Fatalf("stop before epoch start: %v", err)
	}
	active, err := os.ReadFile(config.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	state, err := loadObserverState(
		filepath.Join(config.StateDir, "observer-state.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	oldKeyID, err := contracts.KeyID(oldKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(active, oldKey) ||
		state.KeyID != oldKeyID ||
		state.KeyEpoch != 1 {
		t.Fatalf("candidate activated before start: state=%+v", state)
	}
	if err := RotateKeys(configPath, fixedRotationOptions(newKey)...); err != nil {
		t.Fatal(err)
	}
	active, err = os.ReadFile(config.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(active, newKey) {
		t.Fatal("candidate did not activate after exact durable start")
	}
}

func TestRotationRecoversDurableBoundaryMarkersWithoutDuplicates(
	t *testing.T,
) {
	tests := []struct {
		name    string
		prepare func(*testing.T, string, Config, ed25519.PrivateKey)
		bootID  string
	}{
		{
			name:   "B transition append before boundary marker",
			bootID: testBootID,
			prepare: func(
				t *testing.T,
				configPath string,
				config Config,
				newKey ed25519.PrivateKey,
			) {
				injected := errors.New("injected B marker persistence failure")
				options := append(
					fixedRotationOptions(newKey),
					withRotationPersist(func(
						path string,
						next ObserverState,
					) error {
						if next.BootBoundaryState == bootBoundaryCommitted &&
							next.PendingBootBoundary == nil {
							return injected
						}
						return persistState(path, next)
					}),
				)
				if err := RotateKeys(configPath, options...); !errors.Is(err, injected) {
					t.Fatalf("durable B transition: %v", err)
				}
				statePath := filepath.Join(
					config.StateDir,
					"observer-state.json",
				)
				state, err := loadObserverState(statePath)
				if err != nil {
					t.Fatal(err)
				}
				if state.BootBoundaryState != bootBoundaryPending ||
					state.PublicationHeadSequence != 1 {
					t.Fatalf("B failure did not leave exact durable pending state: %+v", state)
				}
			},
		},
		{
			name:   "C start append before activation marker",
			bootID: testBootID3,
			prepare: func(
				t *testing.T,
				configPath string,
				config Config,
				newKey ed25519.PrivateKey,
			) {
				bootstrapRotationFixture(t, configPath, testBootID)
				transitionOptions := append(
					fixedRotationOptionsForBoot(newKey, testBootID),
					WithRotationStopAfter("transition_spooled"),
				)
				if err := RotateKeys(
					configPath,
					transitionOptions...,
				); !errors.Is(err, ErrInjectedRotationStop) {
					t.Fatalf("durable old-boot transition: %v", err)
				}
				injected := errors.New("injected C activation persistence failure")
				statePath := filepath.Join(
					config.StateDir,
					"observer-state.json",
				)
				startOptions := append(
					fixedRotationOptionsForBoot(newKey, testBootID2),
					withRotationPersist(func(
						path string,
						next ObserverState,
					) error {
						if next.KeyEpoch == 2 &&
							next.BootBoundaryState == bootBoundaryCommitted &&
							next.PendingBootBoundary == nil {
							return injected
						}
						return persistState(path, next)
					}),
				)
				if err := RotateKeys(
					configPath,
					startOptions...,
				); !errors.Is(err, injected) {
					t.Fatalf("durable C start: %v", err)
				}
				pending, err := loadObserverState(statePath)
				if err != nil {
					t.Fatal(err)
				}
				marker, err := loadRotationMarker(config.StateDir)
				if err != nil {
					t.Fatal(err)
				}
				if pending.BootBoundaryState != bootBoundaryPending ||
					pending.KeyEpoch != 1 ||
					pending.PublicationHeadSequence != marker.StartSequence {
					t.Fatalf("C failure did not leave exact durable pending state: %+v", pending)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath, config, _, newKey := rotationFixture(t)
			test.prepare(t, configPath, config, newKey)
			if err := RotateKeys(
				configPath,
				fixedRotationOptionsForBoot(newKey, test.bootID)...,
			); err != nil {
				state, _ := loadObserverState(filepath.Join(
					config.StateDir,
					"observer-state.json",
				))
				t.Fatalf("resume: %v state=%+v", err, state)
			}
			events, snapshot := loadRotationFixtureEvents(
				t,
				config,
				test.bootID,
			)
			rotationEvents := 0
			for _, event := range events {
				if event.EventType == "observer_key_transition" ||
					event.EventType == "observer_key_epoch_start" {
					rotationEvents++
				}
			}
			if rotationEvents != 2 ||
				snapshot.KeyEpoch != 2 ||
				snapshot.BootBoundaryState != bootBoundaryCommitted {
				t.Fatalf(
					"events=%+v state=%+v",
					events,
					snapshot,
				)
			}
		})
	}
}

func TestRotationDoesNotReinterpretDurableBAsC(t *testing.T) {
	configPath, config, oldKey, newKey := rotationFixture(t)
	injected := errors.New("injected B marker persistence failure")
	options := append(
		fixedRotationOptionsForBoot(newKey, testBootID),
		withRotationPersist(func(path string, next ObserverState) error {
			if next.BootBoundaryState == bootBoundaryCommitted &&
				next.PendingBootBoundary == nil {
				return injected
			}
			return persistState(path, next)
		}),
	)
	if err := RotateKeys(configPath, options...); !errors.Is(err, injected) {
		t.Fatalf("durable B transition: %v", err)
	}
	if err := RotateKeys(
		configPath,
		fixedRotationOptionsForBoot(newKey, testBootID2)...,
	); err == nil {
		t.Fatal("durable B transition was reinterpreted as C")
	}
	state, err := loadObserverState(
		filepath.Join(config.StateDir, "observer-state.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	active, keyErr := os.ReadFile(config.PrivateKeyFile)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	if !state.MutationReadOnly ||
		state.KeyEpoch != 1 ||
		!bytes.Equal(active, oldKey) {
		t.Fatalf("conflicting B/C route did not fail closed: %+v", state)
	}
	frames, err := filepath.Glob(
		filepath.Join(config.StateDir, "spool", "priority", "*.agf"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("conflicting B/C route emitted %d priority frames", len(frames))
	}
}

func resignRotationEvent(
	t *testing.T,
	event contracts.EventEnvelopeV1,
	privateKey ed25519.PrivateKey,
) contracts.EventEnvelopeV1 {
	t.Helper()
	event.EventID = ""
	event.SourceSignature = ""
	eventID, err := contracts.DeriveEventID(event)
	if err != nil {
		t.Fatal(err)
	}
	event.EventID = eventID
	message, err := contracts.EventSigningMessage(event)
	if err != nil {
		t.Fatal(err)
	}
	event.SourceSignature = hex.EncodeToString(ed25519.Sign(privateKey, message))
	return event
}

func TestPublicKeyMetadataRejectsNonExactRotationBoundaries(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(
			*contracts.EventEnvelopeV1,
			*contracts.EventEnvelopeV1,
		)
	}{
		{
			name: "wrong start flags",
			tamper: func(
				_ *contracts.EventEnvelopeV1,
				start *contracts.EventEnvelopeV1,
			) {
				start.CoverageFlags = []string{
					"boot_transition",
					"key_rotation",
				}
			},
		},
		{
			name: "wrong boot",
			tamper: func(
				transition *contracts.EventEnvelopeV1,
				_ *contracts.EventEnvelopeV1,
			) {
				transition.BootID = testBootID2
			},
		},
		{
			name: "wrong candidate epoch",
			tamper: func(
				_ *contracts.EventEnvelopeV1,
				start *contracts.EventEnvelopeV1,
			) {
				start.KeyEpoch++
			},
		},
		{
			name: "non adjacent intervening sequence",
			tamper: func(
				_ *contracts.EventEnvelopeV1,
				start *contracts.EventEnvelopeV1,
			) {
				start.SourceSequence++
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath, config, oldKey, newKey := rotationFixture(t)
			if err := RotateKeys(
				configPath,
				fixedRotationOptions(newKey)...,
			); err != nil {
				t.Fatal(err)
			}
			metadata, err := LoadPublicKeyMetadata(config.StateDir)
			if err != nil {
				t.Fatal(err)
			}
			transition := *metadata.Keys[1].TransitionEnvelope
			start := *metadata.Keys[1].EpochStartEnvelope
			test.tamper(&transition, &start)
			transition = resignRotationEvent(t, transition, oldKey)
			start = resignRotationEvent(t, start, newKey)
			metadata.Keys[1].TransitionEnvelope = &transition
			metadata.Keys[1].EpochStartEnvelope = &start
			if err := metadata.Validate(); err == nil {
				t.Fatal("non-exact rotation boundary accepted")
			}
		})
	}
}

func TestRotationAuthorizationRejectsNonExactBoundaryRequests(t *testing.T) {
	configPath, config, oldKey, newKey := rotationFixture(t)
	options := append(
		fixedRotationOptions(newKey),
		WithRotationStopAfter("prepared"),
	)
	if err := RotateKeys(configPath, options...); !errors.Is(
		err,
		ErrInjectedRotationStop,
	) {
		t.Fatalf("prepare rotation: %v", err)
	}
	marker, err := loadRotationMarker(config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := OpenStateStore(
		filepath.Join(config.StateDir, "observer-state.json"),
		StateIdentity{
			HostID:   testHostID,
			BootID:   testBootID,
			KeyID:    marker.Transition.OldKeyID,
			KeyEpoch: marker.Transition.OldEpoch,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := LoadPublicKeyMetadata(config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := metadata.Keyring()
	if err != nil {
		t.Fatal(err)
	}
	newPublic, err := hex.DecodeString(marker.Transition.NewPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Add(
		marker.Transition.NewEpoch,
		ed25519.PublicKey(newPublic),
	); err != nil {
		t.Fatal(err)
	}
	spool, err := NewSpool(
		SpoolConfig{
			StateDir:             config.StateDir,
			MaxBytes:             config.SpoolMaxBytes,
			PriorityReserveBytes: config.SpoolPriorityReserveBytes,
			rotation:             &marker,
		},
		state,
		keyring,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	signer, err := NewEnvelopeSigner(
		SignerConfig{
			HostID:        testHostID,
			BootID:        testBootID,
			KeyEpoch:      marker.Transition.OldEpoch,
			SourceID:      "agmind-observerd",
			SourceVersion: "0.1.0",
			Now:           time.Now,
		},
		state,
		spool,
		oldKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := transitionMap(marker.Transition)
	if err != nil {
		t.Fatal(err)
	}
	eventMetadata, err := rotationMetadata(
		time.Date(2026, 7, 27, 13, 0, 0, 0, time.UTC),
		fields,
		"boot_transition",
		"key_rotation",
	)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(
			*rotationPublicationAuthorization,
			*ObserverState,
			*EnvelopeSigner,
			*map[string]any,
			*EventMetadata,
		)
	}{
		{
			name: "wrong flags",
			mutate: func(
				_ *rotationPublicationAuthorization,
				_ *ObserverState,
				_ *EnvelopeSigner,
				_ *map[string]any,
				metadata *EventMetadata,
			) {
				metadata.CoverageFlags = []string{"key_rotation"}
			},
		},
		{
			name: "wrong boot",
			mutate: func(
				_ *rotationPublicationAuthorization,
				_ *ObserverState,
				signer *EnvelopeSigner,
				_ *map[string]any,
				_ *EventMetadata,
			) {
				signer.config.BootID = testBootID2
			},
		},
		{
			name: "wrong epoch and key",
			mutate: func(
				authorization *rotationPublicationAuthorization,
				_ *ObserverState,
				_ *EnvelopeSigner,
				_ *map[string]any,
				_ *EventMetadata,
			) {
				authorization.marker.Transition.OldEpoch++
				authorization.marker.Transition.OldKeyID =
					strings.Repeat("a", 32)
			},
		},
		{
			name: "non adjacency",
			mutate: func(
				authorization *rotationPublicationAuthorization,
				_ *ObserverState,
				_ *EnvelopeSigner,
				_ *map[string]any,
				_ *EventMetadata,
			) {
				authorization.marker.StartSequence++
			},
		},
		{
			name: "intervening reserved event",
			mutate: func(
				_ *rotationPublicationAuthorization,
				snapshot *ObserverState,
				_ *EnvelopeSigner,
				_ *map[string]any,
				_ *EventMetadata,
			) {
				snapshot.LastSequence++
			},
		},
		{
			name: "wrong source hash",
			mutate: func(
				_ *rotationPublicationAuthorization,
				_ *ObserverState,
				_ *EnvelopeSigner,
				_ *map[string]any,
				metadata *EventMetadata,
			) {
				metadata.SourcePayloadHash = strings.Repeat("0", 64)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authorization := rotationPublicationAuthorization{
				marker: marker,
				role:   rotationTransitionPublication,
			}
			snapshot := state.Snapshot()
			signerCopy := *signer
			fieldsCopy := make(map[string]any, len(fields))
			for key, value := range fields {
				fieldsCopy[key] = value
			}
			metadataCopy := eventMetadata
			metadataCopy.CoverageFlags = append(
				[]string(nil),
				eventMetadata.CoverageFlags...,
			)
			test.mutate(
				&authorization,
				&snapshot,
				&signerCopy,
				&fieldsCopy,
				&metadataCopy,
			)
			if authorization.matchesRequest(
				snapshot,
				&signerCopy,
				"observer_key_transition",
				fieldsCopy,
				metadataCopy,
			) {
				t.Fatal("non-exact rotation request authorized")
			}
		})
	}
}

func TestEpochStartRequiresDurableTransitionBinding(t *testing.T) {
	configPath, config, _, newKey := rotationFixture(t)
	options := append(
		fixedRotationOptions(newKey),
		WithRotationStopAfter("prepared"),
	)
	if err := RotateKeys(configPath, options...); !errors.Is(
		err,
		ErrInjectedRotationStop,
	) {
		t.Fatalf("got %v, want injected stop", err)
	}
	marker, err := loadRotationMarker(config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := LoadPublicKeyMetadata(config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := metadata.Keyring()
	if err != nil {
		t.Fatal(err)
	}
	newPublic, err := hex.DecodeString(marker.Transition.NewPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.Add(marker.Transition.NewEpoch, ed25519.PublicKey(newPublic)); err != nil {
		t.Fatal(err)
	}
	state, err := OpenStateStore(
		filepath.Join(config.StateDir, "observer-state.json"),
		StateIdentity{
			HostID:   testHostID,
			BootID:   testBootID,
			KeyID:    marker.Transition.OldKeyID,
			KeyEpoch: marker.Transition.OldEpoch,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	spool, err := NewSpool(
		SpoolConfig{
			StateDir:             config.StateDir,
			MaxBytes:             config.SpoolMaxBytes,
			PriorityReserveBytes: config.SpoolPriorityReserveBytes,
			rotation:             &marker,
		},
		state,
		keys,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	startSigner := &EnvelopeSigner{
		config: SignerConfig{
			HostID:        testHostID,
			BootID:        testBootID,
			KeyEpoch:      marker.Transition.NewEpoch,
			SourceID:      "agmind-observerd",
			SourceVersion: "0.1.0",
			Now:           time.Now,
		},
		state:      state,
		spool:      spool,
		privateKey: append(ed25519.PrivateKey(nil), newKey...),
		keyID:      marker.Transition.NewKeyID,
	}
	fields := map[string]any{
		"kind":      "observer_key_epoch_start",
		"key_id":    marker.Transition.NewKeyID,
		"key_epoch": marker.Transition.NewEpoch,
	}
	eventMetadata, err := rotationMetadata(time.Now(), fields)
	if err != nil {
		t.Fatal(err)
	}
	before := state.Snapshot()
	if _, err := startSigner.wrapAuthorizedRotation(
		context.Background(),
		marker,
		rotationEpochStartPublication,
		"observer_key_epoch_start",
		fields,
		eventMetadata,
	); !errors.Is(err, ErrRotationPublicationMismatch) {
		t.Fatalf("fabricated epoch-start authority err=%v", err)
	}
	after := state.Snapshot()
	if after.LastSequence != before.LastSequence ||
		spool.containsRotationEvent(
			"observer_key_epoch_start",
			marker.Transition.NewKeyID,
			fields,
		) {
		t.Fatalf("epoch start published without transition: %+v", after)
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
