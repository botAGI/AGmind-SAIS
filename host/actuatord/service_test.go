package actuatord

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"agmind.local/sais/host/observerd"
	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

type prepareObserver struct {
	integrity             observerd.ObserverIntegrityV1
	identity              observerd.ContainerIdentityV1
	unique                observerd.NetNSUniquenessV1
	target                *prepareTarget
	targetOpenDuringNetNS bool
	calls                 int
}

func (observer *prepareObserver) Integrity(context.Context) (observerd.ObserverIntegrityV1, error) {
	observer.calls++
	return observer.integrity, nil
}

func (observer *prepareObserver) LookupContainer(context.Context, string) (observerd.ContainerIdentityV1, error) {
	observer.calls++
	return observer.identity, nil
}

func (observer *prepareObserver) CheckNetNS(context.Context, observerd.NetNSUniquenessRequestV1) (observerd.NetNSUniquenessV1, error) {
	observer.calls++
	observer.targetOpenDuringNetNS = observer.target != nil && !observer.target.closed
	return observer.unique, nil
}

type prepareTarget struct {
	snapshot PrepareTargetSnapshot
	closed   bool
	calls    int
}

type prepareTargetHandle struct{ target *prepareTarget }

func (handle *prepareTargetHandle) Snapshot() PrepareTargetSnapshot {
	return handle.target.snapshot
}

func (handle *prepareTargetHandle) Close() error {
	handle.target.closed = true
	return nil
}

func (target *prepareTarget) ResolveForPrepare(context.Context, string, uint64) (PrepareTargetHandle, error) {
	target.calls++
	target.closed = false
	return &prepareTargetHandle{target: target}, nil
}

type prepareSafety struct{ snapshot SafetySnapshot }

func (safety prepareSafety) Snapshot(context.Context) (SafetySnapshot, error) {
	return safety.snapshot, nil
}

type prepareFixture struct {
	intent   contracts.TemporaryEgressDenyIntentV1
	observer *prepareObserver
	target   *prepareTarget
	safety   prepareSafety
	clock    func() (ClockSample, error)
	key      ed25519.PrivateKey
}

func newPrepareFixture(t *testing.T) prepareFixture {
	t.Helper()
	raw, err := os.ReadFile("../../contracts/fixtures/v1/intent.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := contracts.DecodeStrict[contracts.TemporaryEgressDenyIntentV1](bytes.NewReader(raw), 65_536)
	if err != nil {
		t.Fatal(err)
	}
	registryRaw, err := os.ReadFile("../../contracts/v1/ipv4-special-use.csv")
	if err != nil {
		t.Fatal(err)
	}
	managementHash, err := contracts.PCCManagementDenylistSHA256([]string{}, []string{})
	if err != nil {
		t.Fatal(err)
	}
	networks := []contracts.PCCDockerNetworkV1{{
		NetworkID:        strings.Repeat("9", 64),
		Driver:           "bridge",
		SubnetCIDRs:      []string{"172.18.0.0/16"},
		GatewayAddresses: []string{"172.18.0.1"},
	}}
	networkHash, err := contracts.PCCDockerNetworkSnapshotSHA256(networks)
	if err != nil {
		t.Fatal(err)
	}
	identity := observerd.ContainerIdentityV1{
		FullContainerID:     intent.DockerContainerID,
		DockerStartedAt:     intent.DockerStartedAt,
		ImageID:             intent.ImageID,
		RepoDigests:         []string{},
		ImmutableSpecSHA256: intent.ImmutableSpecSHA256,
		InitPID:             4242,
		NetworkMode:         "bridge",
		NetworkDriver:       "bridge",
		ConfiguredCapAdd:    []string{},
		ConfiguredCapDrop:   []string{},
		Running:             true,
		InventoryGeneration: intent.InventoryGeneration,
		InventoryRevision:   intent.InventoryRevision,
		ObservedAt:          "2026-07-27T12:00:01Z",
		AttachedNetworks: []observerd.AttachedNetworkV1{{
			NetworkID:        networks[0].NetworkID,
			Driver:           "bridge",
			SubnetCIDRs:      []string{"172.18.0.0/16"},
			GatewayAddresses: []string{"172.18.0.1"},
		}},
	}
	snapshot := PrepareTargetSnapshot{
		InitPID:               identity.InitPID,
		PIDStartTicks:         456,
		CgroupPathSHA256:      strings.Repeat("1", 64),
		NetworkNamespaceInode: 789,
	}
	targetResolver := &prepareTarget{snapshot: snapshot}
	observer := &prepareObserver{
		integrity: observerd.ObserverIntegrityV1{
			SchemaVersion:       "agmind.observer-integrity.v1",
			Healthy:             true,
			Reasons:             []string{},
			HostID:              intent.HostID,
			BootID:              "123e4567-e89b-42d3-a456-426614174001",
			KeyID:               strings.Repeat("a", 32),
			KeyEpoch:            1,
			InventoryGeneration: intent.InventoryGeneration,
			ObservedAt:          "2026-07-27T12:00:02Z",
		},
		identity: identity,
		unique: observerd.NetNSUniquenessV1{
			FullContainerID:             intent.DockerContainerID,
			NetworkNamespaceInode:       snapshot.NetworkNamespaceInode,
			InventoryGeneration:         intent.InventoryGeneration,
			InventorySnapshotSHA256:     strings.Repeat("2", 64),
			DockerNetworks:              networks,
			DockerNetworkSnapshotSHA256: networkHash,
			Unique:                      true,
			CheckedAt:                   "2026-07-27T12:00:02Z",
		},
		target: targetResolver,
	}
	return prepareFixture{
		intent:   intent,
		observer: observer,
		target:   targetResolver,
		safety: prepareSafety{snapshot: SafetySnapshot{
			SpecialUseRegistryRaw:     registryRaw,
			SpecialUseRegistrySHA256:  pinnedSpecialUseRegistrySHA256,
			ManagementDeniedNetworks:  []string{},
			ManagementDeniedAddresses: []string{},
			ManagementDenylistSHA256:  managementHash,
		}},
		clock: func() (ClockSample, error) {
			return ClockSample{
				Wall:       time.Date(2026, 7, 27, 12, 0, 2, 0, time.UTC),
				BootTimeNS: 1_000_000_000_000,
				BootID:     "123e4567-e89b-42d3-a456-426614174001",
			}, nil
		},
		key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)),
	}
}

func openFixtureService(t *testing.T, root string, fixture prepareFixture, options ...ServiceOption) *Service {
	t.Helper()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	base := []ServiceOption{
		WithObserver(fixture.observer),
		WithTargetResolver(fixture.target),
		WithSafetyProvider(fixture.safety),
		WithClock(fixture.clock),
		WithRandom(bytes.NewReader(bytes.Repeat([]byte{3}, 256))),
	}
	service, err := OpenService(root, fixture.key, append(base, options...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	return service
}

func TestPrepareCommitsOnlyAfterLiveTargetCloseAndFsync(t *testing.T) {
	fixture := newPrepareFixture(t)
	root := t.TempDir()
	syncObservedClosed := false
	service := openFixtureService(t, root, fixture, withJournalOptions(
		durablefile.WithSync(func(file *os.File) error {
			syncObservedClosed = fixture.target.closed
			return file.Sync()
		}),
	))
	plan, err := service.Prepare(context.Background(), fixture.intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Validate(); err != nil || !fixture.observer.targetOpenDuringNetNS ||
		!syncObservedClosed || service.Pending() != 1 {
		t.Fatalf("plan=%+v validate=%v open_during_netns=%t closed_before_sync=%t pending=%d", plan, err, fixture.observer.targetOpenDuringNetNS, syncObservedClosed, service.Pending())
	}

	for name, mutate := range map[string]func(*prepareFixture){
		"stale identity": func(candidate *prepareFixture) {
			candidate.observer.identity.ImageID = "sha256:" + strings.Repeat("8", 64)
		},
		"unsafe destination": func(candidate *prepareFixture) { candidate.intent.DestinationIPv4 = "172.18.0.9" },
		"privileged target":  func(candidate *prepareFixture) { candidate.observer.identity.Privileged = true },
		"namespace escape capability": func(candidate *prepareFixture) {
			candidate.observer.identity.ConfiguredCapAdd = []string{"SYS_ADMIN"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := newPrepareFixture(t)
			mutate(&candidate)
			blocked := openFixtureService(t, t.TempDir(), candidate)
			if got, err := blocked.Prepare(context.Background(), candidate.intent); err == nil || !reflect.ValueOf(got).IsZero() || blocked.Pending() != 0 {
				t.Fatalf("got=%+v err=%v pending=%d", got, err, blocked.Pending())
			}
		})
	}

	t.Run("fsync failure", func(t *testing.T) {
		candidate := newPrepareFixture(t)
		injected := errors.New("injected sync failure")
		failed := openFixtureService(t, t.TempDir(), candidate, withJournalOptions(
			durablefile.WithSync(func(*os.File) error { return injected }),
		))
		if got, err := failed.Prepare(context.Background(), candidate.intent); !errors.Is(err, injected) || !reflect.ValueOf(got).IsZero() || failed.Pending() != 0 {
			t.Fatalf("got=%+v err=%v pending=%d", got, err, failed.Pending())
		}
		if _, err := failed.Prepare(context.Background(), candidate.intent); !errors.Is(err, durablefile.ErrJournalFailed) {
			t.Fatalf("retry err=%v", err)
		}
	})

	t.Run("durable rate limit", func(t *testing.T) {
		candidate := newPrepareFixture(t)
		root := t.TempDir()
		limited := openFixtureService(t, root, candidate)
		ids := []string{
			"int_11111111111111111111111111111111",
			"int_22222222222222222222222222222222",
		}
		for index := range 2 {
			intent := candidate.intent
			intent.IntentID = ids[0]
			intent.DestinationIPv4 = "172.18.0.9"
			if got, err := limited.Prepare(context.Background(), intent); !errors.Is(err, ErrIntentRejected) || !reflect.ValueOf(got).IsZero() {
				t.Fatalf("rejected attempt %d: got=%+v err=%v", index, got, err)
			}
		}
		if err := limited.Close(); err != nil {
			t.Fatal(err)
		}
		limited = openFixtureService(t, root, candidate)
		third := candidate.intent
		third.IntentID = ids[0]
		third.DestinationIPv4 = "172.18.0.9"
		if got, err := limited.Prepare(context.Background(), third); !errors.Is(err, ErrIntentRejected) || !reflect.ValueOf(got).IsZero() {
			t.Fatalf("rejected attempt after restart: got=%+v err=%v", got, err)
		}
		calls := candidate.observer.calls
		blocked := candidate.intent
		blocked.IntentID = ids[1]
		if _, err := limited.Prepare(context.Background(), blocked); !errors.Is(err, ErrIntentRateLimited) || candidate.observer.calls != calls {
			t.Fatalf("rate err=%v live_calls=%d want=%d", err, candidate.observer.calls, calls)
		}
	})
}

func TestPrepareRecoveryIsIdempotentAndRejectsEquivocationOrTamper(t *testing.T) {
	fixture := newPrepareFixture(t)
	root := t.TempDir()
	service := openFixtureService(t, root, fixture)
	first, err := service.Prepare(context.Background(), fixture.intent)
	if err != nil {
		t.Fatal(err)
	}
	expected := clonePlan(first)
	first.EvidenceIDs[0] = "caller-mutated"
	detached, err := service.Prepare(context.Background(), fixture.intent)
	if err != nil || !reflect.DeepEqual(detached, expected) {
		t.Fatalf("caller mutation reached durable authority: plan=%+v err=%v", detached, err)
	}
	first = expected
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	calls := fixture.observer.calls
	reopened := openFixtureService(t, root, fixture)
	second, err := reopened.Prepare(context.Background(), fixture.intent)
	if err != nil || !reflect.DeepEqual(second, first) || fixture.observer.calls != calls {
		t.Fatalf("first=%+v second=%+v err=%v live_calls=%d want=%d", first, second, err, fixture.observer.calls, calls)
	}
	altered := fixture.intent
	altered.DestinationIPv4 = "8.8.8.8"
	if _, err := reopened.Prepare(context.Background(), altered); !errors.Is(err, ErrIntentEquivocation) {
		t.Fatalf("equivocation err=%v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	recovery, err := durablefile.Recover(actionJournalPath(root), actionJournalMaxFrame)
	if err != nil || len(recovery.Records) != 2 {
		t.Fatalf("recovery=%+v err=%v", recovery, err)
	}
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(recovery.Records[1].Payload))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	document["actuator_signature"] = strings.Repeat("0", ed25519.SignatureSize*2)
	payload, err := contracts.CanonicalJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	firstFrame, firstMeta, err := durablefile.EncodeFrame(
		recovery.Records[0].Payload,
		[32]byte{},
		actionJournalMaxFrame,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondFrame, _, err := durablefile.EncodeFrame(
		payload,
		firstMeta.Hash,
		actionJournalMaxFrame,
	)
	if err != nil {
		t.Fatal(err)
	}
	tampered := make([]byte, 0, len(firstFrame)+len(secondFrame)+4)
	tampered = append(tampered, firstFrame...)
	tampered = append(tampered, secondFrame...)
	tampered = append(tampered, []byte("AGF1")...)
	if err := os.WriteFile(actionJournalPath(root), tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if opened, err := OpenService(root, fixture.key,
		WithObserver(fixture.observer),
		WithTargetResolver(fixture.target),
		WithSafetyProvider(fixture.safety),
		WithClock(fixture.clock),
	); err == nil || opened != nil {
		t.Fatalf("tampered journal opened: service=%v err=%v", opened, err)
	}
	after, err := os.ReadFile(actionJournalPath(root))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, tampered) {
		t.Fatal("semantic corruption prefix was destructively tail-repaired")
	}
}
