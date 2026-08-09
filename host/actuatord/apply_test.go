package actuatord

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

type applyTestTarget struct {
	*prepareTarget
	hostNetNS uint64
	rechecks  int
	applyOpen int
}

type applyTestTargetHandle struct {
	target *applyTestTarget
	closed bool
}

func (target *applyTestTarget) OpenForApply(
	_ context.Context,
	_ string,
	_ uint64,
) (ApplyTargetHandle, error) {
	target.applyOpen++
	return &applyTestTargetHandle{target: target}, nil
}

func (handle *applyTestTargetHandle) Snapshot() PrepareTargetSnapshot {
	return handle.target.snapshot
}

func (handle *applyTestTargetHandle) NetNSFD() int { return 9 }

func (handle *applyTestTargetHandle) HostNetworkNamespaceInode() uint64 {
	return handle.target.hostNetNS
}

func (handle *applyTestTargetHandle) Recheck(context.Context) error {
	handle.target.rechecks++
	return nil
}

func (handle *applyTestTargetHandle) Close() error {
	handle.closed = true
	return nil
}

type applyTestBackend struct {
	prepareCalls        int
	flushCalls          int
	inspectCalls        int
	beforeFlush         func()
	observation         ApplyObservation
	expiryObservation   ExpiryObservation
	recoveryObservation ApplyObservation
	recoveryPresent     bool
	recoveryCalls       int
	flushErr            error
	inspectErr          error
	recoveryErr         error
}

type applyTestMutation struct {
	backend *applyTestBackend
	flushed bool
}

func (backend *applyTestBackend) Prepare(
	_ context.Context,
	_ ApplyTargetHandle,
	_ NftApplySpec,
) (PreparedNftMutation, error) {
	backend.prepareCalls++
	return &applyTestMutation{backend: backend}, nil
}

func (mutation *applyTestMutation) ExpectedRulesetSHA256() string {
	return mutation.backend.observation.RulesetSHA256
}

func (mutation *applyTestMutation) FlushOnceAndVerify(
	context.Context,
) (ApplyObservation, error) {
	if mutation.flushed {
		return ApplyObservation{}, errors.New("second flush")
	}
	mutation.flushed = true
	mutation.backend.flushCalls++
	if mutation.backend.beforeFlush != nil {
		mutation.backend.beforeFlush()
	}
	return mutation.backend.observation, mutation.backend.flushErr
}

func (*applyTestMutation) Close() error { return nil }

func (backend *applyTestBackend) InspectExpiry(
	_ context.Context,
	_ ApplyTargetHandle,
	_ NftApplySpec,
) (ExpiryObservation, error) {
	backend.inspectCalls++
	return backend.expiryObservation, backend.inspectErr
}

func (backend *applyTestBackend) InspectApplied(
	_ context.Context,
	_ ApplyTargetHandle,
	_ NftApplySpec,
) (ApplyObservation, bool, error) {
	backend.recoveryCalls++
	return backend.recoveryObservation, backend.recoveryPresent, backend.recoveryErr
}

func approvedApplyService(
	t *testing.T,
	backend *applyTestBackend,
	syncHook func(*os.File) error,
) (*Service, prepareFixture, contracts.PreparedTemporaryEgressDenyPlanV1, string) {
	t.Helper()
	fixture, sample := approvalFixture(t)
	target := &applyTestTarget{
		prepareTarget: fixture.target,
		hostNetNS:     9001,
	}
	fixture.target = target.prepareTarget
	fixture.observer.target = target.prepareTarget
	root := t.TempDir()
	options := []ServiceOption{
		WithApplyTargetResolver(target),
		WithNftBackend(backend),
	}
	if syncHook != nil {
		options = append(options, withJournalOptions(durablefile.WithSync(syncHook)))
	}
	service := openFixtureService(t, root, fixture, options...)
	plan, err := service.Prepare(context.Background(), fixture.intent)
	if err != nil {
		t.Fatal(err)
	}
	sample.Wall = sample.Wall.Add(time.Second)
	sample.BootTimeNS++
	if _, err := service.Approve(
		context.Background(),
		testRootAdmin,
		exactPlanRef(plan),
	); err != nil {
		t.Fatal(err)
	}
	return service, fixture, plan, root
}

func TestApplyNextFsyncsAttemptBeforeOneFlushAndCommitsVerified(t *testing.T) {
	syncCalls := 0
	backend := &applyTestBackend{observation: ApplyObservation{
		TargetNetNSInode:              789,
		RulesetSHA256:                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ConfiguredTimeoutMilliseconds: 120_000,
		RemainingTimeoutMilliseconds:  119_000,
		CounterPackets:                0,
		CounterBytes:                  0,
		HostNetNSBefore:               9001,
		HostNetNSAfter:                9001,
	}}
	backend.beforeFlush = func() {
		if syncCalls < 4 {
			t.Fatalf("flush before durable APPLY_INTENT: syncs=%d", syncCalls)
		}
	}
	service, fixture, plan, root := approvedApplyService(
		t,
		backend,
		func(file *os.File) error {
			syncCalls++
			return file.Sync()
		},
	)
	record, err := service.ApplyNext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != "VERIFIED" || record.PlanID != plan.PlanID ||
		backend.prepareCalls != 1 || backend.flushCalls != 1 || syncCalls != 6 {
		t.Fatalf(
			"record=%+v prepare=%d flush=%d sync=%d",
			record,
			backend.prepareCalls,
			backend.flushCalls,
			syncCalls,
		)
	}
	outcome, ok := service.Outcome(plan.PlanID)
	if !ok || outcome.State != "VERIFIED" {
		t.Fatalf("outcome=%+v ok=%t", outcome, ok)
	}
	if _, err := service.ApplyNext(context.Background()); !errors.Is(err, ErrNoApprovedPlan) {
		t.Fatalf("duplicate apply err=%v", err)
	}
	current, err := service.dependencies.clock()
	if err != nil {
		t.Fatal(err)
	}
	current.Wall = current.Wall.Add(125 * time.Second)
	current.BootTimeNS += uint64(125 * time.Second)
	service.dependencies.clock = func() (ClockSample, error) { return current, nil }
	fixture.observer.identity.ObservedAt = current.Wall.Add(-2 * time.Second).Format(time.RFC3339Nano)
	fixture.observer.integrity.ObservedAt = current.Wall.Add(-time.Second).Format(time.RFC3339Nano)
	fixture.observer.unique.CheckedAt = current.Wall.Add(-time.Second).Format(time.RFC3339Nano)
	backend.expiryObservation = ExpiryObservation{
		TargetNetNSInode: 789,
		RulesetSHA256:    backend.observation.RulesetSHA256,
		ElementPresent:   false,
		HostNetNSBefore:  9001,
		HostNetNSAfter:   9001,
	}
	if count, err := service.ExpireDue(context.Background()); err != nil || count != 1 {
		t.Fatalf("expiry count=%d err=%v", count, err)
	}
	expired, ok := service.Outcome(plan.PlanID)
	if !ok || expired.State != "EXPIRED" || backend.inspectCalls != 1 ||
		backend.flushCalls != 1 || syncCalls != 7 {
		t.Fatalf(
			"expired=%+v ok=%t inspect=%d flush=%d sync=%d",
			expired,
			ok,
			backend.inspectCalls,
			backend.flushCalls,
			syncCalls,
		)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openFixtureService(t, root, fixture)
	recovered, ok := reopened.Outcome(plan.PlanID)
	if !ok || recovered.State != "EXPIRED" ||
		recovered.RecordSHA256 != expired.RecordSHA256 {
		t.Fatalf("recovered=%+v ok=%t", recovered, ok)
	}
}

func TestApplyNextFailsClosedWithoutTestMatrixExplosion(t *testing.T) {
	t.Run("container restart proves old generation absent", func(t *testing.T) {
		fixture := newPrepareFixture(t)
		service := openFixtureService(t, t.TempDir(), fixture)
		plan, err := service.Prepare(context.Background(), fixture.intent)
		if err != nil {
			t.Fatal(err)
		}
		fixture.observer.identity.DockerStartedAt = "2026-07-27T12:00:00.5Z"
		_, absent, err := service.observeContainerGeneration(context.Background(), plan)
		if err != nil || !absent {
			t.Fatalf("old generation absent=%t err=%v", absent, err)
		}
	})

	t.Run("recovery rejects re-added or extended element", func(t *testing.T) {
		const planID = "plan"
		journal := &actionJournal{
			attempts: map[string]applyAttemptState{planID: {
				BootID:     "123e4567-e89b-42d3-a456-426614174001",
				BootTimeNS: uint64(time.Second),
			}},
			applied: map[string]appliedActionState{planID: {Observation: ApplyObservation{
				RemainingTimeoutMilliseconds: 119_000,
				CounterPackets:               5,
				CounterBytes:                 500,
			}}},
		}
		fresh := ClockSample{BootID: journal.attempts[planID].BootID, BootTimeNS: uint64(2 * time.Second)}
		extended := ApplyObservation{
			RemainingTimeoutMilliseconds: 119_001,
			CounterPackets:               5,
			CounterBytes:                 500,
		}
		if recoveryObservationBounded(journal, planID, PlanOutcome{State: "APPLIED"}, extended, fresh, 120*time.Second) {
			t.Fatal("accepted timeout extension after durable APPLIED")
		}
		readded := ApplyObservation{RemainingTimeoutMilliseconds: 120_000}
		late := ClockSample{BootID: fresh.BootID, BootTimeNS: uint64(30 * time.Second)}
		if recoveryObservationBounded(journal, planID, PlanOutcome{State: "APPROVED"}, readded, late, 120*time.Second) {
			t.Fatal("accepted re-added full-TTL element")
		}
	})

	t.Run("stale target never reaches backend", func(t *testing.T) {
		backend := &applyTestBackend{}
		service, fixture, plan, _ := approvedApplyService(t, backend, nil)
		fixture.observer.identity.DockerStartedAt = "2026-07-27T11:59:59Z"
		if _, err := service.ApplyNext(context.Background()); !errors.Is(err, ErrTargetStale) {
			t.Fatalf("stale err=%v", err)
		}
		if backend.prepareCalls != 0 || backend.flushCalls != 0 {
			t.Fatalf("backend calls prepare=%d flush=%d", backend.prepareCalls, backend.flushCalls)
		}
		outcome, ok := service.Outcome(plan.PlanID)
		if !ok || outcome.State != "STALE_ABORT" {
			t.Fatalf("outcome=%+v ok=%t", outcome, ok)
		}
	})

	t.Run("attempt sync failure makes zero kernel calls", func(t *testing.T) {
		backend := &applyTestBackend{observation: ApplyObservation{
			RulesetSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}}
		syncs := 0
		injected := errors.New("attempt sync failed")
		service, _, _, _ := approvedApplyService(t, backend, func(file *os.File) error {
			syncs++
			if syncs == 4 {
				return injected
			}
			return file.Sync()
		})
		if _, err := service.ApplyNext(context.Background()); !errors.Is(err, injected) {
			t.Fatalf("apply err=%v", err)
		}
		if backend.flushCalls != 0 {
			t.Fatalf("kernel flushes=%d", backend.flushCalls)
		}
	})

	t.Run("ambiguous mutation latches FAILED_DIRTY", func(t *testing.T) {
		backend := &applyTestBackend{
			observation: ApplyObservation{
				RulesetSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			flushErr: ErrNftMutationUncertain,
		}
		service, _, plan, _ := approvedApplyService(t, backend, nil)
		if _, err := service.ApplyNext(context.Background()); !errors.Is(err, ErrNftMutationUncertain) {
			t.Fatalf("apply err=%v", err)
		}
		outcome, ok := service.Outcome(plan.PlanID)
		if !ok || outcome.State != "FAILED_DIRTY" || !service.KillSwitchActive() {
			t.Fatalf("outcome=%+v ok=%t kill=%t", outcome, ok, service.KillSwitchActive())
		}
		if _, err := service.ApplyNext(context.Background()); !errors.Is(err, ErrKillSwitchActive) {
			t.Fatalf("kill switch err=%v", err)
		}
	})

	t.Run("restart reconciles attempt without a second flush", func(t *testing.T) {
		observation := ApplyObservation{
			TargetNetNSInode:              789,
			RulesetSHA256:                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ConfiguredTimeoutMilliseconds: 120_000,
			RemainingTimeoutMilliseconds:  118_000,
			HostNetNSBefore:               9001,
			HostNetNSAfter:                9001,
		}
		backend := &applyTestBackend{
			observation:         observation,
			recoveryObservation: observation,
			recoveryPresent:     true,
		}
		syncs := 0
		injected := errors.New("applied sync ambiguity")
		service, fixture, plan, root := approvedApplyService(
			t,
			backend,
			func(file *os.File) error {
				syncs++
				if syncs == 5 {
					return injected
				}
				return file.Sync()
			},
		)
		if _, err := service.ApplyNext(context.Background()); !errors.Is(err, ErrNftMutationUncertain) {
			t.Fatalf("apply err=%v", err)
		}
		if backend.flushCalls != 1 {
			t.Fatalf("flushes before restart=%d", backend.flushCalls)
		}
		_ = service.Close()
		// Unrelated observer reconciliation may advance the global inventory;
		// read-only recovery remains bound to the exact container/netns generation.
		fixture.observer.integrity.InventoryGeneration++
		fixture.observer.identity.InventoryGeneration++
		fixture.observer.unique.InventoryGeneration++
		target := &applyTestTarget{
			prepareTarget: fixture.target,
			hostNetNS:     9001,
		}
		reopened := openFixtureService(
			t,
			root,
			fixture,
			WithApplyTargetResolver(target),
			WithNftBackend(backend),
		)
		outcome, ok := reopened.Outcome(plan.PlanID)
		if !ok || outcome.State != "VERIFIED" || backend.flushCalls != 1 ||
			backend.recoveryCalls != 1 {
			t.Fatalf(
				"outcome=%+v ok=%t flush=%d recovery=%d",
				outcome,
				ok,
				backend.flushCalls,
				backend.recoveryCalls,
			)
		}
	})
}
