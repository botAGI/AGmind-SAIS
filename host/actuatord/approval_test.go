package actuatord

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

var testRootAdmin = AdminAuthority{
	UID:                0,
	GID:                0,
	AuthorizationBasis: "root",
}

func approvalFixture(t *testing.T) (prepareFixture, *ClockSample) {
	t.Helper()
	fixture := newPrepareFixture(t)
	sample, err := fixture.clock()
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock = func() (ClockSample, error) { return sample, nil }
	return fixture, &sample
}

func exactPlanRef(plan contracts.PreparedTemporaryEgressDenyPlanV1) ExactPlanRef {
	return ExactPlanRef{
		PlanID:        plan.PlanID,
		PlanHashValue: plan.PlanHashValue,
		Nonce:         plan.Nonce,
	}
}

func TestApprovalConsumesExactPlanOnceAcrossRaceRestartAndFsync(t *testing.T) {
	if err := validateRecoveredCapacity(recoveredActionState{
		byPlan:      map[string]preparedState{"open": {}},
		outcomes:    map[string]PlanOutcome{},
		recordCount: actionJournalMaxRecords,
	}, 0); err == nil {
		t.Fatal("recovery accepted journal without terminal capacity")
	}
	fixture, sample := approvalFixture(t)
	root := t.TempDir()
	service := openFixtureService(t, root, fixture)
	plan, err := service.Prepare(context.Background(), fixture.intent)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := service.GetPlan(plan.PlanID)
	if err != nil || !reflect.DeepEqual(stored, plan) {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}
	stored.EvidenceIDs[0] = "caller-mutated"
	storedAgain, err := service.GetPlan(plan.PlanID)
	if err != nil || !reflect.DeepEqual(storedAgain, plan) {
		t.Fatalf("stored alias escaped: plan=%+v err=%v", storedAgain, err)
	}

	ref := exactPlanRef(plan)
	badHash := ref
	badHash.PlanHashValue = strings.Repeat("f", 64)
	if _, err := service.Approve(context.Background(), testRootAdmin, badHash); !errors.Is(err, ErrApprovalMismatch) {
		t.Fatalf("modified hash err=%v", err)
	}
	badNonce := ref
	badNonce.Nonce = strings.Repeat("e", 64)
	if _, err := service.Approve(context.Background(), testRootAdmin, badNonce); !errors.Is(err, ErrApprovalMismatch) {
		t.Fatalf("modified nonce err=%v", err)
	}
	if _, exists := service.Outcome(plan.PlanID); exists {
		t.Fatal("mismatch consumed approval")
	}

	sample.Wall = sample.Wall.Add(time.Second)
	sample.BootTimeNS++
	type result struct {
		record contracts.ActionRecordV1
		err    error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	go func() {
		ready.Done()
		<-start
		record, err := service.Approve(context.Background(), testRootAdmin, ref)
		results <- result{record: record, err: err}
	}()
	go func() {
		ready.Done()
		<-start
		record, err := service.Reject(context.Background(), testRootAdmin, ref)
		results <- result{record: record, err: err}
	}()
	ready.Wait()
	close(start)
	first, second := <-results, <-results
	successes, replays := 0, 0
	var winner contracts.ActionRecordV1
	for _, candidate := range []result{first, second} {
		switch {
		case candidate.err == nil:
			successes++
			winner = candidate.record
		case errors.Is(candidate.err, ErrApprovalReplay):
			replays++
		default:
			t.Fatalf("unexpected decision err=%v", candidate.err)
		}
	}
	if successes != 1 || replays != 1 ||
		(winner.State != "APPROVED" && winner.State != "REJECTED") {
		t.Fatalf("successes=%d replays=%d winner=%+v", successes, replays, winner)
	}
	outcome, exists := service.Outcome(plan.PlanID)
	if !exists || outcome.State != winner.State ||
		outcome.RecordSHA256 != winner.RecordSHA256 {
		t.Fatalf("outcome=%+v exists=%t winner=%+v", outcome, exists, winner)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openFixtureService(t, root, fixture)
	recovered, exists := reopened.Outcome(plan.PlanID)
	if !exists || recovered != outcome {
		t.Fatalf("recovered=%+v exists=%t want=%+v", recovered, exists, outcome)
	}
	if _, err := reopened.Approve(context.Background(), testRootAdmin, ref); !errors.Is(err, ErrApprovalReplay) {
		t.Fatalf("restart replay err=%v", err)
	}

	t.Run("terminal fsync ambiguity is fenced and recovered", func(t *testing.T) {
		candidate, candidateSample := approvalFixture(t)
		candidateRoot := t.TempDir()
		syncCalls := 0
		injected := errors.New("injected terminal sync failure")
		failed := openFixtureService(t, candidateRoot, candidate, withJournalOptions(
			durablefile.WithSync(func(file *os.File) error {
				syncCalls++
				if syncCalls == 3 {
					return injected
				}
				return file.Sync()
			}),
		))
		candidatePlan, err := failed.Prepare(context.Background(), candidate.intent)
		if err != nil {
			t.Fatal(err)
		}
		candidateSample.Wall = candidateSample.Wall.Add(time.Second)
		candidateSample.BootTimeNS++
		candidateRef := exactPlanRef(candidatePlan)
		if _, err := failed.Approve(context.Background(), testRootAdmin, candidateRef); !errors.Is(err, injected) {
			t.Fatalf("terminal sync err=%v", err)
		}
		if _, exists := failed.Outcome(candidatePlan.PlanID); exists {
			t.Fatal("uncertain terminal mutated in-memory authority")
		}
		if _, err := failed.Approve(context.Background(), testRootAdmin, candidateRef); !errors.Is(err, durablefile.ErrJournalFailed) {
			t.Fatalf("unfenced terminal retry err=%v", err)
		}
		if err := failed.Close(); err != nil {
			t.Fatal(err)
		}
		recoveredService := openFixtureService(t, candidateRoot, candidate)
		if recovered, exists := recoveredService.Outcome(candidatePlan.PlanID); !exists || recovered.State != "APPROVED" {
			t.Fatalf("uncertain durable outcome=%+v exists=%t", recovered, exists)
		}
	})
}

func TestApprovalDeadlineUsesWallBootTimeAndBootIdentity(t *testing.T) {
	baseWall := time.Date(2026, 7, 27, 12, 0, 2, 0, time.UTC)
	baseBoot := uint64(1_000_000_000_000)
	baseBootID := "123e4567-e89b-42d3-a456-426614174001"
	cases := []struct {
		name       string
		sample     ClockSample
		want       error
		wantExpiry bool
	}{
		{
			name: "exact wall deadline",
			sample: ClockSample{
				Wall:       baseWall.Add(ApprovalTTL),
				BootTimeNS: baseBoot + 1,
				BootID:     baseBootID,
			},
			want:       ErrApprovalExpired,
			wantExpiry: true,
		},
		{
			name: "exact monotonic deadline",
			sample: ClockSample{
				Wall:       baseWall.Add(time.Second),
				BootTimeNS: baseBoot + uint64(ApprovalTTL),
				BootID:     baseBootID,
			},
			want:       ErrApprovalExpired,
			wantExpiry: true,
		},
		{
			name: "host reboot",
			sample: ClockSample{
				Wall:       baseWall.Add(time.Second),
				BootTimeNS: baseBoot + 1,
				BootID:     "123e4567-e89b-42d3-a456-426614174002",
			},
			want:       ErrApprovalExpired,
			wantExpiry: true,
		},
		{
			name: "wall rollback",
			sample: ClockSample{
				Wall:       baseWall.Add(-time.Nanosecond),
				BootTimeNS: baseBoot + 1,
				BootID:     baseBootID,
			},
			want: ErrApprovalClock,
		},
		{
			name: "wall rollback after monotonic deadline",
			sample: ClockSample{
				Wall:       baseWall.Add(-time.Nanosecond),
				BootTimeNS: baseBoot + uint64(ApprovalTTL),
				BootID:     baseBootID,
			},
			want:       ErrApprovalExpired,
			wantExpiry: true,
		},
		{
			name: "monotonic rollback",
			sample: ClockSample{
				Wall:       baseWall.Add(time.Second),
				BootTimeNS: baseBoot - 1,
				BootID:     baseBootID,
			},
			want: ErrApprovalClock,
		},
		{
			name: "monotonic rollback after wall deadline",
			sample: ClockSample{
				Wall:       baseWall.Add(ApprovalTTL),
				BootTimeNS: baseBoot - 1,
				BootID:     baseBootID,
			},
			want:       ErrApprovalExpired,
			wantExpiry: true,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture, sample := approvalFixture(t)
			service := openFixtureService(t, t.TempDir(), fixture)
			plan, err := service.Prepare(context.Background(), fixture.intent)
			if err != nil {
				t.Fatal(err)
			}
			*sample = testCase.sample
			if _, err := service.Approve(
				context.Background(),
				testRootAdmin,
				exactPlanRef(plan),
			); !errors.Is(err, testCase.want) {
				t.Fatalf("approval err=%v want=%v", err, testCase.want)
			}
			outcome, exists := service.Outcome(plan.PlanID)
			if exists != testCase.wantExpiry ||
				exists && outcome.State != "EXPIRED_UNAPPLIED" {
				t.Fatalf("outcome=%+v exists=%t", outcome, exists)
			}
		})
	}
	t.Run("restart sweeps untouched expiry", func(t *testing.T) {
		fixture, sample := approvalFixture(t)
		root := t.TempDir()
		service := openFixtureService(t, root, fixture)
		plan, err := service.Prepare(context.Background(), fixture.intent)
		if err != nil {
			t.Fatal(err)
		}
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
		*sample = ClockSample{
			Wall:       baseWall.Add(ApprovalTTL),
			BootTimeNS: baseBoot + 1,
			BootID:     baseBootID,
		}
		reopened := openFixtureService(t, root, fixture)
		outcome, exists := reopened.Outcome(plan.PlanID)
		if !exists || outcome.State != "EXPIRED_UNAPPLIED" || reopened.Pending() != 0 {
			t.Fatalf("startup outcome=%+v exists=%t pending=%d", outcome, exists, reopened.Pending())
		}
	})
}
