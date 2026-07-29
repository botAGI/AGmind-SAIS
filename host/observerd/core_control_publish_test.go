package observerd

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

func boundCompletion(
	authorization EvidenceRepairAuthorizeV1,
	publication CoreControlPublication,
) EvidenceRepairCompleteV1 {
	completion := coreControlCompleteFixture()
	completion.RepairID = authorization.RepairID
	completion.AuthorizationEventID = publication.Item.EventID
	completion.AuthorizationContentSHA256 = publication.Item.ContentSHA256
	completion.SegmentID = authorization.SegmentID
	completion.VerifiedBytes = authorization.VerifiedBytes
	completion.LastVerifiedFrameSHA256 = authorization.LastVerifiedFrameSHA256
	completion.CurrentChainHeadSHA256 = authorization.CurrentChainHeadSHA256
	return completion
}

func TestPublishCoreControl(t *testing.T) {
	t.Run("publishes protected context and returns exact durable retry", func(t *testing.T) {
		service, state, spool, _, _ := observerServiceFixture(t)
		request := coreControlAuthorizeFixture()
		before := state.Snapshot().LastSequence

		first, err := service.PublishCoreControl(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if !first.Created || first.Item.Sequence != before+1 {
			t.Fatalf("first publication=%+v before=%d", first, before)
		}
		if err := validateCoreControlPublication(request, first); err != nil {
			t.Fatal(err)
		}
		requestSHA256, err := CoreControlRequestSHA256(request)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := spool.LookupControl(request.OperationKey(), requestSHA256)
		if err != nil {
			t.Fatal(err)
		}
		if !coreControlEventsEqual(stored, first.Item) {
			t.Fatalf("receipt item=%+v publication=%+v", stored, first.Item)
		}

		retry, err := service.PublishCoreControl(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if retry.Created || !coreControlEventsEqual(retry.Item, first.Item) {
			t.Fatalf("retry=%+v first=%+v", retry, first)
		}
		if got := state.Snapshot().LastSequence; got != before+1 {
			t.Fatalf("retry changed sequence to %d", got)
		}
	})

	t.Run("same operation key with different body fences without sequence", func(t *testing.T) {
		service, state, _, _, _ := observerServiceFixture(t)
		request := coreControlAuthorizeFixture()
		if _, err := service.PublishCoreControl(
			context.Background(),
			request,
		); err != nil {
			t.Fatal(err)
		}
		before := state.Snapshot().LastSequence
		conflict := request
		conflict.DiscardedBytes++

		if _, err := service.PublishCoreControl(
			context.Background(),
			conflict,
		); !errors.Is(err, ErrCoreOperationConflict) {
			t.Fatalf("conflict err=%v", err)
		}
		snapshot := state.Snapshot()
		if snapshot.LastSequence != before ||
			!snapshot.MutationReadOnly ||
			snapshot.ReadOnlyReason != "observer_core_operation_conflict" {
			t.Fatalf("conflict state=%+v before=%d", snapshot, before)
		}
	})

	t.Run("completion requires exact retained authorization binding", func(t *testing.T) {
		service, state, _, _, _ := observerServiceFixture(t)
		before := state.Snapshot().LastSequence
		if _, err := service.PublishCoreControl(
			context.Background(),
			coreControlCompleteFixture(),
		); !errors.Is(err, ErrCoreAuthorizationBinding) {
			t.Fatalf("missing authorization err=%v", err)
		}
		if got := state.Snapshot().LastSequence; got != before {
			t.Fatalf("missing authorization reserved sequence %d -> %d", before, got)
		}
		pointerCompletion := coreControlCompleteFixture()
		if _, err := service.PublishCoreControl(
			context.Background(),
			&pointerCompletion,
		); !errors.Is(err, ErrCoreAuthorizationBinding) {
			t.Fatalf("pointer completion bypassed authorization: %v", err)
		}
		if got := state.Snapshot().LastSequence; got != before {
			t.Fatalf("pointer completion reserved sequence %d -> %d", before, got)
		}

		authorization := coreControlAuthorizeFixture()
		authorized, err := service.PublishCoreControl(
			context.Background(),
			authorization,
		)
		if err != nil {
			t.Fatal(err)
		}
		completion := boundCompletion(authorization, authorized)
		completed, err := service.PublishCoreControl(
			context.Background(),
			completion,
		)
		if err != nil {
			t.Fatal(err)
		}
		if !completed.Created {
			t.Fatal("bound completion was not created")
		}
		if err := validateCoreControlPublication(completion, completed); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("every duplicated authorization fact binds before reserve", func(t *testing.T) {
		cases := map[string]func(*EvidenceRepairCompleteV1){
			"authorization event": func(value *EvidenceRepairCompleteV1) {
				value.AuthorizationEventID = "evt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			},
			"authorization content": func(value *EvidenceRepairCompleteV1) {
				value.AuthorizationContentSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			},
			"segment": func(value *EvidenceRepairCompleteV1) {
				value.SegmentID = "99999999-9999-4999-8999-999999999999"
			},
			"verified bytes": func(value *EvidenceRepairCompleteV1) {
				value.VerifiedBytes++
			},
			"last frame": func(value *EvidenceRepairCompleteV1) {
				value.LastVerifiedFrameSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			},
			"chain head": func(value *EvidenceRepairCompleteV1) {
				value.CurrentChainHeadSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			},
		}
		for name, mutate := range cases {
			t.Run(name, func(t *testing.T) {
				service, state, _, _, _ := observerServiceFixture(t)
				authorization := coreControlAuthorizeFixture()
				authorized, err := service.PublishCoreControl(
					context.Background(),
					authorization,
				)
				if err != nil {
					t.Fatal(err)
				}
				completion := boundCompletion(authorization, authorized)
				mutate(&completion)
				before := state.Snapshot().LastSequence
				if _, err := service.PublishCoreControl(
					context.Background(),
					completion,
				); !errors.Is(err, ErrCoreAuthorizationBinding) {
					t.Fatalf("binding err=%v", err)
				}
				if got := state.Snapshot().LastSequence; got != before {
					t.Fatalf("binding failure reserved sequence %d -> %d", before, got)
				}
			})
		}
	})

	t.Run("capacity preflight fails before sequence reservation", func(t *testing.T) {
		service, state, spool, _, _ := observerServiceFixture(t)
		spool.config.MaxBytes =
			spool.totalBytes + ackJournalMaxFrameBytes + 1
		before := state.Snapshot().LastSequence

		if _, err := service.PublishCoreControl(
			context.Background(),
			coreControlAuthorizeFixture(),
		); !errors.Is(err, ErrPriorityQuota) {
			t.Fatalf("preflight err=%v", err)
		}
		if got := state.Snapshot().LastSequence; got != before {
			t.Fatalf("preflight reserved sequence %d -> %d", before, got)
		}
	})

	t.Run("concurrent exact requests publish once", func(t *testing.T) {
		service, state, _, _, _ := observerServiceFixture(t)
		request := coreControlBlockedFixture()
		before := state.Snapshot().LastSequence
		const callers = 4
		results := make([]CoreControlPublication, callers)
		errorsByCaller := make([]error, callers)
		var wait sync.WaitGroup
		wait.Add(callers)
		for index := 0; index < callers; index++ {
			go func(index int) {
				defer wait.Done()
				results[index], errorsByCaller[index] = service.PublishCoreControl(
					context.Background(),
					request,
				)
			}(index)
		}
		wait.Wait()
		created := 0
		for index := range results {
			if errorsByCaller[index] != nil {
				t.Fatalf("caller %d: %v", index, errorsByCaller[index])
			}
			if results[index].Created {
				created++
			}
			if !coreControlEventsEqual(results[index].Item, results[0].Item) {
				t.Fatalf("caller %d received a different durable item", index)
			}
		}
		if created != 1 || state.Snapshot().LastSequence != before+1 {
			t.Fatalf(
				"created=%d sequence=%d want=%d",
				created,
				state.Snapshot().LastSequence,
				before+1,
			)
		}
	})

	t.Run("retry survives ack and restart with the exact outer item", func(t *testing.T) {
		service, state, spool, _, _ := observerServiceFixture(t)
		request := coreControlTombstoneFixture()
		first, err := service.PublishCoreControl(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if err := spool.Ack(
			first.Item.Sequence,
			first.Item.EventID,
			first.Item.ContentSHA256,
		); err != nil {
			t.Fatal(err)
		}
		afterAck, err := service.PublishCoreControl(context.Background(), request)
		if err != nil ||
			afterAck.Created ||
			!coreControlEventsEqual(afterAck.Item, first.Item) {
			t.Fatalf("post-ACK retry=%+v error=%v", afterAck, err)
		}

		config := spool.config
		identity := state.Snapshot()
		privateKey := append(
			ed25519.PrivateKey(nil),
			service.daemon.signer.privateKey...,
		)
		signerConfig := service.daemon.signer.config
		if err := spool.Close(); err != nil {
			t.Fatal(err)
		}
		restartedState, err := OpenStateStore(
			filepath.Join(config.StateDir, "observer-state.json"),
			StateIdentity{
				HostID:   identity.HostID,
				BootID:   identity.BootID,
				KeyID:    identity.KeyID,
				KeyEpoch: identity.KeyEpoch,
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		keys := NewKeyring()
		if err := keys.Add(
			identity.KeyEpoch,
			privateKey.Public().(ed25519.PublicKey),
		); err != nil {
			t.Fatal(err)
		}
		restartedSpool, err := NewSpool(config, restartedState, keys)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = restartedSpool.Close() })
		restartedSigner, err := NewEnvelopeSigner(
			signerConfig,
			restartedState,
			restartedSpool,
			privateKey,
		)
		if err != nil {
			t.Fatal(err)
		}
		restartedService := newObserverService(
			&Daemon{
				state:  restartedState,
				spool:  restartedSpool,
				signer: restartedSigner,
			},
			service.inventory,
			service.docker,
			service.now,
		)
		restarted, err := restartedService.PublishCoreControl(
			context.Background(),
			request,
		)
		if err != nil ||
			restarted.Created ||
			!coreControlEventsEqual(restarted.Item, first.Item) ||
			restartedState.Snapshot().LastSequence != first.Item.Sequence {
			t.Fatalf(
				"restart retry=%+v state=%+v error=%v",
				restarted,
				restartedState.Snapshot(),
				err,
			)
		}
	})
}
