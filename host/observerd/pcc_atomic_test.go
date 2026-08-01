package observerd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"agmind.local/sais/internal/durablefile"
)

type pccAtomicArtifacts struct {
	frame     bool
	prepared  bool
	published bool
}

type pccAtomicFileSnapshot struct {
	exists bool
	raw    []byte
}

func pccAtomicFileState(t *testing.T, path string) pccAtomicFileSnapshot {
	t.Helper()
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return pccAtomicFileSnapshot{}
	}
	if err != nil {
		t.Fatal(err)
	}
	return pccAtomicFileSnapshot{exists: true, raw: raw}
}

func assertPCCAtomicArtifacts(
	t *testing.T,
	spool *Spool,
	sequence uint64,
	want pccAtomicArtifacts,
) {
	t.Helper()
	for _, artifact := range []struct {
		name string
		path string
		want bool
	}{
		{
			name: "frame",
			path: filepath.Join(
				spool.directory(PriorityTier),
				fmt.Sprintf("%020d.agf", sequence),
			),
			want: want.frame,
		},
		{
			name: "prepared publication",
			path: publicationPreparedPath(spool.config.StateDir, sequence),
			want: want.prepared,
		},
		{
			name: "published publication",
			path: publicationPublishedPath(spool.config.StateDir, sequence),
			want: want.published,
		},
	} {
		_, err := os.Lstat(artifact.path)
		got := err == nil
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s lstat error=%v", artifact.name, err)
			continue
		}
		if got != artifact.want {
			t.Errorf("%s existence=%t want=%t path=%q", artifact.name, got, artifact.want, artifact.path)
		}
	}
}

func assertPCCAtomicRestartFailsClosed(
	t *testing.T,
	stage string,
	fixture *pccFailedPublishFixture,
	sequence uint64,
	operationKey string,
	before pccPublicationSurface,
	journalBefore pccAtomicFileSnapshot,
) {
	t.Helper()
	config := fixture.spool.config
	privateKey := fixture.service.daemon.signer.privateKey
	if err := fixture.spool.Close(); err != nil {
		t.Fatal(err)
	}
	identity := fixture.state.Snapshot()
	restartedState, err := OpenStateStore(
		fixture.state.path,
		StateIdentity{
			HostID: identity.HostID, BootID: identity.BootID,
			KeyID: identity.KeyID, KeyEpoch: identity.KeyEpoch,
		},
	)
	if err != nil {
		t.Fatalf("restart state open error=%v", err)
	}
	restarted, restartErr := NewSpool(
		config,
		restartedState,
		pccReceiptKeys(t, privateKey),
	)
	if restarted != nil {
		defer restarted.Close()
	}
	restartedSnapshot := restartedState.Snapshot()
	if !restartedSnapshot.MutationReadOnly ||
		restartedSnapshot.LastSequence != sequence ||
		restartedSnapshot.PublicationHeadSequence !=
			before.state.PublicationHeadSequence ||
		restartedSnapshot.PublicationHeadHash != before.state.PublicationHeadHash ||
		restartedSnapshot.PCCReceiptCount != before.state.PCCReceiptCount ||
		restartedSnapshot.PCCReceiptBytes != before.state.PCCReceiptBytes ||
		restartedSnapshot.PCCReceiptHeadHash != before.state.PCCReceiptHeadHash {
		t.Errorf("restart lost reserved/fenced evidence: %+v", restartedSnapshot)
	}
	switch stage {
	case "frame_error":
		if restartErr != nil || restarted == nil {
			t.Fatalf("prepared-only restart spool=%v err=%v", restarted, restartErr)
		}
		if restartedSnapshot.ReadOnlyReason != "observer_spool_write_uncertain" {
			t.Errorf("prepared-only restart reason=%q", restartedSnapshot.ReadOnlyReason)
		}
		if gaps := restarted.UncoveredGaps(sequence - 1); !reflect.DeepEqual(
			gaps,
			[]SequenceGap{{Start: sequence, End: sequence}},
		) {
			t.Errorf("prepared-only restart gaps=%+v", gaps)
		}
		assertPCCAtomicArtifacts(t, fixture.spool, sequence, pccAtomicArtifacts{})
	case "promote_error", "publication_head_state_error":
		if !errors.Is(restartErr, ErrPCCReceiptCorrupt) &&
			!errors.Is(restartErr, ErrSpoolCorrupt) {
			t.Errorf("receiptless PCC restart error=%v", restartErr)
		}
		if restarted != nil {
			t.Errorf("receiptless PCC restart returned live spool")
		}
		if restartedSnapshot.ReadOnlyReason != "observer_pcc_receipt_corrupt" {
			t.Errorf("receiptless PCC restart reason=%q", restartedSnapshot.ReadOnlyReason)
		}
		want := pccAtomicArtifacts{frame: true, prepared: true}
		if stage == "publication_head_state_error" {
			want = pccAtomicArtifacts{frame: true, published: true}
		}
		assertPCCAtomicArtifacts(t, fixture.spool, sequence, want)
	default:
		t.Fatalf("unsupported atomic restart stage %q", stage)
	}
	if restartErr == nil {
		if _, found := restarted.items[sequence]; found {
			t.Errorf("restart falsely adopted receiptless PCC sequence %d", sequence)
		}
		restarted.pccReceipts.mutex.Lock()
		_, found := restarted.pccReceipts.receipts[operationKey]
		restarted.pccReceipts.mutex.Unlock()
		if found {
			t.Errorf("restart synthesized PCC receipt metadata for %q", operationKey)
		}
	}
	journalAfter := pccAtomicFileState(
		t,
		pccReceiptJournalPath(config.StateDir),
	)
	if !reflect.DeepEqual(journalAfter, journalBefore) {
		t.Errorf("restart changed PCC receipt journal: before=%+v after=%+v", journalBefore, journalAfter)
	}
}

func TestPCCPublishAtomicFrameAndPublicationFailures(t *testing.T) {
	tests := []struct {
		name      string
		reason    string
		artifacts pccAtomicArtifacts
		restart   bool
		hookPaths int
	}{
		{
			name:      "prepare_error",
			reason:    "observer_spool_publication_prepare_failed",
			artifacts: pccAtomicArtifacts{},
			hookPaths: 1,
		},
		{
			name:      "frame_error",
			reason:    "observer_spool_write_uncertain",
			artifacts: pccAtomicArtifacts{prepared: true},
			restart:   true,
			hookPaths: 1,
		},
		{
			name:      "promote_error",
			reason:    "observer_spool_publication_promote_failed",
			artifacts: pccAtomicArtifacts{frame: true, prepared: true},
			restart:   true,
			hookPaths: 2,
		},
		{
			name:      "publication_head_state_error",
			reason:    "observer_publication_head_commit_failed",
			artifacts: pccAtomicArtifacts{frame: true, published: true},
			restart:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPCCFailedPublishFixture(t)
			before := observePCCPublicationSurface(fixture.state, fixture.spool)
			sequence := before.state.LastSequence + 1
			operationKey := "pcc_correlation_snapshot:" + fixture.request.TriggerEventID
			journalBefore := pccAtomicFileState(
				t,
				pccReceiptJournalPath(fixture.spool.config.StateDir),
			)
			injectedErr := fmt.Errorf("injected PCC atomic %s", test.name)
			hookPaths := []string{}
			switch test.name {
			case "prepare_error":
				fixture.spool.preparePublication = func(path string, _ []byte) error {
					hookPaths = append(hookPaths, path)
					return injectedErr
				}
			case "frame_error":
				fixture.spool.publish = func(path string, _ []byte) error {
					hookPaths = append(hookPaths, path)
					return injectedErr
				}
			case "promote_error":
				fixture.spool.promotePublication = func(source, destination string) error {
					hookPaths = append(hookPaths, source, destination)
					return injectedErr
				}
			case "publication_head_state_error":
				persist := fixture.state.persist
				fixture.state.persist = func(path string, next ObserverState) error {
					if next.PublicationHeadSequence == sequence &&
						!next.MutationReadOnly {
						return injectedErr
					}
					return persist(path, next)
				}
			default:
				t.Fatalf("unknown PCC atomic stage %q", test.name)
			}

			publication, err := fixture.service.PublishPCCCorrelationSnapshot(
				context.Background(),
				fixture.request,
			)
			if !errors.Is(err, injectedErr) {
				t.Errorf("publication error=%v want errors.Is %v", err, injectedErr)
			}
			if !reflect.DeepEqual(publication, PCCCorrelationPublication{}) {
				t.Errorf("atomic failure exposed publication=%+v", publication)
			}
			if len(hookPaths) != test.hookPaths {
				t.Errorf("atomic hook paths=%v want count=%d", hookPaths, test.hookPaths)
			}
			if test.name == "prepare_error" && len(hookPaths) == 1 &&
				hookPaths[0] != publicationPreparedPath(fixture.spool.config.StateDir, sequence) {
				t.Errorf("prepare hook path=%q", hookPaths[0])
			}
			if test.name == "frame_error" && len(hookPaths) == 1 &&
				hookPaths[0] != filepath.Join(
					fixture.spool.directory(PriorityTier),
					fmt.Sprintf("%020d.agf", sequence),
				) {
				t.Errorf("frame hook path=%q", hookPaths[0])
			}
			if test.name == "promote_error" && len(hookPaths) == 2 &&
				(hookPaths[0] != publicationPreparedPath(fixture.spool.config.StateDir, sequence) ||
					hookPaths[1] != publicationPublishedPath(fixture.spool.config.StateDir, sequence)) {
				t.Errorf("promote hook paths=%v", hookPaths)
			}

			after := observePCCPublicationSurface(fixture.state, fixture.spool)
			if after.state.LastSequence != sequence ||
				after.state.PublicationHeadSequence != before.state.PublicationHeadSequence ||
				after.state.PublicationHeadHash != before.state.PublicationHeadHash ||
				!after.state.MutationReadOnly ||
				after.state.ReadOnlyReason != test.reason {
				t.Errorf("atomic failure state=%+v want sequence=%d reason=%q", after.state, sequence, test.reason)
			}
			if after.state.PCCReceiptCount != before.state.PCCReceiptCount ||
				after.state.PCCReceiptBytes != before.state.PCCReceiptBytes ||
				after.state.PCCReceiptHeadHash != before.state.PCCReceiptHeadHash ||
				after.receiptAnchor != before.receiptAnchor ||
				!reflect.DeepEqual(after.receipts, before.receipts) {
				t.Errorf("atomic failure changed PCC receipt state: before=%+v after=%+v", before, after)
			}
			if after.totalBytes != before.totalBytes ||
				!reflect.DeepEqual(after.items, before.items) {
				t.Errorf("atomic failure adopted spool item/bytes: before=%+v after=%+v", before, after)
			}
			if _, found := after.receipts[operationKey]; found {
				t.Errorf("atomic failure exposed receipt metadata for %q", operationKey)
			}
			journalAfter := pccAtomicFileState(
				t,
				pccReceiptJournalPath(fixture.spool.config.StateDir),
			)
			if !reflect.DeepEqual(journalAfter, journalBefore) {
				t.Errorf("atomic failure changed PCC receipt journal: before=%+v after=%+v", journalBefore, journalAfter)
			}
			assertPCCAtomicArtifacts(t, fixture.spool, sequence, test.artifacts)
			if test.restart {
				assertPCCAtomicRestartFailsClosed(
					t,
					test.name,
					fixture,
					sequence,
					operationKey,
					before,
					journalBefore,
				)
			}
		})
	}
}

func assertPCCReceiptAtomicRestartFailsClosed(
	t *testing.T,
	fixture *pccFailedPublishFixture,
	sequence uint64,
	before pccPublicationSurface,
	journal []byte,
) {
	t.Helper()
	config := fixture.spool.config
	privateKey := fixture.service.daemon.signer.privateKey
	if err := fixture.spool.Close(); err != nil {
		t.Fatal(err)
	}
	recovery, err := durablefile.Recover(
		pccReceiptJournalPath(config.StateDir),
		pccReceiptMaxFrame,
	)
	if err != nil || recovery.TailRepaired || len(recovery.Records) != 1 ||
		recovery.VerifiedBytes != int64(len(journal)) {
		t.Fatalf("receipt journal recovery=%+v err=%v bytes=%d", recovery, err, len(journal))
	}
	identity := fixture.state.Snapshot()
	restartedState, err := OpenStateStore(
		fixture.state.path,
		StateIdentity{
			HostID: identity.HostID, BootID: identity.BootID,
			KeyID: identity.KeyID, KeyEpoch: identity.KeyEpoch,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	restarted, restartErr := NewSpool(
		config,
		restartedState,
		pccReceiptKeys(t, privateKey),
	)
	if restarted != nil {
		_ = restarted.Close()
		t.Errorf("receiptless PCC restart returned a live spool")
	}
	if !errors.Is(restartErr, ErrPCCReceiptCorrupt) ||
		!errors.Is(restartErr, ErrSpoolCorrupt) {
		t.Errorf("receiptless PCC restart error=%v", restartErr)
	}
	restartedSnapshot := restartedState.Snapshot()
	if !restartedSnapshot.MutationReadOnly ||
		restartedSnapshot.ReadOnlyReason != "observer_spool_root_unknown" ||
		restartedSnapshot.LastSequence != sequence ||
		restartedSnapshot.PublicationHeadSequence != sequence ||
		restartedSnapshot.PCCReceiptCount != before.state.PCCReceiptCount ||
		restartedSnapshot.PCCReceiptBytes != before.state.PCCReceiptBytes ||
		restartedSnapshot.PCCReceiptHeadHash != before.state.PCCReceiptHeadHash {
		t.Errorf("receiptless PCC restart state=%+v", restartedSnapshot)
	}
	journalAfter := pccAtomicFileState(
		t,
		pccReceiptJournalPath(config.StateDir),
	)
	if !journalAfter.exists || !bytes.Equal(journalAfter.raw, journal) {
		t.Errorf("receiptless PCC restart changed journal: got=%+v want=%x", journalAfter, journal)
	}
	assertPCCAtomicArtifacts(
		t,
		fixture.spool,
		sequence,
		pccAtomicArtifacts{frame: true, published: true},
	)
}

func TestPCCPublishAtomicReceiptFailures(t *testing.T) {
	tests := []struct {
		name   string
		reason string
	}{
		{
			name:   "receipt_append_sync_error",
			reason: "observer_pcc_receipt_append_failed",
		},
		{
			name:   "receipt_anchor_state_error",
			reason: "observer_pcc_receipt_anchor_failed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPCCFailedPublishFixture(t)
			before := observePCCPublicationSurface(fixture.state, fixture.spool)
			sequence := before.state.LastSequence + 1
			operationKey := "pcc_correlation_snapshot:" + fixture.request.TriggerEventID
			journalPath := pccReceiptJournalPath(fixture.spool.config.StateDir)
			if journalBefore := pccAtomicFileState(t, journalPath); journalBefore.exists {
				t.Fatalf("receipt failure fixture already has journal=%+v", journalBefore)
			}
			injectedErr := fmt.Errorf("injected PCC atomic %s", test.name)
			hookCalls := 0
			switch test.name {
			case "receipt_append_sync_error":
				if err := fixture.spool.pccReceipts.Close(); err != nil {
					t.Fatal(err)
				}
				receipts, err := openPCCReceiptStore(
					fixture.spool.config.StateDir,
					fixture.state,
					durablefile.WithSync(func(file *os.File) error {
						hookCalls++
						if err := file.Sync(); err != nil {
							return err
						}
						return injectedErr
					}),
				)
				if err != nil {
					t.Fatal(err)
				}
				receipts.spool = fixture.spool
				fixture.spool.pccReceipts = receipts
			case "receipt_anchor_state_error":
				persist := fixture.state.persist
				fixture.state.persist = func(path string, next ObserverState) error {
					if next.PCCReceiptCount == before.state.PCCReceiptCount+1 &&
						!next.MutationReadOnly {
						hookCalls++
						return injectedErr
					}
					return persist(path, next)
				}
			default:
				t.Fatalf("unknown PCC receipt atomic stage %q", test.name)
			}

			publication, err := fixture.service.PublishPCCCorrelationSnapshot(
				context.Background(),
				fixture.request,
			)
			if !errors.Is(err, injectedErr) {
				t.Fatalf(
					"publication error=%v want errors.Is %v hook_calls=%d created=%t sequence=%d",
					err,
					injectedErr,
					hookCalls,
					publication.Created,
					publication.Item.Sequence,
				)
			}
			if hookCalls != 1 {
				t.Errorf("receipt failure hook calls=%d want=1", hookCalls)
			}
			if !reflect.DeepEqual(publication, PCCCorrelationPublication{}) {
				t.Errorf("receipt failure exposed publication=%+v", publication)
			}

			after := observePCCPublicationSurface(fixture.state, fixture.spool)
			if after.state.LastSequence != sequence ||
				after.state.PublicationHeadSequence != sequence ||
				after.state.PublicationHeadHash == before.state.PublicationHeadHash ||
				!after.state.MutationReadOnly ||
				after.state.ReadOnlyReason != test.reason {
				t.Errorf("receipt failure state=%+v want sequence=%d reason=%q", after.state, sequence, test.reason)
			}
			if _, found := after.items[sequence]; !found ||
				after.totalBytes <= before.totalBytes {
				t.Errorf("receipt failure lost durable PCC item/bytes: before=%+v after=%+v", before, after)
			}
			if after.state.PCCReceiptCount != before.state.PCCReceiptCount ||
				after.state.PCCReceiptBytes != before.state.PCCReceiptBytes ||
				after.state.PCCReceiptHeadHash != before.state.PCCReceiptHeadHash ||
				after.receiptAnchor != before.receiptAnchor ||
				!reflect.DeepEqual(after.receipts, before.receipts) {
				t.Errorf("receipt failure adopted receipt metadata: before=%+v after=%+v", before, after)
			}
			if _, found := after.receipts[operationKey]; found {
				t.Errorf("receipt failure exposed receipt metadata for %q", operationKey)
			}
			journal := pccAtomicFileState(t, journalPath)
			if !journal.exists || len(journal.raw) == 0 {
				t.Errorf("receipt failure did not retain complete nonempty journal: %+v", journal)
			}
			assertPCCAtomicArtifacts(
				t,
				fixture.spool,
				sequence,
				pccAtomicArtifacts{frame: true, published: true},
			)
			assertPCCReceiptAtomicRestartFailsClosed(
				t,
				fixture,
				sequence,
				before,
				journal.raw,
			)
		})
	}
}
