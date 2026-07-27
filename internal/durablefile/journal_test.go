package durablefile_test

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"agmind.local/sais/internal/durablefile"
)

const completeGoldenFrameHex = "" +
	"4147463100000013" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"7b226b696e64223a22637269746963616c227d" +
	"bf7947a4" +
	"2cbb22fc60bedacd10fd4bfebc898289fd6b1bcfdcbfb113b2f64f1f08ed9556"

func TestJournalDoesNotAcknowledgeBeforeSyncAndRemainsPoisoned(t *testing.T) {
	syncErr := errors.New("injected fsync failure")
	journal, err := durablefile.NewJournal(
		filepath.Join(t.TempDir(), "events.log"),
		durablefile.WithSync(func(*os.File) error { return syncErr }),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })

	if _, err := journal.Append([]byte(`{"kind":"critical"}`), true); !errors.Is(
		err,
		syncErr,
	) {
		t.Fatalf("got %v, want fsync error", err)
	}
	if !journal.Failed() {
		t.Fatal("journal must remain failed after an uncertain sync")
	}
	if _, err := journal.Append([]byte(`{"kind":"later"}`), true); !errors.Is(
		err,
		durablefile.ErrJournalFailed,
	) {
		t.Fatalf("got %v, want ErrJournalFailed", err)
	}
}

func TestJournalShortWritePermanentlyPoisonsInstance(t *testing.T) {
	journal, err := durablefile.NewJournal(
		filepath.Join(t.TempDir(), "events.log"),
		durablefile.WithWrite(func(_ *os.File, value []byte) (int, error) {
			return len(value) - 1, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	if _, err := journal.Append([]byte(`{"n":1}`), false); !errors.Is(
		err,
		durablefile.ErrShortWrite,
	) {
		t.Fatalf("got %v, want ErrShortWrite", err)
	}
	if !journal.Failed() {
		t.Fatal("short write must poison journal")
	}
}

func TestCriticalAppendSyncsButRoutineAppendDoesNotClaimDurability(t *testing.T) {
	syncCalls := 0
	journal, err := durablefile.NewJournal(
		filepath.Join(t.TempDir(), "events.log"),
		durablefile.WithSync(func(*os.File) error {
			syncCalls++
			return nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	if _, err := journal.Append([]byte(`{"n":1}`), false); err != nil {
		t.Fatal(err)
	}
	if syncCalls != 0 {
		t.Fatalf("routine append unexpectedly synced %d times", syncCalls)
	}
	if _, err := journal.Append([]byte(`{"n":2}`), true); err != nil {
		t.Fatal(err)
	}
	if syncCalls != 1 {
		t.Fatalf("critical append sync calls=%d want=1", syncCalls)
	}
}

func TestTornTailIsTruncatedAndSyncedButCompleteCorruptionIsFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	journal, err := durablefile.NewJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Append([]byte(`{"n":1}`), true); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Append([]byte(`{"n":2}`), true); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, int64(len(raw)-10)); err != nil {
		t.Fatal(err)
	}
	recovered, err := durablefile.Recover(path, 65_536)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered.Records) != 1 || !recovered.TailRepaired {
		t.Fatalf(
			"records=%d repaired=%v",
			len(recovered.Records),
			recovered.TailRepaired,
		)
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Size() != int64(recovered.Records[0].Size) {
		t.Fatalf("size=%d want=%d", stat.Size(), recovered.Records[0].Size)
	}

	corruptPath := filepath.Join(t.TempDir(), "corrupt.log")
	corrupt, err := durablefile.NewJournal(corruptPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := corrupt.Append([]byte(`{"n":1}`), true); err != nil {
		t.Fatal(err)
	}
	if _, err := corrupt.Append([]byte(`{"n":2}`), true); err != nil {
		t.Fatal(err)
	}
	if err := corrupt.Close(); err != nil {
		t.Fatal(err)
	}
	damaged, err := os.ReadFile(corruptPath)
	if err != nil {
		t.Fatal(err)
	}
	damaged[40] ^= 1
	if err := os.WriteFile(corruptPath, damaged, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := durablefile.Recover(
		corruptPath,
		65_536,
	); !errors.Is(err, durablefile.ErrJournalCorrupt) {
		t.Fatalf("got %v, want ErrJournalCorrupt", err)
	}
}

func TestJournalExclusiveLockPreventsConcurrentRecoveryOrAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	first, err := durablefile.NewJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	if _, err := durablefile.NewJournal(path); !errors.Is(
		err,
		durablefile.ErrJournalLocked,
	) {
		t.Fatalf("got %v, want ErrJournalLocked", err)
	}
	if _, err := durablefile.Recover(path, 65_536); !errors.Is(
		err,
		durablefile.ErrJournalLocked,
	) {
		t.Fatalf("recover got %v, want ErrJournalLocked", err)
	}
}

func TestNewJournalRecoversAndContinuesHashChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	first, err := durablefile.NewJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	one, err := first.Append([]byte(`{"n":1}`), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := durablefile.NewJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	two, err := second.Append([]byte(`{"n":2}`), true)
	if err != nil {
		t.Fatal(err)
	}
	if two.PreviousHash != one.Hash {
		t.Fatal("reopened journal did not seed the verified chain head")
	}
}

func TestRecoveryClassifiesEveryTruncationAndRejectsBadMagicPrefix(t *testing.T) {
	golden, err := hex.DecodeString(completeGoldenFrameHex)
	if err != nil {
		t.Fatal(err)
	}
	for cut := 1; cut < len(golden); cut++ {
		t.Run("valid-prefix-"+strconv.Itoa(cut), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.log")
			if err := os.WriteFile(path, golden[:cut], 0o600); err != nil {
				t.Fatal(err)
			}
			recovery, err := durablefile.Recover(path, 65_536)
			if err != nil {
				t.Fatalf("cut=%d: %v", cut, err)
			}
			if !recovery.TailRepaired {
				t.Fatalf("cut=%d not marked repaired", cut)
			}
		})
		if cut >= 4 {
			t.Run("bad-magic-"+strconv.Itoa(cut), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "events.log")
				damaged := append([]byte(nil), golden[:cut]...)
				damaged[0] ^= 1
				if err := os.WriteFile(path, damaged, 0o600); err != nil {
					t.Fatal(err)
				}
				if _, err := durablefile.Recover(
					path,
					65_536,
				); !errors.Is(err, durablefile.ErrJournalCorrupt) {
					t.Fatalf("cut=%d got %v, want corruption", cut, err)
				}
			})
		}
	}
}

func TestConcurrentAppendCloseThenReopenRecoversCompleteFrames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	journal, err := durablefile.NewJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := journal.Append([]byte(`{"n":1}`), true)
			if err != nil && !errors.Is(err, durablefile.ErrJournalClosed) {
				t.Errorf("append: %v", err)
			}
		}()
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		if err := journal.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	}()
	wait.Wait()
	reopened, err := durablefile.NewJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	recovery, err := durablefile.Recover(path, 65_536)
	if err != nil {
		t.Fatal(err)
	}
	if recovery.TailRepaired {
		t.Fatal("serialized append/close left a torn frame")
	}
}
