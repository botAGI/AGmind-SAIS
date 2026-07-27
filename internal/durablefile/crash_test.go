package durablefile

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
)

const createOnlyCrashExit = 86

func TestCreateOnlyKillBoundaryHelper(t *testing.T) {
	if os.Getenv("AGMIND_TEST_HELPER") != "create-only" {
		return
	}
	path := os.Getenv("AGMIND_TEST_PATH")
	payload, err := os.ReadFile(os.Getenv("AGMIND_TEST_PAYLOAD_PATH"))
	if err != nil {
		os.Exit(87)
	}
	stage := os.Getenv("AGMIND_TEST_STAGE")
	err = CreateOnly(
		path,
		payload,
		WithCreateOnlyBoundaryHook(func(boundary CreateOnlyBoundary) {
			if stage == string(boundary) {
				os.Exit(createOnlyCrashExit)
			}
		}),
	)
	if err != nil {
		os.Exit(87)
	}
	os.Exit(88)
}

func TestCreateOnlyKillBoundariesExposeAtMostOneFinalName(t *testing.T) {
	payload := []byte("complete-publication-payload")
	for _, stage := range []string{
		"temp_created",
		"payload_written",
		"file_synced",
		"renamed_pre_dirsync",
		"dir_synced",
	} {
		t.Run(stage, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "event.agf")
			payloadPath := filepath.Join(root, "payload.bin")
			if err := os.WriteFile(payloadPath, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(
				os.Args[0],
				"-test.run=^TestCreateOnlyKillBoundaryHelper$",
			)
			command.Env = append(
				os.Environ(),
				"AGMIND_TEST_HELPER=create-only",
				"AGMIND_TEST_PATH="+path,
				"AGMIND_TEST_PAYLOAD_PATH="+payloadPath,
				"AGMIND_TEST_STAGE="+stage,
			)
			output, err := command.CombinedOutput()
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) ||
				exitError.ExitCode() != createOnlyCrashExit {
				t.Fatalf(
					"stage=%s err=%v output=%s",
					stage,
					err,
					output,
				)
			}
			entries, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			tempPattern := regexp.MustCompile(
				`^\.event\.agf\.tmp-[0-9a-f]{32}$`,
			)
			tempCount := 0
			finalCount := 0
			for _, entry := range entries {
				switch {
				case entry.Name() == "payload.bin":
				case entry.Name() == "event.agf":
					finalCount++
				case tempPattern.MatchString(entry.Name()):
					tempCount++
				default:
					t.Fatalf("unexpected artifact %q", entry.Name())
				}
			}
			if stage == "temp_created" {
				if finalCount != 0 || tempCount != 1 {
					t.Fatalf("final=%d temp=%d", finalCount, tempCount)
				}
				tempPath := filepath.Join(
					root,
					findCreateOnlyTempName(t, entries, tempPattern),
				)
				raw, identity, err := ReadRegularIdentity(tempPath, 1)
				if err != nil || len(raw) != 0 || identity.Size != 0 {
					t.Fatalf("temp identity=%+v raw=%q err=%v", identity, raw, err)
				}
			} else if stage == "payload_written" ||
				stage == "file_synced" {
				if finalCount != 0 || tempCount != 1 {
					t.Fatalf("final=%d temp=%d", finalCount, tempCount)
				}
				tempPath := filepath.Join(
					root,
					findCreateOnlyTempName(t, entries, tempPattern),
				)
				raw, identity, err := ReadRegularIdentity(
					tempPath,
					int64(len(payload)),
				)
				if err != nil ||
					identity.Size != uint64(len(payload)) ||
					!bytes.Equal(raw, payload) {
					t.Fatalf("temp identity=%+v raw=%q err=%v", identity, raw, err)
				}
			} else {
				if finalCount != 1 || tempCount != 0 {
					t.Fatalf("final=%d temp=%d", finalCount, tempCount)
				}
				raw, identity, err := ReadRegularIdentity(
					path,
					int64(len(payload)),
				)
				if err != nil ||
					identity.Size != uint64(len(payload)) ||
					!bytes.Equal(raw, payload) {
					t.Fatalf(
						"final identity=%+v raw=%q err=%v",
						identity,
						raw,
						err,
					)
				}
			}
		})
	}
}

func findCreateOnlyTempName(
	t *testing.T,
	entries []os.DirEntry,
	pattern *regexp.Regexp,
) string {
	t.Helper()
	for _, entry := range entries {
		if pattern.MatchString(entry.Name()) {
			return entry.Name()
		}
	}
	t.Fatal("create-only temporary name is missing")
	return ""
}

func TestCreateOnlyConcurrentPublishersNeverReplaceWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "event.agf")
	payloads := [][]byte{[]byte("first"), []byte("second")}
	results := make(chan error, len(payloads))
	var start sync.WaitGroup
	start.Add(1)
	for _, payload := range payloads {
		payload := append([]byte(nil), payload...)
		go func() {
			start.Wait()
			results <- CreateOnly(path, payload)
		}()
	}
	start.Done()
	first := <-results
	second := <-results
	if (first == nil) == (second == nil) {
		t.Fatalf("results=%v, %v", first, second)
	}
	loser := first
	if loser == nil {
		loser = second
	}
	if !errors.Is(loser, os.ErrExist) {
		t.Fatalf("loser err=%v", loser)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, payloads[0]) && !bytes.Equal(raw, payloads[1]) {
		t.Fatalf("winner payload=%q", raw)
	}
}

func TestNewJournalFirstCreateKillHelper(t *testing.T) {
	if os.Getenv("AGMIND_TEST_HELPER") != "new-journal-first-create" {
		return
	}
	stage := os.Getenv("AGMIND_TEST_STAGE")
	journal, err := NewJournal(
		os.Getenv("AGMIND_TEST_PATH"),
		WithDirectorySync(func(fd int) error {
			if stage == "pre_parent_fsync" {
				os.Exit(createOnlyCrashExit)
			}
			err := syncDirectoryFD(fd)
			if err == nil && stage == "post_parent_fsync" {
				os.Exit(createOnlyCrashExit)
			}
			return err
		}),
	)
	if err != nil {
		os.Exit(87)
	}
	_ = journal.Close()
	os.Exit(88)
}

func TestNewJournalFirstCreateKillRetryReconcilesDirectoryEntry(
	t *testing.T,
) {
	for _, stage := range []string{
		"pre_parent_fsync",
		"post_parent_fsync",
	} {
		t.Run(stage, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "events.agf")
			command := exec.Command(
				os.Args[0],
				"-test.run=^TestNewJournalFirstCreateKillHelper$",
			)
			command.Env = append(
				os.Environ(),
				"AGMIND_TEST_HELPER=new-journal-first-create",
				"AGMIND_TEST_PATH="+path,
				"AGMIND_TEST_STAGE="+stage,
			)
			output, err := command.CombinedOutput()
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) ||
				exitError.ExitCode() != createOnlyCrashExit {
				t.Fatalf(
					"stage=%s err=%v output=%s",
					stage,
					err,
					output,
				)
			}
			raw, identity, err := ReadRegularIdentity(path, 1)
			if err != nil || len(raw) != 0 || identity.Size != 0 {
				t.Fatalf(
					"stage=%s identity=%+v raw=%q err=%v",
					stage,
					identity,
					raw,
					err,
				)
			}
			parentSyncs := 0
			reopened, err := NewJournal(
				path,
				WithDirectorySync(func(fd int) error {
					parentSyncs++
					return syncDirectoryFD(fd)
				}),
			)
			if err != nil {
				t.Fatalf("stage=%s reopen err=%v", stage, err)
			}
			if parentSyncs != 1 {
				_ = reopened.Close()
				t.Fatalf(
					"stage=%s parent syncs=%d",
					stage,
					parentSyncs,
				)
			}
			if _, err := reopened.Append(
				[]byte(`{"kind":"reconciled"}`),
				true,
			); err != nil {
				_ = reopened.Close()
				t.Fatal(err)
			}
			if err := reopened.Close(); err != nil {
				t.Fatal(err)
			}
			recovery, err := Recover(path, 4_096)
			if err != nil {
				t.Fatal(err)
			}
			if len(recovery.Records) != 1 ||
				string(recovery.Records[0].Payload) !=
					`{"kind":"reconciled"}` {
				t.Fatalf(
					"stage=%s recovery=%+v",
					stage,
					recovery,
				)
			}
		})
	}
}

func TestJournalOpenRevalidatesPathIdentityAfterFlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.agf")
	first, err := NewJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	reachedIdentityCheck := make(chan struct{})
	releaseOpen := make(chan struct{})
	type openResult struct {
		journal *Journal
		err     error
	}
	result := make(chan openResult, 1)
	go func() {
		journal, err := NewJournal(
			path,
			withBeforeJournalFlock(func() {
				close(reachedIdentityCheck)
				<-releaseOpen
			}),
		)
		result <- openResult{journal: journal, err: err}
	}()
	<-reachedIdentityCheck
	if _, err := first.Checkpoint([]byte("checkpoint")); err != nil {
		close(releaseOpen)
		t.Fatal(err)
	}
	close(releaseOpen)
	second := <-result
	if second.journal != nil {
		_ = second.journal.Close()
		t.Fatal("second journal acquired an unlinked stale inode")
	}
	if !errors.Is(second.err, ErrUnsafePath) &&
		!errors.Is(second.err, ErrJournalLocked) {
		t.Fatalf("second open err=%v", second.err)
	}
	if _, err := NewJournal(path); !errors.Is(err, ErrJournalLocked) {
		t.Fatalf("published checkpoint was not exclusively locked: %v", err)
	}
	if _, err := first.Append([]byte("after-checkpoint"), true); err != nil {
		t.Fatalf("first journal lost ownership: %v", err)
	}
}
