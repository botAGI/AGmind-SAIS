package durablefile

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

var (
	ErrJournalFailed = errors.New("journal is permanently failed")
	ErrJournalLocked = errors.New("journal is exclusively locked")
	ErrShortWrite    = errors.New("short journal write")
	ErrJournalClosed = errors.New("journal is closed")
)

type journalOptions struct {
	maxFrame    uint32
	sync        func(*os.File) error
	syncDir     func(int) error
	write       func(*os.File, []byte) (int, error)
	beforeFlock func()
}

// Option customizes journal I/O. The injection points are intentionally small
// so durability failure ordering can be tested.
type Option func(*journalOptions)

func WithMaxFrame(maxFrame uint32) Option {
	return func(options *journalOptions) {
		options.maxFrame = maxFrame
	}
}

func WithSync(syncFn func(*os.File) error) Option {
	return func(options *journalOptions) {
		options.sync = syncFn
	}
}

func WithDirectorySync(syncFn func(int) error) Option {
	return func(options *journalOptions) {
		options.syncDir = syncFn
	}
}

func WithWrite(writeFn func(*os.File, []byte) (int, error)) Option {
	return func(options *journalOptions) {
		options.write = writeFn
	}
}

func withBeforeJournalFlock(hook func()) Option {
	return func(options *journalOptions) {
		options.beforeFlock = hook
	}
}

// Recovery contains every verified record and whether an incomplete tail was
// durably removed.
type Recovery struct {
	Records       []Record
	TailRepaired  bool
	VerifiedBytes int64
}

// Journal is an exclusively locked append-only AGF1 stream.
type Journal struct {
	mutex        sync.Mutex
	path         string
	file         *os.File
	maxFrame     uint32
	sync         func(*os.File) error
	syncDir      func(int) error
	write        func(*os.File, []byte) (int, error)
	previousHash [sha256.Size]byte
	offset       int64
	failed       bool
	closed       bool
}

func openLockedRegular(
	path string,
	create bool,
	beforeFlock func(),
) (*os.File, bool, error) {
	parent, err := openSecureParent(path)
	if err != nil {
		return nil, false, err
	}
	defer unix.Close(parent.fd)
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	fd, err := unix.Openat(parent.fd, parent.base, flags, 0)
	created := false
	if errors.Is(err, unix.ENOENT) && create {
		fd, err = unix.Openat(
			parent.fd,
			parent.base,
			flags|unix.O_CREAT|unix.O_EXCL,
			0o600,
		)
		if errors.Is(err, unix.EEXIST) {
			fd, err = unix.Openat(parent.fd, parent.base, flags, 0)
		} else if err == nil {
			created = true
		}
	}
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, false, os.ErrNotExist
		}
		return nil, false, fmt.Errorf("%w: journal open failed", ErrUnsafePath)
	}
	file := os.NewFile(uintptr(fd), parent.base)
	if file == nil {
		_ = unix.Close(fd)
		return nil, false, fmt.Errorf("failed to own journal descriptor")
	}
	cleanup := func(result error) (*os.File, bool, error) {
		_ = file.Close()
		return nil, false, result
	}
	if created {
		if err := unix.Fchmod(fd, 0o600); err != nil {
			return cleanup(err)
		}
	}
	var stat unix.Stat_t
	err = unix.Fstat(fd, &stat)
	if err != nil {
		return cleanup(err)
	}
	if !regularSingleLink(stat) || stat.Mode&0o777 != 0o600 {
		return cleanup(fmt.Errorf("%w: unsafe opened journal", ErrUnsafePath))
	}
	pathStat, err := statDestination(parent)
	if err != nil ||
		pathStat.Dev != stat.Dev ||
		pathStat.Ino != stat.Ino ||
		!regularSingleLink(pathStat) {
		return cleanup(fmt.Errorf("%w: journal path identity changed", ErrUnsafePath))
	}
	if beforeFlock != nil {
		beforeFlock()
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return cleanup(ErrJournalLocked)
		}
		return cleanup(err)
	}
	var lockedStat unix.Stat_t
	lockedStatErr := unix.Fstat(int(file.Fd()), &lockedStat)
	lockedPathStat, lockedPathErr := statDestination(parent)
	if lockedStatErr != nil ||
		lockedPathErr != nil ||
		!regularSingleLink(lockedStat) ||
		!regularSingleLink(lockedPathStat) ||
		lockedStat.Dev != stat.Dev ||
		lockedStat.Ino != stat.Ino ||
		lockedPathStat.Dev != lockedStat.Dev ||
		lockedPathStat.Ino != lockedStat.Ino {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		return cleanup(fmt.Errorf(
			"%w: journal path identity changed while locking",
			ErrUnsafePath,
		))
	}
	return file, created, nil
}

func unlockAndClose(file *os.File) error {
	unlockErr := unix.Flock(int(file.Fd()), unix.LOCK_UN)
	closeErr := file.Close()
	return errors.Join(unlockErr, closeErr)
}

func recoverLocked(
	file *os.File,
	maxFrame uint32,
	beforeTailRepair func() error,
) (Recovery, error) {
	if maxFrame == 0 {
		return Recovery{}, fmt.Errorf("maxFrame must be positive")
	}
	info, err := file.Stat()
	if err != nil {
		return Recovery{}, err
	}
	size := info.Size()
	recovery := Recovery{Records: make([]Record, 0)}
	var expectedPrevious [sha256.Size]byte
	var offset int64
	for offset < size {
		remaining := size - offset
		if remaining >= frameMagicSize {
			var prefix [frameMagicSize]byte
			if _, err := file.ReadAt(prefix[:], offset); err != nil {
				return Recovery{}, err
			}
			if prefix != frameMagic {
				return Recovery{}, fmt.Errorf("%w: invalid frame magic", ErrJournalCorrupt)
			}
		}
		if remaining < frameHeaderSize {
			recovery.TailRepaired = true
			break
		}
		header := make([]byte, frameHeaderSize)
		if _, err := file.ReadAt(header, offset); err != nil {
			if errors.Is(err, io.EOF) {
				recovery.TailRepaired = true
				break
			}
			return Recovery{}, err
		}
		payloadLength := uint32(header[4])<<24 |
			uint32(header[5])<<16 |
			uint32(header[6])<<8 |
			uint32(header[7])
		if payloadLength > maxFrame {
			return Recovery{}, fmt.Errorf("%w: payload length exceeds limit", ErrJournalCorrupt)
		}
		total := int64(frameOverhead) + int64(payloadLength)
		if remaining < total {
			recovery.TailRepaired = true
			break
		}
		raw := make([]byte, int(total))
		if _, err := file.ReadAt(raw, offset); err != nil {
			return Recovery{}, err
		}
		record, err := DecodeFrame(raw, maxFrame, expectedPrevious)
		if err != nil {
			return Recovery{}, err
		}
		record.Offset = offset
		recovery.Records = append(recovery.Records, record)
		expectedPrevious = record.Hash
		offset += total
	}
	recovery.VerifiedBytes = offset
	if recovery.TailRepaired {
		if beforeTailRepair != nil {
			if err := beforeTailRepair(); err != nil {
				return Recovery{}, err
			}
		}
		if err := file.Truncate(offset); err != nil {
			return Recovery{}, err
		}
		if err := file.Sync(); err != nil {
			return Recovery{}, err
		}
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return Recovery{}, err
	}
	return recovery, nil
}

// Recover exclusively verifies a journal and durably truncates only an
// incomplete final frame.
func Recover(path string, maxFrame uint32) (Recovery, error) {
	return RecoverWithTailIntent(path, maxFrame, nil)
}

// RecoverWithTailIntent verifies a journal and, when a torn tail exists,
// invokes beforeTailRepair before destructively truncating it. A callback
// failure leaves the tail intact for a later recovery attempt.
func RecoverWithTailIntent(
	path string,
	maxFrame uint32,
	beforeTailRepair func() error,
) (Recovery, error) {
	file, _, err := openLockedRegular(path, false, nil)
	if err != nil {
		return Recovery{}, err
	}
	defer unlockAndClose(file)
	if err := file.Sync(); err != nil {
		return Recovery{}, err
	}
	return recoverLocked(file, maxFrame, beforeTailRepair)
}

// NewJournal recovers, exclusively locks, and opens a journal for append.
func NewJournal(path string, options ...Option) (*Journal, error) {
	config := journalOptions{
		maxFrame: defaultMaxFrameSize,
		sync:     func(file *os.File) error { return file.Sync() },
		syncDir:  syncDirectoryFD,
		write:    func(file *os.File, value []byte) (int, error) { return file.Write(value) },
	}
	for _, option := range options {
		option(&config)
	}
	if config.maxFrame == 0 || config.sync == nil ||
		config.syncDir == nil || config.write == nil {
		return nil, fmt.Errorf("invalid journal option")
	}
	file, _, err := openLockedRegular(path, true, config.beforeFlock)
	if err != nil {
		return nil, err
	}
	if err := file.Sync(); err != nil {
		_ = unlockAndClose(file)
		return nil, err
	}
	parent, parentErr := openSecureParent(path)
	if parentErr != nil {
		_ = unlockAndClose(file)
		return nil, parentErr
	}
	syncErr := config.syncDir(parent.fd)
	_ = unix.Close(parent.fd)
	if syncErr != nil {
		_ = unlockAndClose(file)
		return nil, errors.Join(ErrCommitUncertain, syncErr)
	}
	recovery, err := recoverLocked(file, config.maxFrame, nil)
	if err != nil {
		_ = unlockAndClose(file)
		return nil, err
	}
	journal := &Journal{
		path:     path,
		file:     file,
		maxFrame: config.maxFrame,
		sync:     config.sync,
		syncDir:  config.syncDir,
		write:    config.write,
		offset:   recovery.VerifiedBytes,
	}
	if len(recovery.Records) > 0 {
		journal.previousHash = recovery.Records[len(recovery.Records)-1].Hash
	}
	return journal, nil
}

// Checkpoint atomically replaces the journal with one fully synced frame while
// retaining an exclusive lock on the published inode. Callers must durably
// re-anchor the returned hash; the payload is unchanged across the replacement
// so they can reconcile either side of a crash.
func (journal *Journal) Checkpoint(payload []byte) (RecordMeta, error) {
	journal.mutex.Lock()
	defer journal.mutex.Unlock()
	if journal.closed {
		return RecordMeta{}, ErrJournalClosed
	}
	if journal.failed {
		return RecordMeta{}, ErrJournalFailed
	}
	frame, meta, err := EncodeFrame(payload, [sha256.Size]byte{}, journal.maxFrame)
	if err != nil {
		return RecordMeta{}, err
	}
	parent, err := openSecureParent(journal.path)
	if err != nil {
		return RecordMeta{}, err
	}
	defer unix.Close(parent.fd)
	temporary, temporaryName, err := createExclusiveTemp(parent)
	if err != nil {
		return RecordMeta{}, err
	}
	published := false
	defer func() {
		if temporary != nil {
			_ = temporary.Close()
		}
		if !published && temporaryName != "" {
			_ = unix.Unlinkat(parent.fd, temporaryName, 0)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return RecordMeta{}, err
	}
	written := 0
	for written < len(frame) {
		count, writeErr := temporary.Write(frame[written:])
		if writeErr != nil {
			return RecordMeta{}, writeErr
		}
		if count == 0 {
			return RecordMeta{}, io.ErrShortWrite
		}
		written += count
	}
	if err := journal.sync(temporary); err != nil {
		return RecordMeta{}, err
	}
	var temporaryStat unix.Stat_t
	if err := unix.Fstat(int(temporary.Fd()), &temporaryStat); err != nil ||
		!regularSingleLink(temporaryStat) ||
		temporaryStat.Mode&0o777 != 0o600 ||
		temporaryStat.Size != int64(len(frame)) {
		return RecordMeta{}, fmt.Errorf(
			"%w: unsafe checkpoint temporary",
			ErrUnsafePath,
		)
	}
	var temporaryPathStat unix.Stat_t
	if err := unix.Fstatat(
		parent.fd,
		temporaryName,
		&temporaryPathStat,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil ||
		temporaryPathStat.Dev != temporaryStat.Dev ||
		temporaryPathStat.Ino != temporaryStat.Ino ||
		!regularSingleLink(temporaryPathStat) {
		return RecordMeta{}, fmt.Errorf(
			"%w: checkpoint temporary identity changed",
			ErrUnsafePath,
		)
	}
	if err := unix.Flock(
		int(temporary.Fd()),
		unix.LOCK_EX|unix.LOCK_NB,
	); err != nil {
		return RecordMeta{}, err
	}
	if err := validateExistingDestination(parent); err != nil {
		return RecordMeta{}, err
	}
	if err := unix.Renameat(
		parent.fd,
		temporaryName,
		parent.fd,
		parent.base,
	); err != nil {
		return RecordMeta{}, err
	}
	published = true
	temporaryName = ""
	old := journal.file
	journal.file = temporary
	temporary = nil
	journal.previousHash = meta.Hash
	journal.offset = int64(meta.Size)
	meta.Offset = 0
	closeErr := unlockAndClose(old)
	syncErr := journal.syncDir(parent.fd)
	if closeErr != nil || syncErr != nil {
		journal.failed = true
		if syncErr != nil {
			syncErr = errors.Join(ErrCommitUncertain, syncErr)
		}
		return RecordMeta{}, errors.Join(closeErr, syncErr)
	}
	return meta, nil
}

// Append writes one frame. critical=true syncs the file before success;
// critical=false is explicitly not a durability acknowledgement.
func (journal *Journal) Append(payload []byte, critical bool) (RecordMeta, error) {
	journal.mutex.Lock()
	defer journal.mutex.Unlock()
	if journal.closed {
		return RecordMeta{}, ErrJournalClosed
	}
	if journal.failed {
		return RecordMeta{}, ErrJournalFailed
	}
	frame, meta, err := EncodeFrame(payload, journal.previousHash, journal.maxFrame)
	if err != nil {
		return RecordMeta{}, err
	}
	meta.Offset = journal.offset
	count, writeErr := journal.write(journal.file, frame)
	if writeErr != nil || count != len(frame) {
		journal.failed = true
		if writeErr != nil {
			return RecordMeta{}, writeErr
		}
		return RecordMeta{}, ErrShortWrite
	}
	if critical {
		if err := journal.sync(journal.file); err != nil {
			journal.failed = true
			return RecordMeta{}, err
		}
	}
	journal.previousHash = meta.Hash
	journal.offset += int64(meta.Size)
	return meta, nil
}

func (journal *Journal) Failed() bool {
	journal.mutex.Lock()
	defer journal.mutex.Unlock()
	return journal.failed
}

func (journal *Journal) Close() error {
	journal.mutex.Lock()
	defer journal.mutex.Unlock()
	if journal.closed {
		return nil
	}
	journal.closed = true
	return unlockAndClose(journal.file)
}
