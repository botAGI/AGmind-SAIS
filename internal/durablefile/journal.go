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
	maxFrame uint32
	sync     func(*os.File) error
	write    func(*os.File, []byte) (int, error)
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

func WithWrite(writeFn func(*os.File, []byte) (int, error)) Option {
	return func(options *journalOptions) {
		options.write = writeFn
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
	write        func(*os.File, []byte) (int, error)
	previousHash [sha256.Size]byte
	offset       int64
	failed       bool
	closed       bool
}

func openLockedRegular(path string, create bool) (*os.File, error) {
	parent, err := openSecureParent(path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent.fd)
	if stat, statErr := statDestination(parent); statErr == nil {
		if !regularSingleLink(stat) {
			return nil, fmt.Errorf("%w: journal path is not a single-link regular file", ErrUnsafePath)
		}
		if stat.Mode&0o777 != 0o600 {
			return nil, fmt.Errorf("%w: journal mode must be 0600", ErrUnsafePath)
		}
	} else if !errors.Is(statErr, unix.ENOENT) {
		return nil, fmt.Errorf("%w: journal stat failed", ErrUnsafePath)
	} else if !create {
		return nil, os.ErrNotExist
	}
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if create {
		flags |= unix.O_CREAT
	}
	fd, err := unix.Openat(parent.fd, parent.base, flags, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), parent.base)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("failed to own journal descriptor")
	}
	cleanup := func(result error) (*os.File, error) {
		_ = file.Close()
		return nil, result
	}
	var stat unix.Stat_t
	err = unix.Fstat(fd, &stat)
	if err != nil {
		return cleanup(err)
	}
	if !regularSingleLink(stat) || stat.Mode&0o777 != 0o600 {
		return cleanup(fmt.Errorf("%w: unsafe opened journal", ErrUnsafePath))
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return cleanup(ErrJournalLocked)
		}
		return cleanup(err)
	}
	return file, nil
}

func unlockAndClose(file *os.File) error {
	unlockErr := unix.Flock(int(file.Fd()), unix.LOCK_UN)
	closeErr := file.Close()
	return errors.Join(unlockErr, closeErr)
}

func recoverLocked(file *os.File, maxFrame uint32) (Recovery, error) {
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
	file, err := openLockedRegular(path, false)
	if err != nil {
		return Recovery{}, err
	}
	defer unlockAndClose(file)
	return recoverLocked(file, maxFrame)
}

// NewJournal recovers, exclusively locks, and opens a journal for append.
func NewJournal(path string, options ...Option) (*Journal, error) {
	config := journalOptions{
		maxFrame: defaultMaxFrameSize,
		sync:     func(file *os.File) error { return file.Sync() },
		write:    func(file *os.File, value []byte) (int, error) { return file.Write(value) },
	}
	for _, option := range options {
		option(&config)
	}
	if config.maxFrame == 0 || config.sync == nil || config.write == nil {
		return nil, fmt.Errorf("invalid journal option")
	}
	file, err := openLockedRegular(path, true)
	if err != nil {
		return nil, err
	}
	recovery, err := recoverLocked(file, config.maxFrame)
	if err != nil {
		_ = unlockAndClose(file)
		return nil, err
	}
	journal := &Journal{
		path:     path,
		file:     file,
		maxFrame: config.maxFrame,
		sync:     config.sync,
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
	syncErr := syncDirectoryFD(parent.fd)
	if closeErr != nil || syncErr != nil {
		journal.failed = true
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
