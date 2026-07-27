// Package durablefile implements the byte-level AGF1 durable frame format.
// Payload schemas and canonicalization remain the caller's responsibility.
package durablefile

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
)

const (
	frameMagicSize      = 4
	frameLengthSize     = 4
	framePreviousSize   = sha256.Size
	frameCRCSize        = 4
	frameHashSize       = sha256.Size
	frameHeaderSize     = frameMagicSize + frameLengthSize + framePreviousSize
	frameOverhead       = frameHeaderSize + frameCRCSize + frameHashSize
	frameHashDomain     = "AGMIND_FRAME_V1\x00"
	defaultMaxFrameSize = 65_536
)

var (
	frameMagic = [frameMagicSize]byte{'A', 'G', 'F', '1'}
	crcTable   = crc32.MakeTable(crc32.Castagnoli)

	ErrFrameTooLarge  = errors.New("frame payload exceeds explicit limit")
	ErrJournalCorrupt = errors.New("journal corrupt")
	ErrTornTail       = errors.New("torn final frame")
)

// RecordMeta describes the durable identity and encoded size of a frame.
type RecordMeta struct {
	Hash          [sha256.Size]byte
	PreviousHash  [sha256.Size]byte
	PayloadLength uint32
	Size          uint64
	Offset        int64
}

// Record is one verified AGF1 payload and its metadata.
type Record struct {
	RecordMeta
	Payload []byte
}

// EncodeFrame creates one complete AGF1 frame. maxFrame is the maximum payload
// size, not the total encoded size.
func EncodeFrame(
	payload []byte,
	previousHash [sha256.Size]byte,
	maxFrame uint32,
) ([]byte, RecordMeta, error) {
	if maxFrame == 0 {
		return nil, RecordMeta{}, fmt.Errorf("maxFrame must be positive")
	}
	if uint64(len(payload)) > uint64(maxFrame) || uint64(len(payload)) > math.MaxUint32 {
		return nil, RecordMeta{}, ErrFrameTooLarge
	}
	total := uint64(frameOverhead) + uint64(len(payload))
	if total > uint64(math.MaxInt) {
		return nil, RecordMeta{}, ErrFrameTooLarge
	}
	frame := make([]byte, int(total))
	copy(frame[:frameMagicSize], frameMagic[:])
	binary.BigEndian.PutUint32(
		frame[frameMagicSize:frameMagicSize+frameLengthSize],
		uint32(len(payload)),
	)
	copy(frame[frameMagicSize+frameLengthSize:frameHeaderSize], previousHash[:])
	copy(frame[frameHeaderSize:frameHeaderSize+len(payload)], payload)
	crcOffset := frameHeaderSize + len(payload)
	binary.BigEndian.PutUint32(
		frame[crcOffset:crcOffset+frameCRCSize],
		crc32.Checksum(frame[:crcOffset], crcTable),
	)
	sum := sha256.Sum256(append(
		[]byte(frameHashDomain),
		frame[:crcOffset+frameCRCSize]...,
	))
	copy(frame[crcOffset+frameCRCSize:], sum[:])
	return frame, RecordMeta{
		Hash:          sum,
		PreviousHash:  previousHash,
		PayloadLength: uint32(len(payload)),
		Size:          total,
	}, nil
}

// DecodeFrame verifies exactly one complete frame and its expected chain link.
func DecodeFrame(
	raw []byte,
	maxFrame uint32,
	expectedPrevious [sha256.Size]byte,
) (Record, error) {
	if maxFrame == 0 {
		return Record{}, fmt.Errorf("maxFrame must be positive")
	}
	if len(raw) >= frameMagicSize &&
		string(raw[:frameMagicSize]) != string(frameMagic[:]) {
		return Record{}, fmt.Errorf("%w: invalid frame magic", ErrJournalCorrupt)
	}
	if len(raw) < frameHeaderSize {
		return Record{}, ErrTornTail
	}
	payloadLength := binary.BigEndian.Uint32(
		raw[frameMagicSize : frameMagicSize+frameLengthSize],
	)
	if payloadLength > maxFrame {
		return Record{}, fmt.Errorf("%w: payload length exceeds limit", ErrJournalCorrupt)
	}
	total := uint64(frameOverhead) + uint64(payloadLength)
	if uint64(len(raw)) < total {
		return Record{}, ErrTornTail
	}
	if uint64(len(raw)) != total {
		return Record{}, fmt.Errorf("%w: trailing frame bytes", ErrJournalCorrupt)
	}
	var previous [sha256.Size]byte
	copy(previous[:], raw[frameMagicSize+frameLengthSize:frameHeaderSize])
	if previous != expectedPrevious {
		return Record{}, fmt.Errorf("%w: previous hash mismatch", ErrJournalCorrupt)
	}
	crcOffset := frameHeaderSize + int(payloadLength)
	storedCRC := binary.BigEndian.Uint32(raw[crcOffset : crcOffset+frameCRCSize])
	if crc32.Checksum(raw[:crcOffset], crcTable) != storedCRC {
		return Record{}, fmt.Errorf("%w: CRC32C mismatch", ErrJournalCorrupt)
	}
	storedHash := raw[crcOffset+frameCRCSize:]
	sum := sha256.Sum256(append(
		[]byte(frameHashDomain),
		raw[:crcOffset+frameCRCSize]...,
	))
	if string(storedHash) != string(sum[:]) {
		return Record{}, fmt.Errorf("%w: frame hash mismatch", ErrJournalCorrupt)
	}
	payload := append([]byte(nil), raw[frameHeaderSize:crcOffset]...)
	return Record{
		RecordMeta: RecordMeta{
			Hash:          sum,
			PreviousHash:  previous,
			PayloadLength: payloadLength,
			Size:          total,
		},
		Payload: payload,
	}, nil
}
