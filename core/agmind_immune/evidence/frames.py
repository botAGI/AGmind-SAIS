"""Go-compatible encoder and bounded streaming reader for AGF1 frames."""

from __future__ import annotations

import hashlib
import io
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from typing import BinaryIO

import google_crc32c

_MAGIC = b"AGF1"
_HEADER_SIZE = 40
_OVERHEAD = 76
_HASH_DOMAIN = b"AGMIND_FRAME_V1\0"


class JournalCorrupt(ValueError):
    """A complete frame or chain link failed integrity validation."""


class TornTail(EOFError):
    """An incomplete final frame followed a verified journal prefix."""

    def __init__(self, verified_bytes: int) -> None:
        super().__init__("torn final frame")
        self.verified_bytes = verified_bytes


@dataclass(frozen=True)
class FrameRecord:
    payload: bytes
    previous_hash: bytes
    record_hash: bytes
    offset: int
    size: int


@dataclass(frozen=True)
class DecodedFrames:
    records: tuple[FrameRecord, ...]
    torn_tail: bool
    verified_bytes: int


def _validate_max_frame(max_frame: int) -> None:
    if max_frame <= 0:
        raise ValueError("max_frame must be positive")
    if max_frame > 0xFFFFFFFF:
        raise ValueError("max_frame exceeds uint32")


def encode_frame(
    payload: bytes,
    *,
    previous_hash: bytes,
    max_frame: int,
) -> bytes:
    """Encode one frame with the exact Go durablefile byte layout."""
    _validate_max_frame(max_frame)
    if len(previous_hash) != 32:
        raise ValueError("previous_hash must contain 32 bytes")
    if len(payload) > max_frame:
        raise ValueError("frame payload exceeds explicit limit")

    header = _MAGIC + struct.pack(">I", len(payload)) + previous_hash
    crc_input = header + payload
    crc = struct.pack(">I", google_crc32c.value(crc_input))
    record_hash = hashlib.sha256(_HASH_DOMAIN + crc_input + crc).digest()
    return crc_input + crc + record_hash


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def iter_frames(
    stream: BinaryIO,
    *,
    max_frame: int,
) -> Iterator[FrameRecord]:
    """Yield verified frames while reading at most one bounded frame at a time."""
    _validate_max_frame(max_frame)
    expected_previous = bytes(32)
    offset = 0
    while True:
        magic = _read_exact(stream, len(_MAGIC))
        if not magic:
            return
        if len(magic) < len(_MAGIC):
            raise TornTail(offset)
        if magic != _MAGIC:
            raise JournalCorrupt("invalid frame magic")

        header_tail = _read_exact(stream, _HEADER_SIZE - len(_MAGIC))
        if len(header_tail) != _HEADER_SIZE - len(_MAGIC):
            raise TornTail(offset)
        header = magic + header_tail
        payload_length = struct.unpack_from(">I", header, len(_MAGIC))[0]
        if payload_length > max_frame:
            raise JournalCorrupt("frame payload length exceeds explicit limit")

        body = _read_exact(stream, payload_length + (_OVERHEAD - _HEADER_SIZE))
        if len(body) != payload_length + (_OVERHEAD - _HEADER_SIZE):
            raise TornTail(offset)
        frame = header + body
        previous_hash = header[8:40]
        if previous_hash != expected_previous:
            raise JournalCorrupt("previous record hash mismatch")

        crc_offset = _HEADER_SIZE + payload_length
        stored_crc = struct.unpack_from(">I", frame, crc_offset)[0]
        computed_crc = google_crc32c.value(frame[:crc_offset])
        if stored_crc != computed_crc:
            raise JournalCorrupt("CRC32C mismatch")
        stored_hash = frame[crc_offset + 4 :]
        computed_hash = hashlib.sha256(_HASH_DOMAIN + frame[: crc_offset + 4]).digest()
        if stored_hash != computed_hash:
            raise JournalCorrupt("frame hash mismatch")

        size = _OVERHEAD + payload_length
        yield FrameRecord(
            payload=bytes(frame[_HEADER_SIZE:crc_offset]),
            previous_hash=bytes(previous_hash),
            record_hash=bytes(stored_hash),
            offset=offset,
            size=size,
        )
        expected_previous = computed_hash
        offset += size


def read_frames(stream: BinaryIO, *, max_frame: int) -> DecodedFrames:
    """Collect records from a bounded streaming verification pass."""
    records: list[FrameRecord] = []
    try:
        records.extend(iter_frames(stream, max_frame=max_frame))
    except TornTail as error:
        return DecodedFrames(tuple(records), True, error.verified_bytes)
    verified_bytes = records[-1].offset + records[-1].size if records else 0
    return DecodedFrames(tuple(records), False, verified_bytes)


def decode_frames(raw: bytes, *, max_frame: int) -> DecodedFrames:
    """Verify in-memory AGF1 bytes without modifying their source."""
    return read_frames(io.BytesIO(raw), max_frame=max_frame)
