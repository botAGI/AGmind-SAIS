"""Read-only decoder for the AGF1 frame format produced by Go host services."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

import google_crc32c

_MAGIC = b"AGF1"
_HEADER_SIZE = 40
_OVERHEAD = 76
_HASH_DOMAIN = b"AGMIND_FRAME_V1\0"


class JournalCorrupt(ValueError):
    """A complete frame or chain link failed integrity validation."""


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


def decode_frames(raw: bytes, *, max_frame: int) -> DecodedFrames:
    """Verify an AGF1 stream without modifying its source."""
    if max_frame <= 0:
        raise ValueError("max_frame must be positive")
    if max_frame > 0xFFFFFFFF:
        raise ValueError("max_frame exceeds uint32")

    records: list[FrameRecord] = []
    offset = 0
    expected_previous = bytes(32)
    torn_tail = False
    while offset < len(raw):
        remaining = len(raw) - offset
        if remaining >= len(_MAGIC) and raw[offset : offset + 4] != _MAGIC:
            raise JournalCorrupt("invalid frame magic")
        if remaining < _HEADER_SIZE:
            torn_tail = True
            break
        payload_length = struct.unpack_from(">I", raw, offset + 4)[0]
        if payload_length > max_frame:
            raise JournalCorrupt("frame payload length exceeds explicit limit")
        total = _OVERHEAD + payload_length
        if remaining < total:
            torn_tail = True
            break

        frame = raw[offset : offset + total]
        previous_hash = frame[8:40]
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
        records.append(
            FrameRecord(
                payload=bytes(frame[_HEADER_SIZE:crc_offset]),
                previous_hash=bytes(previous_hash),
                record_hash=bytes(stored_hash),
                offset=offset,
                size=total,
            )
        )
        expected_previous = computed_hash
        offset += total
    return DecodedFrames(tuple(records), torn_tail, offset)
