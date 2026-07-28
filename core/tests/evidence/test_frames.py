from __future__ import annotations

import io

import pytest
from agmind_immune.evidence import frames as frame_codec
from agmind_immune.evidence.frames import JournalCorrupt, decode_frames

GOLDEN_FRAME = bytes.fromhex(
    "4147463100000013"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "7b226b696e64223a22637269746963616c227d"
    "bf7947a4"
    "2cbb22fc60bedacd10fd4bfebc898289fd6b1bcfdcbfb113b2f64f1f08ed9556"
)

SECOND_GOLDEN_FRAME = bytes.fromhex(
    "414746310000000f"
    "2cbb22fc60bedacd10fd4bfebc898289fd6b1bcfdcbfb113b2f64f1f08ed9556"
    "7b226b696e64223a226e657874227d"
    "6391fe75"
    "9069c7160c8a0839155eeb0caaaed9497958d71d62b8809ae9e329f860c40fbd"
)


class BoundedReadStream(io.BytesIO):
    def read(self, size: int = -1, /) -> bytes:
        assert size >= 0, "streaming decoder attempted an unbounded read"
        return super().read(size)


def test_go_frame_golden_decodes_exactly() -> None:
    decoded = decode_frames(GOLDEN_FRAME, max_frame=65_536)
    assert [record.payload for record in decoded.records] == [b'{"kind":"critical"}']
    assert decoded.torn_tail is False


def test_encoder_matches_go_golden_and_streaming_reader_verifies_chain() -> None:
    encode_frame = getattr(frame_codec, "encode_frame", None)
    read_frames = getattr(frame_codec, "read_frames", None)
    iter_frames = getattr(frame_codec, "iter_frames", None)
    assert callable(encode_frame)
    assert callable(read_frames)
    assert callable(iter_frames)

    first = encode_frame(
        b'{"kind":"critical"}',
        previous_hash=bytes(32),
        max_frame=65_536,
    )
    second = encode_frame(
        b'{"kind":"next"}',
        previous_hash=GOLDEN_FRAME[-32:],
        max_frame=65_536,
    )
    assert first == GOLDEN_FRAME
    assert second == SECOND_GOLDEN_FRAME

    stream = BoundedReadStream(first + second)
    decoded = read_frames(stream, max_frame=65_536)
    assert [record.payload for record in decoded.records] == [
        b'{"kind":"critical"}',
        b'{"kind":"next"}',
    ]
    assert [record.offset for record in decoded.records] == [0, len(GOLDEN_FRAME)]
    assert decoded.verified_bytes == len(GOLDEN_FRAME) + len(SECOND_GOLDEN_FRAME)
    assert decoded.torn_tail is False

    streamed = tuple(iter_frames(BoundedReadStream(first + second), max_frame=65_536))
    assert streamed == decoded.records


def test_streaming_reader_reports_torn_tail_without_hiding_verified_prefix() -> None:
    read_frames = getattr(frame_codec, "read_frames", None)
    assert callable(read_frames)

    decoded = read_frames(
        BoundedReadStream(GOLDEN_FRAME + SECOND_GOLDEN_FRAME[:-7]),
        max_frame=65_536,
    )
    assert decoded.records == decode_frames(GOLDEN_FRAME, max_frame=65_536).records
    assert decoded.verified_bytes == len(GOLDEN_FRAME)
    assert decoded.torn_tail is True


@pytest.mark.parametrize("offset", [40, len(GOLDEN_FRAME) - 1])
def test_frame_rejects_crc_and_hash_mismatch(offset: int) -> None:
    damaged = bytearray(GOLDEN_FRAME)
    damaged[offset] ^= 1
    with pytest.raises(JournalCorrupt):
        decode_frames(bytes(damaged), max_frame=65_536)


def test_torn_tail_is_reported_but_complete_bad_frame_is_corruption() -> None:
    decoded = decode_frames(GOLDEN_FRAME[:-10], max_frame=65_536)
    assert decoded.records == ()
    assert decoded.torn_tail is True

    damaged = bytearray(GOLDEN_FRAME)
    damaged[0] ^= 1
    with pytest.raises(JournalCorrupt):
        decode_frames(bytes(damaged), max_frame=65_536)


def test_payload_bound_is_enforced() -> None:
    with pytest.raises(ValueError, match="positive"):
        decode_frames(GOLDEN_FRAME, max_frame=0)
    with pytest.raises(JournalCorrupt, match="payload length"):
        decode_frames(GOLDEN_FRAME, max_frame=18)


@pytest.mark.parametrize("cut", range(4, len(GOLDEN_FRAME)))
def test_short_final_tail_with_bad_magic_is_corruption(cut: int) -> None:
    damaged = bytearray(GOLDEN_FRAME[:cut])
    damaged[0] ^= 1
    with pytest.raises(JournalCorrupt, match="magic"):
        decode_frames(bytes(damaged), max_frame=65_536)
