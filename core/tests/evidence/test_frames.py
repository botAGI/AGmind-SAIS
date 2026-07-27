from __future__ import annotations

import pytest
from agmind_immune.evidence.frames import JournalCorrupt, decode_frames

GOLDEN_FRAME = bytes.fromhex(
    "4147463100000013"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "7b226b696e64223a22637269746963616c227d"
    "bf7947a4"
    "2cbb22fc60bedacd10fd4bfebc898289fd6b1bcfdcbfb113b2f64f1f08ed9556"
)


def test_go_frame_golden_decodes_exactly() -> None:
    decoded = decode_frames(GOLDEN_FRAME, max_frame=65_536)
    assert [record.payload for record in decoded.records] == [b'{"kind":"critical"}']
    assert decoded.torn_tail is False


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
