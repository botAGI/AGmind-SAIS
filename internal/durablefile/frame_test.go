package durablefile_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"agmind.local/sais/internal/durablefile"
)

const goldenFrameHex = "" +
	"4147463100000013" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"7b226b696e64223a22637269746963616c227d" +
	"bf7947a4" +
	"2cbb22fc60bedacd10fd4bfebc898289fd6b1bcfdcbfb113b2f64f1f08ed9556"

func TestEncodeFrameMatchesCrossLanguageGolden(t *testing.T) {
	frame, meta, err := durablefile.EncodeFrame(
		[]byte(`{"kind":"critical"}`),
		[32]byte{},
		65_536,
	)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString(goldenFrameHex)
	if err != nil {
		t.Fatal(err)
	}
	if string(frame) != string(want) {
		t.Fatalf("frame mismatch:\n got %x\nwant %x", frame, want)
	}
	if meta.Size != uint64(len(want)) {
		t.Fatalf("size=%d want=%d", meta.Size, len(want))
	}
	if meta.PayloadLength != 19 {
		t.Fatalf("payload length=%d", meta.PayloadLength)
	}
}

func TestDecodeFrameRejectsCRCAndHashAndChainMismatch(t *testing.T) {
	raw, err := hex.DecodeString(goldenFrameHex)
	if err != nil {
		t.Fatal(err)
	}
	record, err := durablefile.DecodeFrame(raw, 65_536, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if string(record.Payload) != `{"kind":"critical"}` {
		t.Fatalf("payload=%q", record.Payload)
	}

	for name, offset := range map[string]int{
		"crc":  40,
		"hash": len(raw) - 1,
	} {
		t.Run(name, func(t *testing.T) {
			damaged := append([]byte(nil), raw...)
			damaged[offset] ^= 1
			if _, err := durablefile.DecodeFrame(
				damaged,
				65_536,
				[32]byte{},
			); !errors.Is(err, durablefile.ErrJournalCorrupt) {
				t.Fatalf("got %v, want ErrJournalCorrupt", err)
			}
		})
	}

	var wrongPrevious [32]byte
	wrongPrevious[0] = 1
	if _, err := durablefile.DecodeFrame(
		raw,
		65_536,
		wrongPrevious,
	); !errors.Is(err, durablefile.ErrJournalCorrupt) {
		t.Fatalf("got %v, want ErrJournalCorrupt", err)
	}
}

func TestFramePayloadBoundIsExplicitAndNonzero(t *testing.T) {
	if _, _, err := durablefile.EncodeFrame([]byte("x"), [32]byte{}, 0); err == nil {
		t.Fatal("zero maxFrame must fail")
	}
	if _, _, err := durablefile.EncodeFrame([]byte("xx"), [32]byte{}, 1); !errors.Is(
		err,
		durablefile.ErrFrameTooLarge,
	) {
		t.Fatalf("got %v, want ErrFrameTooLarge", err)
	}
}

func FuzzDecodeAGF1(fuzz *testing.F) {
	golden, err := hex.DecodeString(goldenFrameHex)
	if err != nil {
		fuzz.Fatal(err)
	}
	fuzz.Add(golden)
	fuzz.Add([]byte{})
	fuzz.Add([]byte("AGF1"))
	fuzz.Add([]byte{
		'A', 'G', 'F', '1',
		0xff, 0xff, 0xff, 0xff,
	})
	fuzz.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65_536+76 {
			return
		}
		record, err := durablefile.DecodeFrame(raw, 65_536, [32]byte{})
		if err != nil {
			return
		}
		if record.PayloadLength > 65_536 ||
			record.Size != uint64(len(raw)) ||
			uint64(len(record.Payload)) != uint64(record.PayloadLength) {
			t.Fatalf("decoder returned inconsistent bounded record: %+v", record.RecordMeta)
		}
		reencoded, _, err := durablefile.EncodeFrame(
			record.Payload,
			record.PreviousHash,
			65_536,
		)
		if err != nil || !bytes.Equal(raw, reencoded) {
			t.Fatalf("accepted frame did not round-trip: err=%v", err)
		}
	})
}
