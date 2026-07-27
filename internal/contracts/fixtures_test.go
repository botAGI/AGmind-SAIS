package contracts

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"
)

func TestValidEnvelopeMatchesLockedEventID(t *testing.T) {
	raw, err := os.ReadFile("../../contracts/fixtures/v1/envelope.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeStrict[EventEnvelopeV1](bytes.NewReader(raw), 65536)
	if err != nil {
		t.Fatal(err)
	}
	id, err := EventID(got)
	if err != nil {
		t.Fatal(err)
	}
	if id != got.EventID {
		t.Fatalf("event id %q != %q", id, got.EventID)
	}
}

func TestEventSignatureMatchesCommittedGoldenMessage(t *testing.T) {
	raw, err := os.ReadFile("../../contracts/fixtures/v1/envelope.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	event, err := DecodeStrict[EventEnvelopeV1](bytes.NewReader(raw), 65536)
	if err != nil {
		t.Fatal(err)
	}
	message, err := EventSigningMessage(event)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../contracts/fixtures/v1/signing-message-v1.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, want) {
		t.Fatal("signing message differs from committed golden bytes")
	}
	public, _ := hex.DecodeString("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
	if err := VerifyEventSignature(event, public); err != nil {
		t.Fatal(err)
	}
	bad, err := os.ReadFile("../../contracts/fixtures/v1/envelope.bad-signature.json")
	if err != nil {
		t.Fatal(err)
	}
	badEvent, err := DecodeStrict[EventEnvelopeV1](bytes.NewReader(bad), 65536)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEventSignature(badEvent, public); err == nil {
		t.Fatal("expected changed event to fail signature verification")
	}
}

func FuzzDecodeStrict(f *testing.F) {
	f.Add([]byte(`{"schema_version":"agmind.event-envelope.v1"}`))
	f.Add([]byte(`{"schema_version":"agmind.event-envelope.v1","source_sequence":1.0}`))
	f.Add([]byte(`{"schema_version":"agmind.event-envelope.v1","source_id":"\ud800"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		value, err := DecodeStrict[EventEnvelopeV1](bytes.NewReader(raw), 65536)
		if err != nil {
			return
		}
		if err := value.Validate(); err != nil {
			t.Fatalf("decoder returned invalid contract: %v", err)
		}
		canonical, err := CanonicalJSON(value)
		if err != nil {
			t.Fatalf("accepted contract did not canonicalize: %v", err)
		}
		if len(canonical) == 0 {
			t.Fatal("accepted contract canonicalized to empty bytes")
		}
	})
}

func FuzzCanonicalJSON(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`null`),
		[]byte(`true`),
		[]byte(`1`),
		[]byte(`1.0`),
		[]byte(`["\u2028",1,false,null]`),
		[]byte(`{"\ue000":1,"\ud83d\ude00":2}`),
		{0xff},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		value, err := strictValue(decoder)
		if err != nil {
			return
		}
		if token, err := decoder.Token(); err != io.EOF || token != nil {
			return
		}
		canonical, err := CanonicalJSON(value)
		if err != nil {
			return
		}
		reparsed := json.NewDecoder(bytes.NewReader(canonical))
		reparsed.UseNumber()
		roundTrip, err := strictValue(reparsed)
		if err != nil {
			t.Fatalf("canonical output did not parse: %v", err)
		}
		again, err := CanonicalJSON(roundTrip)
		if err != nil {
			t.Fatalf("canonical output did not re-canonicalize: %v", err)
		}
		if !bytes.Equal(canonical, again) {
			t.Fatalf("canonicalization is not idempotent: %q != %q", canonical, again)
		}
	})
}

func TestIntentRejectsPIDInjection(t *testing.T) {
	raw, err := os.ReadFile("../../contracts/fixtures/v1/intent.pid-injection.invalid.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeStrict[TemporaryEgressDenyIntentV1](bytes.NewReader(raw), 65536); err == nil {
		t.Fatal("expected unknown pid field to be rejected")
	}
}
