package contracts

import (
	"bytes"
	"encoding/hex"
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
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = DecodeStrict[EventEnvelopeV1](bytes.NewReader(raw), 65536) })
}

func FuzzCanonicalJSON(f *testing.F) {
	f.Add("key", "value")
	f.Fuzz(func(t *testing.T, key, value string) { _, _ = CanonicalJSON(map[string]any{key: value}) })
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
