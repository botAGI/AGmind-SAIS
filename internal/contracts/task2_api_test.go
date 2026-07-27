package contracts

import (
	"bytes"
	"os"
	"testing"
)

func TestDeriveEventIDAllowsUnsignedProducerWithoutWeakeningEventID(t *testing.T) {
	raw, err := os.ReadFile("../../contracts/fixtures/v1/envelope.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	event, err := DecodeStrict[EventEnvelopeV1](bytes.NewReader(raw), 65_536)
	if err != nil {
		t.Fatal(err)
	}
	want := event.EventID
	event.EventID = ""
	event.SourceSignature = ""
	got, err := DeriveEventID(event)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("derived %q want %q", got, want)
	}
	if _, err := EventID(event); err == nil {
		t.Fatal("EventID must continue validating the complete signed contract")
	}
}

func TestDeriveEventIDValidatesOnlyLockedDerivationInputs(t *testing.T) {
	event := EventEnvelopeV1{
		HostID:                 "123e4567-e89b-42d3-a456-426614174000",
		BootID:                 "123e4567-e89b-42d3-b456-426614174001",
		KeyEpoch:               1,
		SourceSequence:         7,
		NormalizedFieldsSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	if _, err := DeriveEventID(event); err != nil {
		t.Fatal(err)
	}
	event.KeyEpoch = 0
	if _, err := DeriveEventID(event); err == nil {
		t.Fatal("zero key epoch must fail")
	}
	event.KeyEpoch = 1
	event.SourceSequence = 0
	if _, err := DeriveEventID(event); err == nil {
		t.Fatal("zero source sequence must fail")
	}
}
