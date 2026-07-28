package contracts

import (
	"bytes"
	"os"
	"testing"
)

func TestObserverBootBoundaryContractMatrix(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{
			name: "genesis",
			raw: `{
				"schema_version":"agmind.observer-boot-boundary.v1",
				"kind":"observer_boot_boundary",
				"reason_code":"observer_genesis",
				"previous_source_sequence":0
			}`,
		},
		{
			name: "changed boot",
			raw: `{
				"schema_version":"agmind.observer-boot-boundary.v1",
				"kind":"observer_boot_boundary",
				"reason_code":"kernel_boot_id_changed",
				"previous_boot_id":"123e4567-e89b-42d3-b456-426614174001",
				"previous_source_sequence":7
			}`,
		},
		{
			name: "genesis cannot name predecessor",
			raw: `{
				"schema_version":"agmind.observer-boot-boundary.v1",
				"kind":"observer_boot_boundary",
				"reason_code":"observer_genesis",
				"previous_boot_id":"123e4567-e89b-42d3-b456-426614174001",
				"previous_source_sequence":0
			}`,
			wantErr: true,
		},
		{
			name: "changed boot requires predecessor",
			raw: `{
				"schema_version":"agmind.observer-boot-boundary.v1",
				"kind":"observer_boot_boundary",
				"reason_code":"kernel_boot_id_changed",
				"previous_source_sequence":7
			}`,
			wantErr: true,
		},
		{
			name: "changed boot requires nonzero cursor",
			raw: `{
				"schema_version":"agmind.observer-boot-boundary.v1",
				"kind":"observer_boot_boundary",
				"reason_code":"kernel_boot_id_changed",
				"previous_boot_id":"123e4567-e89b-42d3-b456-426614174001",
				"previous_source_sequence":0
			}`,
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeStrict[ObserverBootBoundaryV1](
				bytes.NewBufferString(test.raw),
				65_536,
			)
			if (err != nil) != test.wantErr {
				t.Fatalf("decode error=%v wantErr=%v", err, test.wantErr)
			}
		})
	}
}

func TestEventEnvelopeRejectsZeroSourceSequence(t *testing.T) {
	raw, err := os.ReadFile("../../contracts/fixtures/v1/envelope.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	event, err := DecodeStrict[EventEnvelopeV1](bytes.NewReader(raw), 65_536)
	if err != nil {
		t.Fatal(err)
	}
	event.SourceSequence = 0
	event.EventID = "evt_46661781770926e5720f74d49d3e6e32d6cc77b5502ab90f6f64a574a70ce145"
	if err := event.Validate(); err == nil {
		t.Fatal("source_sequence=0 was accepted")
	}
}
