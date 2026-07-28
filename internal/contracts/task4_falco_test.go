package contracts

import (
	"bytes"
	"testing"
)

func TestTask4FalcoSensorOmissionsAreExactlyAccounted(t *testing.T) {
	event, err := DecodeStrict[FalcoConnectV1](
		bytes.NewReader(fixtureBytes(t, "falco.sensor-missing.valid.json")),
		65_536,
	)
	if err != nil {
		t.Fatal(err)
	}
	if event.EventTime != "2026-07-27T12:00:03Z" ||
		event.FalcoContainerIDPrefix != nil ||
		event.FalcoContainerStartTS != nil ||
		event.ProcName != nil ||
		event.ProcExePath != nil ||
		event.DestinationIPv4 != nil ||
		event.DestinationPort != nil ||
		event.L4Protocol != nil {
		t.Fatalf("sensor omissions were not preserved: %+v", event)
	}
	event.MissingRequiredFields = []string{}
	if err := event.Validate(); err == nil {
		t.Fatal("unaccounted sensor omissions were accepted")
	}
}

func TestTask4FalcoCandidateRequiresEventTimeAndEverySensorFact(t *testing.T) {
	event, err := DecodeStrict[FalcoConnectV1](
		bytes.NewReader(fixtureBytes(t, "falco.candidate.valid.json")),
		65_536,
	)
	if err != nil {
		t.Fatal(err)
	}
	event.EventTime = ""
	if err := event.Validate(); err == nil {
		t.Fatal("candidate without event_time was accepted")
	}

	event, err = DecodeStrict[FalcoConnectV1](
		bytes.NewReader(fixtureBytes(t, "falco.candidate.valid.json")),
		65_536,
	)
	if err != nil {
		t.Fatal(err)
	}
	event.ProcName = nil
	event.MissingRequiredFields = []string{"proc_name"}
	if err := event.Validate(); err == nil {
		t.Fatal("candidate with an omitted sensor fact was accepted")
	}
}

func TestTask4FalcoMissingRequiredFieldsAreSensorOnly(t *testing.T) {
	event, err := DecodeStrict[FalcoConnectV1](
		bytes.NewReader(fixtureBytes(t, "falco.investigation.valid.json")),
		65_536,
	)
	if err != nil {
		t.Fatal(err)
	}
	event.MissingRequiredFields = []string{"docker_container_id"}
	if err := event.Validate(); err == nil {
		t.Fatal("observer-owned docker_container_id was accepted as sensor missing")
	}
}
