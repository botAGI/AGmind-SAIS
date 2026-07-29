package observerd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"agmind.local/sais/internal/contracts"
)

func falcoIngestFixture() contracts.FalcoConnectV1 {
	rawres := int64(0)
	suppliedFullID := inventoryTestIDOne
	untrustedDockerID := inventoryTestIDTwo
	untrustedStartedAt := "2026-07-27T11:00:00Z"
	untrustedImageID := "sha256:" + strings.Repeat("9", 64)
	untrustedSpec := strings.Repeat("8", 64)
	untrustedRevision := uint64(999)
	prefix := inventoryTestIDOne[:12]
	procName := "curl"
	procExePath := "/usr/bin/curl"
	procParentName := "sh"
	destinationIPv4 := "1.1.1.1"
	destinationPort := uint16(443)
	l4Protocol := "tcp"
	return contracts.FalcoConnectV1{
		DetectorRule:           "AGmind PCC Suspicious Process Outbound Connect",
		DetectorRuleVersion:    "agmind-pcc-rules-v1",
		FalcoVersion:           "0.44.1",
		EventTime:              "2026-07-27T12:00:00.123456789Z",
		EvtType:                "connect",
		EvtRawres:              &rawres,
		EvtRes:                 "SUCCESS",
		SuccessfulConnect:      true,
		InvestigationOnly:      true,
		FalcoContainerIDPrefix: &prefix,
		FalcoContainerFullID:   &suppliedFullID,
		FalcoContainerStartTS:  "2026-07-27T12:00:00.123456789Z",
		DockerContainerID:      &untrustedDockerID,
		DockerStartedAt:        &untrustedStartedAt,
		ImageID:                &untrustedImageID,
		RepoDigests: []string{
			"untrusted.invalid/app@sha256:" + strings.Repeat("7", 64),
		},
		ImmutableSpecSHA256:   &untrustedSpec,
		InventoryRevision:     &untrustedRevision,
		ProcName:              &procName,
		ProcExePath:           &procExePath,
		ProcParentName:        &procParentName,
		DestinationIPv4:       &destinationIPv4,
		DestinationPort:       &destinationPort,
		L4Protocol:            &l4Protocol,
		MissingRequiredFields: []string{},
		RawEventSHA256:        strings.Repeat("d", 64),
	}
}

func decodeFalcoEnvelope(
	t *testing.T,
	event contracts.EventEnvelopeV1,
) contracts.FalcoConnectV1 {
	t.Helper()
	raw, err := contracts.CanonicalJSON(event.NormalizedFields)
	if err != nil {
		t.Fatal(err)
	}
	falco, err := contracts.DecodeStrict[contracts.FalcoConnectV1](
		bytes.NewReader(raw),
		65_536,
	)
	if err != nil {
		t.Fatal(err)
	}
	return falco
}

func TestIngestFalcoReplacesUntrustedDockerFieldsWithAuthoritativeIdentity(
	t *testing.T,
) {
	service, _, _, inventory, _ := observerServiceFixture(t)
	if err := service.ReconcileDocker(
		context.Background(),
		"observer_startup",
	); err != nil {
		t.Fatal(err)
	}
	identity, err := inventory.LookupFullID(inventoryTestIDOne)
	if err != nil {
		t.Fatal(err)
	}

	event, err := service.IngestFalco(
		context.Background(),
		falcoIngestFixture(),
	)
	if err != nil {
		t.Fatal(err)
	}
	got := decodeFalcoEnvelope(t, event)
	if got.InvestigationOnly ||
		got.DockerContainerID == nil ||
		*got.DockerContainerID != identity.FullContainerID ||
		got.DockerStartedAt == nil ||
		*got.DockerStartedAt != identity.DockerStartedAt ||
		got.ImageID == nil ||
		*got.ImageID != identity.ImageID ||
		got.ImmutableSpecSHA256 == nil ||
		*got.ImmutableSpecSHA256 != identity.ImmutableSpecSHA256 ||
		got.InventoryRevision == nil ||
		*got.InventoryRevision != identity.InventoryRevision ||
		!reflect.DeepEqual(got.RepoDigests, identity.RepoDigests) {
		t.Fatalf("Falco authority was not replaced: %+v", got)
	}
	if event.ContainerID == nil ||
		*event.ContainerID != identity.FullContainerID ||
		event.ContainerStartTime == nil ||
		*event.ContainerStartTime != identity.DockerStartedAt ||
		event.InventoryGeneration != identity.InventoryGeneration ||
		event.InventoryRevision == nil ||
		*event.InventoryRevision != identity.InventoryRevision ||
		event.SourcePayloadHash != got.RawEventSHA256 ||
		len(event.CoverageFlags) != 0 {
		t.Fatalf("envelope identity=%+v", event)
	}
}

func TestIngestFalcoFullIDMismatchIsSignedInvestigationOnlyWithoutAuthority(
	t *testing.T,
) {
	service, _, _, _, _ := observerServiceFixture(t)
	if err := service.ReconcileDocker(
		context.Background(),
		"observer_startup",
	); err != nil {
		t.Fatal(err)
	}
	input := falcoIngestFixture()
	mismatch := inventoryTestIDTwo
	input.FalcoContainerFullID = &mismatch

	event, err := service.IngestFalco(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	got := decodeFalcoEnvelope(t, event)
	if !got.InvestigationOnly ||
		got.DockerContainerID != nil ||
		got.DockerStartedAt != nil ||
		got.ImageID != nil ||
		got.ImmutableSpecSHA256 != nil ||
		got.InventoryRevision != nil ||
		len(got.RepoDigests) != 0 ||
		event.ContainerID != nil ||
		event.ContainerStartTime != nil ||
		event.InventoryRevision != nil {
		t.Fatalf("mismatch retained candidate authority: event=%+v falco=%+v", event, got)
	}
	if !reflect.DeepEqual(
		event.CoverageFlags,
		[]string{"docker_identity_mismatch"},
	) || !reflect.DeepEqual(
		got.MissingRequiredFields,
		[]string{},
	) {
		t.Fatalf(
			"mismatch evidence flags=%v missing=%v",
			event.CoverageFlags,
			got.MissingRequiredFields,
		)
	}
}

func TestFalcoIngestHTTPRejectsNonExactOrOversizeJSONWithoutSequence(
	t *testing.T,
) {
	service, state, _, _, _ := observerServiceFixture(t)
	valid, err := contracts.CanonicalJSON(falcoIngestFixture())
	if err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(
		valid,
		[]byte(`"detector_rule":`),
		[]byte(`"detector_rule":"duplicate","detector_rule":`),
		1,
	)
	unknown := append([]byte{}, valid[:len(valid)-1]...)
	unknown = append(unknown, []byte(`,"unknown":true}`)...)
	for name, testCase := range map[string]struct {
		raw    []byte
		status int
	}{
		"duplicate": {raw: duplicate, status: http.StatusBadRequest},
		"unknown":   {raw: unknown, status: http.StatusBadRequest},
		"trailing": {
			raw:    append(append([]byte{}, valid...), []byte(` {}`)...),
			status: http.StatusBadRequest,
		},
		"oversize": {
			raw: bytes.Repeat(
				[]byte("x"),
				int(falcoIngestMaxBytes+1),
			),
			status: http.StatusRequestEntityTooLarge,
		},
	} {
		t.Run(name, func(t *testing.T) {
			before := state.Snapshot().LastSequence
			request := httptest.NewRequest(
				http.MethodPost,
				"http://unix/v1/events/falco",
				bytes.NewReader(testCase.raw),
			)
			response := httptest.NewRecorder()
			falcoIngestHandler(service).ServeHTTP(response, request)
			if response.Code != testCase.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body)
			}
			if got := state.Snapshot().LastSequence; got != before {
				t.Fatalf("invalid input reserved sequence %d -> %d", before, got)
			}
		})
	}
}

func TestFalcoIngestHTTPReturnsOnlyEventID(t *testing.T) {
	service, _, _, _, _ := observerServiceFixture(t)
	if err := service.ReconcileDocker(
		context.Background(),
		"observer_startup",
	); err != nil {
		t.Fatal(err)
	}
	raw, err := contracts.CanonicalJSON(falcoIngestFixture())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"http://unix/v1/events/falco",
		bytes.NewReader(raw),
	)
	response := httptest.NewRecorder()
	falcoIngestHandler(service).ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body)
	}
	var result map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 ||
		!strings.HasPrefix(result["event_id"], "evt_") {
		t.Fatalf("response=%v", result)
	}
}
