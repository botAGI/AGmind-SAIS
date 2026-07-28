package observerd

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"agmind.local/sais/internal/contracts"
)

func TestTask4FalcoEnvelopeUsesSensorEventTime(t *testing.T) {
	service, _, _, _, _ := observerServiceFixture(t)
	if err := service.ReconcileDocker(
		context.Background(),
		"observer_startup",
	); err != nil {
		t.Fatal(err)
	}
	input := falcoIngestFixture()
	input.EventTime = "2026-07-27T11:59:58.123456789Z"
	event, err := service.IngestFalco(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if event.EventTime != input.EventTime {
		t.Fatalf(
			"envelope event_time=%q want sensor=%q",
			event.EventTime,
			input.EventTime,
		)
	}
}

func TestTask4FalcoCoverageRouteDerivesObserverOwnedEnvelopeFields(t *testing.T) {
	service, _, _, _, _ := observerServiceFixture(t)
	sourceHash := strings.Repeat("a", 64)
	input := FalcoAdapterCoverageInputV1{
		Kind:                "falco_parse_rejection",
		OpenedAt:            "2026-07-27T12:00:00.123456789Z",
		ReasonCode:          "invalid_json",
		SourcePayloadSHA256: sourceHash,
	}
	event, err := service.IngestFalcoCoverage(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if event.EventType != "coverage" ||
		event.EventTime != input.OpenedAt ||
		event.SourcePayloadHash != sourceHash ||
		!reflect.DeepEqual(
			event.CoverageFlags,
			[]string{"falco_parse_rejection"},
		) {
		t.Fatalf("coverage envelope=%+v", event)
	}
	raw, err := contracts.CanonicalJSON(event.NormalizedFields)
	if err != nil {
		t.Fatal(err)
	}
	coverage, err := contracts.DecodeStrict[contracts.CoverageEventV1](
		bytes.NewReader(raw),
		65_536,
	)
	if err != nil {
		t.Fatal(err)
	}
	if coverage.Component != "falco-adapter" ||
		coverage.Kind != input.Kind ||
		coverage.Severity != "CRITICAL" ||
		coverage.ReasonCode != input.ReasonCode ||
		coverage.ReconcileGeneration != nil {
		t.Fatalf("derived coverage=%+v", coverage)
	}
}

func TestTask4FalcoCoverageDerivesLeaseAndLifecyclePointSeverity(t *testing.T) {
	service, _, _, _, _ := observerServiceFixture(t)
	timestamp := "2026-07-27T12:00:05Z"
	for _, testCase := range []struct {
		kind     string
		severity string
	}{
		{kind: "falco_adapter_start", severity: "INFO"},
		{kind: "falco_heartbeat_lease", severity: "INFO"},
		{kind: "falco_adapter_stop", severity: "CRITICAL"},
	} {
		t.Run(testCase.kind, func(t *testing.T) {
			input := FalcoAdapterCoverageInputV1{
				Kind:                testCase.kind,
				OpenedAt:            timestamp,
				ClosedAt:            &timestamp,
				ReasonCode:          "test_point",
				SourcePayloadSHA256: strings.Repeat("a", 64),
			}
			event, err := service.IngestFalcoCoverage(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if len(event.CoverageFlags) != 0 {
				t.Fatalf("closed point flags=%v", event.CoverageFlags)
			}
			raw, err := contracts.CanonicalJSON(event.NormalizedFields)
			if err != nil {
				t.Fatal(err)
			}
			coverage, err := contracts.DecodeStrict[contracts.CoverageEventV1](
				bytes.NewReader(raw),
				65_536,
			)
			if err != nil {
				t.Fatal(err)
			}
			if coverage.Severity != testCase.severity ||
				coverage.OpenedAt != timestamp ||
				coverage.ClosedAt == nil ||
				*coverage.ClosedAt != timestamp {
				t.Fatalf("derived point=%+v", coverage)
			}
		})
	}

	badClose := "2026-07-27T12:00:06Z"
	if err := (FalcoAdapterCoverageInputV1{
		Kind:                "falco_heartbeat_lease",
		OpenedAt:            timestamp,
		ClosedAt:            &badClose,
		ReasonCode:          "not_a_point",
		SourcePayloadSHA256: strings.Repeat("a", 64),
	}).Validate(); err == nil {
		t.Fatal("non-point heartbeat lease was accepted")
	}
}

func TestTask4FalcoCoverageRejectsSensorChosenAuthorityAndIsRouteSeparated(
	t *testing.T,
) {
	service, _, _, _, _ := observerServiceFixture(t)
	valid := []byte(
		`{"kind":"falco_parse_rejection",` +
			`"opened_at":"2026-07-27T12:00:00Z",` +
			`"reason_code":"invalid_json",` +
			`"source_payload_sha256":"` + strings.Repeat("a", 64) + `"}`,
	)
	injected := append([]byte{}, valid[:len(valid)-1]...)
	injected = append(
		injected,
		[]byte(`,"component":"sensor","severity":"INFO",`+
			`"reconcile_generation":9}`)...,
	)
	response := httptest.NewRecorder()
	falcoCoverageIngestHandler(service).ServeHTTP(
		response,
		httptest.NewRequest(
			http.MethodPost,
			"http://unix/v1/events/falco-coverage",
			bytes.NewReader(injected),
		),
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("injected authority status=%d body=%s", response.Code, response.Body)
	}

	for _, testCase := range []struct {
		name       string
		handler    http.Handler
		wantStatus int
	}{
		{
			name:       "sensor ingest owns route",
			handler:    newIngestAPI(service, 2001),
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "core socket excludes route",
			handler:    newCoreAPI(service, 2002, 1002),
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "private socket excludes route",
			handler:    newPrivateAPI(service),
			wantStatus: http.StatusNotFound,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			testCase.handler.ServeHTTP(
				response,
				httptest.NewRequest(
					http.MethodPost,
					"http://unix/v1/events/falco-coverage",
					bytes.NewReader(valid),
				),
			)
			if response.Code != testCase.wantStatus {
				t.Fatalf(
					"status=%d want=%d body=%s",
					response.Code,
					testCase.wantStatus,
					response.Body,
				)
			}
		})
	}
}
