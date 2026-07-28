package observerd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/uds"
)

func coreAPIEventFixture(
	t *testing.T,
) (*Service, *Spool, contracts.EventEnvelopeV1) {
	t.Helper()
	service, _, spool, _, _ := observerServiceFixture(t)
	if err := service.ReconcileDocker(
		context.Background(),
		"observer_startup",
	); err != nil {
		t.Fatal(err)
	}
	event, err := service.IngestFalco(
		context.Background(),
		falcoIngestFixture(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return service, spool, event
}

func TestCoreEventsFetchIsBoundedOrderedAndAckDeletesOnlyExactEvent(
	t *testing.T,
) {
	service, spool, _ := coreAPIEventFixture(t)
	request := httptest.NewRequest(
		http.MethodGet,
		"http://unix/v1/events?after=0&limit=1",
		nil,
	)
	response := httptest.NewRecorder()
	coreEventsHandler(service).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("fetch status=%d body=%s", response.Code, response.Body)
	}
	var versionedPage struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &versionedPage); err != nil {
		t.Fatal(err)
	}
	if versionedPage.SchemaVersion != "agmind.observer-events-page.v1" {
		t.Fatalf("events page schema_version=%q", versionedPage.SchemaVersion)
	}
	var page CoreEventsPageV1
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 1 ||
		page.Events[0].Sequence != 1 ||
		page.Events[0].EventID != page.Events[0].Envelope.EventID ||
		len(page.UncoveredGaps) != 0 {
		t.Fatalf("page=%+v", page)
	}

	wrongAck := CoreAckV1{
		SchemaVersion: "agmind.observer-ack.v1",
		Sequence:      page.Events[0].Sequence,
		EventID:       page.Events[0].EventID,
		ContentSHA256: "0000000000000000000000000000000000000000000000000000000000000000",
	}
	raw, err := contracts.CanonicalJSON(wrongAck)
	if err != nil {
		t.Fatal(err)
	}
	ackResponse := httptest.NewRecorder()
	coreAckHandler(service).ServeHTTP(
		ackResponse,
		httptest.NewRequest(
			http.MethodPost,
			"http://unix/v1/events/ack",
			bytes.NewReader(raw),
		),
	)
	if ackResponse.Code != http.StatusConflict {
		t.Fatalf("wrong ack status=%d body=%s", ackResponse.Code, ackResponse.Body)
	}
	if items, err := spool.Fetch(0, 1, 4*1024*1024); err != nil ||
		len(items) != 1 ||
		items[0].Sequence != page.Events[0].Sequence {
		t.Fatalf("wrong ack deleted event: items=%d err=%v", len(items), err)
	}

	exactAck := wrongAck
	exactAck.ContentSHA256 = page.Events[0].ContentSHA256
	raw, err = contracts.CanonicalJSON(exactAck)
	if err != nil {
		t.Fatal(err)
	}
	ackResponse = httptest.NewRecorder()
	coreAckHandler(service).ServeHTTP(
		ackResponse,
		httptest.NewRequest(
			http.MethodPost,
			"http://unix/v1/events/ack",
			bytes.NewReader(raw),
		),
	)
	if ackResponse.Code != http.StatusNoContent {
		t.Fatalf("exact ack status=%d body=%s", ackResponse.Code, ackResponse.Body)
	}
	if items, err := spool.Fetch(0, 1, 4*1024*1024); err != nil ||
		len(items) != 1 ||
		items[0].Sequence != 2 {
		t.Fatalf("exact ack state: items=%d err=%v", len(items), err)
	}
}

func TestCoreEventsRejectsNonCanonicalOrUnboundedQuery(t *testing.T) {
	service, _, _ := coreAPIEventFixture(t)
	for _, rawQuery := range []string{
		"",
		"after=0",
		"limit=1",
		"after=0&limit=0",
		"after=0&limit=101",
		"after=00&limit=1",
		"after=0&after=1&limit=1",
		"after=0&limit=1&unknown=1",
	} {
		request := httptest.NewRequest(
			http.MethodGet,
			"http://unix/v1/events?"+rawQuery,
			nil,
		)
		response := httptest.NewRecorder()
		coreEventsHandler(service).ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf(
				"query=%q status=%d body=%s",
				rawQuery,
				response.Code,
				response.Body,
			)
		}
	}
}

func TestCoreInventoryAndCoverageReturnOnlyBoundedObserverFacts(t *testing.T) {
	service, _, expected := coreAPIEventFixture(t)

	inventoryRequest := httptest.NewRequest(
		http.MethodGet,
		"http://unix/v1/inventory/"+inventoryTestIDOne,
		nil,
	)
	inventoryRequest.SetPathValue("full_id", inventoryTestIDOne)
	inventoryResponse := httptest.NewRecorder()
	coreInventoryHandler(service).ServeHTTP(
		inventoryResponse,
		inventoryRequest,
	)
	if inventoryResponse.Code != http.StatusOK {
		t.Fatalf(
			"inventory status=%d body=%s",
			inventoryResponse.Code,
			inventoryResponse.Body,
		)
	}
	var identity ContainerIdentityV1
	if err := json.Unmarshal(inventoryResponse.Body.Bytes(), &identity); err != nil {
		t.Fatal(err)
	}
	if identity.FullContainerID != inventoryTestIDOne ||
		identity.InventoryGeneration != expected.InventoryGeneration {
		t.Fatalf("identity=%+v", identity)
	}

	coverageResponse := httptest.NewRecorder()
	coreCoverageHandler(service).ServeHTTP(
		coverageResponse,
		httptest.NewRequest(
			http.MethodGet,
			"http://unix/v1/coverage",
			nil,
		),
	)
	if coverageResponse.Code != http.StatusOK {
		t.Fatalf(
			"coverage status=%d body=%s",
			coverageResponse.Code,
			coverageResponse.Body,
		)
	}
	var coverage CoreCoverageV1
	if err := json.Unmarshal(coverageResponse.Body.Bytes(), &coverage); err != nil {
		t.Fatal(err)
	}
	if coverage.SchemaVersion != "agmind.observer-coverage.v1" ||
		coverage.ReconcileRequired ||
		coverage.DockerReconcileGap ||
		coverage.InventoryGeneration != expected.InventoryGeneration ||
		coverage.LastSequence != expected.SourceSequence ||
		coverage.AckSequence != 0 {
		t.Fatalf("coverage=%+v", coverage)
	}

	notFoundRequest := httptest.NewRequest(
		http.MethodGet,
		"http://unix/v1/inventory/"+inventoryTestIDTwo,
		nil,
	)
	notFoundRequest.SetPathValue("full_id", inventoryTestIDTwo)
	notFoundResponse := httptest.NewRecorder()
	coreInventoryHandler(service).ServeHTTP(notFoundResponse, notFoundRequest)
	if notFoundResponse.Code != http.StatusNotFound {
		t.Fatalf(
			"missing inventory status=%d",
			notFoundResponse.Code,
		)
	}
}

func TestCoreAckRejectsUnknownFieldsWithoutChangingAck(t *testing.T) {
	service, _, expected := coreAPIEventFixture(t)
	raw := []byte(
		`{"schema_version":"agmind.observer-ack.v1",` +
			`"sequence":` + strconv.FormatUint(expected.SourceSequence, 10) + `,` +
			`"event_id":"` + expected.EventID + `",` +
			`"content_sha256":"` + strings.Repeat("0", 64) + `",` +
			`"unknown":true}`,
	)
	response := httptest.NewRecorder()
	coreAckHandler(service).ServeHTTP(
		response,
		httptest.NewRequest(
			http.MethodPost,
			"http://unix/v1/events/ack",
			bytes.NewReader(raw),
		),
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body)
	}
	if service.daemon.state.Snapshot().AckSequence != 0 {
		t.Fatal("invalid ack advanced durable cursor")
	}
}

func TestRetentionTombstoneRouteExistsOnlyOnPhysicalCoreSocket(
	t *testing.T,
) {
	service, _, _, _, _ := observerServiceFixture(t)
	ingest := newIngestAPI(service, 2001)
	core := newCoreAPI(service, 2002, 1002)
	for _, testCase := range []struct {
		name       string
		handler    http.Handler
		path       string
		wantStatus int
	}{
		{
			name:       "tombstone absent from sensor-owned ingest",
			handler:    ingest,
			path:       "/v1/events/retention-tombstone",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "tombstone registered on core",
			handler:    core,
			path:       "/v1/events/retention-tombstone",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "Falco absent from core",
			handler:    core,
			path:       "/v1/events/falco",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "Falco registered on ingest",
			handler:    ingest,
			path:       "/v1/events/falco",
			wantStatus: http.StatusForbidden,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodPost,
				"http://unix"+testCase.path,
				nil,
			)
			response := httptest.NewRecorder()
			testCase.handler.ServeHTTP(response, request)
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

func TestRetentionTombstoneAuthorizationUsesExactCoreUID(t *testing.T) {
	for _, peer := range []uds.Peer{
		{UID: 0, GID: 9999},
		{UID: 1002, GID: 9999},
	} {
		if !retentionTombstonePeerAuthorized(peer, 1002) {
			t.Fatalf("authorized exact UID rejected: %+v", peer)
		}
	}
	for _, peer := range []uds.Peer{
		{UID: 1003, GID: 0},
		{UID: 1003, GID: 2002},
	} {
		if retentionTombstonePeerAuthorized(peer, 1002) {
			t.Fatalf("group-only peer authorized: %+v", peer)
		}
	}
}
