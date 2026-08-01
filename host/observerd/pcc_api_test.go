package observerd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"agmind.local/sais/internal/contracts"
)

type pccAPIPublisherStub struct {
	publication PCCCorrelationPublication
	err         error
	calls       int
	requests    []contracts.PCCCorrelationSnapshotRequestV1
}

func (stub *pccAPIPublisherStub) PublishPCCCorrelationSnapshot(
	_ context.Context,
	request contracts.PCCCorrelationSnapshotRequestV1,
) (PCCCorrelationPublication, error) {
	stub.calls++
	stub.requests = append(stub.requests, request)
	return stub.publication, stub.err
}

type pccReadTrackingBody struct {
	reads int
}

func (body *pccReadTrackingBody) Read([]byte) (int, error) {
	body.reads++
	return 0, io.EOF
}

func TestPCCAPIIsCoreOnlyAndAuthenticatesBeforeBodyRead(t *testing.T) {
	body := &pccReadTrackingBody{}
	request := httptest.NewRequest(
		http.MethodPost,
		"http://unix/v1/events/pcc-correlation-snapshot",
		body,
	)
	response := httptest.NewRecorder()
	newCoreAPI(nil, 2002, 1002).ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated route status=%d body=%s", response.Code, response.Body)
	}
	if body.reads != 0 {
		t.Fatalf("unauthenticated request body read %d times", body.reads)
	}

	for name, handler := range map[string]http.Handler{
		"sensor":  newIngestAPI(nil, 2001),
		"private": newPrivateAPI(nil),
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(
			response,
			httptest.NewRequest(
				http.MethodPost,
				"http://unix/v1/events/pcc-correlation-snapshot",
				nil,
			),
		)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s listener exposed PCC route: status=%d", name, response.Code)
		}
	}
}

func TestPCCAPIRequiresOneBoundedCanonicalRequest(t *testing.T) {
	valid, err := contracts.CanonicalJSON(pccPublishRequestFixture())
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"noncanonical": append(bytes.Clone(valid), '\n'),
		"trailing":     append(bytes.Clone(valid), []byte(`{}`)...),
		"unknown": []byte(`{"schema_version":"agmind.pcc-correlation-snapshot-request.v1","trigger_event_id":"evt_` +
			strings.Repeat("a", 64) + `","trigger_content_sha256":"` +
			strings.Repeat("b", 64) + `","trigger_source_sequence":1,"requested_ttl_seconds":120,"extra":true}`),
		"wrong-ttl": bytes.Replace(valid, []byte(`120`), []byte(`121`), 1),
		"too-large": bytes.Repeat([]byte(" "), int(pccCorrelationRequestMaxBytes+1)),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			stub := &pccAPIPublisherStub{}
			response := httptest.NewRecorder()
			pccCorrelationHandler(stub).ServeHTTP(
				response,
				httptest.NewRequest(
					http.MethodPost,
					"http://unix/v1/events/pcc-correlation-snapshot",
					bytes.NewReader(raw),
				),
			)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body)
			}
			if stub.calls != 0 {
				t.Fatalf("invalid request reached publisher %d times", stub.calls)
			}
		})
	}

	for name, publicationErr := range map[string]error{
		"conflict":    ErrPCCPublicationConflict,
		"unavailable": ErrPCCPublicationUnavailable,
		"wrapped":     errors.Join(errors.New("outer"), ErrPCCPublicationUnavailable),
	} {
		t.Run(name, func(t *testing.T) {
			stub := &pccAPIPublisherStub{err: publicationErr}
			response := httptest.NewRecorder()
			pccCorrelationHandler(stub).ServeHTTP(
				response,
				httptest.NewRequest(
					http.MethodPost,
					"http://unix/v1/events/pcc-correlation-snapshot",
					bytes.NewReader(valid),
				),
			)
			want := http.StatusServiceUnavailable
			if name == "conflict" {
				want = http.StatusConflict
			}
			if response.Code != want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, want, response.Body)
			}
		})
	}

	t.Run("canonical ttl-120 request reaches publisher exactly once", func(t *testing.T) {
		stub := &pccAPIPublisherStub{err: ErrPCCPublicationUnavailable}
		response := httptest.NewRecorder()
		pccCorrelationHandler(stub).ServeHTTP(
			response,
			httptest.NewRequest(
				http.MethodPost,
				"http://unix/v1/events/pcc-correlation-snapshot",
				bytes.NewReader(valid),
			),
		)
		if response.Code != http.StatusServiceUnavailable || stub.calls != 1 {
			t.Fatalf(
				"valid request status=%d calls=%d body=%s",
				response.Code,
				stub.calls,
				response.Body,
			)
		}
	})
}

func TestPCCAPISuccessStatusCanonicalResponseAndFixedErrors(t *testing.T) {
	root := t.TempDir()
	privateKey := testKey(t, 126)
	_, spool, signer := openSignerFixture(
		t,
		root,
		testBootID,
		privateKey,
	)
	spoolItem, _ := pccReceiptSnapshotFixture(
		t,
		spool,
		signer,
		"api-success",
	)
	item, err := coreEventFromSpoolItem(spoolItem)
	if err != nil {
		t.Fatal(err)
	}
	if item.Envelope.EventType != "pcc_correlation_snapshot" {
		t.Fatalf("fixture event type=%q", item.Envelope.EventType)
	}

	proofRequest := pccPublishRequestFixture()
	requestRaw, err := contracts.CanonicalJSON(proofRequest)
	if err != nil {
		t.Fatal(err)
	}
	wantCanonical, err := contracts.CanonicalJSON(item)
	if err != nil {
		t.Fatal(err)
	}
	wantWire := append(bytes.Clone(wantCanonical), '\n')

	for _, test := range []struct {
		name    string
		created bool
		status  int
	}{
		{name: "created", created: true, status: http.StatusCreated},
		{name: "idempotent retry", created: false, status: http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			stub := &pccAPIPublisherStub{publication: PCCCorrelationPublication{
				Item:    item,
				Created: test.created,
			}}
			response := httptest.NewRecorder()
			pccCorrelationHandler(stub).ServeHTTP(
				response,
				httptest.NewRequest(
					http.MethodPost,
					"http://unix/v1/events/pcc-correlation-snapshot",
					bytes.NewReader(requestRaw),
				),
			)
			if response.Code != test.status {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.status, response.Body)
			}
			if stub.calls != 1 || len(stub.requests) != 1 ||
				!reflect.DeepEqual(stub.requests[0], proofRequest) {
				t.Fatalf("publisher calls=%d requests=%+v want=%+v", stub.calls, stub.requests, proofRequest)
			}
			if !bytes.Equal(response.Body.Bytes(), wantWire) {
				t.Fatalf("response=%q want canonical=%q", response.Body.Bytes(), wantWire)
			}
			decoded, err := contracts.DecodeStrict[CoreEventV1](
				bytes.NewReader(response.Body.Bytes()),
				65_536,
			)
			if err != nil {
				t.Fatal(err)
			}
			decodedCanonical, err := contracts.CanonicalJSON(decoded)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decodedCanonical, wantCanonical) {
				t.Fatalf("decoded response=%q want=%q", decodedCanonical, wantCanonical)
			}
		})
	}

	for _, test := range []struct {
		name   string
		err    error
		status int
		body   string
	}{
		{
			name:   "publication conflict",
			err:    ErrPCCPublicationConflict,
			status: http.StatusConflict,
			body:   "{\"error\":\"pcc_request_conflict\"}\n",
		},
		{
			name:   "receipt conflict",
			err:    ErrPCCReceiptConflict,
			status: http.StatusConflict,
			body:   "{\"error\":\"pcc_request_conflict\"}\n",
		},
		{
			name:   "publication unavailable",
			err:    ErrPCCPublicationUnavailable,
			status: http.StatusServiceUnavailable,
			body:   "{\"error\":\"pcc_publication_unavailable\"}\n",
		},
		{
			name:   "unexpected publisher failure",
			err:    errors.New("unexpected publisher failure"),
			status: http.StatusServiceUnavailable,
			body:   "{\"error\":\"pcc_publication_unavailable\"}\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stub := &pccAPIPublisherStub{err: test.err}
			response := httptest.NewRecorder()
			pccCorrelationHandler(stub).ServeHTTP(
				response,
				httptest.NewRequest(
					http.MethodPost,
					"http://unix/v1/events/pcc-correlation-snapshot",
					bytes.NewReader(requestRaw),
				),
			)
			if response.Code != test.status || response.Body.String() != test.body {
				t.Fatalf("status=%d body=%q want status=%d body=%q", response.Code, response.Body.String(), test.status, test.body)
			}
			if stub.calls != 1 || len(stub.requests) != 1 ||
				!reflect.DeepEqual(stub.requests[0], proofRequest) {
				t.Fatalf("publisher calls=%d requests=%+v want=%+v", stub.calls, stub.requests, proofRequest)
			}
		})
	}
}
