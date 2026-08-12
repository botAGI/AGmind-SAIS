package observerd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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

type pccAPIRecordingPublisher struct {
	publisher pccCorrelationPublisher
	err       error
}

func (recorder *pccAPIRecordingPublisher) PublishPCCCorrelationSnapshot(
	ctx context.Context,
	request contracts.PCCCorrelationSnapshotRequestV1,
) (PCCCorrelationPublication, error) {
	publication, err := recorder.publisher.PublishPCCCorrelationSnapshot(
		ctx,
		request,
	)
	recorder.err = err
	return publication, err
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

func TestPCCAPIPermanentConflictFencePersistenceFailureIsUnavailable(
	t *testing.T,
) {
	fixture := newPCCFailedPublishFixture(t)
	first, err := fixture.service.PublishPCCCorrelationSnapshot(
		context.Background(),
		fixture.request,
	)
	if err != nil || !first.Created {
		t.Fatalf("initial PCC publication=%+v err=%v", first, err)
	}
	before := fixture.state.Snapshot()
	conflict := fixture.request
	conflict.TriggerContentSHA256 = strings.Repeat("9", 64)
	requestRaw, err := contracts.CanonicalJSON(conflict)
	if err != nil {
		t.Fatal(err)
	}

	fenceErr := errors.New("injected permanent PCC conflict fence persistence failure")
	persist := fixture.state.persist
	fenceAttempts := 0
	fixture.state.persist = func(path string, next ObserverState) error {
		if next.MutationReadOnly &&
			next.ReadOnlyReason == "observer_pcc_request_conflict" {
			fenceAttempts++
			return fenceErr
		}
		return persist(path, next)
	}

	response := httptest.NewRecorder()
	recorder := &pccAPIRecordingPublisher{publisher: fixture.service}
	pccCorrelationHandler(recorder).ServeHTTP(
		response,
		httptest.NewRequest(
			http.MethodPost,
			"http://unix/v1/events/pcc-correlation-snapshot",
			bytes.NewReader(requestRaw),
		),
	)
	if response.Code != http.StatusServiceUnavailable ||
		response.Body.String() != "{\"error\":\"pcc_publication_unavailable\"}\n" {
		t.Errorf(
			"permanent conflict fence failure status=%d body=%q",
			response.Code,
			response.Body.String(),
		)
	}
	if !errors.Is(recorder.err, ErrPCCPublicationUnavailable) ||
		errors.Is(recorder.err, ErrPCCReceiptConflict) ||
		errors.Is(recorder.err, ErrPCCPublicationConflict) ||
		!errors.Is(recorder.err, fenceErr) {
		t.Errorf("permanent conflict publisher error classification=%v", recorder.err)
	}
	if fenceAttempts != 2 {
		t.Errorf("permanent conflict fence persistence attempts=%d want=2", fenceAttempts)
	}
	live := fixture.state.Snapshot()
	if !live.MutationReadOnly ||
		live.ReadOnlyReason != "observer_pcc_request_conflict" ||
		live.LastSequence != before.LastSequence ||
		live.PublicationHeadSequence != before.PublicationHeadSequence ||
		live.PublicationHeadHash != before.PublicationHeadHash ||
		live.PCCReceiptCount != before.PCCReceiptCount ||
		live.PCCReceiptBytes != before.PCCReceiptBytes ||
		live.PCCReceiptHeadHash != before.PCCReceiptHeadHash {
		t.Errorf("permanent conflict live state changed: before=%+v after=%+v", before, live)
	}

	if err := fixture.spool.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStateStore(
		fixture.state.path,
		StateIdentity{
			HostID: live.HostID, BootID: live.BootID,
			KeyID: live.KeyID, KeyEpoch: live.KeyEpoch,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	durable := reopened.Snapshot()
	if durable.MutationReadOnly || durable.ReadOnlyReason != "" ||
		durable.LastSequence != before.LastSequence ||
		durable.PublicationHeadSequence != before.PublicationHeadSequence ||
		durable.PublicationHeadHash != before.PublicationHeadHash ||
		durable.PCCReceiptCount != before.PCCReceiptCount ||
		durable.PCCReceiptBytes != before.PCCReceiptBytes ||
		durable.PCCReceiptHeadHash != before.PCCReceiptHeadHash {
		t.Errorf("permanent conflict durable state changed: before=%+v after=%+v", before, durable)
	}
}

// pccRetiredResponseFixture is the exact wire artifact both sides of the
// retirement contract are pinned to. Core keys its ONLY terminal path on these
// bytes, so the observer must produce them byte-for-byte.
func pccRetiredResponseFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(
		"../../contracts/fixtures/v1/observer-pcc-trigger-retired.response.json",
	)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func pccAckThrough(t *testing.T, spool *Spool, through uint64) {
	t.Helper()
	for {
		acked := spool.state.Snapshot().AckSequence
		if acked >= through {
			return
		}
		next := uint64(0)
		spool.mutex.Lock()
		for sequence := range spool.items {
			if sequence > acked && (next == 0 || sequence < next) {
				next = sequence
			}
		}
		item := spool.items[next]
		spool.mutex.Unlock()
		if next == 0 || next > through {
			t.Fatalf("no retained sequence to ACK toward %d", through)
		}
		if err := spool.Ack(
			item.Sequence,
			item.EventID,
			item.ContentSHA256,
		); err != nil {
			t.Fatalf("ACK of sequence %d failed: %v", next, err)
		}
	}
}

func pccCorrelationResponse(
	t *testing.T,
	service *Service,
	request contracts.PCCCorrelationSnapshotRequestV1,
) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := contracts.CanonicalJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	pccCorrelationHandler(service).ServeHTTP(
		response,
		httptest.NewRequest(
			http.MethodPost,
			"http://unix/v1/events/pcc-correlation-snapshot",
			bytes.NewReader(raw),
		),
	)
	return response
}

// A trigger Core itself acknowledged is retired forever: the observer states
// that as 410 pcc_trigger_retired, the one response Core may treat as terminal.
// Every other unresolvable or unavailable outcome must stay fail-closed.
func TestPCCAPIRetiredTriggerIsTheOnlyTerminalRefusal(t *testing.T) {
	t.Run("acknowledged trigger is stated terminal", func(t *testing.T) {
		fixture := newPCCFailedPublishFixture(t)
		pccAckThrough(
			t,
			fixture.spool,
			fixture.request.TriggerSourceSequence,
		)
		before := fixture.state.Snapshot()
		called := []string{}
		pccFailDownstreamSubstrates(fixture.service, &called)

		_, err := fixture.service.PublishPCCCorrelationSnapshot(
			context.Background(),
			fixture.request,
		)
		if !errors.Is(err, ErrPCCTriggerRetired) {
			t.Fatalf("retired trigger error=%v want ErrPCCTriggerRetired", err)
		}
		if errors.Is(err, ErrPCCPublicationUnavailable) ||
			errors.Is(err, ErrPCCPublicationConflict) {
			t.Fatalf("retired trigger error is ambiguous: %v", err)
		}

		response := pccCorrelationResponse(t, fixture.service, fixture.request)
		if response.Code != http.StatusGone {
			t.Fatalf("retired trigger status=%d body=%q", response.Code, response.Body)
		}
		if !bytes.Equal(response.Body.Bytes(), pccRetiredResponseFixture(t)) {
			t.Fatalf(
				"retired trigger body=%q want the committed fixture bytes",
				response.Body.Bytes(),
			)
		}
		if response.Header().Get("Content-Type") != "application/json" {
			t.Fatalf(
				"retired trigger Content-Type=%q",
				response.Header().Get("Content-Type"),
			)
		}
		after := fixture.state.Snapshot()
		if after.MutationReadOnly ||
			after.LastSequence != before.LastSequence ||
			after.PCCReceiptCount != before.PCCReceiptCount {
			t.Fatalf("retired refusal changed state: before=%+v after=%+v", before, after)
		}
		if len(called) != 0 {
			t.Fatalf("retired trigger invoked downstream substrates: %v", called)
		}
	})

	for name, mutate := range map[string]func(
		*testing.T,
		*pccFailedPublishFixture,
	){
		"unknown sequence": func(t *testing.T, fixture *pccFailedPublishFixture) {
			t.Helper()
			fixture.request.TriggerSourceSequence =
				fixture.state.Snapshot().LastSequence + 100
		},
		"mismatched content hash": func(t *testing.T, fixture *pccFailedPublishFixture) {
			t.Helper()
			fixture.request.TriggerContentSHA256 = strings.Repeat("9", 64)
		},
		"read-only observer": func(t *testing.T, fixture *pccFailedPublishFixture) {
			t.Helper()
			// Retired AND read-only: ambiguity must win over terminality.
			pccAckThrough(
				t,
				fixture.spool,
				fixture.request.TriggerSourceSequence,
			)
			if err := fixture.state.PersistReadOnly(
				"observer_pcc_retirement_ambiguity_test",
			); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run("fail-closed: "+name, func(t *testing.T) {
			fixture := newPCCFailedPublishFixture(t)
			mutate(t, fixture)
			called := []string{}
			pccFailDownstreamSubstrates(fixture.service, &called)

			_, err := fixture.service.PublishPCCCorrelationSnapshot(
				context.Background(),
				fixture.request,
			)
			if err == nil || errors.Is(err, ErrPCCTriggerRetired) {
				t.Fatalf("ambiguous refusal claimed retirement: %v", err)
			}
			response := pccCorrelationResponse(t, fixture.service, fixture.request)
			if response.Code == http.StatusGone ||
				bytes.Contains(response.Body.Bytes(), []byte("pcc_trigger_retired")) {
				t.Fatalf(
					"ambiguous refusal status=%d body=%q",
					response.Code,
					response.Body,
				)
			}
			if len(called) != 0 {
				t.Fatalf("rejected trigger invoked downstream substrates: %v", called)
			}
		})
	}
}
