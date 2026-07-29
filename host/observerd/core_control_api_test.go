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

type coreControlPublisherFunc func(
	context.Context,
	CoreControlRequest,
) (CoreControlPublication, error)

func (publish coreControlPublisherFunc) PublishCoreControl(
	ctx context.Context,
	request CoreControlRequest,
) (CoreControlPublication, error) {
	return publish(ctx, request)
}

type panicCoreControlBody struct{}

func (panicCoreControlBody) Read([]byte) (int, error) {
	panic("unauthorized or absent route read the request body")
}

func TestC2AControlHTTPDecodesExactRouteTypeAndReturnsFullItem(t *testing.T) {
	testCases := []struct {
		name        string
		request     CoreControlRequest
		handler     func(any) http.Handler
		item        CoreEventV1
		requestType reflect.Type
	}{
		{
			name:        "authorize",
			request:     coreControlAuthorizeFixture(),
			handler:     coreControlHandler[EvidenceRepairAuthorizeV1],
			item:        controlReceiptTestItem(t, 11, "evidence_repair_authorized", "repair_id", coreControlRepairID),
			requestType: reflect.TypeOf(EvidenceRepairAuthorizeV1{}),
		},
		{
			name:        "complete",
			request:     coreControlCompleteFixture(),
			handler:     coreControlHandler[EvidenceRepairCompleteV1],
			item:        controlReceiptTestItem(t, 12, "evidence_repair_completed", "repair_id", coreControlRepairID),
			requestType: reflect.TypeOf(EvidenceRepairCompleteV1{}),
		},
		{
			name:        "tombstone",
			request:     coreControlTombstoneFixture(),
			handler:     coreControlHandler[RetentionTombstoneV2],
			item:        controlReceiptTestItem(t, 13, "retention_tombstone", "tombstone_id", "33333333-3333-4333-8333-333333333333"),
			requestType: reflect.TypeOf(RetentionTombstoneV2{}),
		},
		{
			name:        "blocked",
			request:     coreControlBlockedFixture(),
			handler:     coreControlHandler[RetentionBlockedV1],
			item:        controlReceiptTestItem(t, 14, "retention_blocked_priority_evidence", "blocked_id", "44444444-4444-4444-8444-444444444444"),
			requestType: reflect.TypeOf(RetentionBlockedV1{}),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			raw, err := CanonicalCoreControlRequest(testCase.request)
			if err != nil {
				t.Fatal(err)
			}
			var published CoreControlRequest
			backend := coreControlPublisherFunc(func(
				_ context.Context,
				request CoreControlRequest,
			) (CoreControlPublication, error) {
				published = request
				return CoreControlPublication{
					Item:    testCase.item,
					Created: true,
				}, nil
			})
			response := httptest.NewRecorder()
			testCase.handler(backend).ServeHTTP(
				response,
				httptest.NewRequest(
					http.MethodPost,
					"http://unix/v1/events/"+testCase.name,
					bytes.NewReader(raw),
				),
			)
			if response.Code != http.StatusCreated {
				t.Fatalf("status=%d body=%s", response.Code, response.Body)
			}
			if published == nil ||
				reflect.TypeOf(published) != testCase.requestType {
				t.Fatalf(
					"published type=%T want=%v",
					published,
					testCase.requestType,
				)
			}
			publishedHash, err := CoreControlRequestSHA256(published)
			if err != nil {
				t.Fatal(err)
			}
			requestHash, err := CoreControlRequestSHA256(testCase.request)
			if err != nil {
				t.Fatal(err)
			}
			if publishedHash != requestHash {
				t.Fatalf(
					"published hash=%s want=%s",
					publishedHash,
					requestHash,
				)
			}
			want, err := contracts.CanonicalJSON(testCase.item)
			if err != nil {
				t.Fatal(err)
			}
			want = append(want, '\n')
			if !bytes.Equal(response.Body.Bytes(), want) {
				t.Fatalf(
					"response=%s want=%s",
					response.Body.Bytes(),
					want,
				)
			}
		})
	}
}

func TestC2AControlHTTPMapsPublicationOutcomeExactly(t *testing.T) {
	request := coreControlAuthorizeFixture()
	raw, err := CanonicalCoreControlRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	item := controlReceiptTestItem(
		t,
		21,
		"evidence_repair_authorized",
		"repair_id",
		coreControlRepairID,
	)
	testCases := []struct {
		name        string
		publication CoreControlPublication
		err         error
		wantStatus  int
	}{
		{
			name:        "created",
			publication: CoreControlPublication{Item: item, Created: true},
			wantStatus:  http.StatusCreated,
		},
		{
			name:        "exact retry",
			publication: CoreControlPublication{Item: item},
			wantStatus:  http.StatusOK,
		},
		{
			name:       "operation conflict",
			err:        ErrCoreOperationConflict,
			wantStatus: http.StatusConflict,
		},
		{
			name:       "authorization binding",
			err:        ErrCoreAuthorizationBinding,
			wantStatus: http.StatusConflict,
		},
		{
			name:       "raw receipt conflict",
			err:        ErrControlReceiptConflict,
			wantStatus: http.StatusConflict,
		},
		{
			name:       "receipt quota",
			err:        ErrControlReceiptQuota,
			wantStatus: http.StatusInsufficientStorage,
		},
		{
			name:       "global priority quota",
			err:        ErrPriorityQuota,
			wantStatus: http.StatusInsufficientStorage,
		},
		{
			name:       "canceled",
			err:        context.Canceled,
			wantStatus: http.StatusRequestTimeout,
		},
		{
			name:       "deadline",
			err:        context.DeadlineExceeded,
			wantStatus: http.StatusRequestTimeout,
		},
		{
			name:       "other",
			err:        errors.New("publication failed"),
			wantStatus: http.StatusServiceUnavailable,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			backend := coreControlPublisherFunc(func(
				_ context.Context,
				_ CoreControlRequest,
			) (CoreControlPublication, error) {
				return testCase.publication, testCase.err
			})
			response := httptest.NewRecorder()
			coreControlHandler[EvidenceRepairAuthorizeV1](backend).ServeHTTP(
				response,
				httptest.NewRequest(
					http.MethodPost,
					"http://unix/v1/events/evidence-repair-authorize",
					bytes.NewReader(raw),
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
			if testCase.err != nil &&
				strings.Contains(response.Body.String(), item.EventID) {
				t.Fatal("error response leaked a publication item")
			}
		})
	}
}

func TestC2AControlHTTPRejectsWrongTypeUnknownFieldAndBoundOverflow(
	t *testing.T,
) {
	authorizeRaw, err := CanonicalCoreControlRequest(
		coreControlAuthorizeFixture(),
	)
	if err != nil {
		t.Fatal(err)
	}
	unknown := append([]byte(nil), authorizeRaw[:len(authorizeRaw)-1]...)
	unknown = append(unknown, []byte(`,"unknown":true}`)...)
	oversize := append([]byte(nil), authorizeRaw...)
	oversize = append(
		oversize,
		[]byte(strings.Repeat(" ", int(evidenceRepairAuthorizeRequestMaxBytes)))...,
	)
	testCases := []struct {
		name        string
		makeHandler func(any) http.Handler
		raw         []byte
	}{
		{
			name:        "wrong route type",
			makeHandler: coreControlHandler[EvidenceRepairCompleteV1],
			raw:         authorizeRaw,
		},
		{
			name:        "unknown field",
			makeHandler: coreControlHandler[EvidenceRepairAuthorizeV1],
			raw:         unknown,
		},
		{
			name:        "request bound overflow",
			makeHandler: coreControlHandler[EvidenceRepairAuthorizeV1],
			raw:         oversize,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			calls := 0
			backend := coreControlPublisherFunc(func(
				_ context.Context,
				_ CoreControlRequest,
			) (CoreControlPublication, error) {
				calls++
				return CoreControlPublication{}, nil
			})
			response := httptest.NewRecorder()
			testCase.makeHandler(backend).ServeHTTP(
				response,
				httptest.NewRequest(
					http.MethodPost,
					"http://unix/v1/events/control",
					bytes.NewReader(testCase.raw),
				),
			)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body)
			}
			if calls != 0 {
				t.Fatalf("invalid body reached publisher %d times", calls)
			}
		})
	}
}

func TestC2AControlHTTPRejectsInvalidOrMismatchedBackendItem(t *testing.T) {
	request := coreControlAuthorizeFixture()
	raw, err := CanonicalCoreControlRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	invalid := controlReceiptTestItem(
		t,
		31,
		"evidence_repair_authorized",
		"repair_id",
		coreControlRepairID,
	)
	invalid.Sequence++
	mismatched := controlReceiptTestItem(
		t,
		32,
		"evidence_repair_authorized",
		"repair_id",
		"55555555-5555-4555-8555-555555555555",
	)
	for name, item := range map[string]CoreEventV1{
		"invalid outer binding": invalid,
		"different request":     mismatched,
	} {
		t.Run(name, func(t *testing.T) {
			backend := coreControlPublisherFunc(func(
				_ context.Context,
				_ CoreControlRequest,
			) (CoreControlPublication, error) {
				return CoreControlPublication{
					Item:    item,
					Created: true,
				}, nil
			})
			response := httptest.NewRecorder()
			coreControlHandler[EvidenceRepairAuthorizeV1](backend).ServeHTTP(
				response,
				httptest.NewRequest(
					http.MethodPost,
					"http://unix/v1/events/evidence-repair-authorize",
					bytes.NewReader(raw),
				),
			)
			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("status=%d body=%s", response.Code, response.Body)
			}
		})
	}
}

func TestC2AControlHTTPRoutesAreCoreOnlyAndAuthorizeBeforeBodyRead(
	t *testing.T,
) {
	core := newCoreAPI(nil, 2002, 1002)
	sensor := newIngestAPI(nil, 2001)
	private := newPrivateAPI(nil)
	paths := []string{
		"/v1/events/evidence-repair-authorize",
		"/v1/events/evidence-repair-complete",
		"/v1/events/retention-tombstone",
		"/v1/events/retention-blocked",
	}
	for _, path := range paths {
		for _, testCase := range []struct {
			name       string
			handler    http.Handler
			wantStatus int
		}{
			{
				name:       "core requires UID",
				handler:    core,
				wantStatus: http.StatusForbidden,
			},
			{
				name:       "sensor absent",
				handler:    sensor,
				wantStatus: http.StatusNotFound,
			},
			{
				name:       "private absent",
				handler:    private,
				wantStatus: http.StatusNotFound,
			},
		} {
			t.Run(testCase.name+" "+path, func(t *testing.T) {
				response := httptest.NewRecorder()
				testCase.handler.ServeHTTP(
					response,
					httptest.NewRequest(
						http.MethodPost,
						"http://unix"+path,
						io.Reader(panicCoreControlBody{}),
					),
				)
				if response.Code != testCase.wantStatus {
					t.Fatalf(
						"path=%s status=%d want=%d body=%s",
						path,
						response.Code,
						testCase.wantStatus,
						response.Body,
					)
				}
			})
		}
	}
}
