package actuatord

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/uds"
)

func callIntentRoute(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	body []byte,
) (int, []byte) {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	raw, err := io.ReadAll(response.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.Code, raw
}

func TestIntentAPIAcceptsOnlyExactAuthorizedCoreIntent(t *testing.T) {
	const coreUID = uint32(2001)
	if !intentPeerAuthorized(uds.Peer{UID: 0, GID: 9000}, coreUID) ||
		!intentPeerAuthorized(uds.Peer{UID: coreUID, GID: 9000}, coreUID) ||
		intentPeerAuthorized(uds.Peer{UID: 2002, GID: 2001}, coreUID) {
		t.Fatal("intent mutation authority is not root-or-exact-core-UID")
	}

	fixture := newPrepareFixture(t)
	service := openFixtureService(t, t.TempDir(), fixture)
	valid, err := contracts.CanonicalJSON(fixture.intent)
	if err != nil {
		t.Fatal(err)
	}

	status, raw := callIntentRoute(
		t,
		newIntentAPI(service, coreUID),
		http.MethodPost,
		"/v1/intents",
		valid,
	)
	if status != http.StatusForbidden || string(raw) != "{\"error\":\"peer_not_authorized\"}\n" ||
		fixture.observer.calls != 0 {
		t.Fatalf("missing peer status=%d body=%q observer_calls=%d", status, raw, fixture.observer.calls)
	}

	routes := newIntentRoutes(service)
	status, first := callIntentRoute(
		t,
		routes,
		http.MethodPost,
		"/v1/intents",
		valid,
	)
	if status != http.StatusOK {
		t.Fatalf("first status=%d body=%q", status, first)
	}
	plan, err := contracts.DecodeStrict[contracts.PreparedTemporaryEgressDenyPlanV1](
		bytes.NewReader(first),
		intentAPIMaxBody,
	)
	if err != nil {
		t.Fatalf("decode plan: %v body=%q", err, first)
	}
	stored, err := service.GetPlan(plan.PlanID)
	if err != nil || !reflect.DeepEqual(plan, stored) {
		t.Fatalf("returned plan is not exact persisted plan: err=%v", err)
	}
	prepareCalls := fixture.observer.calls
	status, retry := callIntentRoute(
		t,
		routes,
		http.MethodPost,
		"/v1/intents",
		valid,
	)
	if status != http.StatusOK || !bytes.Equal(first, retry) ||
		fixture.observer.calls != prepareCalls || service.Pending() != 1 {
		t.Fatalf(
			"retry status=%d exact=%t observer_calls=%d want=%d pending=%d",
			status,
			bytes.Equal(first, retry),
			fixture.observer.calls,
			prepareCalls,
			service.Pending(),
		)
	}

	unknown := append([]byte(nil), valid[:len(valid)-1]...)
	unknown = append(unknown, []byte(`,"action":"shell","authority":"root"}`)...)
	status, raw = callIntentRoute(
		t,
		routes,
		http.MethodPost,
		"/v1/intents",
		unknown,
	)
	if status != http.StatusBadRequest || string(raw) != "{\"error\":\"invalid_intent\"}\n" ||
		fixture.observer.calls != prepareCalls {
		t.Fatalf("unknown fields status=%d body=%q observer_calls=%d", status, raw, fixture.observer.calls)
	}

	conflict := fixture.intent
	conflict.CreatedAt = "2026-07-27T12:00:00.000000001Z"
	conflictRaw, err := contracts.CanonicalJSON(conflict)
	if err != nil {
		t.Fatal(err)
	}
	status, raw = callIntentRoute(
		t,
		routes,
		http.MethodPost,
		"/v1/intents",
		conflictRaw,
	)
	if status != http.StatusConflict || string(raw) != "{\"error\":\"intent_conflict\"}\n" ||
		fixture.observer.calls != prepareCalls {
		t.Fatalf("conflict status=%d body=%q observer_calls=%d", status, raw, fixture.observer.calls)
	}

	if status, _ := callIntentRoute(t, routes, http.MethodGet, "/v1/intents", nil); status != http.StatusMethodNotAllowed {
		t.Fatalf("GET /v1/intents status=%d", status)
	}
	if status, _ := callIntentRoute(t, routes, http.MethodPost, "/v1/actions", valid); status != http.StatusNotFound {
		t.Fatalf("POST /v1/actions status=%d", status)
	}
	if _, err := ListenIntent("/invalid", -1, int(coreUID), service); !errors.Is(err, uds.ErrUnsafeSocket) {
		t.Fatalf("negative core GID error=%v", err)
	}
}
