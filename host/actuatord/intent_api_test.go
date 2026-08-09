package actuatord

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

func TestIntentAPIReadsPinnedMixedJournalWithoutMutationAuthority(t *testing.T) {
	fixture := newPrepareFixture(t)
	service := openFixtureService(t, t.TempDir(), fixture)
	routes := newIntentRoutes(service)
	intentRaw, err := contracts.CanonicalJSON(fixture.intent)
	if err != nil {
		t.Fatal(err)
	}
	status, planRaw := callIntentRoute(
		t,
		routes,
		http.MethodPost,
		"/v1/intents",
		intentRaw,
	)
	if status != http.StatusOK {
		t.Fatalf("prepare status=%d body=%q", status, planRaw)
	}
	plan, err := contracts.DecodeStrict[contracts.PreparedTemporaryEgressDenyPlanV1](
		bytes.NewReader(planRaw),
		intentAPIMaxBody,
	)
	if err != nil {
		t.Fatal(err)
	}

	status, raw := callIntentRoute(
		t,
		routes,
		http.MethodGet,
		"/v1/intents/"+fixture.intent.IntentID,
		nil,
	)
	if status != http.StatusOK {
		t.Fatalf("intent status=%d body=%q", status, raw)
	}
	var intentStatus struct {
		SchemaVersion string                                      `json:"schema_version"`
		IntentID      string                                      `json:"intent_id"`
		IntentSHA256  string                                      `json:"intent_sha256"`
		State         string                                      `json:"state"`
		PreparedPlan  contracts.PreparedTemporaryEgressDenyPlanV1 `json:"prepared_plan"`
		LatestAction  struct {
			State        string `json:"state"`
			RecordID     string `json:"record_id"`
			RecordSHA256 string `json:"record_sha256"`
			ObservedAt   string `json:"observed_at"`
		} `json:"latest_action"`
	}
	if err := json.Unmarshal(raw, &intentStatus); err != nil {
		t.Fatal(err)
	}
	if intentStatus.SchemaVersion != "agmind.actuator-intent-status.v1" ||
		intentStatus.IntentID != fixture.intent.IntentID ||
		intentStatus.State != "PREPARED" ||
		intentStatus.IntentSHA256 == "" ||
		intentStatus.LatestAction.State != "PREPARED" ||
		intentStatus.LatestAction.RecordID == "" ||
		!reflect.DeepEqual(intentStatus.PreparedPlan, plan) {
		t.Fatalf("unexpected intent status: %+v", intentStatus)
	}

	type snapshotDocument struct {
		RecordCount   uint64 `json:"record_count"`
		VerifiedBytes int64  `json:"verified_bytes"`
		HeadSHA256    string `json:"head_sha256"`
	}
	type recordDocument struct {
		Index               uint64 `json:"index"`
		Offset              int64  `json:"offset"`
		Size                uint64 `json:"size"`
		PayloadLength       uint32 `json:"payload_length"`
		PreviousFrameSHA256 string `json:"previous_frame_sha256"`
		FrameSHA256         string `json:"frame_sha256"`
		PayloadBase64       string `json:"payload_base64"`
	}
	type pageDocument struct {
		SchemaVersion string           `json:"schema_version"`
		Snapshot      snapshotDocument `json:"snapshot"`
		After         uint64           `json:"after"`
		Records       []recordDocument `json:"records"`
		NextAfter     uint64           `json:"next_after"`
		More          bool             `json:"more"`
	}

	status, firstRaw := callIntentRoute(
		t,
		routes,
		http.MethodGet,
		"/v1/journal-records?after=0&limit=1",
		nil,
	)
	if status != http.StatusOK || len(firstRaw) > 4*1024*1024 {
		t.Fatalf("first page status=%d bytes=%d body=%q", status, len(firstRaw), firstRaw)
	}
	var first pageDocument
	if err := json.Unmarshal(firstRaw, &first); err != nil {
		t.Fatal(err)
	}
	if first.SchemaVersion != "agmind.actuator-journal-page.v1" ||
		first.Snapshot.RecordCount != 2 || first.Snapshot.VerifiedBytes <= 0 ||
		first.Snapshot.HeadSHA256 == fmt.Sprintf("%064x", 0) ||
		first.After != 0 || first.NextAfter != 1 || !first.More ||
		len(first.Records) != 1 || first.Records[0].Index != 1 ||
		first.Records[0].Offset != 0 ||
		first.Records[0].PreviousFrameSHA256 != fmt.Sprintf("%064x", 0) {
		t.Fatalf("unexpected first page: %+v", first)
	}
	firstPayload, err := base64.StdEncoding.DecodeString(first.Records[0].PayloadBase64)
	if err != nil {
		t.Fatal(err)
	}
	if schema, err := journalRecordSchema(firstPayload); err != nil ||
		schema != "agmind.intent-rate-reservation.v1" {
		t.Fatalf("first record schema=%q err=%v", schema, err)
	}

	if _, err := service.Approve(
		context.Background(),
		AdminAuthority{UID: 0, GID: 0, AuthorizationBasis: "root"},
		ExactPlanRef{
			PlanID:        plan.PlanID,
			PlanHashValue: plan.PlanHashValue,
			Nonce:         plan.Nonce,
		},
	); err != nil {
		t.Fatal(err)
	}
	continuation := fmt.Sprintf(
		"/v1/journal-records?after=1&limit=1&snapshot_records=%d&snapshot_bytes=%d&snapshot_head=%s",
		first.Snapshot.RecordCount,
		first.Snapshot.VerifiedBytes,
		first.Snapshot.HeadSHA256,
	)
	status, secondRaw := callIntentRoute(t, routes, http.MethodGet, continuation, nil)
	if status != http.StatusOK || len(secondRaw) > 4*1024*1024 {
		t.Fatalf("second page status=%d bytes=%d body=%q", status, len(secondRaw), secondRaw)
	}
	var second pageDocument
	if err := json.Unmarshal(secondRaw, &second); err != nil {
		t.Fatal(err)
	}
	if second.Snapshot != first.Snapshot || second.After != 1 ||
		second.NextAfter != 2 || second.More || len(second.Records) != 1 ||
		second.Records[0].Index != 2 ||
		second.Records[0].PreviousFrameSHA256 != first.Records[0].FrameSHA256 {
		t.Fatalf("unexpected pinned continuation: %+v", second)
	}
	secondPayload, err := base64.StdEncoding.DecodeString(second.Records[0].PayloadBase64)
	if err != nil {
		t.Fatal(err)
	}
	if schema, err := journalRecordSchema(secondPayload); err != nil ||
		schema != "agmind.action-record.v1" {
		t.Fatalf("second record schema=%q err=%v", schema, err)
	}
	tamperedHead := first.Snapshot.HeadSHA256[:63] + "0"
	if tamperedHead == first.Snapshot.HeadSHA256 {
		tamperedHead = first.Snapshot.HeadSHA256[:63] + "1"
	}
	tamperedContinuation := fmt.Sprintf(
		"/v1/journal-records?after=1&limit=1&snapshot_records=%d&snapshot_bytes=%d&snapshot_head=%s",
		first.Snapshot.RecordCount,
		first.Snapshot.VerifiedBytes,
		tamperedHead,
	)
	if status, _ := callIntentRoute(
		t,
		routes,
		http.MethodGet,
		tamperedContinuation,
		nil,
	); status != http.StatusConflict {
		t.Fatalf("tampered snapshot status=%d", status)
	}

	if status, _ := callIntentRoute(
		t,
		routes,
		http.MethodGet,
		"/v1/journal-records?limit=1&after=0",
		nil,
	); status != http.StatusBadRequest {
		t.Fatalf("non-canonical query status=%d", status)
	}
	if status, _ := callIntentRoute(
		t,
		routes,
		http.MethodGet,
		"/v1/journal-records?after=1&limit=1",
		nil,
	); status != http.StatusBadRequest {
		t.Fatalf("unpinned continuation status=%d", status)
	}
	if status, _ := callIntentRoute(
		t,
		routes,
		http.MethodGet,
		"/v1/intents/int_00000000000000000000000000000000",
		nil,
	); status != http.StatusNotFound {
		t.Fatalf("unknown intent status=%d", status)
	}
	if status, _ := callIntentRoute(
		t,
		routes,
		http.MethodPost,
		"/v1/journal-records",
		[]byte(`{}`),
	); status != http.StatusMethodNotAllowed {
		t.Fatalf("journal mutation status=%d", status)
	}
}
