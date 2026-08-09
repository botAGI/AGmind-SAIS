package actuatord

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
	"agmind.local/sais/internal/uds"
)

const (
	intentAPIMaxBody                    = int64(64 * 1024)
	intentJournalPageMaxLimit           = 100
	intentJournalPageMaxResponseBytes   = 4 * 1024 * 1024
	intentJournalPageMaxRawPayloadBytes = int64(3_000_000)
)

var ErrIntentNotFound = errors.New("intent not found")

type intentActionStatusV1 struct {
	State        string `json:"state"`
	RecordID     string `json:"record_id"`
	RecordSHA256 string `json:"record_sha256"`
	ObservedAt   string `json:"observed_at"`
}

type intentStatusV1 struct {
	SchemaVersion string                                       `json:"schema_version"`
	IntentID      string                                       `json:"intent_id"`
	IntentSHA256  string                                       `json:"intent_sha256"`
	State         string                                       `json:"state"`
	PreparedPlan  *contracts.PreparedTemporaryEgressDenyPlanV1 `json:"prepared_plan,omitempty"`
	LatestAction  *intentActionStatusV1                        `json:"latest_action,omitempty"`
}

type journalSnapshotV1 struct {
	RecordCount   uint64 `json:"record_count"`
	VerifiedBytes int64  `json:"verified_bytes"`
	HeadSHA256    string `json:"head_sha256"`
}

type journalRecordV1 struct {
	Index               uint64 `json:"index"`
	Offset              int64  `json:"offset"`
	Size                uint64 `json:"size"`
	PayloadLength       uint32 `json:"payload_length"`
	PreviousFrameSHA256 string `json:"previous_frame_sha256"`
	FrameSHA256         string `json:"frame_sha256"`
	PayloadBase64       string `json:"payload_base64"`
}

type journalPageV1 struct {
	SchemaVersion string            `json:"schema_version"`
	Snapshot      journalSnapshotV1 `json:"snapshot"`
	After         uint64            `json:"after"`
	Records       []journalRecordV1 `json:"records"`
	NextAfter     uint64            `json:"next_after"`
	More          bool              `json:"more"`
}

type journalPageQuery struct {
	after    uint64
	limit    int
	snapshot *durablefile.JournalSnapshot
}

func intentPeerAuthorized(peer uds.Peer, coreUID uint32) bool {
	return peer.UID == 0 || peer.UID == coreUID
}

func intentAPIError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrIntentNotFound):
		writeAdminError(writer, http.StatusNotFound, "intent_not_found")
	case errors.Is(err, durablefile.ErrJournalSnapshotMismatch):
		writeAdminError(writer, http.StatusConflict, "snapshot_mismatch")
	case errors.Is(err, ErrIntentEquivocation):
		writeAdminError(writer, http.StatusConflict, "intent_conflict")
	case errors.Is(err, ErrTargetStale):
		writeAdminError(writer, http.StatusConflict, "target_stale")
	case errors.Is(err, ErrIntentRejected):
		writeAdminError(writer, http.StatusUnprocessableEntity, "intent_rejected")
	case errors.Is(err, ErrIntentRateLimited):
		writeAdminError(writer, http.StatusTooManyRequests, "intent_rate_limited")
	case errors.Is(err, ErrPendingLimit):
		writeAdminError(writer, http.StatusTooManyRequests, "pending_plan_limit")
	case errors.Is(err, ErrObserverUnhealthy):
		writeAdminError(writer, http.StatusServiceUnavailable, "observer_unavailable")
	case errors.Is(err, ErrKillSwitchActive):
		writeAdminError(writer, http.StatusServiceUnavailable, "mutation_disabled")
	case errors.Is(err, durablefile.ErrJournalFailed),
		errors.Is(err, durablefile.ErrJournalClosed):
		writeAdminError(writer, http.StatusServiceUnavailable, "actuator_unavailable")
	default:
		writeAdminError(writer, http.StatusServiceUnavailable, "actuator_unavailable")
	}
}

func canonicalUint(raw string, bits int) (uint64, bool) {
	value, err := strconv.ParseUint(raw, 10, bits)
	return value, err == nil && strconv.FormatUint(value, 10) == raw
}

func parseJournalPageQuery(request *http.Request) (journalPageQuery, bool) {
	if request.ContentLength != 0 {
		return journalPageQuery{}, false
	}
	parts := strings.Split(request.URL.RawQuery, "&")
	if len(parts) != 2 && len(parts) != 5 {
		return journalPageQuery{}, false
	}
	if !strings.HasPrefix(parts[0], "after=") ||
		!strings.HasPrefix(parts[1], "limit=") {
		return journalPageQuery{}, false
	}
	afterRaw := strings.TrimPrefix(parts[0], "after=")
	limitRaw := strings.TrimPrefix(parts[1], "limit=")
	after, afterOK := canonicalUint(afterRaw, 64)
	limitValue, limitOK := canonicalUint(limitRaw, 8)
	if !afterOK || !limitOK || limitValue < 1 ||
		limitValue > intentJournalPageMaxLimit {
		return journalPageQuery{}, false
	}
	query := journalPageQuery{after: after, limit: int(limitValue)}
	if after == 0 {
		return query, len(parts) == 2
	}
	if len(parts) != 5 ||
		!strings.HasPrefix(parts[2], "snapshot_records=") ||
		!strings.HasPrefix(parts[3], "snapshot_bytes=") ||
		!strings.HasPrefix(parts[4], "snapshot_head=") {
		return journalPageQuery{}, false
	}
	recordsRaw := strings.TrimPrefix(parts[2], "snapshot_records=")
	bytesRaw := strings.TrimPrefix(parts[3], "snapshot_bytes=")
	headRaw := strings.TrimPrefix(parts[4], "snapshot_head=")
	recordCount, recordsOK := canonicalUint(recordsRaw, 64)
	verifiedBytes, bytesOK := canonicalUint(bytesRaw, 63)
	headBytes, headErr := hex.DecodeString(headRaw)
	if !recordsOK || !bytesOK || after > recordCount ||
		recordCount > actionJournalMaxRecords ||
		verifiedBytes > uint64(actionJournalMaxBytes) ||
		headErr != nil || len(headBytes) != 32 || !digestPattern.MatchString(headRaw) {
		return journalPageQuery{}, false
	}
	var head [32]byte
	copy(head[:], headBytes)
	query.snapshot = &durablefile.JournalSnapshot{
		RecordCount:   recordCount,
		VerifiedBytes: int64(verifiedBytes),
		Head:          head,
	}
	return query, true
}

func (service *Service) intentStatus(intentID string) (intentStatusV1, error) {
	if service == nil || !intentIDPattern.MatchString(intentID) {
		return intentStatusV1{}, ErrIntentNotFound
	}
	service.mutex.Lock()
	defer service.mutex.Unlock()
	if service.closed || service.journal == nil {
		return intentStatusV1{}, durablefile.ErrJournalClosed
	}
	if service.journal.failed() {
		return intentStatusV1{}, durablefile.ErrJournalFailed
	}
	reservation, reserved := service.journal.reservations[intentID]
	prepared, preparedOK := service.journal.byIntent[intentID]
	if !reserved && !preparedOK {
		return intentStatusV1{}, ErrIntentNotFound
	}
	response := intentStatusV1{
		SchemaVersion: "agmind.actuator-intent-status.v1",
		IntentID:      intentID,
		IntentSHA256:  reservation.IntentSHA256,
		State:         "RESERVED",
	}
	if !preparedOK {
		return response, nil
	}
	plan := clonePlan(prepared.Plan)
	response.IntentSHA256 = prepared.IntentSHA256
	response.State = "PREPARED"
	response.PreparedPlan = &plan
	response.LatestAction = &intentActionStatusV1{
		State:        "PREPARED",
		RecordID:     contracts.ActionRecordID(prepared.PreparedRecordSHA256),
		RecordSHA256: prepared.PreparedRecordSHA256,
		ObservedAt:   prepared.Plan.PreparedAt,
	}
	if outcome, ok := service.journal.outcomes[prepared.Plan.PlanID]; ok {
		response.State = outcome.State
		response.LatestAction = &intentActionStatusV1{
			State:        outcome.State,
			RecordID:     outcome.RecordID,
			RecordSHA256: outcome.RecordSHA256,
			ObservedAt:   outcome.ObservedAt,
		}
	}
	return response, nil
}

func (service *Service) journalPage(query journalPageQuery) (durablefile.JournalPage, error) {
	if service == nil {
		return durablefile.JournalPage{}, durablefile.ErrJournalClosed
	}
	service.mutex.Lock()
	if service.closed || service.journal == nil {
		service.mutex.Unlock()
		return durablefile.JournalPage{}, durablefile.ErrJournalClosed
	}
	stream := service.journal.stream
	service.mutex.Unlock()
	if stream == nil {
		return durablefile.JournalPage{}, durablefile.ErrJournalClosed
	}
	return stream.ReadPage(durablefile.JournalPageRequest{
		After:               query.after,
		Limit:               query.limit,
		MaxRecords:          actionJournalMaxRecords,
		MaxBytes:            actionJournalMaxBytes,
		MaxPagePayloadBytes: intentJournalPageMaxRawPayloadBytes,
		Snapshot:            query.snapshot,
	})
}

func journalPageDocument(after uint64, page durablefile.JournalPage) (journalPageV1, error) {
	document := journalPageV1{
		SchemaVersion: "agmind.actuator-journal-page.v1",
		Snapshot: journalSnapshotV1{
			RecordCount:   page.Snapshot.RecordCount,
			VerifiedBytes: page.Snapshot.VerifiedBytes,
			HeadSHA256:    hex.EncodeToString(page.Snapshot.Head[:]),
		},
		After:     after,
		Records:   make([]journalRecordV1, len(page.Records)),
		NextAfter: page.NextAfter,
		More:      page.More,
	}
	for index, record := range page.Records {
		document.Records[index] = journalRecordV1{
			Index:               after + uint64(index) + 1,
			Offset:              record.Offset,
			Size:                record.Size,
			PayloadLength:       record.PayloadLength,
			PreviousFrameSHA256: hex.EncodeToString(record.PreviousHash[:]),
			FrameSHA256:         hex.EncodeToString(record.Hash[:]),
			PayloadBase64:       base64.StdEncoding.EncodeToString(record.Payload),
		}
	}
	for {
		payload, err := contracts.CanonicalJSON(document)
		if err != nil {
			return journalPageV1{}, err
		}
		if len(payload) <= intentJournalPageMaxResponseBytes {
			return document, nil
		}
		if len(document.Records) == 0 {
			return journalPageV1{}, durablefile.ErrJournalPageBounds
		}
		document.Records = document.Records[:len(document.Records)-1]
		document.NextAfter = after + uint64(len(document.Records))
		document.More = document.NextAfter < document.Snapshot.RecordCount
	}
}

func newIntentRoutes(service *Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/intents", func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.RawQuery != "" {
			http.NotFound(writer, request)
			return
		}
		intent, err := contracts.DecodeStrict[contracts.TemporaryEgressDenyIntentV1](
			request.Body,
			intentAPIMaxBody,
		)
		if err != nil {
			writeAdminError(writer, http.StatusBadRequest, "invalid_intent")
			return
		}
		plan, err := service.Prepare(request.Context(), intent)
		if err != nil {
			intentAPIError(writer, err)
			return
		}
		writeAdminJSON(writer, http.StatusOK, plan)
	})
	mux.HandleFunc("GET /v1/intents/{intent_id}", func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		intentID := request.PathValue("intent_id")
		if request.URL.RawQuery != "" || request.ContentLength != 0 ||
			!intentIDPattern.MatchString(intentID) {
			http.NotFound(writer, request)
			return
		}
		status, err := service.intentStatus(intentID)
		if err != nil {
			intentAPIError(writer, err)
			return
		}
		writeAdminJSON(writer, http.StatusOK, status)
	})
	mux.HandleFunc("GET /v1/journal-records", func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		query, ok := parseJournalPageQuery(request)
		if !ok {
			writeAdminError(writer, http.StatusBadRequest, "invalid_query")
			return
		}
		page, err := service.journalPage(query)
		if err != nil {
			intentAPIError(writer, err)
			return
		}
		document, err := journalPageDocument(query.after, page)
		if err != nil {
			intentAPIError(writer, err)
			return
		}
		writeAdminJSON(writer, http.StatusOK, document)
	})
	return mux
}

func newIntentAPI(service *Service, coreUID uint32) http.Handler {
	var routes http.Handler = http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		writeAdminError(writer, http.StatusServiceUnavailable, "actuator_unavailable")
	})
	if service != nil {
		routes = newIntentRoutes(service)
	}
	return uds.RequirePeer(func(peer uds.Peer) bool {
		return intentPeerAuthorized(peer, coreUID)
	})(routes)
}

func ListenIntent(
	path string,
	coreGID int,
	coreUID int,
	service *Service,
) (*uds.HTTPServer, error) {
	if service == nil || coreGID < 0 || uint64(coreGID) > math.MaxUint32 ||
		coreUID < 0 || uint64(coreUID) > math.MaxUint32 {
		return nil, uds.ErrUnsafeSocket
	}
	return uds.ListenHTTP(
		path,
		os.FileMode(0o660),
		coreGID,
		intentAPIMaxBody,
		newIntentAPI(service, uint32(coreUID)),
	)
}
