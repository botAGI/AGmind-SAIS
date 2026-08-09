package actuatord

import (
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
	"agmind.local/sais/internal/uds"
)

const adminAPIMaxBody = int64(4 * 1024)

type planDecisionRequestV1 struct {
	SchemaVersion string `json:"schema_version"`
	PlanHashValue string `json:"plan_hash"`
	Nonce         string `json:"nonce"`
}

func (request planDecisionRequestV1) Validate() error {
	if request.SchemaVersion != "agmind.local-plan-decision.v1" ||
		!digestPattern.MatchString(request.PlanHashValue) ||
		!digestPattern.MatchString(request.Nonce) {
		return ErrApprovalMismatch
	}
	return nil
}

func writeAdminError(writer http.ResponseWriter, status int, reason string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, `{"error":"`+reason+`"}`+"\n")
}

func writeAdminJSON(writer http.ResponseWriter, status int, value any) {
	payload, err := contracts.CanonicalJSON(value)
	if err != nil {
		writeAdminError(writer, http.StatusInternalServerError, "response_unavailable")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write(payload)
}

func adminAPIError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrPlanNotFound):
		writeAdminError(writer, http.StatusNotFound, "plan_not_found")
	case errors.Is(err, ErrApprovalMismatch):
		writeAdminError(writer, http.StatusConflict, "plan_mismatch")
	case errors.Is(err, ErrApprovalReplay):
		writeAdminError(writer, http.StatusConflict, "decision_already_consumed")
	case errors.Is(err, ErrApprovalExpired):
		writeAdminError(writer, http.StatusConflict, "approval_expired")
	case errors.Is(err, ErrApprovalClock),
		errors.Is(err, durablefile.ErrJournalFailed),
		errors.Is(err, durablefile.ErrJournalClosed):
		writeAdminError(writer, http.StatusServiceUnavailable, "actuator_unavailable")
	default:
		writeAdminError(writer, http.StatusServiceUnavailable, "actuator_unavailable")
	}
}

func adminAuthorityFromRequest(
	request *http.Request,
	adminGID uint32,
) (AdminAuthority, error) {
	peer, ok := uds.PeerFromContext(request.Context())
	if !ok {
		return AdminAuthority{}, uds.ErrInvalidPeer
	}
	switch {
	case peer.UID == 0:
		return AdminAuthority{
			UID:                peer.UID,
			GID:                peer.GID,
			AuthorizationBasis: "root",
		}, nil
	case peer.GID == adminGID:
		return AdminAuthority{
			UID:                peer.UID,
			GID:                peer.GID,
			AuthorizationBasis: "primary_group",
		}, nil
	default:
		member, err := uds.PeerInGroup(peer, adminGID)
		if err != nil || !member {
			return AdminAuthority{}, uds.ErrInvalidPeer
		}
		return AdminAuthority{
			UID:                peer.UID,
			GID:                peer.GID,
			AuthorizationBasis: "supplementary_group",
		}, nil
	}
}

func pendingPlanLimit(request *http.Request) (int, bool) {
	if request.ContentLength != 0 {
		return 0, false
	}
	values, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil || len(values) != 2 || len(values["state"]) != 1 ||
		len(values["limit"]) != 1 || values["state"][0] != "PENDING_APPROVAL" {
		return 0, false
	}
	raw := values["limit"][0]
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 || limit > 100 || strconv.Itoa(limit) != raw ||
		request.URL.RawQuery != "state=PENDING_APPROVAL&limit="+raw {
		return 0, false
	}
	return limit, true
}

func exactEmptyAdminRequest(request *http.Request) bool {
	if request.URL.RawQuery != "" || request.ContentLength != 0 ||
		len(request.TransferEncoding) != 0 ||
		request.Header.Get("Content-Type") != "" ||
		request.Header.Get("Content-Encoding") != "" ||
		request.Header.Get("Expect") != "" {
		return false
	}
	if request.Body == nil {
		return true
	}
	var probe [1]byte
	count, err := request.Body.Read(probe[:])
	return count == 0 && errors.Is(err, io.EOF)
}

func newAdminRoutes(service *Service, adminGID uint32) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(
		"GET /v1/admin/kill-switch",
		func(writer http.ResponseWriter, request *http.Request) {
			if !exactEmptyAdminRequest(request) {
				writeAdminError(writer, http.StatusBadRequest, "invalid_request")
				return
			}
			writeAdminJSON(writer, http.StatusOK, service.KillSwitchStatus())
		},
	)
	setKillSwitch := func(enabled bool) http.HandlerFunc {
		return func(writer http.ResponseWriter, request *http.Request) {
			if !exactEmptyAdminRequest(request) {
				writeAdminError(writer, http.StatusBadRequest, "invalid_request")
				return
			}
			var status KillSwitchStatusV1
			var err error
			if enabled {
				status, err = service.EnableManualKillSwitch()
			} else {
				status, err = service.DisableManualKillSwitch()
			}
			if err != nil {
				adminAPIError(writer, err)
				return
			}
			writeAdminJSON(writer, http.StatusOK, status)
		}
	}
	mux.Handle("POST /v1/admin/kill-switch/enable", setKillSwitch(true))
	mux.Handle("POST /v1/admin/kill-switch/disable", setKillSwitch(false))
	mux.HandleFunc(
		"GET /v1/plans",
		func(writer http.ResponseWriter, request *http.Request) {
			limit, ok := pendingPlanLimit(request)
			if !ok {
				writeAdminError(writer, http.StatusBadRequest, "invalid_query")
				return
			}
			listing, err := service.PendingPlans(limit)
			if err != nil {
				adminAPIError(writer, err)
				return
			}
			writeAdminJSON(writer, http.StatusOK, listing)
		},
	)
	mux.HandleFunc(
		"GET /v1/admin/plans/{plan_id}",
		func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.RawQuery != "" || request.ContentLength != 0 ||
				!planIDPattern.MatchString(request.PathValue("plan_id")) {
				http.NotFound(writer, request)
				return
			}
			plan, err := service.GetPlan(request.PathValue("plan_id"))
			if err != nil {
				adminAPIError(writer, err)
				return
			}
			writeAdminJSON(writer, http.StatusOK, plan)
		},
	)
	decision := func(reject bool) http.HandlerFunc {
		return func(writer http.ResponseWriter, request *http.Request) {
			planID := request.PathValue("plan_id")
			if request.URL.RawQuery != "" || !planIDPattern.MatchString(planID) {
				http.NotFound(writer, request)
				return
			}
			authority, err := adminAuthorityFromRequest(request, adminGID)
			if err != nil {
				writeAdminError(writer, http.StatusForbidden, "peer_not_authorized")
				return
			}
			body, err := contracts.DecodeStrict[planDecisionRequestV1](
				request.Body,
				adminAPIMaxBody,
			)
			if err != nil {
				writeAdminError(writer, http.StatusBadRequest, "invalid_decision")
				return
			}
			reference := ExactPlanRef{
				PlanID:        planID,
				PlanHashValue: body.PlanHashValue,
				Nonce:         body.Nonce,
			}
			var record contracts.ActionRecordV1
			if reject {
				record, err = service.Reject(request.Context(), authority, reference)
			} else {
				record, err = service.Approve(request.Context(), authority, reference)
			}
			if err != nil {
				adminAPIError(writer, err)
				return
			}
			writeAdminJSON(writer, http.StatusOK, record)
		}
	}
	mux.Handle(
		"POST /v1/admin/plans/{plan_id}/approve",
		decision(false),
	)
	mux.Handle(
		"POST /v1/admin/plans/{plan_id}/reject",
		decision(true),
	)
	return mux
}

func NewAdminAPI(service *Service, adminGID uint32) http.Handler {
	if service == nil {
		return uds.RequireRootOrGroup(adminGID)(http.HandlerFunc(
			func(writer http.ResponseWriter, _ *http.Request) {
				writeAdminError(
					writer,
					http.StatusServiceUnavailable,
					"actuator_unavailable",
				)
			},
		))
	}
	return uds.RequireRootOrGroup(adminGID)(newAdminRoutes(service, adminGID))
}

func ListenAdmin(
	path string,
	adminGID int,
	service *Service,
) (*uds.HTTPServer, error) {
	if service == nil || adminGID < 0 || uint64(adminGID) > math.MaxUint32 {
		return nil, uds.ErrUnsafeSocket
	}
	return uds.ListenHTTP(
		path,
		os.FileMode(0o660),
		adminGID,
		adminAPIMaxBody,
		NewAdminAPI(service, uint32(adminGID)),
	)
}
