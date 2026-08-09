package actuatord

import (
	"errors"
	"math"
	"net/http"
	"os"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
	"agmind.local/sais/internal/uds"
)

const intentAPIMaxBody = int64(64 * 1024)

func intentPeerAuthorized(peer uds.Peer, coreUID uint32) bool {
	return peer.UID == 0 || peer.UID == coreUID
}

func intentAPIError(writer http.ResponseWriter, err error) {
	switch {
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
