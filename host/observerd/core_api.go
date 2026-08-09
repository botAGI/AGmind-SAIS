package observerd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/uds"
)

const (
	coreAckMaxBytes     int64  = 4_096
	coreFetchMaxBytes   uint64 = 4 * 1024 * 1024
	coreMaxReportedGaps        = 100
)

type CoreEventV1 struct {
	Sequence      uint64                    `json:"sequence"`
	EventID       string                    `json:"event_id"`
	ContentSHA256 string                    `json:"content_sha256"`
	Envelope      contracts.EventEnvelopeV1 `json:"envelope"`
}

func (event CoreEventV1) Validate() error {
	canonical, err := contracts.CanonicalJSON(event.Envelope)
	if err != nil {
		return err
	}
	_, err = coreEventFromSpoolItem(SpoolItem{
		Sequence:      event.Sequence,
		EventID:       event.EventID,
		ContentSHA256: event.ContentSHA256,
		Canonical:     canonical,
	})
	return err
}

type CoreSequenceGapV1 struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

type CoreEventsPageV1 struct {
	SchemaVersion   string              `json:"schema_version"`
	Events          []CoreEventV1       `json:"events"`
	UncoveredGaps   []CoreSequenceGapV1 `json:"uncovered_gaps"`
	GapsTruncated   bool                `json:"gaps_truncated"`
	AckedThrough    uint64              `json:"acked_through"`
	ReservedThrough uint64              `json:"reserved_through"`
}

type CoreAckV1 struct {
	SchemaVersion string `json:"schema_version"`
	Sequence      uint64 `json:"sequence"`
	EventID       string `json:"event_id"`
	ContentSHA256 string `json:"content_sha256"`
}

func coreEventFromSpoolItem(item SpoolItem) (CoreEventV1, error) {
	envelope, err := contracts.DecodeStrict[contracts.EventEnvelopeV1](
		bytes.NewReader(item.Canonical),
		65_536,
	)
	if err != nil {
		return CoreEventV1{}, errors.Join(ErrSpoolCorrupt, err)
	}
	if item.Sequence == 0 ||
		item.Sequence != envelope.SourceSequence ||
		item.EventID != envelope.EventID ||
		!hex64Pattern.MatchString(item.ContentSHA256) {
		return CoreEventV1{}, ErrSpoolCorrupt
	}
	canonical, err := contracts.CanonicalJSON(envelope)
	if err != nil || !bytes.Equal(canonical, item.Canonical) {
		return CoreEventV1{}, ErrSpoolCorrupt
	}
	sum := sha256.Sum256(canonical)
	if item.ContentSHA256 != hex.EncodeToString(sum[:]) {
		return CoreEventV1{}, ErrSpoolCorrupt
	}
	return CoreEventV1{
		Sequence:      item.Sequence,
		EventID:       item.EventID,
		ContentSHA256: item.ContentSHA256,
		Envelope:      envelope,
	}, nil
}

func (ack CoreAckV1) Validate() error {
	if ack.SchemaVersion != "agmind.observer-ack.v1" ||
		ack.Sequence == 0 ||
		!eventPattern.MatchString(ack.EventID) ||
		!hex64Pattern.MatchString(ack.ContentSHA256) {
		return ErrAckInvalid
	}
	return nil
}

type CoreCoverageV1 struct {
	SchemaVersion       string `json:"schema_version"`
	HostID              string `json:"host_id"`
	BootID              string `json:"boot_id"`
	KeyID               string `json:"key_id"`
	KeyEpoch            uint64 `json:"key_epoch"`
	MutationReadOnly    bool   `json:"mutation_read_only"`
	ReadOnlyReason      string `json:"read_only_reason"`
	ReconcileRequired   bool   `json:"reconcile_required"`
	InventoryGeneration uint64 `json:"inventory_generation"`
	DockerReconcileGap  bool   `json:"docker_reconcile_gap"`
	LastSequence        uint64 `json:"last_sequence"`
	AckSequence         uint64 `json:"ack_sequence"`
	RoutineDropped      uint64 `json:"routine_dropped"`
	DropEventPending    bool   `json:"drop_event_pending"`
	ObservedAt          string `json:"observed_at"`
}

type coreAPIBackend interface {
	coreControlPublisher
	FetchCoreEvents(context.Context, uint64, int) (CoreEventsPageV1, error)
	AckCoreEvent(context.Context, CoreAckV1) error
	LookupCoreInventory(context.Context, string) (ContainerIdentityV1, error)
	CoreCoverage(context.Context) (CoreCoverageV1, error)
	CorePublicKeys(context.Context) (PublicKeyMetadata, error)
}

func (service *Service) FetchCoreEvents(
	ctx context.Context,
	after uint64,
	limit int,
) (CoreEventsPageV1, error) {
	if service == nil ||
		service.daemon == nil ||
		service.daemon.spool == nil {
		return CoreEventsPageV1{}, fmt.Errorf("observer core API unavailable")
	}
	if err := ctx.Err(); err != nil {
		return CoreEventsPageV1{}, err
	}
	items, err := service.daemon.spool.Fetch(
		after,
		limit,
		coreFetchMaxBytes,
	)
	if err != nil {
		return CoreEventsPageV1{}, err
	}
	events := make([]CoreEventV1, 0, len(items))
	for _, item := range items {
		event, err := coreEventFromSpoolItem(item)
		if err != nil {
			return CoreEventsPageV1{}, err
		}
		events = append(events, event)
	}
	allGaps := service.daemon.spool.UncoveredGaps(after)
	gapCount := min(len(allGaps), coreMaxReportedGaps)
	gaps := make([]CoreSequenceGapV1, 0, gapCount)
	for _, gap := range allGaps[:gapCount] {
		gaps = append(gaps, CoreSequenceGapV1{
			Start: gap.Start,
			End:   gap.End,
		})
	}
	snapshot := service.daemon.state.Snapshot()
	return CoreEventsPageV1{
		SchemaVersion:   "agmind.observer-events-page.v1",
		Events:          events,
		UncoveredGaps:   gaps,
		GapsTruncated:   len(allGaps) > gapCount,
		AckedThrough:    snapshot.AckSequence,
		ReservedThrough: snapshot.LastSequence,
	}, nil
}

func (service *Service) AckCoreEvent(
	ctx context.Context,
	ack CoreAckV1,
) error {
	if service == nil ||
		service.daemon == nil ||
		service.daemon.spool == nil {
		return fmt.Errorf("observer core API unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ack.Validate(); err != nil {
		return err
	}
	return service.daemon.spool.Ack(
		ack.Sequence,
		ack.EventID,
		ack.ContentSHA256,
	)
}

func (service *Service) LookupCoreInventory(
	ctx context.Context,
	fullID string,
) (ContainerIdentityV1, error) {
	if service == nil || service.inventory == nil {
		return ContainerIdentityV1{}, fmt.Errorf("observer inventory unavailable")
	}
	if err := ctx.Err(); err != nil {
		return ContainerIdentityV1{}, err
	}
	if service.daemon == nil ||
		service.daemon.state == nil ||
		service.daemon.state.Snapshot().ReconcileRequired {
		return ContainerIdentityV1{}, ErrInventoryReconcileRequired
	}
	return service.inventory.LookupFullID(fullID)
}

func (service *Service) CoreCoverage(
	ctx context.Context,
) (CoreCoverageV1, error) {
	if service == nil ||
		service.daemon == nil ||
		service.daemon.state == nil ||
		service.inventory == nil ||
		service.now == nil {
		return CoreCoverageV1{}, fmt.Errorf("observer coverage unavailable")
	}
	if err := ctx.Err(); err != nil {
		return CoreCoverageV1{}, err
	}
	state := service.daemon.state.Snapshot()
	return CoreCoverageV1{
		SchemaVersion:       "agmind.observer-coverage.v1",
		HostID:              state.HostID,
		BootID:              state.BootID,
		KeyID:               state.KeyID,
		KeyEpoch:            state.KeyEpoch,
		MutationReadOnly:    state.MutationReadOnly,
		ReadOnlyReason:      state.ReadOnlyReason,
		ReconcileRequired:   state.ReconcileRequired,
		InventoryGeneration: service.inventory.Generation(),
		DockerReconcileGap:  service.inventory.ReconcileGapOpen(),
		LastSequence:        state.LastSequence,
		AckSequence:         state.AckSequence,
		RoutineDropped:      state.RoutineDropped,
		DropEventPending:    state.DropEventPending,
		ObservedAt: service.now().UTC().Format(
			time.RFC3339Nano,
		),
	}, nil
}

func (service *Service) CorePublicKeys(
	ctx context.Context,
) (PublicKeyMetadata, error) {
	if service == nil ||
		service.daemon == nil ||
		service.daemon.state == nil ||
		service.daemon.config.StateDir == "" {
		return PublicKeyMetadata{}, fmt.Errorf(
			"observer public-key metadata unavailable",
		)
	}
	if err := ctx.Err(); err != nil {
		return PublicKeyMetadata{}, err
	}
	metadata, err := LoadPublicKeyMetadata(service.daemon.config.StateDir)
	if err != nil {
		return PublicKeyMetadata{}, err
	}
	if err := metadata.Validate(); err != nil {
		return PublicKeyMetadata{}, err
	}
	state := service.daemon.state.Snapshot()
	if metadata.HostID != state.HostID ||
		metadata.CurrentKeyID != state.KeyID ||
		metadata.CurrentEpoch != state.KeyEpoch {
		return PublicKeyMetadata{}, fmt.Errorf(
			"observer public-key metadata does not match current state",
		)
	}
	return metadata, nil
}

func exactFetchQuery(
	request *http.Request,
) (uint64, int, error) {
	query := request.URL.Query()
	if len(query) != 2 ||
		len(query["after"]) != 1 ||
		len(query["limit"]) != 1 {
		return 0, 0, fmt.Errorf("expected exact after and limit query")
	}
	afterRaw := query["after"][0]
	limitRaw := query["limit"][0]
	after, err := strconv.ParseUint(afterRaw, 10, 64)
	if err != nil || strconv.FormatUint(after, 10) != afterRaw {
		return 0, 0, fmt.Errorf("invalid after cursor")
	}
	limit64, err := strconv.ParseUint(limitRaw, 10, 8)
	if err != nil ||
		limit64 < 1 ||
		limit64 > 100 ||
		strconv.FormatUint(limit64, 10) != limitRaw {
		return 0, 0, fmt.Errorf("invalid page limit")
	}
	return after, int(limit64), nil
}

func coreEventsHandler(backend coreAPIBackend) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if backend == nil {
			unavailableAPIHandler(writer, request)
			return
		}
		after, limit, err := exactFetchQuery(request)
		if err != nil {
			fixedAPIError(writer, http.StatusBadRequest, "invalid_query")
			return
		}
		page, err := backend.FetchCoreEvents(
			request.Context(),
			after,
			limit,
		)
		if err != nil {
			fixedAPIError(writer, http.StatusServiceUnavailable, "fetch_failed")
			return
		}
		writeAPIJSON(writer, http.StatusOK, page)
	})
}

func coreAckHandler(backend coreAPIBackend) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if backend == nil {
			unavailableAPIHandler(writer, request)
			return
		}
		ack, err := contracts.DecodeStrict[CoreAckV1](
			request.Body,
			coreAckMaxBytes,
		)
		if err != nil {
			fixedAPIError(writer, http.StatusBadRequest, "invalid_ack")
			return
		}
		if err := backend.AckCoreEvent(request.Context(), ack); err != nil {
			status := http.StatusServiceUnavailable
			reason := "ack_failed"
			if errors.Is(err, ErrAckInvalid) ||
				errors.Is(err, ErrSpoolCorrupt) {
				status = http.StatusConflict
				reason = "ack_conflict"
			}
			fixedAPIError(writer, status, reason)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
}

func coreInventoryHandler(backend coreAPIBackend) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if backend == nil {
			unavailableAPIHandler(writer, request)
			return
		}
		fullID := request.PathValue("full_id")
		if !dockerIDPattern.MatchString(fullID) {
			http.NotFound(writer, request)
			return
		}
		identity, err := backend.LookupCoreInventory(
			request.Context(),
			fullID,
		)
		if err != nil {
			if errors.Is(err, ErrContainerNotFound) {
				http.NotFound(writer, request)
				return
			}
			fixedAPIError(
				writer,
				http.StatusServiceUnavailable,
				"inventory_unavailable",
			)
			return
		}
		writeAPIJSON(writer, http.StatusOK, identity)
	})
}

func coreCoverageHandler(backend coreAPIBackend) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if backend == nil {
			unavailableAPIHandler(writer, request)
			return
		}
		coverage, err := backend.CoreCoverage(request.Context())
		if err != nil {
			fixedAPIError(
				writer,
				http.StatusServiceUnavailable,
				"coverage_unavailable",
			)
			return
		}
		writeAPIJSON(writer, http.StatusOK, coverage)
	})
}

func corePublicKeysHandler(backend coreAPIBackend) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if backend == nil {
			unavailableAPIHandler(writer, request)
			return
		}
		metadata, err := backend.CorePublicKeys(request.Context())
		if err != nil {
			fixedAPIError(
				writer,
				http.StatusServiceUnavailable,
				"public_keys_unavailable",
			)
			return
		}
		writeAPIJSON(writer, http.StatusOK, metadata)
	})
}

func coreMutationPeerAuthorized(peer uds.Peer, coreUID uint32) bool {
	return peer.UID == 0 || peer.UID == coreUID
}

func newCoreAPI(
	backend coreAPIBackend,
	coreGID uint32,
	coreUID uint32,
) http.Handler {
	mux := http.NewServeMux()
	authorize := uds.RequireRootOrGroup(coreGID)
	mux.Handle(
		"GET /v1/events",
		authorize(coreEventsHandler(backend)),
	)
	mux.Handle(
		"POST /v1/events/ack",
		uds.RequirePeer(func(peer uds.Peer) bool {
			return coreMutationPeerAuthorized(peer, coreUID)
		})(coreAckHandler(backend)),
	)
	mux.Handle(
		"POST /v1/events/pcc-correlation-snapshot",
		uds.RequirePeer(func(peer uds.Peer) bool {
			return coreMutationPeerAuthorized(peer, coreUID)
		})(pccCorrelationHandler(backend)),
	)
	mux.Handle(
		"GET /v1/inventory/{full_id}",
		authorize(coreInventoryHandler(backend)),
	)
	mux.Handle(
		"GET /v1/coverage",
		authorize(coreCoverageHandler(backend)),
	)
	mux.Handle(
		"GET /v1/public-keys",
		authorize(corePublicKeysHandler(backend)),
	)
	mux.Handle(
		"POST /v1/events/retention-tombstone",
		uds.RequirePeer(func(peer uds.Peer) bool {
			return coreMutationPeerAuthorized(peer, coreUID)
		})(coreControlHandler[RetentionTombstoneV2](backend)),
	)
	mux.Handle(
		"POST /v1/events/evidence-repair-authorize",
		uds.RequirePeer(func(peer uds.Peer) bool {
			return coreMutationPeerAuthorized(peer, coreUID)
		})(coreControlHandler[EvidenceRepairAuthorizeV1](backend)),
	)
	mux.Handle(
		"POST /v1/events/evidence-repair-complete",
		uds.RequirePeer(func(peer uds.Peer) bool {
			return coreMutationPeerAuthorized(peer, coreUID)
		})(coreControlHandler[EvidenceRepairCompleteV1](backend)),
	)
	mux.Handle(
		"POST /v1/events/retention-blocked",
		uds.RequirePeer(func(peer uds.Peer) bool {
			return coreMutationPeerAuthorized(peer, coreUID)
		})(coreControlHandler[RetentionBlockedV1](backend)),
	)
	return mux
}
