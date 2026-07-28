package observerd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/uds"
)

const falcoIngestMaxBytes int64 = 65_536

type ingestAPIBackend interface {
	IngestFalco(
		context.Context,
		contracts.FalcoConnectV1,
	) (contracts.EventEnvelopeV1, error)
}

type retentionTombstoneAPIBackend interface {
	IngestRetentionTombstone(
		context.Context,
		RetentionTombstoneV1,
	) (contracts.EventEnvelopeV1, error)
}

type RetentionTombstoneV1 struct {
	SchemaVersion               string   `json:"schema_version"`
	RemovedManifestHashes       []string `json:"removed_manifest_hashes"`
	LastRemovedManifestSHA256   string   `json:"last_removed_manifest_sha256"`
	FirstRetainedManifestSHA256 string   `json:"first_retained_manifest_sha256"`
	RemovedBytes                uint64   `json:"removed_bytes"`
	Reason                      string   `json:"reason"`
	PolicyVersion               string   `json:"policy_version"`
	CurrentChainHeadSHA256      string   `json:"current_chain_head_sha256"`
}

func (tombstone RetentionTombstoneV1) Validate() error {
	if tombstone.SchemaVersion != "agmind.retention-tombstone.v1" ||
		tombstone.RemovedManifestHashes == nil ||
		len(tombstone.RemovedManifestHashes) < 1 ||
		len(tombstone.RemovedManifestHashes) > 512 ||
		tombstone.RemovedBytes == 0 ||
		!safeASCII(tombstone.Reason, 1, 64) ||
		!safeASCII(tombstone.PolicyVersion, 1, 64) ||
		!hex64Pattern.MatchString(tombstone.LastRemovedManifestSHA256) ||
		!hex64Pattern.MatchString(tombstone.FirstRetainedManifestSHA256) ||
		!hex64Pattern.MatchString(tombstone.CurrentChainHeadSHA256) {
		return fmt.Errorf("invalid retention tombstone")
	}
	seen := make(map[string]struct{}, len(tombstone.RemovedManifestHashes))
	for _, manifestHash := range tombstone.RemovedManifestHashes {
		if !hex64Pattern.MatchString(manifestHash) {
			return fmt.Errorf("invalid removed manifest hash")
		}
		if _, duplicate := seen[manifestHash]; duplicate {
			return fmt.Errorf("duplicate removed manifest hash")
		}
		seen[manifestHash] = struct{}{}
	}
	lastRemoved := tombstone.RemovedManifestHashes[len(tombstone.RemovedManifestHashes)-1]
	if lastRemoved != tombstone.LastRemovedManifestSHA256 {
		return fmt.Errorf("last removed manifest does not match ordered list")
	}
	return nil
}

func unavailableAPIHandler(
	writer http.ResponseWriter,
	_ *http.Request,
) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusServiceUnavailable)
	_, _ = writer.Write([]byte("{\"error\":\"service_unavailable\"}\n"))
}

func fixedAPIError(writer http.ResponseWriter, status int, reason string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = io.WriteString(
		writer,
		"{\"error\":\""+reason+"\"}\n",
	)
}

func writeAPIJSON(
	writer http.ResponseWriter,
	status int,
	value any,
) {
	raw, err := contracts.CanonicalJSON(value)
	if err != nil {
		fixedAPIError(
			writer,
			http.StatusInternalServerError,
			"response_encoding_failed",
		)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(raw, '\n'))
}

func falcoIngestHandler(backend ingestAPIBackend) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if backend == nil {
			unavailableAPIHandler(writer, request)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(
			request.Body,
			falcoIngestMaxBytes+1,
		))
		if err != nil {
			fixedAPIError(writer, http.StatusBadRequest, "invalid_body")
			return
		}
		if int64(len(raw)) > falcoIngestMaxBytes {
			fixedAPIError(
				writer,
				http.StatusRequestEntityTooLarge,
				"body_too_large",
			)
			return
		}
		event, err := contracts.DecodeStrict[contracts.FalcoConnectV1](
			bytes.NewReader(raw),
			falcoIngestMaxBytes,
		)
		if err != nil {
			fixedAPIError(writer, http.StatusBadRequest, "invalid_falco_event")
			return
		}
		envelope, err := backend.IngestFalco(request.Context(), event)
		if err != nil {
			status := http.StatusServiceUnavailable
			reason := "ingest_unavailable"
			if errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) {
				status = http.StatusRequestTimeout
				reason = "request_canceled"
			}
			fixedAPIError(writer, status, reason)
			return
		}
		writeAPIJSON(
			writer,
			http.StatusCreated,
			struct {
				EventID string `json:"event_id"`
			}{EventID: envelope.EventID},
		)
	})
}

func (service *Service) IngestRetentionTombstone(
	ctx context.Context,
	tombstone RetentionTombstoneV1,
) (contracts.EventEnvelopeV1, error) {
	if service == nil ||
		service.daemon == nil ||
		service.daemon.signer == nil ||
		service.inventory == nil ||
		service.now == nil {
		return contracts.EventEnvelopeV1{}, fmt.Errorf(
			"observer tombstone ingest unavailable",
		)
	}
	if err := tombstone.Validate(); err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	canonical, err := contracts.CanonicalJSON(tombstone)
	if err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	var fields map[string]any
	if err := decoder.Decode(&fields); err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	payloadHash := sha256.Sum256(canonical)
	return service.daemon.signer.Wrap(
		ctx,
		"retention_tombstone",
		fields,
		EventMetadata{
			EventTime:           service.now().UTC(),
			InventoryGeneration: service.inventory.Generation(),
			RedactionFlags:      []string{},
			CoverageFlags:       []string{},
			SourcePayloadHash:   hex.EncodeToString(payloadHash[:]),
		},
	)
}

func retentionTombstoneHandler(
	backend retentionTombstoneAPIBackend,
) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if backend == nil {
			unavailableAPIHandler(writer, request)
			return
		}
		tombstone, err := contracts.DecodeStrict[RetentionTombstoneV1](
			request.Body,
			falcoIngestMaxBytes,
		)
		if err != nil {
			fixedAPIError(
				writer,
				http.StatusBadRequest,
				"invalid_retention_tombstone",
			)
			return
		}
		envelope, err := backend.IngestRetentionTombstone(
			request.Context(),
			tombstone,
		)
		if err != nil {
			fixedAPIError(
				writer,
				http.StatusServiceUnavailable,
				"tombstone_ingest_unavailable",
			)
			return
		}
		writeAPIJSON(
			writer,
			http.StatusCreated,
			struct {
				EventID string `json:"event_id"`
			}{EventID: envelope.EventID},
		)
	})
}

func newIngestAPI(
	backend ingestAPIBackend,
	sensorGID uint32,
) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(
		"POST /v1/events/falco",
		uds.RequireRootOrGroup(sensorGID)(
			falcoIngestHandler(backend),
		),
	)
	return mux
}
