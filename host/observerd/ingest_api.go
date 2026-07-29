package observerd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/uds"
)

const falcoIngestMaxBytes int64 = 65_536

type ingestAPIBackend interface {
	IngestFalco(
		context.Context,
		contracts.FalcoConnectV1,
	) (contracts.EventEnvelopeV1, error)
	IngestFalcoCoverage(
		context.Context,
		FalcoAdapterCoverageInputV1,
	) (contracts.EventEnvelopeV1, error)
}

type FalcoAdapterCoverageInputV1 struct {
	Kind                string  `json:"kind"`
	OpenedAt            string  `json:"opened_at"`
	ClosedAt            *string `json:"closed_at,omitempty"`
	DroppedCount        *uint64 `json:"dropped_count,omitempty"`
	ReasonCode          string  `json:"reason_code"`
	SourcePayloadSHA256 string  `json:"source_payload_sha256"`
}

var falcoAdapterCoverageSeverities = map[string]string{
	"falco_adapter_start":          "INFO",
	"falco_adapter_stop":           "CRITICAL",
	"falco_heartbeat_lease":        "INFO",
	"falco_parse_rejection":        "CRITICAL",
	"falco_queue_drop":             "CRITICAL",
	"falco_delivery_failure":       "CRITICAL",
	"falco_heartbeat_gap":          "CRITICAL",
	"falco_configuration_mismatch": "CRITICAL",
	"falco_kernel_event_drop":      "CRITICAL",
	"falco_outputs_queue_drop":     "CRITICAL",
}

func parseCanonicalCoverageTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil ||
		parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, fmt.Errorf("coverage timestamp must be canonical UTC")
	}
	return parsed.UTC(), nil
}

func (input FalcoAdapterCoverageInputV1) Validate() error {
	if _, ok := falcoAdapterCoverageSeverities[input.Kind]; !ok {
		return fmt.Errorf("unsupported Falco adapter coverage kind")
	}
	opened, err := parseCanonicalCoverageTime(input.OpenedAt)
	if err != nil ||
		!safeASCII(input.ReasonCode, 1, 64) ||
		!hex64Pattern.MatchString(input.SourcePayloadSHA256) ||
		input.DroppedCount != nil && *input.DroppedCount == 0 {
		return fmt.Errorf("invalid Falco adapter coverage input")
	}
	if input.ClosedAt != nil {
		closed, err := parseCanonicalCoverageTime(*input.ClosedAt)
		if err != nil || closed.Before(opened) {
			return fmt.Errorf("invalid Falco adapter coverage interval")
		}
	}
	switch input.Kind {
	case "falco_adapter_start",
		"falco_adapter_stop",
		"falco_heartbeat_lease":
		if input.ClosedAt == nil ||
			*input.ClosedAt != input.OpenedAt ||
			input.DroppedCount != nil {
			return fmt.Errorf("Falco adapter lifecycle and lease must be closed points")
		}
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

func (service *Service) IngestFalcoCoverage(
	ctx context.Context,
	input FalcoAdapterCoverageInputV1,
) (contracts.EventEnvelopeV1, error) {
	if service == nil ||
		service.daemon == nil ||
		service.daemon.signer == nil ||
		service.inventory == nil {
		return contracts.EventEnvelopeV1{}, fmt.Errorf(
			"observer Falco coverage ingest unavailable",
		)
	}
	if err := input.Validate(); err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	opened, _ := parseCanonicalCoverageTime(input.OpenedAt)
	eventTime := opened
	coverageFlags := []string{input.Kind}
	if input.ClosedAt != nil {
		eventTime, _ = parseCanonicalCoverageTime(*input.ClosedAt)
		coverageFlags = []string{}
	}
	severity := falcoAdapterCoverageSeverities[input.Kind]
	coverage := contracts.CoverageEventV1{
		Component:    "falco-adapter",
		Kind:         input.Kind,
		Severity:     severity,
		OpenedAt:     input.OpenedAt,
		ClosedAt:     input.ClosedAt,
		DroppedCount: input.DroppedCount,
		ReasonCode:   input.ReasonCode,
	}
	if err := coverage.Validate(); err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	fields := map[string]any{
		"component":   coverage.Component,
		"kind":        coverage.Kind,
		"severity":    coverage.Severity,
		"opened_at":   coverage.OpenedAt,
		"reason_code": coverage.ReasonCode,
	}
	if coverage.ClosedAt != nil {
		fields["closed_at"] = *coverage.ClosedAt
	}
	if coverage.DroppedCount != nil {
		fields["dropped_count"] = *coverage.DroppedCount
	}
	return service.daemon.signer.Wrap(
		ctx,
		"coverage",
		fields,
		EventMetadata{
			EventTime:           eventTime,
			InventoryGeneration: service.inventory.Generation(),
			RedactionFlags:      []string{},
			CoverageFlags:       coverageFlags,
			SourcePayloadHash:   input.SourcePayloadSHA256,
		},
	)
}

func falcoCoverageIngestHandler(backend ingestAPIBackend) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if backend == nil {
			unavailableAPIHandler(writer, request)
			return
		}
		input, err := contracts.DecodeStrict[FalcoAdapterCoverageInputV1](
			request.Body,
			4_096,
		)
		if err != nil {
			fixedAPIError(
				writer,
				http.StatusBadRequest,
				"invalid_falco_coverage",
			)
			return
		}
		envelope, err := backend.IngestFalcoCoverage(
			request.Context(),
			input,
		)
		if err != nil {
			fixedAPIError(
				writer,
				http.StatusServiceUnavailable,
				"coverage_ingest_unavailable",
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
	mux.Handle(
		"POST /v1/events/falco-coverage",
		uds.RequireRootOrGroup(sensorGID)(
			falcoCoverageIngestHandler(backend),
		),
	)
	return mux
}
