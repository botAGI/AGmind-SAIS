package observerd

import (
	"bytes"
	"errors"
	"io"
	"net/http"

	"agmind.local/sais/internal/contracts"
)

const pccCorrelationRequestMaxBytes int64 = 4_096

func decodeCanonicalPCCCorrelationRequest(
	reader io.Reader,
) (contracts.PCCCorrelationSnapshotRequestV1, error) {
	raw, err := io.ReadAll(io.LimitReader(
		reader,
		pccCorrelationRequestMaxBytes+1,
	))
	if err != nil || int64(len(raw)) > pccCorrelationRequestMaxBytes {
		return contracts.PCCCorrelationSnapshotRequestV1{}, errors.Join(
			ErrPCCTriggerInvalid,
			err,
		)
	}
	request, err := contracts.DecodeStrict[contracts.PCCCorrelationSnapshotRequestV1](bytes.NewReader(raw), pccCorrelationRequestMaxBytes)
	if err != nil || request.RequestedTTLSeconds != 120 {
		return contracts.PCCCorrelationSnapshotRequestV1{}, errors.Join(
			ErrPCCTriggerInvalid,
			err,
		)
	}
	canonical, err := contracts.CanonicalJSON(request)
	if err != nil || !bytes.Equal(canonical, raw) {
		return contracts.PCCCorrelationSnapshotRequestV1{}, errors.Join(
			ErrPCCTriggerInvalid,
			err,
		)
	}
	return request, nil
}

func pccCorrelationHandler(backend any) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		publisher, ok := backend.(pccCorrelationPublisher)
		if !ok {
			unavailableAPIHandler(writer, request)
			return
		}
		proofRequest, err := decodeCanonicalPCCCorrelationRequest(request.Body)
		if err != nil {
			fixedAPIError(
				writer,
				http.StatusBadRequest,
				"invalid_pcc_correlation_request",
			)
			return
		}
		publication, err := publisher.PublishPCCCorrelationSnapshot(
			request.Context(),
			proofRequest,
		)
		if err != nil {
			if errors.Is(err, ErrPCCTriggerRetired) {
				// Terminal, and stated as such: the trigger is retired, so no
				// retry of this exact request can ever succeed. 410 Gone plus a
				// dedicated code, never reused for a transport or availability
				// failure, is the entire signal Core may treat as terminal.
				fixedAPIError(
					writer,
					http.StatusGone,
					"pcc_trigger_retired",
				)
			} else if errors.Is(err, ErrPCCPublicationConflict) ||
				errors.Is(err, ErrPCCReceiptConflict) {
				fixedAPIError(
					writer,
					http.StatusConflict,
					"pcc_request_conflict",
				)
			} else {
				fixedAPIError(
					writer,
					http.StatusServiceUnavailable,
					"pcc_publication_unavailable",
				)
			}
			return
		}
		if err := publication.Item.Validate(); err != nil {
			fixedAPIError(
				writer,
				http.StatusServiceUnavailable,
				"invalid_pcc_publication",
			)
			return
		}
		status := http.StatusOK
		if publication.Created {
			status = http.StatusCreated
		}
		writeAPIJSON(writer, status, publication.Item)
	})
}
