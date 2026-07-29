package observerd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

var (
	ErrCoreOperationConflict = errors.New(
		"core control operation conflict",
	)
	ErrCoreAuthorizationBinding = errors.New(
		"core control authorization binding mismatch",
	)
)

type CoreControlPublication struct {
	Item    CoreEventV1
	Created bool
}

type coreControlPublisher interface {
	PublishCoreControl(
		context.Context,
		CoreControlRequest,
	) (CoreControlPublication, error)
}

func validateCoreControlPublication(
	request CoreControlRequest,
	publication CoreControlPublication,
) error {
	if request == nil {
		return fmt.Errorf("nil core control request")
	}
	if err := publication.Item.Validate(); err != nil {
		return err
	}
	requestSHA256, err := CoreControlRequestSHA256(request)
	if err != nil {
		return err
	}
	envelope := publication.Item.Envelope
	if envelope.EventType != request.EventType() ||
		envelope.SourceID != "agmind-observerd" ||
		envelope.ClockUncertaintyMS != 0 ||
		envelope.ContainerID != nil ||
		envelope.ContainerStartTime != nil ||
		envelope.ReleaseID != nil ||
		envelope.InventoryGeneration != 0 ||
		envelope.InventoryRevision != nil ||
		len(envelope.RedactionFlags) != 0 ||
		len(envelope.CoverageFlags) != 0 ||
		envelope.NormalizedFieldsSHA256 != requestSHA256 ||
		envelope.SourcePayloadHash != requestSHA256 {
		return fmt.Errorf("invalid core control publication context")
	}
	publishedRequest, err := coreControlRequestFromEnvelope(envelope)
	if err != nil || publishedRequest == nil {
		return fmt.Errorf("invalid core control publication request")
	}
	publishedSHA256, err := CoreControlRequestSHA256(publishedRequest)
	if err != nil ||
		publishedSHA256 != requestSHA256 ||
		publishedRequest.OperationKey() != request.OperationKey() {
		return fmt.Errorf("core control publication request mismatch")
	}
	return nil
}

func coreControlFailure(err error) (int, string) {
	switch {
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return http.StatusRequestTimeout, "request_canceled"
	case errors.Is(err, ErrCoreOperationConflict),
		errors.Is(err, ErrCoreAuthorizationBinding),
		errors.Is(err, ErrControlReceiptConflict):
		return http.StatusConflict, "core_operation_conflict"
	case errors.Is(err, ErrControlReceiptQuota),
		errors.Is(err, ErrPriorityQuota):
		return http.StatusInsufficientStorage, "core_control_quota"
	default:
		return http.StatusServiceUnavailable, "core_control_unavailable"
	}
}

func coreControlHandler[T CoreControlRequest](backend any) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		publisher, ok := backend.(coreControlPublisher)
		if !ok {
			unavailableAPIHandler(writer, request)
			return
		}
		control, err := DecodeCoreControlRequest[T](request.Body)
		if err != nil {
			fixedAPIError(
				writer,
				http.StatusBadRequest,
				"invalid_core_control_request",
			)
			return
		}
		publication, err := publisher.PublishCoreControl(
			request.Context(),
			control,
		)
		if err != nil {
			status, reason := coreControlFailure(err)
			fixedAPIError(writer, status, reason)
			return
		}
		if err := validateCoreControlPublication(
			control,
			publication,
		); err != nil {
			fixedAPIError(
				writer,
				http.StatusServiceUnavailable,
				"invalid_core_control_publication",
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
