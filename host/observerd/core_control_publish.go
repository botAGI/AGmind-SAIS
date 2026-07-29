package observerd

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"time"

	"agmind.local/sais/internal/contracts"
)

func exactCoreControlRequest(
	request CoreControlRequest,
) (CoreControlRequest, error) {
	switch value := request.(type) {
	case EvidenceRepairAuthorizeV1:
		return value, nil
	case *EvidenceRepairAuthorizeV1:
		if value != nil {
			return *value, nil
		}
	case EvidenceRepairCompleteV1:
		return value, nil
	case *EvidenceRepairCompleteV1:
		if value != nil {
			return *value, nil
		}
	case RetentionTombstoneV2:
		return value, nil
	case *RetentionTombstoneV2:
		if value != nil {
			return *value, nil
		}
	case RetentionBlockedV1:
		return value, nil
	case *RetentionBlockedV1:
		if value != nil {
			return *value, nil
		}
	}
	return nil, fmt.Errorf("unsupported core control request type")
}

func coreControlConflict(
	state *StateStore,
	cause error,
) error {
	if state == nil {
		return errors.Join(ErrCoreOperationConflict, cause)
	}
	return errors.Join(
		ErrCoreOperationConflict,
		cause,
		state.PersistReadOnly("observer_core_operation_conflict"),
	)
}

func validateCompletionAuthorization(
	spool *Spool,
	completion EvidenceRepairCompleteV1,
) error {
	if spool == nil {
		return ErrCoreAuthorizationBinding
	}
	authorizationKey := EvidenceRepairAuthorizeV1{
		RepairID: completion.RepairID,
	}.EventType() + ":" + completion.RepairID
	receipt, found, err := spool.FindControl(authorizationKey)
	if err != nil {
		return err
	}
	if !found ||
		receipt.Item.EventID != completion.AuthorizationEventID ||
		receipt.Item.ContentSHA256 != completion.AuthorizationContentSHA256 {
		return ErrCoreAuthorizationBinding
	}
	control, err := coreControlRequestFromEnvelope(receipt.Item.Envelope)
	if err != nil {
		return errors.Join(ErrCoreAuthorizationBinding, err)
	}
	authorization, ok := control.(EvidenceRepairAuthorizeV1)
	if !ok {
		return ErrCoreAuthorizationBinding
	}
	requestSHA256, err := CoreControlRequestSHA256(authorization)
	if err != nil ||
		receipt.RequestSHA256 != requestSHA256 ||
		validateCoreControlPublication(
			authorization,
			CoreControlPublication{Item: receipt.Item},
		) != nil ||
		authorization.RepairID != completion.RepairID ||
		authorization.SegmentID != completion.SegmentID ||
		authorization.VerifiedBytes != completion.VerifiedBytes ||
		authorization.LastVerifiedFrameSHA256 !=
			completion.LastVerifiedFrameSHA256 ||
		authorization.CurrentChainHeadSHA256 !=
			completion.CurrentChainHeadSHA256 {
		return ErrCoreAuthorizationBinding
	}
	return nil
}

func coreControlCandidate(
	service *Service,
	request CoreControlRequest,
	requestSHA256 string,
	snapshot ObserverState,
	sequence uint64,
) (contracts.EventEnvelopeV1, error) {
	signer := service.daemon.signer
	if signer.config.SourceID != "agmind-observerd" ||
		signer.config.Now == nil ||
		service.now == nil ||
		signer.config.HostID != snapshot.HostID ||
		signer.config.BootID != snapshot.BootID ||
		signer.keyID != snapshot.KeyID ||
		signer.config.KeyEpoch != snapshot.KeyEpoch ||
		len(signer.privateKey) != ed25519.PrivateKeySize ||
		sequence == 0 {
		return contracts.EventEnvelopeV1{}, fmt.Errorf(
			"observer core control signer unavailable",
		)
	}
	fields, canonical, err := cloneNormalized(request.NormalizedFields())
	if err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	normalizedDigest := sha256.Sum256(canonical)
	if hex.EncodeToString(normalizedDigest[:]) != requestSHA256 {
		return contracts.EventEnvelopeV1{}, fmt.Errorf(
			"core control normalized hash mismatch",
		)
	}
	event := contracts.EventEnvelopeV1{
		SchemaVersion:          "agmind.event-envelope.v1",
		EventType:              request.EventType(),
		SourceID:               "agmind-observerd",
		SourceVersion:          signer.config.SourceVersion,
		KeyID:                  signer.keyID,
		KeyEpoch:               signer.config.KeyEpoch,
		HostID:                 signer.config.HostID,
		BootID:                 signer.config.BootID,
		SourceSequence:         sequence,
		EventTime:              service.now().UTC().Format(time.RFC3339Nano),
		IngestTime:             signer.config.Now().UTC().Format(time.RFC3339Nano),
		ClockUncertaintyMS:     0,
		InventoryGeneration:    0,
		NormalizedFields:       fields,
		NormalizedFieldsSHA256: requestSHA256,
		RedactionFlags:         []string{},
		CoverageFlags:          []string{},
		SourcePayloadHash:      requestSHA256,
	}
	event.EventID, err = contracts.DeriveEventID(event)
	if err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	message, err := contracts.EventSigningMessage(event)
	if err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	event.SourceSignature = hex.EncodeToString(
		ed25519.Sign(signer.privateKey, message),
	)
	if err := event.Validate(); err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	return event, nil
}

func (service *Service) PublishCoreControl(
	ctx context.Context,
	request CoreControlRequest,
) (CoreControlPublication, error) {
	if service == nil ||
		service.daemon == nil ||
		service.daemon.state == nil ||
		service.daemon.spool == nil ||
		service.daemon.signer == nil ||
		service.daemon.signer.state != service.daemon.state ||
		service.daemon.signer.spool != service.daemon.spool {
		return CoreControlPublication{}, fmt.Errorf(
			"observer core control publisher unavailable",
		)
	}
	if err := ctx.Err(); err != nil {
		return CoreControlPublication{}, err
	}
	request, err := exactCoreControlRequest(request)
	if err != nil {
		return CoreControlPublication{}, err
	}
	canonical, err := CanonicalCoreControlRequest(request)
	if err != nil {
		return CoreControlPublication{}, err
	}
	requestDigest := sha256.Sum256(canonical)
	requestSHA256 := hex.EncodeToString(requestDigest[:])
	key := request.OperationKey()

	state := service.daemon.state
	spool := service.daemon.spool
	state.publicationMutex.Lock()
	defer state.publicationMutex.Unlock()
	if err := ctx.Err(); err != nil {
		return CoreControlPublication{}, err
	}

	existing, err := spool.LookupControl(key, requestSHA256)
	switch {
	case err == nil:
		if completion, ok := request.(EvidenceRepairCompleteV1); ok {
			if err := validateCompletionAuthorization(
				spool,
				completion,
			); err != nil {
				return CoreControlPublication{}, err
			}
		}
		publication := CoreControlPublication{Item: existing, Created: false}
		if err := validateCoreControlPublication(
			request,
			publication,
		); err != nil {
			return CoreControlPublication{}, errors.Join(
				ErrControlReceiptCorrupt,
				err,
			)
		}
		return publication, nil
	case errors.Is(err, ErrControlReceiptConflict):
		return CoreControlPublication{}, coreControlConflict(state, err)
	case !errors.Is(err, os.ErrNotExist):
		return CoreControlPublication{}, err
	}

	if completion, ok := request.(EvidenceRepairCompleteV1); ok {
		if err := validateCompletionAuthorization(
			spool,
			completion,
		); err != nil {
			return CoreControlPublication{}, err
		}
	}
	snapshot := state.Snapshot()
	if snapshot.LastSequence == math.MaxUint64 {
		return CoreControlPublication{}, errors.Join(
			fmt.Errorf("observer sequence exhausted"),
			state.PersistReadOnly("observer_sequence_exhausted"),
		)
	}
	if snapshot.BootBoundaryState == bootBoundaryPending {
		return CoreControlPublication{}, ErrBootBoundaryPending
	}
	sequence := snapshot.LastSequence + 1
	event, err := coreControlCandidate(
		service,
		request,
		requestSHA256,
		snapshot,
		sequence,
	)
	if err != nil {
		return CoreControlPublication{}, err
	}
	control := controlReceiptAppend{
		key:           key,
		requestSHA256: requestSHA256,
	}
	if err := ctx.Err(); err != nil {
		return CoreControlPublication{}, err
	}
	identity := StateIdentity{
		HostID:   snapshot.HostID,
		BootID:   snapshot.BootID,
		KeyID:    snapshot.KeyID,
		KeyEpoch: snapshot.KeyEpoch,
	}
	item, err := spool.publishControl(
		event,
		control,
		func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			reserved, reserveErr := state.reserveExpected(
				identity,
				sequence,
			)
			if reserveErr != nil {
				return reserveErr
			}
			if reserved != sequence {
				return fmt.Errorf(
					"observer reserved unexpected sequence",
				)
			}
			return nil
		},
	)
	if err != nil {
		return CoreControlPublication{}, err
	}
	published, err := coreEventFromSpoolItem(item)
	if err != nil {
		return CoreControlPublication{}, err
	}
	return CoreControlPublication{Item: published, Created: true}, nil
}
