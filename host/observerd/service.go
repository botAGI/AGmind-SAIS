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
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/uds"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
)

var ErrDockerEventGap = errors.New("Docker event stream gap")

type Service struct {
	reconcileMutex       sync.Mutex
	eventMutex           sync.Mutex
	daemon               *Daemon
	inventory            *Inventory
	docker               DockerReader
	now                  func() time.Time
	eventSession         *dockerEventSession
	pccInventorySnapshot func(string) (CorrelationInventorySnapshot, error)
	pccLoadPins          func() (PCCSafetyPinSnapshot, error)
	pccBoundaryChain     func(string, string) ([]contracts.PCCBootTransitionHopV1, error)
	pccNow               func() time.Time
}

type dockerEventSession struct {
	mutex          sync.Mutex
	stream         DockerEventStream
	cancel         context.CancelFunc
	closeOnce      sync.Once
	dirty          chan struct{}
	terminalSignal chan struct{}
	done           chan struct{}
	terminalErr    error
	closing        bool
	onTerminal     func() error
}

func newDockerEventSession(
	ctx context.Context,
	docker DockerReader,
	onTerminal func() error,
) (*dockerEventSession, error) {
	if docker == nil || onTerminal == nil {
		return nil, fmt.Errorf("Docker event reader unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sessionContext, cancel := context.WithCancel(ctx)
	stream, err := docker.Events(
		sessionContext,
		client.EventsListOptions{},
	)
	if err != nil {
		cancel()
		return nil, err
	}
	if stream.Messages == nil || stream.Err == nil {
		cancel()
		return nil, fmt.Errorf(
			"%w: invalid event stream channels",
			ErrDockerEventSubscription,
		)
	}
	select {
	case streamErr, open := <-stream.Err:
		cancel()
		return nil, errors.Join(
			ErrDockerEventSubscription,
			normalizeDockerEventStreamError(streamErr, open),
		)
	default:
	}
	session := &dockerEventSession{
		stream:         stream,
		cancel:         cancel,
		dirty:          make(chan struct{}, 1),
		terminalSignal: make(chan struct{}),
		done:           make(chan struct{}),
		onTerminal:     onTerminal,
	}
	go session.pump(sessionContext)
	return session, nil
}

func (session *dockerEventSession) markTerminal(streamErr error) {
	if session == nil {
		return
	}
	session.mutex.Lock()
	defer session.mutex.Unlock()
	if session.terminalErr != nil {
		return
	}
	session.terminalErr = errors.Join(ErrDockerEventGap, streamErr)
	if !session.closing && !errors.Is(streamErr, context.Canceled) {
		session.terminalErr = errors.Join(
			session.terminalErr,
			session.onTerminal(),
		)
	}
	close(session.terminalSignal)
}

// dockerEventInventoryNoise lists the Docker actions that provably cannot change anything
// ContainerIdentityV1 or the network snapshot holds: an exec runs a process INSIDE an already
// identified container, and a health status transition is a label on that same container. Neither
// can alter the full ID, start time, image ID, repo digests, immutable spec, init PID, network
// attachment, privilege or capability set the inventory is built from.
//
// This matters far beyond tidiness. Container healthchecks — including this product's own — emit
// exec_create/exec_start/exec_die continuously: measured on the reference host, 188 Docker events
// in 30 s of which ~85% were exec noise. Every one of them drove a full inventory reconcile that
// signed a docker_reconcile_gap / docker_reconcile_recovered coverage PAIR into the spool, so the
// observer manufactured evidence about its own healthchecks faster than Core could consume it,
// the spool climbed to its 256 MB cap over nine hours and the observer fenced itself read-only.
//
// The filter is a denylist, not an allowlist, and that direction is deliberate: an action this
// function has never heard of still reconciles. Missing a real change would leave a stale identity
// bound to a containment plan; reconciling once too often only costs work.
func dockerEventCanChangeInventory(message events.Message) bool {
	switch message.Action {
	case "exec_create", "exec_start", "exec_die", "exec_detach", "health_status":
		return false
	}
	// Docker reports exec actions with the command appended, e.g.
	// `exec_start: /bin/health-probe`, so the prefix has to be matched too.
	for _, prefix := range [...]string{"exec_create:", "exec_start:", "health_status:"} {
		if strings.HasPrefix(string(message.Action), prefix) {
			return false
		}
	}
	return true
}

func (session *dockerEventSession) pump(ctx context.Context) {
	defer close(session.done)
	for {
		select {
		case streamErr, open := <-session.stream.Err:
			session.markTerminal(
				normalizeDockerEventStreamError(streamErr, open),
			)
			return
		default:
		}
		select {
		case streamErr, open := <-session.stream.Err:
			session.markTerminal(
				normalizeDockerEventStreamError(streamErr, open),
			)
			return
		case message, open := <-session.stream.Messages:
			if !open {
				session.markTerminal(io.EOF)
				return
			}
			if !dockerEventCanChangeInventory(message) {
				continue
			}
			select {
			case session.dirty <- struct{}{}:
			default:
			}
		case <-ctx.Done():
			session.markTerminal(ctx.Err())
			return
		}
	}
}

func (session *dockerEventSession) CommitIfLive(
	commit func() error,
) error {
	if session == nil || commit == nil {
		return fmt.Errorf("invalid Docker event session commit")
	}
	session.mutex.Lock()
	defer session.mutex.Unlock()
	if session.terminalErr != nil {
		return session.terminalErr
	}
	if session.closing {
		return context.Canceled
	}
	return commit()
}

func (session *dockerEventSession) TerminalError() error {
	if session == nil {
		return fmt.Errorf("Docker event session unavailable")
	}
	session.mutex.Lock()
	defer session.mutex.Unlock()
	return session.terminalErr
}

func (session *dockerEventSession) close() {
	if session == nil {
		return
	}
	session.closeOnce.Do(func() {
		session.mutex.Lock()
		session.closing = true
		session.mutex.Unlock()
		session.cancel()
		<-session.done
	})
}

func newObserverService(
	daemon *Daemon,
	inventory *Inventory,
	docker DockerReader,
	now func() time.Time,
) *Service {
	service := &Service{
		daemon:    daemon,
		inventory: inventory,
		docker:    docker,
		now:       now,
		pccNow:    now,
	}
	if inventory != nil {
		service.pccInventorySnapshot = inventory.SnapshotForCorrelation
	}
	service.pccLoadPins = LoadPCCSafetyPinSnapshot
	service.pccBoundaryChain = func(fromBootID, toBootID string) (
		[]contracts.PCCBootTransitionHopV1,
		error,
	) {
		if daemon == nil || daemon.spool == nil ||
			daemon.spool.boundaryArchive == nil {
			return nil, ErrPCCJournalCorrupt
		}
		return daemon.spool.boundaryArchive.Chain(fromBootID, toBootID)
	}
	return service
}

func falcoResolutionCoverage(err error) string {
	switch {
	case errors.Is(err, ErrContainerIdentityMismatch):
		return "docker_identity_mismatch"
	case errors.Is(err, ErrAmbiguousContainerPrefix):
		return "docker_identity_ambiguous"
	case errors.Is(err, ErrInventoryReconcileRequired),
		errors.Is(err, ErrInventoryStale):
		return "docker_reconcile_gap"
	default:
		return "docker_identity_unresolved"
	}
}

func falcoNormalizedFields(
	event contracts.FalcoConnectV1,
) (map[string]any, error) {
	canonical, err := contracts.CanonicalJSON(event)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	var result map[string]any
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// IngestFalco removes every caller-supplied Docker authority field before
// resolving and attaching observer-owned identity.
func (service *Service) IngestFalco(
	ctx context.Context,
	input contracts.FalcoConnectV1,
) (contracts.EventEnvelopeV1, error) {
	if service == nil ||
		service.daemon == nil ||
		service.daemon.signer == nil ||
		service.inventory == nil ||
		service.now == nil {
		return contracts.EventEnvelopeV1{}, fmt.Errorf(
			"observer ingest unavailable",
		)
	}
	if err := input.Validate(); err != nil {
		return contracts.EventEnvelopeV1{}, err
	}

	normalized := input
	normalized.DockerContainerID = nil
	normalized.DockerStartedAt = nil
	normalized.ImageID = nil
	normalized.RepoDigests = []string{}
	normalized.ImmutableSpecSHA256 = nil
	normalized.InventoryRevision = nil
	normalized.MissingRequiredFields = normalizeSortedUnique(
		input.MissingRequiredFields,
	)

	var identity ContainerIdentityV1
	var resolutionErr error
	if input.FalcoContainerIDPrefix == nil {
		resolutionErr = ErrContainerNotFound
	} else if service.daemon.state == nil ||
		service.daemon.state.Snapshot().ReconcileRequired {
		resolutionErr = ErrInventoryReconcileRequired
	} else {
		identity, resolutionErr = service.inventory.ResolvePrefix(
			*input.FalcoContainerIDPrefix,
		)
	}
	if resolutionErr == nil &&
		input.FalcoContainerFullID != nil &&
		*input.FalcoContainerFullID != identity.FullContainerID {
		resolutionErr = ErrContainerIdentityMismatch
	}

	generation := service.inventory.Generation()
	coverageFlags := []string{}
	eventTime, err := time.Parse(time.RFC3339Nano, input.EventTime)
	if err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	metadata := EventMetadata{
		EventTime:           eventTime.UTC(),
		InventoryGeneration: generation,
		RedactionFlags:      []string{},
		SourcePayloadHash:   input.RawEventSHA256,
	}
	if resolutionErr == nil {
		fullID := identity.FullContainerID
		startedAt := identity.DockerStartedAt
		imageID := identity.ImageID
		immutableSpec := identity.ImmutableSpecSHA256
		revision := identity.InventoryRevision
		releaseID, err := contracts.ReleaseID(imageID, immutableSpec)
		if err != nil {
			return contracts.EventEnvelopeV1{}, err
		}
		normalized.DockerContainerID = &fullID
		normalized.DockerStartedAt = &startedAt
		normalized.ImageID = &imageID
		normalized.RepoDigests = append(
			[]string{},
			identity.RepoDigests...,
		)
		normalized.ImmutableSpecSHA256 = &immutableSpec
		normalized.InventoryRevision = &revision
		metadata.ContainerID = &fullID
		metadata.ContainerStartTime = &startedAt
		metadata.ReleaseID = &releaseID
		metadata.InventoryGeneration = identity.InventoryGeneration
		metadata.InventoryRevision = &revision
	} else {
		coverageFlags = []string{falcoResolutionCoverage(resolutionErr)}
	}
	normalized.InvestigationOnly = !normalized.SuccessfulConnect ||
		len(normalized.MissingRequiredFields) != 0 ||
		resolutionErr != nil
	if err := normalized.Validate(); err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	sort.Strings(coverageFlags)
	metadata.CoverageFlags = coverageFlags
	fields, err := falcoNormalizedFields(normalized)
	if err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	return service.daemon.signer.Wrap(
		ctx,
		"falco_connect",
		fields,
		metadata,
	)
}

func (service *Service) signDockerCoverage(
	ctx context.Context,
	kind string,
	severity string,
	reason string,
	openedAt time.Time,
	closedAt *time.Time,
	generation uint64,
) error {
	_, err := service.signDockerCoverageEnvelope(
		ctx,
		kind,
		severity,
		reason,
		openedAt,
		closedAt,
		generation,
	)
	return err
}

func (service *Service) signDockerCoverageEnvelope(
	ctx context.Context,
	kind string,
	severity string,
	reason string,
	openedAt time.Time,
	closedAt *time.Time,
	generation uint64,
) (contracts.EventEnvelopeV1, error) {
	if service == nil ||
		service.daemon == nil ||
		service.daemon.signer == nil {
		return contracts.EventEnvelopeV1{},
			fmt.Errorf("observer signer unavailable")
	}
	fields := map[string]any{
		"component":            "observer",
		"kind":                 kind,
		"severity":             severity,
		"opened_at":            openedAt.UTC().Format(time.RFC3339Nano),
		"reason_code":          reason,
		"reconcile_generation": generation,
	}
	if closedAt != nil {
		fields["closed_at"] = closedAt.UTC().Format(time.RFC3339Nano)
	}
	canonical, err := contracts.CanonicalJSON(fields)
	if err != nil {
		return contracts.EventEnvelopeV1{}, err
	}
	payloadHash := sha256.Sum256(canonical)
	eventTime := openedAt.UTC()
	if closedAt != nil {
		eventTime = closedAt.UTC()
	}
	return service.daemon.signer.Wrap(
		ctx,
		"coverage",
		fields,
		EventMetadata{
			EventTime:           eventTime,
			InventoryGeneration: generation,
			RedactionFlags:      []string{},
			CoverageFlags: []string{
				"docker_event_gap",
				"reconcile_required",
			},
			SourcePayloadHash: hex.EncodeToString(payloadHash[:]),
		},
	)
}

func (service *Service) signDockerLoggingCoverage(
	ctx context.Context,
	observedAt time.Time,
	generation uint64,
) error {
	fields := map[string]any{
		"component":            "observer",
		"kind":                 "docker_logging_visibility_degraded",
		"severity":             "WARNING",
		"opened_at":            observedAt.UTC().Format(time.RFC3339Nano),
		"reason_code":          "docker_logging_unavailable",
		"reconcile_generation": generation,
	}
	canonical, err := contracts.CanonicalJSON(fields)
	if err != nil {
		return err
	}
	payloadHash := sha256.Sum256(canonical)
	_, err = service.daemon.signer.Wrap(
		ctx,
		"coverage",
		fields,
		EventMetadata{
			EventTime:           observedAt.UTC(),
			InventoryGeneration: generation,
			RedactionFlags:      []string{},
			CoverageFlags: []string{
				"docker_logging_unavailable",
			},
			SourcePayloadHash: hex.EncodeToString(payloadHash[:]),
		},
	)
	return err
}

func validDockerReconcileReason(reason string) bool {
	switch reason {
	case "observer_startup",
		"docker_event_stream_error",
		"docker_event_reconcile_retry",
		// "docker_inventory_event" is the routine dirty-signal reconcile
		// emitted by monitorDockerOnce; Core's _DOCKER_OPEN_REASONS must
		// enumerate the identical set.
		"docker_inventory_event":
		return true
	default:
		return false
	}
}

func (service *Service) validateDockerReconcile(reason string) error {
	if service == nil ||
		service.daemon == nil ||
		service.daemon.state == nil ||
		service.inventory == nil ||
		service.docker == nil ||
		service.now == nil ||
		!validDockerReconcileReason(reason) {
		return fmt.Errorf("invalid Docker reconcile service")
	}
	return nil
}

func (service *Service) openDockerReconcileFences() error {
	state := service.daemon.state
	state.publicationMutex.Lock()
	defer state.publicationMutex.Unlock()

	stateErr := state.requireDockerReconcile()
	inventoryErr := service.inventory.openReconcileGap()
	return errors.Join(stateErr, inventoryErr)
}

func (service *Service) finishDockerReconcileLocked(
	ctx context.Context,
	reason string,
	session *dockerEventSession,
) error {
	_, err := service.finishDockerReconcileLockedReceipt(
		ctx,
		reason,
		session,
	)
	return err
}

// retireDockerReconcileWindow closes a window whose reconcile already landed
// durably but whose close was never signed — the commit aborts after the
// snapshot is adopted whenever the subscribed event session died. The window
// cannot be carried into the next reconcile because that reconcile will advance
// the generation past the one the open announced, and Core pairs an open with a
// close on (opened_at, reconcile_generation).
func (service *Service) retireDockerReconcileWindow(
	ctx context.Context,
	window PendingDockerReconcile,
) error {
	openedAt, err := time.Parse(time.RFC3339Nano, window.OpenedAt)
	if err != nil {
		return err
	}
	openedAt = openedAt.UTC()
	closedAt := service.now().UTC()
	if closedAt.Before(openedAt) {
		return errors.Join(
			fmt.Errorf("Docker recovery closed_at precedes opened_at"),
			service.openDockerReconcileFences(),
		)
	}
	if err := service.daemon.state.clearDockerReconcileWindow(); err != nil {
		return err
	}
	return service.signDockerCoverage(
		ctx,
		"docker_reconcile_recovered",
		"INFO",
		"docker_full_reconcile_succeeded",
		openedAt,
		&closedAt,
		window.Generation,
	)
}

func (service *Service) finishDockerReconcileLockedReceipt(
	ctx context.Context,
	reason string,
	session *dockerEventSession,
) (dockerReconcileReceipt, error) {
	state := service.daemon.state
	pending := state.Snapshot().PendingDockerReconcile
	if pending != nil &&
		service.inventory.Generation() >= pending.Generation {
		if err := service.retireDockerReconcileWindow(
			ctx,
			*pending,
		); err != nil {
			return dockerReconcileReceipt{}, err
		}
		pending = nil
	}
	var openedAt time.Time
	var targetGeneration uint64
	if pending != nil {
		// A failed reconcile never advances the inventory generation, so the
		// window signed by the failed attempt still describes exactly this gap.
		// Reuse it: signing a second open would leave the first one unpaired
		// forever, and Core latches mutation_readiness on any unpaired open.
		parsed, err := time.Parse(time.RFC3339Nano, pending.OpenedAt)
		if err != nil {
			return dockerReconcileReceipt{}, err
		}
		openedAt = parsed.UTC()
		targetGeneration = pending.Generation
	} else {
		openedAt = service.now().UTC()
		targetGeneration = service.inventory.Generation()
		if targetGeneration != ^uint64(0) {
			targetGeneration++
		}
		if err := service.signDockerCoverage(
			ctx,
			"docker_reconcile_gap",
			"CRITICAL",
			reason,
			openedAt,
			nil,
			targetGeneration,
		); err != nil {
			return dockerReconcileReceipt{}, err
		}
		if err := state.beginDockerReconcile(PendingDockerReconcile{
			OpenedAt:   openedAt.Format(time.RFC3339Nano),
			Generation: targetGeneration,
		}); err != nil {
			return dockerReconcileReceipt{}, errors.Join(
				err,
				service.openDockerReconcileFences(),
			)
		}
	}
	if err := service.inventory.Reconcile(ctx); err != nil {
		return dockerReconcileReceipt{}, err
	}
	if service.inventory.Generation() != targetGeneration {
		// The close must report the generation the open announced. Fail closed
		// rather than sign a pair Core cannot match; the retry retires the
		// window above and starts a fresh one.
		return dockerReconcileReceipt{}, errors.Join(
			fmt.Errorf("Docker reconcile generation diverged from signed open"),
			service.openDockerReconcileFences(),
		)
	}
	if service.inventory.LoggingUnavailable() {
		if err := service.signDockerLoggingCoverage(
			ctx,
			service.now().UTC(),
			targetGeneration,
		); err != nil {
			return dockerReconcileReceipt{}, err
		}
	}
	closedAt := service.now().UTC()
	if closedAt.Before(openedAt) {
		return dockerReconcileReceipt{}, errors.Join(
			fmt.Errorf("Docker recovery closed_at precedes opened_at"),
			service.openDockerReconcileFences(),
		)
	}
	var receipt dockerReconcileReceipt
	commit := func() error {
		// Release the window before the close is signed. A lost signature then
		// leaves one unpaired open, which the next reconcile supersedes; the
		// reverse order would let a retry sign a SECOND close for an open Core
		// has already matched, which is an unrecoverable coverage conflict.
		if err := state.clearDockerReconcileWindow(); err != nil {
			return err
		}
		event, err := service.signDockerCoverageEnvelope(
			ctx,
			"docker_reconcile_recovered",
			"INFO",
			"docker_full_reconcile_succeeded",
			openedAt,
			&closedAt,
			targetGeneration,
		)
		if err != nil {
			return err
		}
		receipt = dockerReconcileReceipt{
			SourceSequence: event.SourceSequence,
			Generation:     event.InventoryGeneration,
			ClosedAt:       event.EventTime,
			openedAt:       openedAt.Format(time.RFC3339Nano),
		}
		return state.completeDockerReconcile()
	}
	if session == nil {
		if err := commit(); err != nil {
			return dockerReconcileReceipt{}, err
		}
		return receipt, nil
	}
	if err := session.CommitIfLive(commit); err != nil {
		return dockerReconcileReceipt{}, errors.Join(
			err,
			service.openDockerReconcileFences(),
		)
	}
	return receipt, nil
}

func (service *Service) reconcileDockerLocked(
	ctx context.Context,
	reason string,
) error {
	if err := service.validateDockerReconcile(reason); err != nil {
		return err
	}
	if err := service.openDockerReconcileFences(); err != nil {
		return err
	}
	return service.finishDockerReconcileLocked(ctx, reason, nil)
}

func (service *Service) reconcileDockerWithSessionLocked(
	ctx context.Context,
	reason string,
	session *dockerEventSession,
) error {
	_, err := service.reconcileDockerWithSessionLockedReceipt(
		ctx,
		reason,
		session,
	)
	return err
}

func (service *Service) reconcileDockerWithSessionLockedReceipt(
	ctx context.Context,
	reason string,
	session *dockerEventSession,
) (dockerReconcileReceipt, error) {
	if err := service.validateDockerReconcile(reason); err != nil {
		return dockerReconcileReceipt{}, err
	}
	if session == nil {
		return dockerReconcileReceipt{},
			fmt.Errorf("Docker reconcile lacks subscribed event session")
	}
	if err := service.openDockerReconcileFences(); err != nil {
		return dockerReconcileReceipt{}, err
	}
	return service.finishDockerReconcileLockedReceipt(ctx, reason, session)
}

func (service *Service) ReconcileDocker(
	ctx context.Context,
	reason string,
) error {
	if service == nil {
		return fmt.Errorf("invalid Docker reconcile service")
	}
	service.reconcileMutex.Lock()
	defer service.reconcileMutex.Unlock()
	return service.reconcileDockerLocked(ctx, reason)
}

func (service *Service) prepareDockerEventSession(
	ctx context.Context,
) error {
	if service == nil || service.docker == nil {
		return fmt.Errorf("Docker event service unavailable")
	}
	service.eventMutex.Lock()
	defer service.eventMutex.Unlock()
	return service.prepareDockerEventSessionLocked(ctx)
}

func (service *Service) prepareDockerEventSessionLocked(
	ctx context.Context,
) error {
	if service.eventSession != nil {
		return nil
	}
	session, err := newDockerEventSession(
		ctx,
		service.docker,
		service.openDockerReconcileFences,
	)
	if err != nil {
		return errors.Join(err, service.openDockerReconcileFences())
	}
	service.eventSession = session
	return nil
}

func (service *Service) closeDockerEventSession() {
	if service == nil {
		return
	}
	service.eventMutex.Lock()
	defer service.eventMutex.Unlock()
	if service.eventSession != nil {
		service.eventSession.close()
		service.eventSession = nil
	}
}

func (service *Service) recoverDockerWithSubscribedSession(
	ctx context.Context,
	reason string,
) error {
	_, err := service.recoverDockerWithSubscribedSessionReceipt(ctx, reason)
	return err
}

func (service *Service) recoverDockerWithSubscribedSessionReceipt(
	ctx context.Context,
	reason string,
) (dockerReconcileReceipt, error) {
	// Recovery may arrive here after replacement subscription setup failed.
	// Never run the snapshot first: the gap remains open until a session is
	// active for the complete reconcile and its signed close.
	if service == nil || service.docker == nil {
		return dockerReconcileReceipt{},
			fmt.Errorf("Docker event service unavailable")
	}
	service.eventMutex.Lock()
	defer service.eventMutex.Unlock()
	if service.eventSession != nil &&
		service.eventSession.TerminalError() != nil {
		service.eventSession.close()
		service.eventSession = nil
	}
	if err := service.prepareDockerEventSessionLocked(ctx); err != nil {
		return dockerReconcileReceipt{}, err
	}
	service.reconcileMutex.Lock()
	defer service.reconcileMutex.Unlock()
	return service.reconcileDockerWithSessionLockedReceipt(
		ctx,
		reason,
		service.eventSession,
	)
}

func (service *Service) replaceDockerEventSessionLocked(
	ctx context.Context,
	streamErr error,
) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	service.reconcileMutex.Lock()
	defer service.reconcileMutex.Unlock()
	if err := service.validateDockerReconcile(
		"docker_event_stream_error",
	); err != nil {
		return true, errors.Join(ErrDockerEventGap, streamErr, err)
	}

	// The old session remains subscribed until the live and durable fences are
	// opened. Its child context is then canceled before the replacement is
	// created. The replacement is already subscribed for the entire snapshot.
	fenceErr := service.openDockerReconcileFences()
	if service.eventSession != nil {
		service.eventSession.close()
	}
	replacement, subscribeErr := newDockerEventSession(
		ctx,
		service.docker,
		service.openDockerReconcileFences,
	)
	if subscribeErr == nil {
		service.eventSession = replacement
	} else {
		service.eventSession = nil
	}
	reconcileErr := errors.Join(fenceErr, subscribeErr)
	if reconcileErr == nil {
		reconcileErr = service.finishDockerReconcileLocked(
			ctx,
			"docker_event_stream_error",
			replacement,
		)
	}
	return reconcileErr != nil, errors.Join(
		ErrDockerEventGap,
		streamErr,
		reconcileErr,
	)
}

func (service *Service) monitorDockerOnce(
	ctx context.Context,
) (bool, error) {
	if service == nil || service.docker == nil {
		return true, fmt.Errorf("Docker event service unavailable")
	}
	service.eventMutex.Lock()
	defer service.eventMutex.Unlock()
	if err := service.prepareDockerEventSessionLocked(ctx); err != nil {
		return true, err
	}
	session := service.eventSession
	if session == nil {
		return true, fmt.Errorf("Docker event session unavailable")
	}
	select {
	case <-session.terminalSignal:
		return service.replaceDockerEventSessionLocked(
			ctx,
			session.TerminalError(),
		)
	default:
	}
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-session.dirty:
		service.reconcileMutex.Lock()
		reconcileErr := service.reconcileDockerWithSessionLocked(
			ctx,
			"docker_inventory_event",
			session,
		)
		service.reconcileMutex.Unlock()
		if reconcileErr != nil {
			if terminalErr := session.TerminalError(); terminalErr != nil {
				return service.replaceDockerEventSessionLocked(
					ctx,
					terminalErr,
				)
			}
			return true, reconcileErr
		}
		return false, nil
	case <-session.terminalSignal:
		return service.replaceDockerEventSessionLocked(
			ctx,
			session.TerminalError(),
		)
	}
}

func (service *Service) MonitorDockerOnce(ctx context.Context) error {
	_, err := service.monitorDockerOnce(ctx)
	return err
}

type observerRuntimeServer interface {
	Serve() error
	Close() error
}

type observerRuntimeOptions struct {
	openDocker func() (DockerReader, io.Closer, error)
	processes  processIdentityReader
	groupID    func(string) (uint32, error)
	userID     func(string) (uint32, error)
	listen     func(
		string,
		os.FileMode,
		int,
		int64,
		http.Handler,
	) (observerRuntimeServer, error)
	now func() time.Time
}

func namedGroupID(name string) (uint32, error) {
	group, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil || strconv.FormatUint(value, 10) != group.Gid {
		return 0, fmt.Errorf("invalid service group ID")
	}
	return uint32(value), nil
}

func namedUserID(name string) (uint32, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || strconv.FormatUint(value, 10) != account.Uid {
		return 0, fmt.Errorf("invalid service user ID")
	}
	return uint32(value), nil
}

func defaultObserverRuntimeOptions() observerRuntimeOptions {
	return observerRuntimeOptions{
		openDocker: newMobyDockerReader,
		processes:  newPlatformProcessIdentityReader(),
		groupID:    namedGroupID,
		userID:     namedUserID,
		listen: func(
			path string,
			mode os.FileMode,
			gid int,
			maxBody int64,
			handler http.Handler,
		) (observerRuntimeServer, error) {
			return uds.ListenHTTP(path, mode, gid, maxBody, handler)
		},
		now: time.Now,
	}
}

func (service *Service) monitorDockerContinuously(ctx context.Context) {
	defer service.closeDockerEventSession()
	if err := service.prepareDockerEventSession(ctx); err != nil {
		return
	}
	reconcilePending := false
	for ctx.Err() == nil {
		if reconcilePending {
			err := service.recoverDockerWithSubscribedSession(
				ctx,
				"docker_event_reconcile_retry",
			)
			if err == nil {
				reconcilePending = false
				continue
			}
		} else {
			pending, err := service.monitorDockerOnce(ctx)
			reconcilePending = pending
			if err == nil {
				continue
			}
		}
		if ctx.Err() != nil {
			return
		}
		if !reconcilePending {
			continue
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

// missingObserverRuntimeDependency names the first dependency the runtime needs and does not have,
// or "" when every one is present. Ten nil checks used to collapse into a single opaque sentence,
// which was all an operator saw in the journal when the daemon refused to start: it identified
// nothing, so diagnosis meant reading this source. The names describe internal wiring an operator
// already controls on the host, so stating them discloses nothing.
func missingObserverRuntimeDependency(
	daemon *Daemon,
	options observerRuntimeOptions,
) string {
	if daemon == nil {
		return "daemon"
	}
	switch {
	case daemon.state == nil:
		return "durable state"
	case daemon.spool == nil:
		return "evidence spool"
	case daemon.signer == nil:
		return "event signer"
	case options.openDocker == nil:
		return "Docker reader"
	case options.processes == nil:
		return "process table reader"
	case options.groupID == nil:
		return "group resolver"
	case options.userID == nil:
		return "user resolver"
	case options.listen == nil:
		return "socket listener"
	case options.now == nil:
		return "clock"
	}
	return ""
}

func (daemon *Daemon) runWithOptions(
	ctx context.Context,
	options observerRuntimeOptions,
) error {
	if missing := missingObserverRuntimeDependency(daemon, options); missing != "" {
		return fmt.Errorf("observer runtime dependency unavailable: %s", missing)
	}
	if err := daemon.config.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	sensorGID, err := options.groupID("agmind-sensor")
	if err != nil {
		return err
	}
	coreGID, err := options.groupID("agmind-core")
	if err != nil {
		return err
	}
	coreUID, err := options.userID("agmind-core")
	if err != nil {
		return err
	}
	docker, dockerCloser, err := options.openDocker()
	if err != nil {
		return err
	}
	if docker == nil || dockerCloser == nil {
		if dockerCloser != nil {
			_ = dockerCloser.Close()
		}
		return fmt.Errorf("Docker reader unavailable")
	}
	defer dockerCloser.Close()
	inventory, err := openInventory(
		daemon.config.StateDir,
		docker,
		options.processes,
		options.now,
	)
	if err != nil {
		return err
	}
	service := newObserverService(
		daemon,
		inventory,
		docker,
		options.now,
	)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer service.closeDockerEventSession()
	baselineGeneration := inventory.Generation()
	receipt, err := service.recoverDockerWithSubscribedSessionReceipt(
		runCtx,
		"observer_startup",
	)
	if err != nil {
		return err
	}
	if err := service.closeOutstandingSequenceGaps(
		runCtx,
		baselineGeneration,
		receipt,
	); err != nil {
		return err
	}

	specifications := []struct {
		path    string
		mode    os.FileMode
		gid     int
		handler http.Handler
	}{
		{
			path: filepath.Join(
				daemon.config.RunDir,
				"observer-ingest",
				"socket",
			),
			mode:    0o660,
			gid:     int(sensorGID),
			handler: newIngestAPI(service, sensorGID),
		},
		{
			path: filepath.Join(
				daemon.config.RunDir,
				"observer-core",
				"socket",
			),
			mode:    0o660,
			gid:     int(coreGID),
			handler: newCoreAPI(service, coreGID, coreUID),
		},
		{
			path: filepath.Join(
				daemon.config.RunDir,
				"observer-actuator",
				"socket",
			),
			mode:    0o600,
			gid:     0,
			handler: newPrivateAPI(service),
		},
	}
	servers := make([]observerRuntimeServer, 0, len(specifications))
	closeServers := func() error {
		var closeErr error
		for index := len(servers) - 1; index >= 0; index-- {
			closeErr = errors.Join(closeErr, servers[index].Close())
		}
		return closeErr
	}
	for _, specification := range specifications {
		server, err := options.listen(
			specification.path,
			specification.mode,
			specification.gid,
			65_536,
			specification.handler,
		)
		if err != nil {
			return errors.Join(err, closeServers())
		}
		if server == nil {
			return errors.Join(
				fmt.Errorf("observer listener unavailable"),
				closeServers(),
			)
		}
		servers = append(servers, server)
	}

	serveResults := make(chan error, len(servers))
	for _, server := range servers {
		go func(server observerRuntimeServer) {
			serveResults <- server.Serve()
		}(server)
	}
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		service.monitorDockerContinuously(runCtx)
	}()

	var runErr error
	received := 0
	select {
	case <-ctx.Done():
	case serveErr := <-serveResults:
		received++
		if serveErr == nil || errors.Is(serveErr, http.ErrServerClosed) {
			runErr = fmt.Errorf("observer listener stopped unexpectedly")
		} else {
			runErr = serveErr
		}
	}
	cancel()
	closeErr := closeServers()
	for received < len(servers) {
		serveErr := <-serveResults
		received++
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			runErr = errors.Join(runErr, serveErr)
		}
	}
	<-monitorDone
	if ctx.Err() != nil && runErr == nil {
		return closeErr
	}
	return errors.Join(runErr, closeErr)
}

// Run adds the Task 3 Docker reader, full startup reconcile, event monitor,
// and three independently owned UDS APIs to a bootstrapped daemon.
func (daemon *Daemon) Run(ctx context.Context) error {
	return daemon.runWithOptions(ctx, defaultObserverRuntimeOptions())
}
