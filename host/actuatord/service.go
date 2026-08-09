package actuatord

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"sync"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

type serviceOptions struct {
	dependencies   planDependencies
	journalOptions []durablefile.Option
}

type ServiceOption func(*serviceOptions)

func WithObserver(observer Observer) ServiceOption {
	return func(options *serviceOptions) {
		options.dependencies.observer = observer
	}
}

func WithTargetResolver(target TargetResolver) ServiceOption {
	return func(options *serviceOptions) {
		options.dependencies.target = target
	}
}

func WithSafetyProvider(safety SafetyProvider) ServiceOption {
	return func(options *serviceOptions) {
		options.dependencies.safety = safety
	}
}

func WithClock(clock func() (ClockSample, error)) ServiceOption {
	return func(options *serviceOptions) {
		options.dependencies.clock = clock
	}
}

func WithRandom(random io.Reader) ServiceOption {
	return func(options *serviceOptions) {
		options.dependencies.random = random
	}
}

// withJournalOptions exists only for deterministic durability fault injection.
func withJournalOptions(values ...durablefile.Option) ServiceOption {
	return func(options *serviceOptions) {
		options.journalOptions = append(options.journalOptions, values...)
	}
}

type Service struct {
	mutex        sync.Mutex
	journal      *actionJournal
	dependencies planDependencies
	closed       bool
}

func OpenService(
	stateDir string,
	privateKey ed25519.PrivateKey,
	values ...ServiceOption,
) (*Service, error) {
	options := serviceOptions{dependencies: defaultPlanDependencies()}
	for _, value := range values {
		if value == nil {
			return nil, fmt.Errorf("nil actuator service option")
		}
		value(&options)
	}
	if err := options.dependencies.validate(); err != nil {
		return nil, err
	}
	journal, err := openActionJournal(
		stateDir,
		privateKey,
		options.journalOptions...,
	)
	if err != nil {
		return nil, err
	}
	return &Service{
		journal:      journal,
		dependencies: options.dependencies,
	}, nil
}

func (service *Service) Prepare(
	ctx context.Context,
	intent contracts.TemporaryEgressDenyIntentV1,
) (contracts.PreparedTemporaryEgressDenyPlanV1, error) {
	if service == nil {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, fmt.Errorf("nil actuator service")
	}
	if err := ctx.Err(); err != nil {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, err
	}
	intent = cloneIntent(intent)
	intentSHA256, err := canonicalIntentSHA256(intent)
	if err != nil {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, err
	}
	service.mutex.Lock()
	defer service.mutex.Unlock()
	if service.closed {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, durablefile.ErrJournalClosed
	}
	if service.journal.failed() {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, durablefile.ErrJournalFailed
	}
	if existing, ok, err := service.journal.existing(
		intent.IntentID,
		intentSHA256,
	); err != nil {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, err
	} else if ok {
		return clonePlan(existing), nil
	}
	if _, err := service.journal.reservation(
		intent.IntentID,
		intentSHA256,
	); err != nil {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, err
	}
	rateClock, err := service.dependencies.clock()
	if err != nil {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, err
	}
	if err := rateClock.validate(); err != nil {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, err
	}
	if err := service.journal.rateAllowed(rateClock.Wall); err != nil {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, err
	}
	if service.journal.pendingAt(rateClock.Wall) >= MaxPendingPlans {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, ErrPendingLimit
	}
	// A signed, fsynced token is consumed before observer, Docker, procfs, or
	// namespace work so rejected attempts cannot bypass rate limits or restart.
	if err := service.journal.reserveIntent(
		intent.IntentID,
		intentSHA256,
		rateClock.Wall,
	); err != nil {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, err
	}
	built, err := buildPreparedPlan(ctx, intent, service.dependencies)
	if err != nil {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, err
	}
	state := preparedState{
		Plan:                       built.plan,
		IntentSHA256:               intentSHA256,
		ApprovalDeadlineBootTimeNS: built.approvalDeadlineBootTimeNS,
	}
	if err := service.journal.appendPrepared(state); err != nil {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, err
	}
	return clonePlan(built.plan), nil
}

func (service *Service) Pending() int {
	if service == nil {
		return 0
	}
	service.mutex.Lock()
	defer service.mutex.Unlock()
	if service.journal == nil {
		return 0
	}
	return len(service.journal.byIntent)
}

func (service *Service) Close() error {
	if service == nil {
		return nil
	}
	service.mutex.Lock()
	defer service.mutex.Unlock()
	if service.closed {
		return nil
	}
	service.closed = true
	return service.journal.close()
}
