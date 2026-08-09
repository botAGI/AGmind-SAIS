package actuatord

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"sync"
	"time"

	"agmind.local/sais/internal/contracts"
)

const (
	daemonWorkerIdleInterval = 250 * time.Millisecond
	daemonApplyTimeout       = 30 * time.Second
)

type daemonObserverClient interface {
	Observer
	Close() error
}

type daemonRuntimeServer interface {
	Serve() error
	Close() error
}

type daemonBootstrapOptions struct {
	goos           string
	geteuid        func() int
	loadConfig     func(string) (Config, error)
	loadPrivateKey func(string) (ed25519.PrivateKey, error)
	newObserver    func(string) (daemonObserverClient, error)
	newSafety      func(string, string) (SafetyProvider, error)
	openService    func(
		string,
		ed25519.PrivateKey,
		Observer,
		SafetyProvider,
	) (*Service, error)
}

type daemonRuntimeOptions struct {
	groupID      func(string) (uint32, error)
	userID       func(string) (uint32, error)
	listenIntent func(string, int, int, *Service) (daemonRuntimeServer, error)
	listenAdmin  func(string, int, *Service) (daemonRuntimeServer, error)
	wait         func(context.Context, time.Duration) error
	applyTimeout time.Duration
}

type Daemon struct {
	config           Config
	service          *Service
	observer         daemonObserverClient
	applyNext        func(context.Context) (contracts.ActionRecordV1, error)
	killSwitchActive func() bool
	closeService     func() error
	closeOnce        sync.Once
	closeErr         error
}

func defaultDaemonBootstrapOptions() daemonBootstrapOptions {
	return daemonBootstrapOptions{
		goos:           runtime.GOOS,
		geteuid:        os.Geteuid,
		loadConfig:     LoadConfig,
		loadPrivateKey: LoadPrivateKey,
		newObserver: func(path string) (daemonObserverClient, error) {
			return NewObserverClient(path)
		},
		newSafety: func(
			registryPath string,
			managementPath string,
		) (SafetyProvider, error) {
			return NewFileSafetyProvider(registryPath, managementPath)
		},
		openService: func(
			stateDir string,
			privateKey ed25519.PrivateKey,
			observer Observer,
			safety SafetyProvider,
		) (*Service, error) {
			return OpenService(
				stateDir,
				privateKey,
				WithObserver(observer),
				WithSafetyProvider(safety),
			)
		},
	}
}

func validDaemonBootstrapOptions(options daemonBootstrapOptions) bool {
	return options.goos != "" && options.geteuid != nil &&
		options.loadConfig != nil && options.loadPrivateKey != nil &&
		options.newObserver != nil && options.newSafety != nil &&
		options.openService != nil
}

func bootstrapWithOptions(
	ctx context.Context,
	configPath string,
	options daemonBootstrapOptions,
) (*Daemon, error) {
	if ctx == nil || !validDaemonBootstrapOptions(options) {
		return nil, fmt.Errorf("actuator bootstrap dependencies unavailable")
	}
	if options.goos != "linux" {
		return nil, ErrUnsupportedPlatform
	}
	if options.geteuid() != 0 {
		return nil, fmt.Errorf("actuator daemon requires effective UID 0")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	config, err := options.loadConfig(configPath)
	if err != nil {
		return nil, err
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	privateKey, err := options.loadPrivateKey(config.PrivateKeyFile)
	if err != nil {
		return nil, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid actuator private key")
	}
	observer, err := options.newObserver(config.ObserverSocket)
	if err != nil {
		return nil, err
	}
	if observer == nil {
		return nil, fmt.Errorf("observer client unavailable")
	}
	fail := func(cause error) (*Daemon, error) {
		return nil, errors.Join(cause, observer.Close())
	}
	safety, err := options.newSafety(
		config.SpecialUseRegistryFile,
		config.ManagementDenylistFile,
	)
	if err != nil {
		return fail(err)
	}
	if safety == nil {
		return fail(fmt.Errorf("actuator safety provider unavailable"))
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	// OpenService verifies and reconciles the durable journal before Bootstrap
	// can return a daemon capable of binding either local socket.
	service, err := options.openService(
		config.StateDir,
		privateKey,
		observer,
		safety,
	)
	if err != nil {
		return fail(err)
	}
	if service == nil {
		return fail(fmt.Errorf("actuator service unavailable"))
	}
	daemon := &Daemon{
		config:           config,
		service:          service,
		observer:         observer,
		applyNext:        service.ApplyNext,
		killSwitchActive: service.KillSwitchActive,
		closeService:     service.Close,
	}
	return daemon, nil
}

// Bootstrap opens all trusted inputs and completes journal/kernel recovery.
// It never creates a listener; Run owns both Unix sockets only after this
// function succeeds.
func Bootstrap(ctx context.Context, configPath string) (*Daemon, error) {
	return bootstrapWithOptions(ctx, configPath, defaultDaemonBootstrapOptions())
}

func (daemon *Daemon) Close() error {
	if daemon == nil {
		return nil
	}
	daemon.closeOnce.Do(func() {
		var serviceErr error
		if daemon.closeService != nil {
			serviceErr = daemon.closeService()
		}
		var observerErr error
		if daemon.observer != nil {
			observerErr = daemon.observer.Close()
		}
		daemon.closeErr = errors.Join(serviceErr, observerErr)
	})
	return daemon.closeErr
}

func daemonNumericID(value string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return 0, fmt.Errorf("invalid service identity ID")
	}
	return uint32(parsed), nil
}

func daemonNamedGroupID(name string) (uint32, error) {
	group, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return daemonNumericID(group.Gid)
}

func daemonNamedUserID(name string) (uint32, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	return daemonNumericID(account.Uid)
}

func validateDaemonServiceIDs(coreUID, coreGID, adminGID uint32) error {
	if coreUID == 0 || coreGID == 0 || adminGID == 0 {
		return fmt.Errorf("actuator service identities must not be root")
	}
	if coreGID == adminGID {
		return fmt.Errorf("actuator Core and admin groups must be distinct")
	}
	return nil
}

func daemonWait(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return fmt.Errorf("invalid actuator worker delay")
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func defaultDaemonRuntimeOptions() daemonRuntimeOptions {
	return daemonRuntimeOptions{
		groupID: daemonNamedGroupID,
		userID:  daemonNamedUserID,
		listenIntent: func(
			path string,
			gid int,
			uid int,
			service *Service,
		) (daemonRuntimeServer, error) {
			return ListenIntent(path, gid, uid, service)
		},
		listenAdmin: func(
			path string,
			gid int,
			service *Service,
		) (daemonRuntimeServer, error) {
			return ListenAdmin(path, gid, service)
		},
		wait:         daemonWait,
		applyTimeout: daemonApplyTimeout,
	}
}

func validDaemonRuntimeOptions(options daemonRuntimeOptions) bool {
	return options.groupID != nil && options.userID != nil &&
		options.listenIntent != nil && options.listenAdmin != nil &&
		options.wait != nil && options.applyTimeout > 0 &&
		options.applyTimeout <= time.Minute
}

func emptyActionRecord(record contracts.ActionRecordV1) bool {
	return record.SchemaVersion == "" && record.RecordID == "" &&
		record.ActionID == nil && record.PlanID == "" &&
		record.PlanHashValue == "" && record.State == "" &&
		record.ReasonCode == "" && record.ObservedAt == "" &&
		record.PreviousRecordSHA256 == "" && record.RecordSHA256 == "" &&
		record.Details == nil && record.ActuatorKeyID == "" &&
		record.ActuatorSignature == ""
}

func terminalApplyState(state string) bool {
	switch state {
	case "VERIFIED", "EXPIRED", "STALE_ABORT", "REJECTED", "EXPIRED_UNAPPLIED":
		return true
	default:
		return false
	}
}

func (daemon *Daemon) runApplyWorker(
	ctx context.Context,
	options daemonRuntimeOptions,
) error {
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if daemon.killSwitchActive() {
			if err := options.wait(ctx, daemonWorkerIdleInterval); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
			continue
		}
		applyCtx, cancel := context.WithTimeout(ctx, options.applyTimeout)
		record, applyErr := daemon.applyNext(applyCtx)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if emptyActionRecord(record) {
			switch {
			case errors.Is(applyErr, ErrNoApprovedPlan),
				errors.Is(applyErr, ErrKillSwitchActive):
				if err := options.wait(ctx, daemonWorkerIdleInterval); err != nil {
					if ctx.Err() != nil {
						return nil
					}
					return err
				}
				continue
			case applyErr == nil:
				return fmt.Errorf("actuator apply worker returned an empty result")
			default:
				return fmt.Errorf("actuator apply worker failed: %w", applyErr)
			}
		}
		if err := record.Validate(); err != nil {
			return fmt.Errorf("actuator apply worker returned an invalid record: %w", err)
		}
		switch {
		case record.State == "FAILED_DIRTY":
			if err := options.wait(ctx, daemonWorkerIdleInterval); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		case terminalApplyState(record.State):
			// A complete durable outcome drains immediately, including the
			// typed error that explains a rejection or stale abort.
			continue
		case record.State == "APPLIED":
			if applyErr == nil {
				return fmt.Errorf(
					"actuator apply worker stopped after APPLIED without VERIFIED",
				)
			}
			return fmt.Errorf(
				"actuator apply worker stopped after APPLIED without VERIFIED: %w",
				applyErr,
			)
		default:
			return fmt.Errorf(
				"actuator apply worker returned nonterminal state %q",
				record.State,
			)
		}
	}
}

func closeDaemonServers(servers []daemonRuntimeServer) error {
	var result error
	for index := len(servers) - 1; index >= 0; index-- {
		result = errors.Join(result, servers[index].Close())
	}
	return result
}

func (daemon *Daemon) runWithOptions(
	ctx context.Context,
	options daemonRuntimeOptions,
) (result error) {
	if daemon == nil || daemon.service == nil || daemon.observer == nil ||
		daemon.applyNext == nil || daemon.killSwitchActive == nil ||
		daemon.closeService == nil || ctx == nil ||
		!validDaemonRuntimeOptions(options) {
		return fmt.Errorf("actuator runtime dependencies unavailable")
	}
	defer func() { result = errors.Join(result, daemon.Close()) }()
	if err := daemon.config.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
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
	adminGID, err := options.groupID("agmind-admin")
	if err != nil {
		return err
	}
	if err := validateDaemonServiceIDs(coreUID, coreGID, adminGID); err != nil {
		return err
	}
	intent, err := options.listenIntent(
		daemon.config.IntentSocket,
		int(coreGID),
		int(coreUID),
		daemon.service,
	)
	if err != nil {
		return err
	}
	if intent == nil {
		return fmt.Errorf("actuator intent listener unavailable")
	}
	servers := []daemonRuntimeServer{intent}
	admin, err := options.listenAdmin(
		daemon.config.AdminSocket,
		int(adminGID),
		daemon.service,
	)
	if err != nil {
		return errors.Join(err, closeDaemonServers(servers))
	}
	if admin == nil {
		return errors.Join(
			fmt.Errorf("actuator admin listener unavailable"),
			closeDaemonServers(servers),
		)
	}
	servers = append(servers, admin)

	runCtx, cancel := context.WithCancel(ctx)
	serveResults := make(chan error, len(servers))
	for _, server := range servers {
		go func(server daemonRuntimeServer) {
			serveResults <- server.Serve()
		}(server)
	}
	workerResult := make(chan error, 1)
	go func() {
		workerResult <- daemon.runApplyWorker(runCtx, options)
	}()

	serveReceived := 0
	workerReceived := false
	var runErr error
	select {
	case <-ctx.Done():
	case serveErr := <-serveResults:
		serveReceived++
		if ctx.Err() == nil {
			if serveErr == nil || errors.Is(serveErr, http.ErrServerClosed) {
				runErr = fmt.Errorf("actuator listener stopped unexpectedly")
			} else {
				runErr = serveErr
			}
		}
	case workerErr := <-workerResult:
		workerReceived = true
		if ctx.Err() == nil {
			if workerErr == nil {
				runErr = fmt.Errorf("actuator apply worker stopped unexpectedly")
			} else {
				runErr = workerErr
			}
		}
	}
	cancel()
	closeErr := closeDaemonServers(servers)
	for serveReceived < len(servers) {
		serveErr := <-serveResults
		serveReceived++
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			runErr = errors.Join(runErr, serveErr)
		}
	}
	if !workerReceived {
		workerErr := <-workerResult
		if workerErr != nil {
			runErr = errors.Join(runErr, workerErr)
		}
	}
	return errors.Join(runErr, closeErr)
}

// Run binds the two local Unix APIs and owns one serialized apply worker.
func (daemon *Daemon) Run(ctx context.Context) error {
	return daemon.runWithOptions(ctx, defaultDaemonRuntimeOptions())
}
