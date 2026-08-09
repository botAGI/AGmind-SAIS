package actuatord

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"agmind.local/sais/host/observerd"
	"agmind.local/sais/internal/contracts"
)

type daemonTestEvents struct {
	mutex  sync.Mutex
	values []string
}

func (events *daemonTestEvents) add(value string) {
	events.mutex.Lock()
	defer events.mutex.Unlock()
	events.values = append(events.values, value)
}

func (events *daemonTestEvents) snapshot() []string {
	events.mutex.Lock()
	defer events.mutex.Unlock()
	return slices.Clone(events.values)
}

type daemonTestObserver struct {
	events *daemonTestEvents
}

func (*daemonTestObserver) Integrity(
	context.Context,
) (observerd.ObserverIntegrityV1, error) {
	return observerd.ObserverIntegrityV1{}, nil
}

func (*daemonTestObserver) LookupContainer(
	context.Context,
	string,
) (observerd.ContainerIdentityV1, error) {
	return observerd.ContainerIdentityV1{}, nil
}

func (*daemonTestObserver) CheckNetNS(
	context.Context,
	observerd.NetNSUniquenessRequestV1,
) (observerd.NetNSUniquenessV1, error) {
	return observerd.NetNSUniquenessV1{}, nil
}

func (observer *daemonTestObserver) Close() error {
	observer.events.add("observer-close")
	return nil
}

type daemonTestSafety struct{}

func (daemonTestSafety) Snapshot(context.Context) (SafetySnapshot, error) {
	return SafetySnapshot{}, nil
}

type daemonTestServer struct {
	name      string
	events    *daemonTestEvents
	closed    chan struct{}
	closeOnce sync.Once
}

func (server *daemonTestServer) Serve() error {
	server.events.add(server.name + "-serve")
	<-server.closed
	server.events.add(server.name + "-serve-done")
	return http.ErrServerClosed
}

func (server *daemonTestServer) Close() error {
	server.closeOnce.Do(func() {
		server.events.add(server.name + "-close")
		close(server.closed)
	})
	return nil
}

func daemonTestRecord(t *testing.T, state string) contracts.ActionRecordV1 {
	t.Helper()
	record := contracts.ActionRecordV1{
		SchemaVersion:        "agmind.action-record.v1",
		PlanID:               "plan_11111111111111111111111111111111",
		PlanHashValue:        "2222222222222222222222222222222222222222222222222222222222222222",
		State:                state,
		ReasonCode:           "test_terminal",
		ObservedAt:           "2026-08-09T08:00:00Z",
		PreviousRecordSHA256: "3333333333333333333333333333333333333333333333333333333333333333",
		Details:              map[string]any{},
		ActuatorKeyID:        "44444444444444444444444444444444",
		ActuatorSignature:    "55555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555",
	}
	hash, err := contracts.ActionRecordHash(record)
	if err != nil {
		t.Fatal(err)
	}
	record.RecordSHA256 = hash
	record.RecordID = contracts.ActionRecordID(hash)
	if err := record.Validate(); err != nil {
		t.Fatalf("invalid test action record: %v", err)
	}
	return record
}

func eventIndex(t *testing.T, values []string, value string) int {
	t.Helper()
	index := slices.Index(values, value)
	if index < 0 {
		t.Fatalf("event %q absent from %v", value, values)
	}
	return index
}

func eventIndexAfter(
	t *testing.T,
	values []string,
	value string,
	after int,
) int {
	t.Helper()
	if after+1 >= len(values) {
		t.Fatalf("event %q absent after %d in %v", value, after, values)
	}
	index := slices.Index(values[after+1:], value)
	if index < 0 {
		t.Fatalf("event %q absent after %d in %v", value, after, values)
	}
	return after + 1 + index
}

func TestDaemonRecoversBeforeListeningAndShutsDownInOwnershipOrder(
	t *testing.T,
) {
	for _, identities := range [][3]uint32{
		{0, 1201, 1202},
		{1101, 0, 1202},
		{1101, 1201, 0},
		{1101, 1201, 1201},
	} {
		if err := validateDaemonServiceIDs(
			identities[0],
			identities[1],
			identities[2],
		); err == nil {
			t.Fatalf("unsafe service identities accepted: %v", identities)
		}
	}

	events := &daemonTestEvents{}
	observer := &daemonTestObserver{events: events}
	config := Config{
		SchemaVersion:           "agmind.actuator-config.v1",
		StateDir:                "/var/lib/agmind-sais/actuator",
		PrivateKeyFile:          "/etc/agmind-sais/secrets/actuator-ed25519.key",
		ObserverSocket:          "/run/agmind-sais/observer-actuator/socket",
		IntentSocket:            "/run/agmind-sais/actuator-intent/socket",
		AdminSocket:             "/run/agmind-sais/actuator-admin/socket",
		ManagementDenylistFile:  "/etc/agmind-sais/management-destinations.json",
		SpecialUseRegistryFile:  "/usr/share/agmind-sais/ipv4-special-use.csv",
		ApprovalTTLSeconds:      300,
		DefaultActionTTLSeconds: 120,
	}
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	daemon, err := bootstrapWithOptions(
		context.Background(),
		DefaultConfigPath,
		daemonBootstrapOptions{
			goos: "linux",
			geteuid: func() int {
				return 0
			},
			loadConfig: func(path string) (Config, error) {
				if path != DefaultConfigPath {
					t.Fatalf("config path=%q", path)
				}
				events.add("config")
				return config, nil
			},
			loadPrivateKey: func(path string) (ed25519.PrivateKey, error) {
				if path != config.PrivateKeyFile {
					t.Fatalf("private key path=%q", path)
				}
				events.add("key")
				return privateKey, nil
			},
			newObserver: func(path string) (daemonObserverClient, error) {
				if path != config.ObserverSocket {
					t.Fatalf("observer path=%q", path)
				}
				events.add("observer")
				return observer, nil
			},
			newSafety: func(registryPath, managementPath string) (SafetyProvider, error) {
				if registryPath != config.SpecialUseRegistryFile ||
					managementPath != config.ManagementDenylistFile {
					t.Fatalf("safety paths=%q %q", registryPath, managementPath)
				}
				events.add("safety")
				return daemonTestSafety{}, nil
			},
			openService: func(
				stateDir string,
				key ed25519.PrivateKey,
				client Observer,
				safety SafetyProvider,
			) (*Service, error) {
				if stateDir != config.StateDir || !privateKey.Equal(key) ||
					client != observer || safety == nil {
					t.Fatal("OpenService wiring changed")
				}
				events.add("recovery")
				return &Service{}, nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := events.snapshot(); !slices.Equal(
		got,
		[]string{"config", "key", "observer", "safety", "recovery"},
	) {
		t.Fatalf("bootstrap events=%v", got)
	}

	terminal := daemonTestRecord(t, "REJECTED")
	applyCalls := 0
	applyBlocked := make(chan struct{})
	daemon.applyNext = func(ctx context.Context) (contracts.ActionRecordV1, error) {
		applyCalls++
		events.add("apply")
		switch applyCalls {
		case 1:
			return terminal, ErrIntentRejected
		case 2:
			return contracts.ActionRecordV1{}, ErrNoApprovedPlan
		case 3:
			close(applyBlocked)
			<-ctx.Done()
			events.add("worker-cancelled")
			return contracts.ActionRecordV1{}, ctx.Err()
		default:
			return contracts.ActionRecordV1{}, fmt.Errorf(
				"unexpected apply call %d",
				applyCalls,
			)
		}
	}
	daemon.killSwitchActive = func() bool { return false }
	daemon.closeService = func() error {
		events.add("service-close")
		return nil
	}

	intentServer := &daemonTestServer{
		name: "intent", events: events, closed: make(chan struct{}),
	}
	adminServer := &daemonTestServer{
		name: "admin", events: events, closed: make(chan struct{}),
	}
	runCtx, cancel := context.WithCancel(context.Background())
	runResult := make(chan error, 1)
	go func() {
		runResult <- daemon.runWithOptions(runCtx, daemonRuntimeOptions{
			groupID: func(name string) (uint32, error) {
				switch name {
				case "agmind-core":
					return 1201, nil
				case "agmind-admin":
					return 1202, nil
				default:
					return 0, errors.New("unexpected group")
				}
			},
			userID: func(name string) (uint32, error) {
				if name != "agmind-core" {
					return 0, errors.New("unexpected user")
				}
				return 1101, nil
			},
			listenIntent: func(
				path string,
				gid int,
				uid int,
				service *Service,
			) (daemonRuntimeServer, error) {
				if path != config.IntentSocket || gid != 1201 || uid != 1101 ||
					service != daemon.service {
					return nil, errors.New("intent listener wiring changed")
				}
				events.add("intent-listen")
				return intentServer, nil
			},
			listenAdmin: func(
				path string,
				gid int,
				service *Service,
			) (daemonRuntimeServer, error) {
				if path != config.AdminSocket || gid != 1202 || service != daemon.service {
					return nil, errors.New("admin listener wiring changed")
				}
				events.add("admin-listen")
				return adminServer, nil
			},
			wait: func(ctx context.Context, delay time.Duration) error {
				if delay != daemonWorkerIdleInterval {
					return fmt.Errorf("worker delay=%v", delay)
				}
				events.add("worker-idle")
				return nil
			},
			applyTimeout: daemonApplyTimeout,
		})
	}()

	select {
	case <-applyBlocked:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not drain terminal action and enter next apply")
	}
	cancel()
	select {
	case err := <-runResult:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not complete bounded shutdown")
	}

	got := events.snapshot()
	firstApply := eventIndex(t, got, "apply")
	secondApply := eventIndexAfter(t, got, "apply", firstApply)
	workerIdle := eventIndex(t, got, "worker-idle")
	thirdApply := eventIndexAfter(t, got, "apply", secondApply)
	if eventIndex(t, got, "recovery") >= eventIndex(t, got, "intent-listen") ||
		eventIndex(t, got, "intent-listen") >= eventIndex(t, got, "admin-listen") ||
		secondApply >= workerIdle || workerIdle >= thirdApply {
		t.Fatalf("startup/drain order=%v", got)
	}
	serviceClosed := eventIndex(t, got, "service-close")
	if serviceClosed <= eventIndex(t, got, "worker-cancelled") ||
		serviceClosed <= eventIndex(t, got, "intent-serve-done") ||
		serviceClosed <= eventIndex(t, got, "admin-serve-done") ||
		serviceClosed >= eventIndex(t, got, "observer-close") {
		t.Fatalf("shutdown ownership order=%v", got)
	}
}
