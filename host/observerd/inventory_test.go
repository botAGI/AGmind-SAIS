package observerd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"agmind.local/sais/internal/contracts"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

type fakeDockerReader struct {
	listResult   client.ContainerListResult
	listErr      error
	inspectByID  map[string]client.ContainerInspectResult
	inspectErr   map[string]error
	imageByID    map[string]client.ImageInspectResult
	networkByID  map[string]client.NetworkInspectResult
	listOptions  []client.ContainerListOptions
	inspectIDs   []string
	eventsResult *DockerEventStream
	eventsErr    error
}

func (reader *fakeDockerReader) ContainerList(
	_ context.Context,
	options client.ContainerListOptions,
) (client.ContainerListResult, error) {
	reader.listOptions = append(reader.listOptions, options)
	if reader.listErr != nil {
		return client.ContainerListResult{}, reader.listErr
	}
	return reader.listResult, nil
}

func (reader *fakeDockerReader) ContainerInspect(
	_ context.Context,
	fullID string,
	_ client.ContainerInspectOptions,
) (client.ContainerInspectResult, error) {
	reader.inspectIDs = append(reader.inspectIDs, fullID)
	if err := reader.inspectErr[fullID]; err != nil {
		return client.ContainerInspectResult{}, err
	}
	result, ok := reader.inspectByID[fullID]
	if !ok {
		return client.ContainerInspectResult{}, errors.New("missing fake inspect")
	}
	return result, nil
}

func (reader *fakeDockerReader) ImageInspect(
	_ context.Context,
	imageID string,
	_ ...client.ImageInspectOption,
) (client.ImageInspectResult, error) {
	result, ok := reader.imageByID[imageID]
	if !ok {
		return client.ImageInspectResult{}, errors.New("missing fake image")
	}
	return result, nil
}

func (reader *fakeDockerReader) NetworkInspect(
	_ context.Context,
	networkID string,
	_ client.NetworkInspectOptions,
) (client.NetworkInspectResult, error) {
	result, ok := reader.networkByID[networkID]
	if !ok {
		return client.NetworkInspectResult{}, errors.New("missing fake network")
	}
	return result, nil
}

func (reader *fakeDockerReader) Events(
	context.Context,
	client.EventsListOptions,
) (DockerEventStream, error) {
	if reader.eventsErr != nil {
		return DockerEventStream{}, reader.eventsErr
	}
	if reader.eventsResult != nil {
		return *reader.eventsResult, nil
	}
	messages := make(chan events.Message)
	errs := make(chan error)
	close(messages)
	close(errs)
	return DockerEventStream{Messages: messages, Err: errs}, nil
}

type fakeProcessIdentityReader struct {
	byPID map[int]processIdentity
}

type mutableProcessIdentityReader struct {
	byPID       map[int]processIdentity
	readErrByID map[string]error
	readCalls   []string
	inodeCalls  []int
}

func validProcessIdentity() processIdentity {
	return processIdentity{
		PIDStartTicks:         12345,
		CgroupPathSHA256:      strings.Repeat("f", 64),
		NetworkNamespaceInode: 67890,
		EffectiveCapNetAdmin:  false,
	}
}

func inventoryTempDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func (reader fakeProcessIdentityReader) ReadProcessIdentity(
	_ string,
	pid int,
) (processIdentity, error) {
	identity, ok := reader.byPID[pid]
	if !ok {
		return processIdentity{}, errors.New("missing fake process identity")
	}
	return identity, nil
}

func (reader fakeProcessIdentityReader) NetworkNamespaceInode(
	pid int,
) (uint64, error) {
	identity, ok := reader.byPID[pid]
	if !ok {
		return 0, errors.New("missing fake process identity")
	}
	return identity.NetworkNamespaceInode, nil
}

func (reader *mutableProcessIdentityReader) ReadProcessIdentity(
	fullID string,
	pid int,
) (processIdentity, error) {
	reader.readCalls = append(reader.readCalls, fullID)
	if err := reader.readErrByID[fullID]; err != nil {
		return processIdentity{}, err
	}
	identity, ok := reader.byPID[pid]
	if !ok {
		return processIdentity{}, errors.New("missing mutable process identity")
	}
	return identity, nil
}

func (reader *mutableProcessIdentityReader) NetworkNamespaceInode(
	pid int,
) (uint64, error) {
	reader.inodeCalls = append(reader.inodeCalls, pid)
	identity, ok := reader.byPID[pid]
	if !ok {
		return 0, errors.New("missing mutable process identity")
	}
	return identity.NetworkNamespaceInode, nil
}

const (
	inventoryTestIDOne = "aaaaaaaaaaaa1111111111111111111111111111111111111111111111111111"
	inventoryTestIDTwo = "aaaaaaaaaaaa2222222222222222222222222222222222222222222222222222"
	inventoryImageID   = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	inventoryNetworkID = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func inventoryInspect(fullID string, running bool) client.ContainerInspectResult {
	return client.ContainerInspectResult{
		Container: container.InspectResponse{
			ID:    fullID,
			Image: inventoryImageID,
			State: &container.State{
				Status:    container.StateRunning,
				Running:   running,
				Pid:       4242,
				StartedAt: "2026-07-27T12:00:00Z",
			},
			Config: &container.Config{
				Entrypoint: []string{"/usr/bin/example"},
				Cmd:        []string{"serve", "--foreground"},
				Env:        []string{"PASSWORD=SECRET_ENV_CANARY"},
				Labels:     map[string]string{"secret": "SECRET_LABEL_CANARY"},
			},
			HostConfig: &container.HostConfig{
				NetworkMode:    "bridge",
				Privileged:     false,
				CapAdd:         []string{"CHOWN", "SETUID"},
				CapDrop:        []string{"NET_RAW"},
				ReadonlyRootfs: true,
				LogConfig: container.LogConfig{
					Type: "json-file",
				},
			},
			Mounts: []container.MountPoint{{
				Type:        mount.TypeBind,
				Source:      "/secret/host/path",
				Destination: "/var/lib/example",
				RW:          false,
			}},
			NetworkSettings: &container.NetworkSettings{
				Networks: map[string]*network.EndpointSettings{
					"default": {
						NetworkID: inventoryNetworkID,
						Gateway:   netip.MustParseAddr("172.18.0.1"),
						IPAddress: netip.MustParseAddr("172.18.0.2"),
					},
				},
			},
		},
	}
}

func inventoryDocker(
	inspectByID map[string]client.ContainerInspectResult,
) *fakeDockerReader {
	items := make([]container.Summary, 0, len(inspectByID))
	for fullID, inspect := range inspectByID {
		state := container.StateExited
		if inspect.Container.State != nil && inspect.Container.State.Running {
			state = container.StateRunning
		}
		items = append(items, container.Summary{ID: fullID, State: state})
	}
	sort.Slice(items, func(left, right int) bool {
		return items[left].ID < items[right].ID
	})
	return &fakeDockerReader{
		listResult:  client.ContainerListResult{Items: items},
		inspectByID: inspectByID,
		inspectErr:  make(map[string]error),
		imageByID: map[string]client.ImageInspectResult{
			inventoryImageID: {
				InspectResponse: image.InspectResponse{
					ID: inventoryImageID,
					RepoDigests: []string{
						"example.invalid/app@sha256:" +
							strings.Repeat("e", 64),
						"example.invalid/app@sha256:" +
							strings.Repeat("d", 64),
					},
				},
			},
		},
		networkByID: map[string]client.NetworkInspectResult{
			inventoryNetworkID: {
				Network: network.Inspect{Network: network.Network{
					ID:     inventoryNetworkID,
					Driver: "bridge",
					IPAM: network.IPAM{Config: []network.IPAMConfig{{
						Subnet:  netip.MustParsePrefix("172.18.0.0/16"),
						Gateway: netip.MustParseAddr("172.18.0.1"),
					}}},
				}},
			},
		},
	}
}

func resolvedInventoryFixture(
	t *testing.T,
	mutate func(*fakeDockerReader),
) ContainerIdentityV1 {
	t.Helper()
	docker := inventoryDocker(map[string]client.ContainerInspectResult{
		inventoryTestIDOne: inventoryInspect(inventoryTestIDOne, true),
	})
	if mutate != nil {
		mutate(docker)
	}
	inventory, err := openInventory(
		inventoryTempDir(t),
		docker,
		fakeProcessIdentityReader{byPID: map[int]processIdentity{
			4242: validProcessIdentity(),
		}},
		func() time.Time {
			return time.Date(2026, 7, 27, 12, 0, 5, 0, time.UTC)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	identity, err := inventory.ResolvePrefix(inventoryTestIDOne[:12])
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func TestPublicDockerReaderHasExactReadOnlyAllowlist(t *testing.T) {
	interfaceType := reflect.TypeOf((*DockerReader)(nil)).Elem()
	got := make([]string, 0, interfaceType.NumMethod())
	for index := 0; index < interfaceType.NumMethod(); index++ {
		got = append(got, interfaceType.Method(index).Name)
	}
	want := []string{
		"ContainerInspect",
		"ContainerList",
		"Events",
		"ImageInspect",
		"NetworkInspect",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DockerReader methods=%v want=%v", got, want)
	}
}

func TestResolvePrefixRequiresExactlyOneRunningContainer(t *testing.T) {
	docker := inventoryDocker(map[string]client.ContainerInspectResult{
		inventoryTestIDOne: inventoryInspect(inventoryTestIDOne, true),
		inventoryTestIDTwo: inventoryInspect(inventoryTestIDTwo, true),
	})
	inventory, err := openInventory(
		inventoryTempDir(t),
		docker,
		fakeProcessIdentityReader{byPID: map[int]processIdentity{
			4242: validProcessIdentity(),
		}},
		time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := inventory.ResolvePrefix("aaaaaaaaaaaa"); !errors.Is(
		err,
		ErrAmbiguousContainerPrefix,
	) {
		t.Fatalf("ambiguous prefix err=%v", err)
	}
}

func TestResolvePrefixExcludesStoppedContainers(t *testing.T) {
	stopped := inventoryInspect(inventoryTestIDOne, false)
	docker := inventoryDocker(map[string]client.ContainerInspectResult{
		inventoryTestIDOne: stopped,
	})
	inventory, err := openInventory(
		inventoryTempDir(t),
		docker,
		fakeProcessIdentityReader{},
		time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(docker.inspectIDs) != 0 {
		t.Fatalf("stopped containers inspected: %v", docker.inspectIDs)
	}
	if _, err := inventory.ResolvePrefix(inventoryTestIDOne[:12]); !errors.Is(
		err,
		ErrContainerNotFound,
	) {
		t.Fatalf("stopped prefix err=%v", err)
	}
}

func TestPublicIdentityContainsExactAllowlistedFieldsAndNoCanaries(t *testing.T) {
	identity := resolvedInventoryFixture(t, nil)
	identityType := reflect.TypeOf(identity)
	gotFields := make([]string, 0, identityType.NumField())
	for index := 0; index < identityType.NumField(); index++ {
		gotFields = append(
			gotFields,
			identityType.Field(index).Tag.Get("json"),
		)
	}
	wantFields := []string{
		"full_container_id",
		"docker_started_at",
		"image_id",
		"repo_digests",
		"immutable_spec_sha256",
		"init_pid",
		"network_mode",
		"network_driver",
		"privileged",
		"configured_cap_add",
		"configured_cap_drop",
		"effective_cap_net_admin",
		"running",
		"inventory_generation",
		"inventory_revision",
		"observed_at",
		"attached_networks",
	}
	if !reflect.DeepEqual(gotFields, wantFields) {
		t.Fatalf("identity fields=%v want=%v", gotFields, wantFields)
	}
	raw, err := contracts.CanonicalJSON(identity)
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range [][]byte{
		[]byte("SECRET_ENV_CANARY"),
		[]byte("SECRET_LABEL_CANARY"),
		[]byte("/secret/host/path"),
		[]byte("/usr/bin/example"),
		[]byte("--foreground"),
	} {
		if bytes.Contains(raw, canary) {
			t.Fatalf("public identity leaked %q: %s", canary, raw)
		}
	}
}

func TestCommittedDockerInspectFixtureIsExactRedactedPublicIdentity(
	t *testing.T,
) {
	raw, err := os.ReadFile(
		"../../contracts/fixtures/v1/docker-inspect.redacted.json",
	)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var identity ContainerIdentityV1
	if err := decoder.Decode(&identity); err != nil {
		t.Fatal(err)
	}
	if err := identity.Validate(); err != nil {
		t.Fatal(err)
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		t.Fatalf("trailing fixture data token=%v err=%v", token, err)
	}
	for _, forbidden := range []string{
		"Env",
		"Labels",
		"SECRET_",
		"/var/run/docker.sock",
		"/secret/host/path",
		"Entrypoint",
		"Cmd",
	} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("redacted Docker fixture leaked %q", forbidden)
		}
	}
}

func TestPublicIdentityRequiresImageIDAndSortsOptionalRepoDigests(t *testing.T) {
	identity := resolvedInventoryFixture(t, nil)
	if identity.ImageID != inventoryImageID ||
		!sort.StringsAreSorted(identity.RepoDigests) ||
		len(identity.RepoDigests) != 2 {
		t.Fatalf("image identity=%+v", identity)
	}

	docker := inventoryDocker(map[string]client.ContainerInspectResult{
		inventoryTestIDOne: inventoryInspect(inventoryTestIDOne, true),
	})
	docker.imageByID[inventoryImageID] = client.ImageInspectResult{
		InspectResponse: image.InspectResponse{},
	}
	inventory, err := openInventory(
		inventoryTempDir(t),
		docker,
		fakeProcessIdentityReader{byPID: map[int]processIdentity{
			4242: validProcessIdentity(),
		}},
		time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.Reconcile(context.Background()); !errors.Is(
		err,
		ErrMissingImageIdentity,
	) {
		t.Fatalf("missing image ID err=%v", err)
	}
}

func TestImmutableSpecHashIgnoresEnvLabelsAndHostSource(t *testing.T) {
	control := resolvedInventoryFixture(t, nil)
	changedSecrets := resolvedInventoryFixture(
		t,
		func(docker *fakeDockerReader) {
			inspect := docker.inspectByID[inventoryTestIDOne]
			inspect.Container.Config.Env = []string{"TOKEN=DIFFERENT_SECRET"}
			inspect.Container.Config.Labels = map[string]string{
				"different": "DIFFERENT_LABEL",
			}
			inspect.Container.Mounts[0].Source = "/another/private/host/path"
			docker.inspectByID[inventoryTestIDOne] = inspect
		},
	)
	if changedSecrets.ImmutableSpecSHA256 != control.ImmutableSpecSHA256 {
		t.Fatalf(
			"secret-only changes altered immutable hash %s != %s",
			changedSecrets.ImmutableSpecSHA256,
			control.ImmutableSpecSHA256,
		)
	}
}

func TestImmutableSpecHashChangesForAuthorityBearingFields(t *testing.T) {
	control := resolvedInventoryFixture(t, nil)
	for _, testCase := range []struct {
		name   string
		mutate func(*container.InspectResponse)
	}{
		{
			name: "entrypoint",
			mutate: func(inspect *container.InspectResponse) {
				inspect.Config.Entrypoint = []string{"/usr/bin/changed"}
			},
		},
		{
			name: "command",
			mutate: func(inspect *container.InspectResponse) {
				inspect.Config.Cmd = []string{"changed"}
			},
		},
		{
			name: "network mode",
			mutate: func(inspect *container.InspectResponse) {
				inspect.HostConfig.NetworkMode = "none"
			},
		},
		{
			name: "capability",
			mutate: func(inspect *container.InspectResponse) {
				inspect.HostConfig.CapAdd = append(
					inspect.HostConfig.CapAdd,
					"SYS_ADMIN",
				)
			},
		},
		{
			name: "mount target",
			mutate: func(inspect *container.InspectResponse) {
				inspect.Mounts[0].Destination = "/changed"
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			changed := resolvedInventoryFixture(
				t,
				func(docker *fakeDockerReader) {
					inspect := docker.inspectByID[inventoryTestIDOne]
					testCase.mutate(&inspect.Container)
					docker.inspectByID[inventoryTestIDOne] = inspect
				},
			)
			if changed.ImmutableSpecSHA256 == control.ImmutableSpecSHA256 {
				t.Fatalf(
					"%s change retained immutable hash %s",
					testCase.name,
					control.ImmutableSpecSHA256,
				)
			}
		})
	}
}

func TestInventoryPersistsGenerationRevisionAndRedactedSnapshot(
	t *testing.T,
) {
	root := inventoryTempDir(t)
	docker := inventoryDocker(map[string]client.ContainerInspectResult{
		inventoryTestIDOne: inventoryInspect(inventoryTestIDOne, true),
	})
	processes := fakeProcessIdentityReader{byPID: map[int]processIdentity{
		4242: validProcessIdentity(),
	}}
	now := func() time.Time {
		return time.Date(2026, 7, 27, 12, 0, 5, 0, time.UTC)
	}
	inventory, err := openInventory(root, docker, processes, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := inventory.LookupFullID(inventoryTestIDOne)
	if err != nil {
		t.Fatal(err)
	}
	if first.InventoryGeneration != 1 || first.InventoryRevision != 1 {
		t.Fatalf("first identity=%+v", first)
	}
	if err := inventory.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	unchanged, err := inventory.LookupFullID(inventoryTestIDOne)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.InventoryGeneration != 2 ||
		unchanged.InventoryRevision != 1 {
		t.Fatalf("unchanged identity=%+v", unchanged)
	}

	inspect := docker.inspectByID[inventoryTestIDOne]
	inspect.Container.Config.Labels["changed"] = "label-only"
	docker.inspectByID[inventoryTestIDOne] = inspect
	reopened, err := openInventory(root, docker, processes, now)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := reopened.LookupFullID(inventoryTestIDOne)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.InventoryGeneration != 2 ||
		persisted.InventoryRevision != 1 {
		t.Fatalf("reopened identity=%+v", persisted)
	}
	if err := reopened.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	labelOnly, err := reopened.LookupFullID(inventoryTestIDOne)
	if err != nil {
		t.Fatal(err)
	}
	if labelOnly.InventoryGeneration != 3 ||
		labelOnly.InventoryRevision != 1 {
		t.Fatalf("label-only identity=%+v", labelOnly)
	}

	inspect = docker.inspectByID[inventoryTestIDOne]
	inspect.Container.HostConfig.CapAdd = append(
		inspect.Container.HostConfig.CapAdd,
		"SYS_ADMIN",
	)
	docker.inspectByID[inventoryTestIDOne] = inspect
	if err := reopened.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	changed, err := reopened.LookupFullID(inventoryTestIDOne)
	if err != nil {
		t.Fatal(err)
	}
	if changed.InventoryGeneration != 4 ||
		changed.InventoryRevision != 2 {
		t.Fatalf("authority change identity=%+v", changed)
	}

	raw, err := os.ReadFile(filepath.Join(root, "docker-inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range [][]byte{
		[]byte("SECRET_ENV_CANARY"),
		[]byte("SECRET_LABEL_CANARY"),
		[]byte("/secret/host/path"),
		[]byte("/usr/bin/example"),
		[]byte("--foreground"),
	} {
		if bytes.Contains(raw, canary) {
			t.Fatalf("persisted inventory leaked %q", canary)
		}
	}
}

func TestInventoryRevisionLedgerSurvivesStoppedReconcileAndReopen(
	t *testing.T,
) {
	root := inventoryTempDir(t)
	docker := inventoryDocker(map[string]client.ContainerInspectResult{
		inventoryTestIDOne: inventoryInspect(inventoryTestIDOne, true),
	})
	processes := fakeProcessIdentityReader{byPID: map[int]processIdentity{
		4242: validProcessIdentity(),
	}}
	inventory, err := openInventory(root, docker, processes, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := inventory.LookupFullID(inventoryTestIDOne)
	if err != nil {
		t.Fatal(err)
	}
	if first.InventoryRevision != 1 {
		t.Fatalf("first revision=%d want=1", first.InventoryRevision)
	}

	docker.listResult.Items[0].State = container.StateExited
	if err := inventory.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	stoppedState, err := loadInventoryState(inventory.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(stoppedState.RevisionLedger) != 1 ||
		stoppedState.RevisionLedger[0].FullContainerID != inventoryTestIDOne ||
		stoppedState.RevisionLedger[0].InventoryRevision != 1 {
		t.Fatalf("stopped revision ledger=%+v", stoppedState.RevisionLedger)
	}

	reopened, err := openInventory(root, docker, processes, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	docker.listResult.Items[0].State = container.StateRunning
	if err := reopened.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	same, err := reopened.LookupFullID(inventoryTestIDOne)
	if err != nil {
		t.Fatal(err)
	}
	if same.InventoryRevision != 1 {
		t.Fatalf("same selected identity revision=%d want=1", same.InventoryRevision)
	}

	docker.listResult.Items[0].State = container.StateExited
	if err := reopened.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	reopened, err = openInventory(root, docker, processes, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	inspect := docker.inspectByID[inventoryTestIDOne]
	inspect.Container.HostConfig.CapAdd = append(
		inspect.Container.HostConfig.CapAdd,
		"SYS_ADMIN",
	)
	docker.inspectByID[inventoryTestIDOne] = inspect
	docker.listResult.Items[0].State = container.StateRunning
	if err := reopened.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	changed, err := reopened.LookupFullID(inventoryTestIDOne)
	if err != nil {
		t.Fatal(err)
	}
	if changed.InventoryRevision != 2 {
		t.Fatalf(
			"changed selected identity revision=%d want=2",
			changed.InventoryRevision,
		)
	}
}

func TestInventoryRevisionLedgerCapacityFailsClosedWithoutPruning(
	t *testing.T,
) {
	root := inventoryTempDir(t)
	ledger := make(
		[]inventoryRevisionLedgerEntry,
		inventoryRevisionLedgerMaxEntries,
	)
	for index := range ledger {
		ledger[index] = inventoryRevisionLedgerEntry{
			FullContainerID:   fmt.Sprintf("%064x", index+1),
			InventoryRevision: 1,
			RevisionSHA256:    strings.Repeat("d", 64),
		}
	}
	path := filepath.Join(root, "docker-inventory.json")
	if err := persistInventoryState(path, inventoryDiskState{
		SchemaVersion:      inventorySchema,
		Generation:         1,
		DockerReconcileGap: false,
		Records:            []inventoryRecord{},
		RevisionLedger:     ledger,
	}); err != nil {
		t.Fatal(err)
	}
	docker := inventoryDocker(map[string]client.ContainerInspectResult{
		inventoryTestIDOne: inventoryInspect(inventoryTestIDOne, true),
	})
	inventory, err := openInventory(
		root,
		docker,
		fakeProcessIdentityReader{byPID: map[int]processIdentity{
			4242: validProcessIdentity(),
		}},
		time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.Reconcile(context.Background()); !errors.Is(
		err,
		ErrInventoryRevisionLedgerExhausted,
	) {
		t.Fatalf("ledger capacity err=%v", err)
	}
	persisted, err := loadInventoryState(path)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.DockerReconcileGap ||
		len(persisted.RevisionLedger) != inventoryRevisionLedgerMaxEntries {
		t.Fatalf(
			"capacity failure state gap=%v ledger=%d",
			persisted.DockerReconcileGap,
			len(persisted.RevisionLedger),
		)
	}
}

func TestInventoryRevisionExhaustionFailsClosed(t *testing.T) {
	root := inventoryTempDir(t)
	docker := inventoryDocker(map[string]client.ContainerInspectResult{
		inventoryTestIDOne: inventoryInspect(inventoryTestIDOne, true),
	})
	processes := fakeProcessIdentityReader{byPID: map[int]processIdentity{
		4242: validProcessIdentity(),
	}}
	inventory, err := openInventory(root, docker, processes, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, err := loadInventoryState(inventory.path)
	if err != nil {
		t.Fatal(err)
	}
	state.Records[0].Identity.InventoryRevision = math.MaxUint64
	state.RevisionLedger[0].InventoryRevision = math.MaxUint64
	if err := persistInventoryState(inventory.path, state); err != nil {
		t.Fatal(err)
	}
	inventory, err = openInventory(root, docker, processes, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	inspect := docker.inspectByID[inventoryTestIDOne]
	inspect.Container.HostConfig.CapAdd = append(
		inspect.Container.HostConfig.CapAdd,
		"SYS_ADMIN",
	)
	docker.inspectByID[inventoryTestIDOne] = inspect
	if err := inventory.Reconcile(context.Background()); !errors.Is(
		err,
		ErrInventoryRevisionLedgerExhausted,
	) {
		t.Fatalf("revision exhaustion err=%v", err)
	}
	if !inventory.ReconcileGapOpen() {
		t.Fatal("revision exhaustion did not retain live gap")
	}
}

func TestNetNSUniquenessRequiresFullProcessIdentityForEveryContainer(
	t *testing.T,
) {
	secondInspect := inventoryInspect(inventoryTestIDTwo, true)
	secondInspect.Container.State.Pid = 4343
	docker := inventoryDocker(map[string]client.ContainerInspectResult{
		inventoryTestIDOne: inventoryInspect(inventoryTestIDOne, true),
		inventoryTestIDTwo: secondInspect,
	})
	secondIdentity := validProcessIdentity()
	secondIdentity.PIDStartTicks++
	secondIdentity.NetworkNamespaceInode++
	processes := &mutableProcessIdentityReader{
		byPID: map[int]processIdentity{
			4242: validProcessIdentity(),
			4343: secondIdentity,
		},
		readErrByID: make(map[string]error),
	}
	inventory, err := openInventory(
		inventoryTempDir(t),
		docker,
		processes,
		time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	processes.readCalls = nil
	processes.inodeCalls = nil
	processes.readErrByID[inventoryTestIDTwo] = errors.New(
		"injected exact cgroup/full-ID mismatch",
	)

	_, err = inventory.CheckNetNSUniqueness(
		context.Background(),
		inventoryTestIDOne,
		validProcessIdentity().NetworkNamespaceInode,
	)
	if !errors.Is(err, ErrInventoryStale) {
		t.Fatalf("full process identity mismatch err=%v", err)
	}
	if len(processes.inodeCalls) != 0 {
		t.Fatalf(
			"uniqueness used inode-only reads for PIDs %v",
			processes.inodeCalls,
		)
	}
	if !reflect.DeepEqual(
		processes.readCalls,
		[]string{inventoryTestIDOne, inventoryTestIDTwo},
	) {
		t.Fatalf("full process identity calls=%v", processes.readCalls)
	}
}

func TestNetNSUniquenessRejectsTargetPIDIdentityReuse(t *testing.T) {
	docker := inventoryDocker(map[string]client.ContainerInspectResult{
		inventoryTestIDOne: inventoryInspect(inventoryTestIDOne, true),
	})
	processes := &mutableProcessIdentityReader{
		byPID: map[int]processIdentity{
			4242: validProcessIdentity(),
		},
		readErrByID: make(map[string]error),
	}
	inventory, err := openInventory(
		inventoryTempDir(t),
		docker,
		processes,
		time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	reused := processes.byPID[4242]
	reused.PIDStartTicks++
	processes.byPID[4242] = reused
	if _, err := inventory.CheckNetNSUniqueness(
		context.Background(),
		inventoryTestIDOne,
		reused.NetworkNamespaceInode,
	); !errors.Is(err, ErrInventoryStale) {
		t.Fatalf("PID identity reuse err=%v", err)
	}
}

func TestInventoryFailurePersistsGapAndAtomicallyRetainsPriorSnapshot(
	t *testing.T,
) {
	root := inventoryTempDir(t)
	docker := inventoryDocker(map[string]client.ContainerInspectResult{
		inventoryTestIDOne: inventoryInspect(inventoryTestIDOne, true),
	})
	processes := fakeProcessIdentityReader{byPID: map[int]processIdentity{
		4242: validProcessIdentity(),
	}}
	inventory, err := openInventory(root, docker, processes, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(root, "docker-inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected Docker list disconnect")
	docker.listErr = injected
	if err := inventory.Reconcile(context.Background()); !errors.Is(
		err,
		injected,
	) {
		t.Fatalf("reconcile failure err=%v", err)
	}
	if _, err := inventory.LookupFullID(inventoryTestIDOne); !errors.Is(
		err,
		ErrInventoryReconcileRequired,
	) {
		t.Fatalf("gap did not fence lookup: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(root, "docker-inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("reconcile failure did not durably open the gap")
	}

	reopened, err := openInventory(root, docker, processes, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.ResolvePrefix(
		inventoryTestIDOne[:12],
	); !errors.Is(err, ErrInventoryReconcileRequired) {
		t.Fatalf("restart lost reconcile gap: %v", err)
	}
	docker.listErr = nil
	if err := reopened.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	recovered, err := reopened.LookupFullID(inventoryTestIDOne)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.InventoryGeneration != 2 ||
		recovered.InventoryRevision != 1 {
		t.Fatalf("recovered identity=%+v", recovered)
	}
}
