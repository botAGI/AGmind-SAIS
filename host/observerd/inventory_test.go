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
	listResult         client.ContainerListResult
	listErr            error
	inspectByID        map[string]client.ContainerInspectResult
	inspectErr         map[string]error
	imageByID          map[string]client.ImageInspectResult
	networkListResult  client.NetworkListResult
	networkListErr     error
	networkByID        map[string]client.NetworkInspectResult
	listOptions        []client.ContainerListOptions
	inspectIDs         []string
	networkListOptions []client.NetworkListOptions
	networkInspectIDs  []string
	eventsResult       *DockerEventStream
	eventsErr          error
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
	reader.networkInspectIDs = append(reader.networkInspectIDs, networkID)
	result, ok := reader.networkByID[networkID]
	if !ok {
		return client.NetworkInspectResult{}, errors.New("missing fake network")
	}
	return result, nil
}

func (reader *fakeDockerReader) NetworkList(
	_ context.Context,
	options client.NetworkListOptions,
) (client.NetworkListResult, error) {
	reader.networkListOptions = append(reader.networkListOptions, options)
	if reader.networkListErr != nil {
		return client.NetworkListResult{}, reader.networkListErr
	}
	return reader.networkListResult, nil
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
		networkListResult: client.NetworkListResult{
			Items: []network.Summary{{
				Network: network.Network{ID: inventoryNetworkID},
			}},
		},
	}
}

func inventoryNetworkInspect(
	networkID,
	driver string,
	config ...network.IPAMConfig,
) client.NetworkInspectResult {
	return client.NetworkInspectResult{
		Network: network.Inspect{Network: network.Network{
			ID:     networkID,
			Driver: driver,
			IPAM:   network.IPAM{Config: config},
		}},
	}
}

func replaceGlobalNetworkFixture(
	docker *fakeDockerReader,
	networks []client.NetworkInspectResult,
) {
	docker.networkListResult.Items = make(
		[]network.Summary,
		0,
		len(networks),
	)
	for _, inspected := range networks {
		networkID := inspected.Network.ID
		docker.networkListResult.Items = append(
			docker.networkListResult.Items,
			network.Summary{Network: network.Network{ID: networkID}},
		)
		docker.networkByID[networkID] = inspected
	}
}

func exactSizeDockerNetworksFixture(
	t *testing.T,
	target int,
) []client.NetworkInspectResult {
	t.Helper()
	for subnetCount := 0; subnetCount <= 128; subnetCount++ {
		for gatewayCount := 0; gatewayCount <= 128; gatewayCount++ {
			inspects := make([]client.NetworkInspectResult, 64)
			canonical := make([]contracts.PCCDockerNetworkV1, 64)
			for networkIndex := range inspects {
				networkID := fmt.Sprintf("%064x", networkIndex+1)
				config := make([]network.IPAMConfig, 0, 4)
				for item := networkIndex; item < subnetCount; item += 64 {
					config = append(config, network.IPAMConfig{
						Subnet: netip.MustParsePrefix(fmt.Sprintf(
							"2001:db8:%x:%x::/64",
							networkIndex+1,
							item/64+1,
						)),
					})
				}
				for item := networkIndex; item < gatewayCount; item += 64 {
					config = append(config, network.IPAMConfig{
						Gateway: netip.MustParseAddr(fmt.Sprintf(
							"2001:db8:%x:%x::1",
							networkIndex+1,
							item/64+1,
						)),
					})
				}
				inspects[networkIndex] = inventoryNetworkInspect(
					networkID,
					"d",
					config...,
				)
				subnets := make([]string, 0, len(config))
				gateways := make([]string, 0, len(config))
				for _, fact := range config {
					if fact.Subnet.IsValid() {
						subnets = append(subnets, fact.Subnet.String())
					}
					if fact.Gateway.IsValid() {
						gateways = append(gateways, fact.Gateway.String())
					}
				}
				canonical[networkIndex] = contracts.PCCDockerNetworkV1{
					NetworkID:        networkID,
					Driver:           "d",
					SubnetCIDRs:      subnets,
					GatewayAddresses: gateways,
				}
			}
			raw, err := contracts.CanonicalJSON(canonical)
			if err != nil {
				t.Fatal(err)
			}
			padding := target - len(raw)
			if padding < 0 || padding > 64*63 {
				continue
			}
			for index := range inspects {
				extra := min(padding, 63)
				driver := strings.Repeat("d", 1+extra)
				inspects[index].Network.Driver = driver
				canonical[index].Driver = driver
				padding -= extra
			}
			raw, err = contracts.CanonicalJSON(canonical)
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) != target {
				t.Fatalf(
					"exact-size fixture bytes=%d want=%d",
					len(raw),
					target,
				)
			}
			return inspects
		}
	}
	t.Fatalf("could not construct %d-byte Docker network fixture", target)
	return nil
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
		"NetworkList",
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
		DockerNetworks:     []contracts.PCCDockerNetworkV1{},
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

func TestInventoryGlobalNetworksUseUnfilteredListAndExactIDInspect(
	t *testing.T,
) {
	firstID := strings.Repeat("1", 64)
	secondID := strings.Repeat("2", 64)
	inspect := inventoryInspect(inventoryTestIDOne, true)
	inspect.Container.NetworkSettings.Networks = map[string]*network.EndpointSettings{}
	docker := inventoryDocker(map[string]client.ContainerInspectResult{
		inventoryTestIDOne: inspect,
	})
	replaceGlobalNetworkFixture(docker, []client.NetworkInspectResult{
		inventoryNetworkInspect(
			secondID,
			"overlay",
			network.IPAMConfig{
				Subnet:  netip.MustParsePrefix("2001:db8:2::/64"),
				Gateway: netip.MustParseAddr("2001:db8:2::1"),
			},
		),
		inventoryNetworkInspect(
			firstID,
			"bridge",
			network.IPAMConfig{
				Subnet:  netip.MustParsePrefix("10.0.0.0/8"),
				Gateway: netip.MustParseAddr("10.0.0.1"),
			},
		),
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
	if !reflect.DeepEqual(
		docker.networkListOptions,
		[]client.NetworkListOptions{{}},
	) {
		t.Fatalf("network list options=%+v", docker.networkListOptions)
	}
	if !reflect.DeepEqual(
		docker.networkInspectIDs,
		[]string{secondID, firstID},
	) {
		t.Fatalf("network inspect IDs=%v", docker.networkInspectIDs)
	}
	snapshot, err := inventory.SnapshotForCorrelation(inventoryTestIDOne)
	if err != nil {
		t.Fatal(err)
	}
	want := []contracts.PCCDockerNetworkV1{
		{
			NetworkID:        firstID,
			Driver:           "bridge",
			SubnetCIDRs:      []string{"10.0.0.0/8"},
			GatewayAddresses: []string{"10.0.0.1"},
		},
		{
			NetworkID:        secondID,
			Driver:           "overlay",
			SubnetCIDRs:      []string{"2001:db8:2::/64"},
			GatewayAddresses: []string{"2001:db8:2::1"},
		},
	}
	if !reflect.DeepEqual(snapshot.DockerNetworks, want) {
		t.Fatalf(
			"global Docker networks=%+v want=%+v",
			snapshot.DockerNetworks,
			want,
		)
	}
}

func TestInventoryGlobalNetworkCanonicalizationAndBounds(t *testing.T) {
	firstID := strings.Repeat("3", 64)
	secondID := strings.Repeat("4", 64)
	inspect := inventoryInspect(inventoryTestIDOne, true)
	inspect.Container.NetworkSettings.Networks = map[string]*network.EndpointSettings{}
	docker := inventoryDocker(map[string]client.ContainerInspectResult{
		inventoryTestIDOne: inspect,
	})
	replaceGlobalNetworkFixture(docker, []client.NetworkInspectResult{
		inventoryNetworkInspect(
			secondID,
			"overlay",
			network.IPAMConfig{
				Subnet:  netip.MustParsePrefix("2001:db8:2::/64"),
				Gateway: netip.MustParseAddr("2001:db8:2::1"),
			},
			network.IPAMConfig{
				Subnet:  netip.MustParsePrefix("10.2.0.0/16"),
				Gateway: netip.MustParseAddr("10.2.0.1"),
			},
			network.IPAMConfig{
				Subnet:  netip.MustParsePrefix("2001:db8:2::/64"),
				Gateway: netip.MustParseAddr("2001:db8:2::1"),
			},
		),
		inventoryNetworkInspect(firstID, "bridge"),
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
	snapshot, err := inventory.SnapshotForCorrelation(inventoryTestIDOne)
	if err != nil {
		t.Fatal(err)
	}
	want := []contracts.PCCDockerNetworkV1{
		{
			NetworkID:        firstID,
			Driver:           "bridge",
			SubnetCIDRs:      []string{},
			GatewayAddresses: []string{},
		},
		{
			NetworkID:   secondID,
			Driver:      "overlay",
			SubnetCIDRs: []string{"10.2.0.0/16", "2001:db8:2::/64"},
			GatewayAddresses: []string{
				"10.2.0.1",
				"2001:db8:2::1",
			},
		},
	}
	if !reflect.DeepEqual(snapshot.DockerNetworks, want) {
		t.Fatalf(
			"canonical Docker networks=%+v want=%+v",
			snapshot.DockerNetworks,
			want,
		)
	}
}

func TestInventoryGlobalNetworkFailureRetainsPriorGeneration(t *testing.T) {
	makeNetworks := func(
		count,
		subnetsPerNetwork,
		gatewaysPerNetwork int,
	) []client.NetworkInspectResult {
		result := make([]client.NetworkInspectResult, count)
		for networkIndex := range result {
			configCount := max(subnetsPerNetwork, gatewaysPerNetwork)
			config := make([]network.IPAMConfig, configCount)
			for item := range config {
				if item < subnetsPerNetwork {
					config[item].Subnet = netip.MustParsePrefix(fmt.Sprintf(
						"10.%d.%d.0/24",
						networkIndex,
						item,
					))
				}
				if item < gatewaysPerNetwork {
					config[item].Gateway = netip.MustParseAddr(fmt.Sprintf(
						"10.%d.%d.1",
						networkIndex,
						item,
					))
				}
			}
			result[networkIndex] = inventoryNetworkInspect(
				fmt.Sprintf("%064x", networkIndex+1),
				"bridge",
				config...,
			)
		}
		return result
	}
	oversize := exactSizeDockerNetworksFixture(t, 16*1024+1)
	injectedList := errors.New("injected Docker network list failure")
	injectedPersist := errors.New("injected Docker inventory persistence failure")
	testCases := []struct {
		name   string
		mutate func(*Inventory, *fakeDockerReader)
	}{
		{
			name: "network list failure",
			mutate: func(_ *Inventory, docker *fakeDockerReader) {
				docker.networkListErr = injectedList
			},
		},
		{
			name: "empty listed ID",
			mutate: func(_ *Inventory, docker *fakeDockerReader) {
				docker.networkListResult.Items = []network.Summary{{
					Network: network.Network{},
				}}
			},
		},
		{
			name: "duplicate listed ID",
			mutate: func(_ *Inventory, docker *fakeDockerReader) {
				docker.networkListResult.Items = []network.Summary{
					{Network: network.Network{ID: inventoryNetworkID}},
					{Network: network.Network{ID: inventoryNetworkID}},
				}
			},
		},
		{
			name: "list inspect ID disagreement",
			mutate: func(_ *Inventory, docker *fakeDockerReader) {
				docker.networkByID[inventoryNetworkID] =
					inventoryNetworkInspect(
						strings.Repeat("9", 64),
						"bridge",
					)
			},
		},
		{
			name: "listed network disappears",
			mutate: func(_ *Inventory, docker *fakeDockerReader) {
				delete(docker.networkByID, inventoryNetworkID)
			},
		},
		{
			name: "malformed unmasked subnet",
			mutate: func(_ *Inventory, docker *fakeDockerReader) {
				replaceGlobalNetworkFixture(
					docker,
					[]client.NetworkInspectResult{
						inventoryNetworkInspect(
							strings.Repeat("5", 64),
							"bridge",
							network.IPAMConfig{
								Subnet: netip.MustParsePrefix(
									"10.0.0.1/24",
								),
							},
						),
					},
				)
			},
		},
		{
			name: "IPv4 mapped IPv6 subnet",
			mutate: func(_ *Inventory, docker *fakeDockerReader) {
				replaceGlobalNetworkFixture(
					docker,
					[]client.NetworkInspectResult{
						inventoryNetworkInspect(
							strings.Repeat("5", 64),
							"bridge",
							network.IPAMConfig{
								Subnet: netip.MustParsePrefix(
									"::ffff:192.0.2.0/120",
								),
							},
						),
					},
				)
			},
		},
		{
			name: "IPv4 mapped IPv6 gateway",
			mutate: func(_ *Inventory, docker *fakeDockerReader) {
				replaceGlobalNetworkFixture(
					docker,
					[]client.NetworkInspectResult{
						inventoryNetworkInspect(
							strings.Repeat("5", 64),
							"bridge",
							network.IPAMConfig{
								Gateway: netip.MustParseAddr(
									"::ffff:192.0.2.1",
								),
							},
						),
					},
				)
			},
		},
		{
			name: "33 subnets in one network",
			mutate: func(_ *Inventory, docker *fakeDockerReader) {
				replaceGlobalNetworkFixture(docker, makeNetworks(1, 33, 0))
			},
		},
		{
			name: "33 gateways in one network",
			mutate: func(_ *Inventory, docker *fakeDockerReader) {
				replaceGlobalNetworkFixture(docker, makeNetworks(1, 0, 33))
			},
		},
		{
			name: "65 networks",
			mutate: func(_ *Inventory, docker *fakeDockerReader) {
				replaceGlobalNetworkFixture(docker, makeNetworks(65, 0, 0))
			},
		},
		{
			name: "129 global subnets",
			mutate: func(_ *Inventory, docker *fakeDockerReader) {
				networks := makeNetworks(5, 26, 0)
				networks[4].Network.IPAM.Config =
					networks[4].Network.IPAM.Config[:25]
				replaceGlobalNetworkFixture(docker, networks)
			},
		},
		{
			name: "129 global gateways",
			mutate: func(_ *Inventory, docker *fakeDockerReader) {
				networks := makeNetworks(5, 0, 26)
				networks[4].Network.IPAM.Config =
					networks[4].Network.IPAM.Config[:25]
				replaceGlobalNetworkFixture(docker, networks)
			},
		},
		{
			name: "16 KiB plus one canonical bytes",
			mutate: func(_ *Inventory, docker *fakeDockerReader) {
				replaceGlobalNetworkFixture(docker, oversize)
			},
		},
		{
			name: "final persistence hook failure",
			mutate: func(inventory *Inventory, _ *fakeDockerReader) {
				call := 0
				inventory.persist = func(
					path string,
					state inventoryDiskState,
				) error {
					call++
					if call == 2 {
						return injectedPersist
					}
					return persistInventoryState(path, state)
				}
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			root := inventoryTempDir(t)
			inspect := inventoryInspect(inventoryTestIDOne, true)
			inspect.Container.NetworkSettings.Networks =
				map[string]*network.EndpointSettings{}
			docker := inventoryDocker(
				map[string]client.ContainerInspectResult{
					inventoryTestIDOne: inspect,
				},
			)
			inventory, err := openInventory(
				root,
				docker,
				fakeProcessIdentityReader{
					byPID: map[int]processIdentity{
						4242: validProcessIdentity(),
					},
				},
				time.Now,
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := inventory.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			prior, err := loadInventoryState(inventory.path)
			if err != nil {
				t.Fatal(err)
			}
			testCase.mutate(inventory, docker)
			if err := inventory.Reconcile(context.Background()); err == nil {
				t.Fatal("invalid global network reconcile succeeded")
			}
			after, err := loadInventoryState(inventory.path)
			if err != nil {
				t.Fatal(err)
			}
			if !after.DockerReconcileGap {
				t.Fatal("global network failure did not persist reconcile gap")
			}
			if after.Generation != prior.Generation ||
				!reflect.DeepEqual(after.Records, prior.Records) ||
				!reflect.DeepEqual(
					after.DockerNetworks,
					prior.DockerNetworks,
				) {
				t.Fatalf(
					"failure split paired generation: prior=%+v after=%+v",
					prior,
					after,
				)
			}
		})
	}
}

func TestCorrelationInventorySnapshotIsOneReadLockedGeneration(
	t *testing.T,
) {
	docker := inventoryDocker(map[string]client.ContainerInspectResult{
		inventoryTestIDOne: inventoryInspect(inventoryTestIDOne, true),
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

	inventory.mutex.Lock()
	started := make(chan struct{})
	type result struct {
		snapshot CorrelationInventorySnapshot
		err      error
	}
	resultChannel := make(chan result, 1)
	go func() {
		close(started)
		snapshot, err := inventory.SnapshotForCorrelation(inventoryTestIDOne)
		resultChannel <- result{snapshot: snapshot, err: err}
	}()
	<-started
	nextGeneration := inventory.state.Generation + 1
	inventory.state.Generation = nextGeneration
	inventory.state.DockerNetworks[0].Driver = "paired-next-generation"
	record := inventory.records[inventoryTestIDOne]
	record.Identity.InventoryGeneration = nextGeneration
	inventory.records[inventoryTestIDOne] = record
	inventory.mutex.Unlock()

	got := <-resultChannel
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.snapshot.Generation != nextGeneration ||
		got.snapshot.Identity.InventoryGeneration != nextGeneration ||
		got.snapshot.DockerNetworks[0].Driver !=
			"paired-next-generation" {
		t.Fatalf("snapshot crossed inventory generations: %+v", got.snapshot)
	}
	got.snapshot.Identity.RepoDigests[0] = "mutated"
	got.snapshot.Identity.AttachedNetworks[0].SubnetCIDRs[0] = "mutated"
	got.snapshot.DockerNetworks[0].SubnetCIDRs[0] = "mutated"
	cloned, err := inventory.SnapshotForCorrelation(inventoryTestIDOne)
	if err != nil {
		t.Fatal(err)
	}
	if cloned.Identity.RepoDigests[0] == "mutated" ||
		cloned.Identity.AttachedNetworks[0].SubnetCIDRs[0] == "mutated" ||
		cloned.DockerNetworks[0].SubnetCIDRs[0] == "mutated" {
		t.Fatal("correlation inventory snapshot was not deeply cloned")
	}
	if _, err := inventory.SnapshotForCorrelation(
		"not-a-full-ID",
	); !errors.Is(err, ErrContainerNotFound) {
		t.Fatalf("invalid full ID snapshot err=%v", err)
	}
	inventory.mutex.Lock()
	record = inventory.records[inventoryTestIDOne]
	record.Identity.InventoryGeneration--
	inventory.records[inventoryTestIDOne] = record
	inventory.mutex.Unlock()
	if _, err := inventory.SnapshotForCorrelation(
		inventoryTestIDOne,
	); !errors.Is(err, ErrInventoryStale) {
		t.Fatalf("split generation snapshot err=%v", err)
	}
	inventory.mutex.Lock()
	record.Identity.InventoryGeneration++
	inventory.records[inventoryTestIDOne] = record
	inventory.mutex.Unlock()

	inventory.mutex.Lock()
	inventory.state.DockerReconcileGap = true
	inventory.mutex.Unlock()
	if _, err := inventory.SnapshotForCorrelation(
		inventoryTestIDOne,
	); !errors.Is(err, ErrInventoryReconcileRequired) {
		t.Fatalf("gap snapshot err=%v", err)
	}
}

func TestInventoryGlobalNetworksPersistAcrossRestart(t *testing.T) {
	root := inventoryTempDir(t)
	docker := inventoryDocker(map[string]client.ContainerInspectResult{
		inventoryTestIDOne: inventoryInspect(inventoryTestIDOne, true),
	})
	processes := fakeProcessIdentityReader{
		byPID: map[int]processIdentity{4242: validProcessIdentity()},
	}
	inventory, err := openInventory(root, docker, processes, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := inventory.SnapshotForCorrelation(inventoryTestIDOne)
	if err != nil {
		t.Fatal(err)
	}
	docker.networkListErr = errors.New(
		"restart must not perform a live Docker network walk",
	)
	docker.networkListOptions = nil
	docker.networkInspectIDs = nil
	reopened, err := openInventory(root, docker, processes, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	after, err := reopened.SnapshotForCorrelation(inventoryTestIDOne)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("restarted snapshot=%+v want=%+v", after, before)
	}
	if len(docker.networkListOptions) != 0 ||
		len(docker.networkInspectIDs) != 0 {
		t.Fatal("restart performed a live Docker network walk")
	}
}
