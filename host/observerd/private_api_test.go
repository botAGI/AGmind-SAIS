package observerd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/uds"
	"github.com/moby/moby/client"
)

func requestStatus(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
) int {
	t.Helper()
	request := httptest.NewRequest(method, "http://unix"+path, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response.Code
}

func TestPrivateEndpointIsAbsentFromBothPublicSockets(t *testing.T) {
	privatePath := "/v1/private/container/" + inventoryTestIDOne
	for name, handler := range map[string]http.Handler{
		"ingest": newIngestAPI(nil, 2001),
		"core":   newCoreAPI(nil, 2002, 1002),
	} {
		t.Run(name, func(t *testing.T) {
			if status := requestStatus(
				t,
				handler,
				http.MethodGet,
				privatePath,
			); status != http.StatusNotFound {
				t.Fatalf("private route status=%d", status)
			}
		})
	}
}

func TestPrivateAPIExposesOnlyExactRouteAllowlist(t *testing.T) {
	handler := newPrivateAPI(nil)
	for _, request := range []struct {
		method string
		path   string
	}{
		{
			method: http.MethodGet,
			path:   "/v1/private/container/" + inventoryTestIDOne,
		},
		{
			method: http.MethodPost,
			path:   "/v1/private/netns-uniqueness",
		},
		{
			method: http.MethodGet,
			path:   "/v1/private/integrity",
		},
	} {
		if status := requestStatus(
			t,
			handler,
			request.method,
			request.path,
		); status != http.StatusForbidden {
			t.Fatalf(
				"%s %s status=%d want=%d",
				request.method,
				request.path,
				status,
				http.StatusForbidden,
			)
		}
	}
	for _, path := range []string{
		"/v1/events",
		"/v1/events/falco",
		"/v1/private/container/" + strings.Repeat("a", 63),
		"/v1/private/container/" + inventoryTestIDOne + "/extra",
		"/v1/private/unknown",
	} {
		if status := requestStatus(
			t,
			handler,
			http.MethodGet,
			path,
		); status != http.StatusNotFound {
			t.Fatalf("unexpected route %s status=%d", path, status)
		}
	}
}

func TestPrivateAPIAuthorizesOnlyRootPeer(t *testing.T) {
	if !privatePeerAuthorized(uds.Peer{UID: 0, GID: 1234}) {
		t.Fatal("root peer was rejected")
	}
	for _, peer := range []uds.Peer{
		{UID: 1000, GID: 0},
		{UID: 1000, GID: 2002},
	} {
		if privatePeerAuthorized(peer) {
			t.Fatalf("non-root peer was authorized: %+v", peer)
		}
	}
}

func TestPrivateNetNSUniquenessRejectsAnotherContainerWithSameInode(
	t *testing.T,
) {
	second := inventoryInspect(inventoryTestIDTwo, true)
	second.Container.State.Pid = 4243
	docker := inventoryDocker(map[string]client.ContainerInspectResult{
		inventoryTestIDOne: inventoryInspect(inventoryTestIDOne, true),
		inventoryTestIDTwo: second,
	})
	firstIdentity := validProcessIdentity()
	secondIdentity := validProcessIdentity()
	secondIdentity.PIDStartTicks++
	processes := fakeProcessIdentityReader{byPID: map[int]processIdentity{
		4242: firstIdentity,
		4243: secondIdentity,
	}}
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
	if _, err := inventory.CheckNetNSUniqueness(
		context.Background(),
		inventoryTestIDOne,
		firstIdentity.NetworkNamespaceInode,
	); !errors.Is(err, ErrSharedNetworkNamespace) {
		t.Fatalf("shared namespace err=%v", err)
	}

	secondIdentity.NetworkNamespaceInode++
	processes.byPID[4243] = secondIdentity
	result, err := inventory.CheckNetNSUniqueness(
		context.Background(),
		inventoryTestIDOne,
		firstIdentity.NetworkNamespaceInode,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Unique ||
		result.FullContainerID != inventoryTestIDOne ||
		result.NetworkNamespaceInode !=
			firstIdentity.NetworkNamespaceInode ||
		result.InventoryGeneration != 1 {
		t.Fatalf("uniqueness result=%+v", result)
	}
}

func TestPrivateNetNSUniquenessFailsClosedOnGapOrMissingProcIdentity(
	t *testing.T,
) {
	second := inventoryInspect(inventoryTestIDTwo, true)
	second.Container.State.Pid = 4243
	docker := inventoryDocker(map[string]client.ContainerInspectResult{
		inventoryTestIDOne: inventoryInspect(inventoryTestIDOne, true),
		inventoryTestIDTwo: second,
	})
	processes := fakeProcessIdentityReader{byPID: map[int]processIdentity{
		4242: validProcessIdentity(),
		4243: validProcessIdentity(),
	}}
	processes.byPID[4243] = processIdentity{
		PIDStartTicks:         23456,
		CgroupPathSHA256:      strings.Repeat("e", 64),
		NetworkNamespaceInode: 98765,
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
	delete(processes.byPID, 4243)
	if _, err := inventory.CheckNetNSUniqueness(
		context.Background(),
		inventoryTestIDOne,
		validProcessIdentity().NetworkNamespaceInode,
	); !errors.Is(err, ErrInventoryStale) {
		t.Fatalf("missing proc identity err=%v", err)
	}
	if err := inventory.openReconcileGap(); err != nil {
		t.Fatal(err)
	}
	if _, err := inventory.CheckNetNSUniqueness(
		context.Background(),
		inventoryTestIDOne,
		validProcessIdentity().NetworkNamespaceInode,
	); !errors.Is(err, ErrInventoryReconcileRequired) {
		t.Fatalf("gap uniqueness err=%v", err)
	}
}

func TestPrivateIntegrityMarksUnsupportedNetworkAndPrivilegeModes(
	t *testing.T,
) {
	control := resolvedInventoryFixture(t, nil)
	if reasons := containerIntegrityReasons(control, true); len(reasons) != 0 {
		t.Fatalf("supported control reasons=%v", reasons)
	}
	for _, testCase := range []struct {
		name   string
		mutate func(*ContainerIdentityV1)
		logs   bool
		want   []string
	}{
		{
			name: "host network",
			mutate: func(identity *ContainerIdentityV1) {
				identity.NetworkMode = "host"
			},
			logs: true,
			want: []string{"unsupported_network_mode"},
		},
		{
			name: "none network",
			mutate: func(identity *ContainerIdentityV1) {
				identity.NetworkMode = "none"
			},
			logs: true,
			want: []string{"unsupported_network_mode"},
		},
		{
			name: "container network",
			mutate: func(identity *ContainerIdentityV1) {
				identity.NetworkMode = "container:" + inventoryTestIDTwo
			},
			logs: true,
			want: []string{"unsupported_network_mode"},
		},
		{
			name: "compose service network",
			mutate: func(identity *ContainerIdentityV1) {
				identity.NetworkMode = "service:database"
			},
			logs: true,
			want: []string{"unsupported_network_mode"},
		},
		{
			name: "macvlan driver",
			mutate: func(identity *ContainerIdentityV1) {
				identity.NetworkDriver = "macvlan"
				identity.AttachedNetworks[0].Driver = "macvlan"
			},
			logs: true,
			want: []string{"unsupported_network_driver"},
		},
		{
			name: "ipvlan driver",
			mutate: func(identity *ContainerIdentityV1) {
				identity.NetworkDriver = "ipvlan"
				identity.AttachedNetworks[0].Driver = "ipvlan"
			},
			logs: true,
			want: []string{"unsupported_network_driver"},
		},
		{
			name: "privileged",
			mutate: func(identity *ContainerIdentityV1) {
				identity.Privileged = true
			},
			logs: true,
			want: []string{"container_privileged"},
		},
		{
			name: "configured net admin",
			mutate: func(identity *ContainerIdentityV1) {
				identity.ConfiguredCapAdd = append(
					identity.ConfiguredCapAdd,
					"NET_ADMIN",
				)
			},
			logs: true,
			want: []string{"configured_cap_net_admin"},
		},
		{
			name: "effective net admin",
			mutate: func(identity *ContainerIdentityV1) {
				identity.EffectiveCapNetAdmin = true
			},
			logs: true,
			want: []string{"effective_cap_net_admin"},
		},
		{
			name:   "logging unavailable",
			mutate: func(*ContainerIdentityV1) {},
			logs:   false,
			want:   []string{"docker_logging_unavailable"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			identity := cloneContainerIdentity(control)
			testCase.mutate(&identity)
			if got := containerIntegrityReasons(
				identity,
				testCase.logs,
			); !reflect.DeepEqual(got, testCase.want) {
				t.Fatalf("reasons=%v want=%v", got, testCase.want)
			}
		})
	}
}

func TestPrivatePayloadHandlersReturnExactIdentityUniquenessAndIntegrity(
	t *testing.T,
) {
	service, _, _, _, _ := observerServiceFixture(t)
	if err := service.ReconcileDocker(
		context.Background(),
		"observer_startup",
	); err != nil {
		t.Fatal(err)
	}

	containerRequest := httptest.NewRequest(
		http.MethodGet,
		"http://unix/v1/private/container/"+inventoryTestIDOne,
		nil,
	)
	containerRequest.SetPathValue("full_id", inventoryTestIDOne)
	containerResponse := httptest.NewRecorder()
	privateContainerHandler(service).ServeHTTP(
		containerResponse,
		containerRequest,
	)
	if containerResponse.Code != http.StatusOK {
		t.Fatalf(
			"container status=%d body=%s",
			containerResponse.Code,
			containerResponse.Body,
		)
	}
	var identity ContainerIdentityV1
	if err := json.Unmarshal(containerResponse.Body.Bytes(), &identity); err != nil {
		t.Fatal(err)
	}
	if identity.FullContainerID != inventoryTestIDOne ||
		identity.InitPID != 4242 {
		t.Fatalf("identity=%+v", identity)
	}

	requestBody, err := contracts.CanonicalJSON(NetNSUniquenessRequestV1{
		FullContainerID:       inventoryTestIDOne,
		NetworkNamespaceInode: validProcessIdentity().NetworkNamespaceInode,
	})
	if err != nil {
		t.Fatal(err)
	}
	uniquenessResponse := httptest.NewRecorder()
	privateNetNSHandler(service).ServeHTTP(
		uniquenessResponse,
		httptest.NewRequest(
			http.MethodPost,
			"http://unix/v1/private/netns-uniqueness",
			bytes.NewReader(requestBody),
		),
	)
	if uniquenessResponse.Code != http.StatusOK {
		t.Fatalf(
			"uniqueness status=%d body=%s",
			uniquenessResponse.Code,
			uniquenessResponse.Body,
		)
	}
	var uniqueness NetNSUniquenessV1
	if err := json.Unmarshal(
		uniquenessResponse.Body.Bytes(),
		&uniqueness,
	); err != nil {
		t.Fatal(err)
	}
	if !uniqueness.Unique ||
		uniqueness.FullContainerID != inventoryTestIDOne ||
		uniqueness.InventorySnapshotSHA256 == "" {
		t.Fatalf("uniqueness=%+v", uniqueness)
	}

	integrityResponse := httptest.NewRecorder()
	privateIntegrityHandler(service).ServeHTTP(
		integrityResponse,
		httptest.NewRequest(
			http.MethodGet,
			"http://unix/v1/private/integrity",
			nil,
		),
	)
	if integrityResponse.Code != http.StatusOK {
		t.Fatalf(
			"integrity status=%d body=%s",
			integrityResponse.Code,
			integrityResponse.Body,
		)
	}
	var integrity ObserverIntegrityV1
	if err := json.Unmarshal(integrityResponse.Body.Bytes(), &integrity); err != nil {
		t.Fatal(err)
	}
	if !integrity.Healthy ||
		len(integrity.Reasons) != 0 ||
		integrity.InventoryGeneration != identity.InventoryGeneration {
		t.Fatalf("integrity=%+v", integrity)
	}
}

func TestMissingDockerLoggingVisibilityIsSignedAndDegradesIntegrity(
	t *testing.T,
) {
	service, _, spool, _, docker := observerServiceFixture(t)
	inspect := docker.inspectByID[inventoryTestIDOne]
	inspect.Container.HostConfig.LogConfig.Type = "none"
	docker.inspectByID[inventoryTestIDOne] = inspect
	if err := service.ReconcileDocker(
		context.Background(),
		"observer_startup",
	); err != nil {
		t.Fatal(err)
	}
	integrity, err := service.PrivateIntegrity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if integrity.Healthy || !reflect.DeepEqual(
		integrity.Reasons,
		[]string{"docker_logging_unavailable"},
	) {
		t.Fatalf("integrity=%+v", integrity)
	}
	items, err := spool.Fetch(0, 100, 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range items {
		event, err := contracts.DecodeStrict[contracts.EventEnvelopeV1](
			bytes.NewReader(item.Canonical),
			65_536,
		)
		if err != nil {
			t.Fatal(err)
		}
		if event.NormalizedFields["kind"] ==
			"docker_logging_visibility_degraded" {
			found = true
			if !reflect.DeepEqual(
				event.CoverageFlags,
				[]string{"docker_logging_unavailable"},
			) {
				t.Fatalf("logging coverage=%+v", event)
			}
		}
	}
	if !found {
		t.Fatal("missing Docker logging visibility was not signed")
	}
}

func TestPrivateNetNSHandlerRejectsUnknownInputWithoutDockerRead(t *testing.T) {
	service, _, _, _, docker := observerServiceFixture(t)
	before := len(docker.listOptions)
	response := httptest.NewRecorder()
	privateNetNSHandler(service).ServeHTTP(
		response,
		httptest.NewRequest(
			http.MethodPost,
			"http://unix/v1/private/netns-uniqueness",
			strings.NewReader(
				`{"full_container_id":"`+inventoryTestIDOne+`",`+
					`"network_namespace_inode":67890,"unknown":true}`,
			),
		),
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body)
	}
	if len(docker.listOptions) != before {
		t.Fatal("invalid private request reached Docker")
	}
}
