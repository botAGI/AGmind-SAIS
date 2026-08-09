package observerd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/uds"
)

const privateRequestMaxBytes int64 = 4_096

type NetNSUniquenessRequestV1 struct {
	FullContainerID       string `json:"full_container_id"`
	NetworkNamespaceInode uint64 `json:"network_namespace_inode"`
}

func (request NetNSUniquenessRequestV1) Validate() error {
	if !dockerIDPattern.MatchString(request.FullContainerID) ||
		request.NetworkNamespaceInode == 0 {
		return fmt.Errorf("invalid network namespace uniqueness request")
	}
	return nil
}

type ObserverIntegrityV1 struct {
	SchemaVersion       string   `json:"schema_version"`
	Healthy             bool     `json:"healthy"`
	Reasons             []string `json:"reasons"`
	HostID              string   `json:"host_id"`
	BootID              string   `json:"boot_id"`
	KeyID               string   `json:"key_id"`
	KeyEpoch            uint64   `json:"key_epoch"`
	InventoryGeneration uint64   `json:"inventory_generation"`
	ObservedAt          string   `json:"observed_at"`
}

func (integrity ObserverIntegrityV1) Validate() error {
	if integrity.SchemaVersion != "agmind.observer-integrity.v1" ||
		!uuid4Pattern.MatchString(integrity.HostID) ||
		!uuid4Pattern.MatchString(integrity.BootID) ||
		!regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(integrity.KeyID) ||
		integrity.KeyEpoch == 0 ||
		integrity.InventoryGeneration == 0 ||
		!strictUTCTime(integrity.ObservedAt) ||
		integrity.Reasons == nil ||
		integrity.Healthy != (len(integrity.Reasons) == 0) {
		return fmt.Errorf("invalid observer integrity response")
	}
	allowed := map[string]bool{
		"docker_logging_unavailable": true,
		"docker_reconcile_gap":       true,
		"mutation_read_only":         true,
		"reconcile_required":         true,
	}
	for index, reason := range integrity.Reasons {
		if !allowed[reason] || index > 0 && integrity.Reasons[index-1] >= reason {
			return fmt.Errorf("invalid observer integrity reason")
		}
	}
	return nil
}

func (result NetNSUniquenessV1) Validate() error {
	if !dockerIDPattern.MatchString(result.FullContainerID) ||
		result.NetworkNamespaceInode == 0 ||
		result.InventoryGeneration == 0 ||
		!hex64Pattern.MatchString(result.InventorySnapshotSHA256) ||
		result.DockerNetworks == nil ||
		!hex64Pattern.MatchString(result.DockerNetworkSnapshotSHA256) ||
		!result.Unique ||
		!strictUTCTime(result.CheckedAt) {
		return fmt.Errorf("invalid network namespace uniqueness response")
	}
	expected, err := contracts.PCCDockerNetworkSnapshotSHA256(
		result.DockerNetworks,
	)
	if err != nil || expected != result.DockerNetworkSnapshotSHA256 {
		return fmt.Errorf("invalid Docker network snapshot binding")
	}
	return nil
}

type privateAPIBackend interface {
	LookupPrivateContainer(
		context.Context,
		string,
	) (ContainerIdentityV1, error)
	CheckPrivateNetNS(
		context.Context,
		NetNSUniquenessRequestV1,
	) (NetNSUniquenessV1, error)
	PrivateIntegrity(context.Context) (ObserverIntegrityV1, error)
}

func privatePeerAuthorized(peer uds.Peer) bool {
	return peer.UID == 0
}

func containerIntegrityReasons(
	identity ContainerIdentityV1,
	dockerLoggingVisible bool,
) []string {
	reasons := make([]string, 0, 6)
	if identity.NetworkMode == "host" ||
		identity.NetworkMode == "none" ||
		strings.HasPrefix(identity.NetworkMode, "container:") ||
		strings.HasPrefix(identity.NetworkMode, "service:") {
		reasons = append(reasons, "unsupported_network_mode")
	}
	unsupportedDriver := identity.NetworkDriver != "bridge"
	for _, attached := range identity.AttachedNetworks {
		if attached.Driver != "bridge" {
			unsupportedDriver = true
		}
	}
	if unsupportedDriver {
		reasons = append(reasons, "unsupported_network_driver")
	}
	if identity.Privileged {
		reasons = append(reasons, "container_privileged")
	}
	for _, capability := range identity.ConfiguredCapAdd {
		normalized := strings.TrimPrefix(strings.ToUpper(capability), "CAP_")
		if normalized == "NET_ADMIN" || normalized == "ALL" {
			reasons = append(reasons, "configured_cap_net_admin")
			break
		}
	}
	if identity.EffectiveCapNetAdmin {
		reasons = append(reasons, "effective_cap_net_admin")
	}
	if !dockerLoggingVisible {
		reasons = append(reasons, "docker_logging_unavailable")
	}
	sort.Strings(reasons)
	return reasons
}

func (service *Service) LookupPrivateContainer(
	ctx context.Context,
	fullID string,
) (ContainerIdentityV1, error) {
	if service == nil ||
		service.daemon == nil ||
		service.daemon.state == nil ||
		service.inventory == nil {
		return ContainerIdentityV1{}, fmt.Errorf("private inventory unavailable")
	}
	if err := ctx.Err(); err != nil {
		return ContainerIdentityV1{}, err
	}
	if service.daemon.state.Snapshot().ReconcileRequired {
		return ContainerIdentityV1{}, ErrInventoryReconcileRequired
	}
	return service.inventory.LookupFullID(fullID)
}

func (service *Service) CheckPrivateNetNS(
	ctx context.Context,
	request NetNSUniquenessRequestV1,
) (NetNSUniquenessV1, error) {
	if service == nil ||
		service.daemon == nil ||
		service.daemon.state == nil ||
		service.inventory == nil {
		return NetNSUniquenessV1{}, fmt.Errorf(
			"private namespace check unavailable",
		)
	}
	if err := request.Validate(); err != nil {
		return NetNSUniquenessV1{}, err
	}
	if service.daemon.state.Snapshot().ReconcileRequired {
		return NetNSUniquenessV1{}, ErrInventoryReconcileRequired
	}
	return service.inventory.CheckNetNSUniqueness(
		ctx,
		request.FullContainerID,
		request.NetworkNamespaceInode,
	)
}

func (service *Service) PrivateIntegrity(
	ctx context.Context,
) (ObserverIntegrityV1, error) {
	if service == nil ||
		service.daemon == nil ||
		service.daemon.state == nil ||
		service.inventory == nil ||
		service.now == nil {
		return ObserverIntegrityV1{}, fmt.Errorf(
			"private integrity unavailable",
		)
	}
	if err := ctx.Err(); err != nil {
		return ObserverIntegrityV1{}, err
	}
	state := service.daemon.state.Snapshot()
	reasons := make([]string, 0, 4)
	if state.MutationReadOnly {
		reasons = append(reasons, "mutation_read_only")
	}
	if state.ReconcileRequired {
		reasons = append(reasons, "reconcile_required")
	}
	if service.inventory.ReconcileGapOpen() {
		reasons = append(reasons, "docker_reconcile_gap")
	}
	if service.inventory.LoggingUnavailable() {
		reasons = append(reasons, "docker_logging_unavailable")
	}
	reasons = normalizeSortedUnique(reasons)
	return ObserverIntegrityV1{
		SchemaVersion:       "agmind.observer-integrity.v1",
		Healthy:             len(reasons) == 0,
		Reasons:             reasons,
		HostID:              state.HostID,
		BootID:              state.BootID,
		KeyID:               state.KeyID,
		KeyEpoch:            state.KeyEpoch,
		InventoryGeneration: service.inventory.Generation(),
		ObservedAt: service.now().UTC().Format(
			time.RFC3339Nano,
		),
	}, nil
}

func privateContainerHandler(backend privateAPIBackend) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if backend == nil {
			unavailableAPIHandler(writer, request)
			return
		}
		fullID := request.PathValue("full_id")
		if !dockerIDPattern.MatchString(fullID) {
			http.NotFound(writer, request)
			return
		}
		identity, err := backend.LookupPrivateContainer(
			request.Context(),
			fullID,
		)
		if err != nil {
			if errors.Is(err, ErrContainerNotFound) {
				http.NotFound(writer, request)
				return
			}
			fixedAPIError(
				writer,
				http.StatusServiceUnavailable,
				"inventory_unavailable",
			)
			return
		}
		writeAPIJSON(writer, http.StatusOK, identity)
	})
}

func privateNetNSHandler(backend privateAPIBackend) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if backend == nil {
			unavailableAPIHandler(writer, request)
			return
		}
		check, err := contracts.DecodeStrict[NetNSUniquenessRequestV1](
			request.Body,
			privateRequestMaxBytes,
		)
		if err != nil {
			fixedAPIError(
				writer,
				http.StatusBadRequest,
				"invalid_netns_request",
			)
			return
		}
		result, err := backend.CheckPrivateNetNS(
			request.Context(),
			check,
		)
		if err != nil {
			status := http.StatusServiceUnavailable
			reason := "netns_check_unavailable"
			if errors.Is(err, ErrSharedNetworkNamespace) {
				status = http.StatusConflict
				reason = "shared_network_namespace"
			} else if errors.Is(err, ErrContainerNotFound) {
				status = http.StatusNotFound
				reason = "container_not_found"
			}
			fixedAPIError(writer, status, reason)
			return
		}
		writeAPIJSON(writer, http.StatusOK, result)
	})
}

func privateIntegrityHandler(backend privateAPIBackend) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if backend == nil {
			unavailableAPIHandler(writer, request)
			return
		}
		integrity, err := backend.PrivateIntegrity(request.Context())
		if err != nil {
			fixedAPIError(
				writer,
				http.StatusServiceUnavailable,
				"integrity_unavailable",
			)
			return
		}
		writeAPIJSON(writer, http.StatusOK, integrity)
	})
}

func newPrivateAPI(backend privateAPIBackend) http.Handler {
	mux := http.NewServeMux()
	rootOnly := uds.RequirePeer(privatePeerAuthorized)
	mux.HandleFunc(
		"GET /v1/private/container/{full_id}",
		func(writer http.ResponseWriter, request *http.Request) {
			if !dockerIDPattern.MatchString(request.PathValue("full_id")) {
				http.NotFound(writer, request)
				return
			}
			rootOnly(privateContainerHandler(backend)).
				ServeHTTP(writer, request)
		},
	)
	mux.Handle(
		"POST /v1/private/netns-uniqueness",
		rootOnly(privateNetNSHandler(backend)),
	)
	mux.Handle(
		"GET /v1/private/integrity",
		rootOnly(privateIntegrityHandler(backend)),
	)
	return mux
}
