package observerd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

const (
	inventorySchema                         = "agmind.observer-inventory.v1"
	immutableSpecSchema                     = "agmind.immutable-container-spec.v1"
	inventoryMaxBytes                 int64 = 4 * 1024 * 1024
	inventoryRevisionLedgerMaxEntries       = 4_096
)

var (
	ErrAmbiguousContainerPrefix  = errors.New("ambiguous container prefix")
	ErrContainerNotFound         = errors.New("container not found")
	ErrContainerIdentityMismatch = errors.New(
		"container identity mismatch",
	)
	ErrInventoryReconcileRequired = errors.New(
		"Docker inventory reconcile required",
	)
	ErrMissingImageIdentity             = errors.New("missing immutable image identity")
	ErrInventoryStale                   = errors.New("Docker inventory is stale")
	ErrInventoryRevisionLedgerExhausted = errors.New(
		"Docker inventory revision ledger exhausted",
	)
	ErrSharedNetworkNamespace = errors.New(
		"network namespace is shared by multiple containers",
	)
)

var (
	dockerIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	imageIDPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	utcTimePattern  = regexp.MustCompile(
		`^(?:[0-9]{3}[1-9]|[0-9]{2}[1-9][0-9]|[0-9][1-9][0-9]{2}|[1-9][0-9]{3})-` +
			`(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T` +
			`(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]` +
			`(?:\.[0-9]{1,9})?Z$`,
	)
)

// AttachedNetworkV1 is the redacted network identity exported by observerd.
type AttachedNetworkV1 struct {
	NetworkID        string   `json:"network_id"`
	Driver           string   `json:"driver"`
	SubnetCIDRs      []string `json:"subnet_cidrs"`
	GatewayAddresses []string `json:"gateway_addresses"`
}

// ContainerIdentityV1 is the complete public/private Docker identity
// allowlist. It intentionally contains no generic inspect payload.
type ContainerIdentityV1 struct {
	FullContainerID      string              `json:"full_container_id"`
	DockerStartedAt      string              `json:"docker_started_at"`
	ImageID              string              `json:"image_id"`
	RepoDigests          []string            `json:"repo_digests"`
	ImmutableSpecSHA256  string              `json:"immutable_spec_sha256"`
	InitPID              uint64              `json:"init_pid"`
	NetworkMode          string              `json:"network_mode"`
	NetworkDriver        string              `json:"network_driver"`
	Privileged           bool                `json:"privileged"`
	ConfiguredCapAdd     []string            `json:"configured_cap_add"`
	ConfiguredCapDrop    []string            `json:"configured_cap_drop"`
	EffectiveCapNetAdmin bool                `json:"effective_cap_net_admin"`
	Running              bool                `json:"running"`
	InventoryGeneration  uint64              `json:"inventory_generation"`
	InventoryRevision    uint64              `json:"inventory_revision"`
	ObservedAt           string              `json:"observed_at"`
	AttachedNetworks     []AttachedNetworkV1 `json:"attached_networks"`
}

type CorrelationInventorySnapshot struct {
	Generation     uint64
	Identity       ContainerIdentityV1
	DockerNetworks []contracts.PCCDockerNetworkV1
}

// NetNSUniquenessV1 records the inventory generation and live namespace inode
// over which a root-only uniqueness decision was made.
type NetNSUniquenessV1 struct {
	FullContainerID         string `json:"full_container_id"`
	NetworkNamespaceInode   uint64 `json:"network_namespace_inode"`
	InventoryGeneration     uint64 `json:"inventory_generation"`
	InventorySnapshotSHA256 string `json:"inventory_snapshot_sha256"`
	Unique                  bool   `json:"unique"`
	CheckedAt               string `json:"checked_at"`
}

type processIdentity struct {
	PIDStartTicks         uint64 `json:"pid_start_ticks"`
	CgroupPathSHA256      string `json:"cgroup_path_sha256"`
	NetworkNamespaceInode uint64 `json:"network_namespace_inode"`
	EffectiveCapNetAdmin  bool   `json:"effective_cap_net_admin"`
}

type processIdentityReader interface {
	ReadProcessIdentity(string, int) (processIdentity, error)
}

type inventoryRecord struct {
	Identity             ContainerIdentityV1 `json:"identity"`
	ProcessIdentity      processIdentity     `json:"process_identity"`
	DockerLoggingVisible bool                `json:"docker_logging_visible"`
	RevisionSHA256       string              `json:"revision_sha256"`
}

type inventoryRevisionLedgerEntry struct {
	FullContainerID   string `json:"full_container_id"`
	InventoryRevision uint64 `json:"inventory_revision"`
	RevisionSHA256    string `json:"revision_sha256"`
}

type inventoryDiskState struct {
	SchemaVersion      string                         `json:"schema_version"`
	Generation         uint64                         `json:"inventory_generation"`
	DockerReconcileGap bool                           `json:"docker_reconcile_gap"`
	Records            []inventoryRecord              `json:"records"`
	RevisionLedger     []inventoryRevisionLedgerEntry `json:"revision_ledger"`
	DockerNetworks     []contracts.PCCDockerNetworkV1 `json:"docker_networks"`
}

type Inventory struct {
	reconcileMutex sync.Mutex
	mutex          sync.RWMutex
	path           string
	docker         DockerReader
	processes      processIdentityReader
	now            func() time.Time
	persist        func(string, inventoryDiskState) error
	state          inventoryDiskState
	records        map[string]inventoryRecord
}

type immutableMountTuple struct {
	Type       string `json:"type"`
	Target     string `json:"target"`
	ReadOnly   bool   `json:"read_only"`
	SourceKind string `json:"source_kind"`
}

type immutableSpecV1 struct {
	SchemaVersion    string                `json:"schema_version"`
	ImageID          string                `json:"image_id"`
	EntrypointSHA256 string                `json:"entrypoint_sha256"`
	CommandSHA256    string                `json:"command_sha256"`
	NetworkMode      string                `json:"network_mode"`
	Privileged       bool                  `json:"privileged"`
	CapAdd           []string              `json:"cap_add"`
	CapDrop          []string              `json:"cap_drop"`
	ReadOnlyRootFS   bool                  `json:"read_only_rootfs"`
	Mounts           []immutableMountTuple `json:"mounts"`
}

func safeASCII(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

func strictUTCTime(value string) bool {
	if !utcTimePattern.MatchString(value) {
		return false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.Location() == time.UTC
}

func sortedUniqueStrings(values []string, maximum int) bool {
	if values == nil || len(values) > maximum {
		return false
	}
	for index, value := range values {
		if index > 0 && value <= values[index-1] {
			return false
		}
	}
	return true
}

func (networkIdentity AttachedNetworkV1) Validate() error {
	if !dockerIDPattern.MatchString(networkIdentity.NetworkID) ||
		!safeASCII(networkIdentity.Driver, 1, 64) ||
		!sortedUniqueStrings(networkIdentity.SubnetCIDRs, 64) ||
		!sortedUniqueStrings(networkIdentity.GatewayAddresses, 64) {
		return fmt.Errorf("invalid attached Docker network")
	}
	for _, subnet := range networkIdentity.SubnetCIDRs {
		parsed, err := netip.ParsePrefix(subnet)
		if err != nil || parsed.String() != subnet {
			return fmt.Errorf("invalid Docker network subnet")
		}
	}
	for _, gateway := range networkIdentity.GatewayAddresses {
		parsed, err := netip.ParseAddr(gateway)
		if err != nil || parsed.String() != gateway {
			return fmt.Errorf("invalid Docker network gateway")
		}
	}
	return nil
}

func (identity ContainerIdentityV1) Validate() error {
	if !dockerIDPattern.MatchString(identity.FullContainerID) ||
		!strictUTCTime(identity.DockerStartedAt) ||
		!imageIDPattern.MatchString(identity.ImageID) ||
		!hex64Pattern.MatchString(identity.ImmutableSpecSHA256) ||
		identity.InitPID == 0 ||
		!safeASCII(identity.NetworkMode, 1, 128) ||
		!safeASCII(identity.NetworkDriver, 1, 64) ||
		!identity.Running ||
		identity.InventoryGeneration == 0 ||
		identity.InventoryRevision == 0 ||
		!strictUTCTime(identity.ObservedAt) ||
		!sortedUniqueStrings(identity.RepoDigests, 16) ||
		!sortedUniqueStrings(identity.ConfiguredCapAdd, 128) ||
		!sortedUniqueStrings(identity.ConfiguredCapDrop, 128) ||
		identity.AttachedNetworks == nil ||
		len(identity.AttachedNetworks) > 32 {
		return fmt.Errorf("invalid Docker container identity")
	}
	for _, digest := range identity.RepoDigests {
		if !safeASCII(digest, 1, 256) {
			return fmt.Errorf("invalid Docker repository digest")
		}
	}
	for _, capability := range append(
		append([]string{}, identity.ConfiguredCapAdd...),
		identity.ConfiguredCapDrop...,
	) {
		if !safeASCII(capability, 1, 64) {
			return fmt.Errorf("invalid Docker capability")
		}
	}
	var priorNetworkID string
	for index, attached := range identity.AttachedNetworks {
		if err := attached.Validate(); err != nil {
			return err
		}
		if index > 0 && attached.NetworkID <= priorNetworkID {
			return fmt.Errorf("attached Docker networks are not sorted")
		}
		priorNetworkID = attached.NetworkID
	}
	return nil
}

func (identity processIdentity) Validate() error {
	if identity.PIDStartTicks == 0 ||
		identity.NetworkNamespaceInode == 0 ||
		!hex64Pattern.MatchString(identity.CgroupPathSHA256) {
		return fmt.Errorf("invalid Linux process identity")
	}
	return nil
}

func (record inventoryRecord) Validate() error {
	if err := record.Identity.Validate(); err != nil {
		return err
	}
	if err := record.ProcessIdentity.Validate(); err != nil {
		return err
	}
	if record.Identity.EffectiveCapNetAdmin !=
		record.ProcessIdentity.EffectiveCapNetAdmin ||
		!hex64Pattern.MatchString(record.RevisionSHA256) {
		return fmt.Errorf("inconsistent inventory record")
	}
	return nil
}

func (state inventoryDiskState) Validate() error {
	if state.SchemaVersion != inventorySchema ||
		state.Records == nil ||
		len(state.Records) > 4_096 ||
		state.RevisionLedger == nil ||
		len(state.RevisionLedger) > inventoryRevisionLedgerMaxEntries {
		return fmt.Errorf("invalid Docker inventory state")
	}
	if _, err := contracts.PCCDockerNetworkSnapshotSHA256(
		state.DockerNetworks,
	); err != nil {
		return err
	}
	ledgerByID := make(
		map[string]inventoryRevisionLedgerEntry,
		len(state.RevisionLedger),
	)
	var priorLedgerID string
	for index, entry := range state.RevisionLedger {
		if !dockerIDPattern.MatchString(entry.FullContainerID) ||
			entry.InventoryRevision == 0 ||
			!hex64Pattern.MatchString(entry.RevisionSHA256) ||
			index > 0 && entry.FullContainerID <= priorLedgerID {
			return fmt.Errorf("invalid Docker inventory revision ledger")
		}
		ledgerByID[entry.FullContainerID] = entry
		priorLedgerID = entry.FullContainerID
	}
	var priorID string
	for index, record := range state.Records {
		if err := record.Validate(); err != nil {
			return err
		}
		if record.Identity.InventoryGeneration != state.Generation ||
			index > 0 && record.Identity.FullContainerID <= priorID {
			return fmt.Errorf("invalid Docker inventory ordering")
		}
		ledger, ok := ledgerByID[record.Identity.FullContainerID]
		if !ok ||
			ledger.InventoryRevision != record.Identity.InventoryRevision ||
			ledger.RevisionSHA256 != record.RevisionSHA256 {
			return fmt.Errorf("inventory record is not anchored in revision ledger")
		}
		priorID = record.Identity.FullContainerID
	}
	if state.Generation == 0 &&
		(len(state.Records) != 0 || len(state.DockerNetworks) != 0) {
		return fmt.Errorf("unreconciled inventory cannot contain records")
	}
	return nil
}

func cloneContainerIdentity(identity ContainerIdentityV1) ContainerIdentityV1 {
	cloned := identity
	cloned.RepoDigests = append([]string{}, identity.RepoDigests...)
	cloned.ConfiguredCapAdd = append([]string{}, identity.ConfiguredCapAdd...)
	cloned.ConfiguredCapDrop = append([]string{}, identity.ConfiguredCapDrop...)
	cloned.AttachedNetworks = make(
		[]AttachedNetworkV1,
		len(identity.AttachedNetworks),
	)
	for index, attached := range identity.AttachedNetworks {
		cloned.AttachedNetworks[index] = attached
		cloned.AttachedNetworks[index].SubnetCIDRs = append(
			[]string{},
			attached.SubnetCIDRs...,
		)
		cloned.AttachedNetworks[index].GatewayAddresses = append(
			[]string{},
			attached.GatewayAddresses...,
		)
	}
	return cloned
}

func cloneInventoryRecord(record inventoryRecord) inventoryRecord {
	cloned := record
	cloned.Identity = cloneContainerIdentity(record.Identity)
	return cloned
}

func cloneDockerNetworks(
	networks []contracts.PCCDockerNetworkV1,
) []contracts.PCCDockerNetworkV1 {
	cloned := make([]contracts.PCCDockerNetworkV1, len(networks))
	for index, dockerNetwork := range networks {
		cloned[index] = dockerNetwork
		cloned[index].SubnetCIDRs = append(
			[]string{},
			dockerNetwork.SubnetCIDRs...,
		)
		cloned[index].GatewayAddresses = append(
			[]string{},
			dockerNetwork.GatewayAddresses...,
		)
	}
	return cloned
}

func inventoryRecordsMap(
	records []inventoryRecord,
) map[string]inventoryRecord {
	result := make(map[string]inventoryRecord, len(records))
	for _, record := range records {
		result[record.Identity.FullContainerID] = cloneInventoryRecord(record)
	}
	return result
}

func persistInventoryState(path string, state inventoryDiskState) error {
	if err := state.Validate(); err != nil {
		return err
	}
	raw, err := contracts.CanonicalJSON(state)
	if err != nil {
		return err
	}
	if int64(len(raw)) > inventoryMaxBytes {
		return fmt.Errorf("Docker inventory exceeds explicit byte limit")
	}
	return durablefile.AtomicWrite(path, raw)
}

func loadInventoryState(path string) (inventoryDiskState, error) {
	raw, err := readSingleLinkRegular(path, inventoryMaxBytes)
	if err != nil {
		return inventoryDiskState{}, err
	}
	state, err := contracts.DecodeStrict[inventoryDiskState](
		bytes.NewReader(raw),
		inventoryMaxBytes,
	)
	if err != nil {
		return inventoryDiskState{}, err
	}
	canonical, err := contracts.CanonicalJSON(state)
	if err != nil || !bytes.Equal(raw, canonical) {
		return inventoryDiskState{}, fmt.Errorf(
			"Docker inventory is not exact canonical JSON",
		)
	}
	if err := state.Validate(); err != nil {
		return inventoryDiskState{}, err
	}
	return state, nil
}

func openInventory(
	stateDir string,
	docker DockerReader,
	processes processIdentityReader,
	now func() time.Time,
) (*Inventory, error) {
	if docker == nil || processes == nil || now == nil {
		return nil, fmt.Errorf("Docker inventory dependencies are required")
	}
	if err := durablefile.EnsurePrivateDirectory(stateDir); err != nil {
		return nil, err
	}
	path := filepath.Join(stateDir, "docker-inventory.json")
	state, err := loadInventoryState(path)
	if errors.Is(err, os.ErrNotExist) {
		state = inventoryDiskState{
			SchemaVersion:      inventorySchema,
			DockerReconcileGap: true,
			Records:            []inventoryRecord{},
			RevisionLedger:     []inventoryRevisionLedgerEntry{},
			DockerNetworks:     []contracts.PCCDockerNetworkV1{},
		}
		if err := persistInventoryState(path, state); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return &Inventory{
		path:      path,
		docker:    docker,
		processes: processes,
		now:       now,
		persist:   persistInventoryState,
		state:     state,
		records:   inventoryRecordsMap(state.Records),
	}, nil
}

func normalizeSortedUnique(values []string) []string {
	result := append([]string{}, values...)
	sort.Strings(result)
	if len(result) == 0 {
		return []string{}
	}
	destination := 1
	for index := 1; index < len(result); index++ {
		if result[index] == result[destination-1] {
			continue
		}
		result[destination] = result[index]
		destination++
	}
	return result[:destination]
}

func hashCanonical(value any) (string, error) {
	raw, err := contracts.CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func mountSourceKind(mountPoint container.MountPoint) string {
	switch mountPoint.Type {
	case mount.TypeBind:
		return "bind"
	case mount.TypeVolume:
		return "named-volume"
	case mount.TypeTmpfs:
		return "tmpfs"
	default:
		return "other"
	}
}

func immutableSpecHash(
	inspect container.InspectResponse,
	imageID string,
) (string, error) {
	if inspect.Config == nil || inspect.HostConfig == nil {
		return "", fmt.Errorf("Docker inspect lacks immutable configuration")
	}
	entrypoint := append([]string{}, inspect.Config.Entrypoint...)
	command := append([]string{}, inspect.Config.Cmd...)
	entrypointHash, err := hashCanonical(entrypoint)
	if err != nil {
		return "", err
	}
	commandHash, err := hashCanonical(command)
	if err != nil {
		return "", err
	}
	mounts := make([]immutableMountTuple, 0, len(inspect.Mounts))
	for _, mountPoint := range inspect.Mounts {
		mounts = append(mounts, immutableMountTuple{
			Type:       string(mountPoint.Type),
			Target:     mountPoint.Destination,
			ReadOnly:   !mountPoint.RW,
			SourceKind: mountSourceKind(mountPoint),
		})
	}
	sort.Slice(mounts, func(left, right int) bool {
		leftRaw, _ := contracts.CanonicalJSON(mounts[left])
		rightRaw, _ := contracts.CanonicalJSON(mounts[right])
		return bytes.Compare(leftRaw, rightRaw) < 0
	})
	return hashCanonical(immutableSpecV1{
		SchemaVersion:    immutableSpecSchema,
		ImageID:          imageID,
		EntrypointSHA256: entrypointHash,
		CommandSHA256:    commandHash,
		NetworkMode:      string(inspect.HostConfig.NetworkMode),
		Privileged:       inspect.HostConfig.Privileged,
		CapAdd:           normalizeSortedUnique(inspect.HostConfig.CapAdd),
		CapDrop:          normalizeSortedUnique(inspect.HostConfig.CapDrop),
		ReadOnlyRootFS:   inspect.HostConfig.ReadonlyRootfs,
		Mounts:           mounts,
	})
}

func (inventory *Inventory) attachedNetworks(
	ctx context.Context,
	inspect container.InspectResponse,
) ([]AttachedNetworkV1, string, error) {
	if inspect.NetworkSettings == nil {
		return []AttachedNetworkV1{}, string(inspect.HostConfig.NetworkMode), nil
	}
	networkIDs := make([]string, 0, len(inspect.NetworkSettings.Networks))
	for _, endpoint := range inspect.NetworkSettings.Networks {
		if endpoint == nil ||
			!dockerIDPattern.MatchString(endpoint.NetworkID) {
			return nil, "", fmt.Errorf("invalid Docker network attachment")
		}
		networkIDs = append(networkIDs, endpoint.NetworkID)
	}
	sort.Strings(networkIDs)
	for index := 1; index < len(networkIDs); index++ {
		if networkIDs[index] == networkIDs[index-1] {
			return nil, "", fmt.Errorf("duplicate Docker network attachment")
		}
	}
	result := make([]AttachedNetworkV1, 0, len(networkIDs))
	drivers := make([]string, 0, len(networkIDs))
	for _, networkID := range networkIDs {
		inspected, err := inventory.docker.NetworkInspect(
			ctx,
			networkID,
			client.NetworkInspectOptions{},
		)
		if err != nil {
			return nil, "", err
		}
		if inspected.Network.ID != networkID ||
			!safeASCII(inspected.Network.Driver, 1, 64) {
			return nil, "", fmt.Errorf("Docker network identity mismatch")
		}
		subnets := make([]string, 0, len(inspected.Network.IPAM.Config))
		gateways := make([]string, 0, len(inspected.Network.IPAM.Config))
		for _, configuration := range inspected.Network.IPAM.Config {
			if configuration.Subnet.IsValid() {
				subnets = append(subnets, configuration.Subnet.String())
			}
			if configuration.Gateway.IsValid() {
				gateways = append(gateways, configuration.Gateway.String())
			}
		}
		subnets = normalizeSortedUnique(subnets)
		gateways = normalizeSortedUnique(gateways)
		result = append(result, AttachedNetworkV1{
			NetworkID:        networkID,
			Driver:           inspected.Network.Driver,
			SubnetCIDRs:      subnets,
			GatewayAddresses: gateways,
		})
		drivers = append(drivers, inspected.Network.Driver)
	}
	drivers = normalizeSortedUnique(drivers)
	switch len(drivers) {
	case 0:
		return result, string(inspect.HostConfig.NetworkMode), nil
	case 1:
		return result, drivers[0], nil
	default:
		return result, "mixed", nil
	}
}

func (inventory *Inventory) globalDockerNetworks(
	ctx context.Context,
) ([]contracts.PCCDockerNetworkV1, error) {
	listed, err := inventory.docker.NetworkList(
		ctx,
		client.NetworkListOptions{},
	)
	if err != nil {
		return nil, err
	}
	networkIDs := make([]string, 0, len(listed.Items))
	seen := make(map[string]struct{}, len(listed.Items))
	for _, summary := range listed.Items {
		networkID := summary.ID
		if !dockerIDPattern.MatchString(networkID) {
			return nil, fmt.Errorf("invalid Docker network list identity")
		}
		if _, duplicate := seen[networkID]; duplicate {
			return nil, fmt.Errorf("duplicate Docker network list identity")
		}
		seen[networkID] = struct{}{}
		networkIDs = append(networkIDs, networkID)
	}
	networks := make(
		[]contracts.PCCDockerNetworkV1,
		0,
		len(networkIDs),
	)
	for _, networkID := range networkIDs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		inspected, err := inventory.docker.NetworkInspect(
			ctx,
			networkID,
			client.NetworkInspectOptions{},
		)
		if err != nil {
			return nil, err
		}
		if inspected.Network.ID != networkID {
			return nil, fmt.Errorf("Docker network identity mismatch")
		}
		subnets := make(
			[]string,
			0,
			len(inspected.Network.IPAM.Config),
		)
		gateways := make(
			[]string,
			0,
			len(inspected.Network.IPAM.Config),
		)
		for _, configuration := range inspected.Network.IPAM.Config {
			if configuration.Subnet.IsValid() {
				if configuration.Subnet.Addr().Is4In6() ||
					configuration.Subnet != configuration.Subnet.Masked() {
					return nil, fmt.Errorf(
						"invalid Docker network subnet",
					)
				}
				subnets = append(
					subnets,
					configuration.Subnet.String(),
				)
			}
			if configuration.Gateway.IsValid() {
				if configuration.Gateway.Is4In6() {
					return nil, fmt.Errorf(
						"invalid Docker network gateway",
					)
				}
				gateways = append(
					gateways,
					configuration.Gateway.String(),
				)
			}
		}
		networks = append(networks, contracts.PCCDockerNetworkV1{
			NetworkID:        networkID,
			Driver:           inspected.Network.Driver,
			SubnetCIDRs:      normalizeSortedUnique(subnets),
			GatewayAddresses: normalizeSortedUnique(gateways),
		})
	}
	sort.Slice(networks, func(left, right int) bool {
		return networks[left].NetworkID < networks[right].NetworkID
	})
	if _, err := contracts.PCCDockerNetworkSnapshotSHA256(
		networks,
	); err != nil {
		return nil, err
	}
	return networks, nil
}

func (inventory *Inventory) inspectRunningContainer(
	ctx context.Context,
	fullID string,
) (inventoryRecord, bool, error) {
	if !dockerIDPattern.MatchString(fullID) {
		return inventoryRecord{}, false, fmt.Errorf("invalid Docker container ID")
	}
	result, err := inventory.docker.ContainerInspect(
		ctx,
		fullID,
		client.ContainerInspectOptions{Size: false},
	)
	if err != nil {
		return inventoryRecord{}, false, err
	}
	inspect := result.Container
	if inspect.ID != fullID {
		return inventoryRecord{}, false, ErrContainerIdentityMismatch
	}
	if inspect.State == nil || !inspect.State.Running {
		return inventoryRecord{}, false, nil
	}
	if inspect.State.Pid <= 0 ||
		!strictUTCTime(inspect.State.StartedAt) ||
		inspect.Config == nil ||
		inspect.HostConfig == nil {
		return inventoryRecord{}, false, ErrContainerIdentityMismatch
	}
	process, err := inventory.processes.ReadProcessIdentity(
		fullID,
		inspect.State.Pid,
	)
	if err != nil {
		return inventoryRecord{}, false, errors.Join(ErrInventoryStale, err)
	}
	if err := process.Validate(); err != nil {
		return inventoryRecord{}, false, errors.Join(ErrInventoryStale, err)
	}
	imageResult, err := inventory.docker.ImageInspect(ctx, inspect.Image)
	if err != nil {
		return inventoryRecord{}, false, err
	}
	if !imageIDPattern.MatchString(imageResult.ID) {
		return inventoryRecord{}, false, ErrMissingImageIdentity
	}
	if inspect.Image != imageResult.ID {
		return inventoryRecord{}, false, ErrContainerIdentityMismatch
	}
	specHash, err := immutableSpecHash(inspect, imageResult.ID)
	if err != nil {
		return inventoryRecord{}, false, err
	}
	attached, driver, err := inventory.attachedNetworks(ctx, inspect)
	if err != nil {
		return inventoryRecord{}, false, err
	}
	return inventoryRecord{
		Identity: ContainerIdentityV1{
			FullContainerID:      fullID,
			DockerStartedAt:      inspect.State.StartedAt,
			ImageID:              imageResult.ID,
			RepoDigests:          normalizeSortedUnique(imageResult.RepoDigests),
			ImmutableSpecSHA256:  specHash,
			InitPID:              uint64(inspect.State.Pid),
			NetworkMode:          string(inspect.HostConfig.NetworkMode),
			NetworkDriver:        driver,
			Privileged:           inspect.HostConfig.Privileged,
			ConfiguredCapAdd:     normalizeSortedUnique(inspect.HostConfig.CapAdd),
			ConfiguredCapDrop:    normalizeSortedUnique(inspect.HostConfig.CapDrop),
			EffectiveCapNetAdmin: process.EffectiveCapNetAdmin,
			Running:              true,
			AttachedNetworks:     attached,
		},
		ProcessIdentity: process,
		DockerLoggingVisible: inspect.HostConfig.LogConfig.Type != "" &&
			inspect.HostConfig.LogConfig.Type != "none",
	}, true, nil
}

func revisionHash(record inventoryRecord) (string, error) {
	identity := cloneContainerIdentity(record.Identity)
	identity.InventoryGeneration = 0
	identity.InventoryRevision = 0
	identity.ObservedAt = ""
	return hashCanonical(struct {
		Identity             ContainerIdentityV1 `json:"identity"`
		ProcessIdentity      processIdentity     `json:"process_identity"`
		DockerLoggingVisible bool                `json:"docker_logging_visible"`
	}{
		Identity:             identity,
		ProcessIdentity:      record.ProcessIdentity,
		DockerLoggingVisible: record.DockerLoggingVisible,
	})
}

func (inventory *Inventory) persistAndAdopt(
	next inventoryDiskState,
) error {
	err := inventory.persist(inventory.path, next)
	if errors.Is(err, durablefile.ErrCommitUncertain) {
		expected, canonicalErr := contracts.CanonicalJSON(next)
		actual, readErr := readSingleLinkRegular(
			inventory.path,
			inventoryMaxBytes,
		)
		if canonicalErr == nil &&
			readErr == nil &&
			bytes.Equal(actual, expected) {
			if syncErr := durablefile.SyncDirectory(
				filepath.Dir(inventory.path),
			); syncErr == nil {
				err = nil
			} else {
				err = errors.Join(err, syncErr)
			}
		} else {
			err = errors.Join(err, canonicalErr, readErr)
		}
	}
	if err != nil {
		return err
	}
	inventory.state = next
	inventory.records = inventoryRecordsMap(next.Records)
	return nil
}

func (inventory *Inventory) openReconcileGap() error {
	inventory.mutex.Lock()
	defer inventory.mutex.Unlock()
	if inventory.state.DockerReconcileGap {
		return nil
	}
	next := inventory.state
	next.DockerReconcileGap = true
	// Mirror the observer state fence: the live inventory becomes
	// non-authoritative before a persistence attempt that may fail.
	inventory.state = next
	return inventory.persistAndAdopt(next)
}

func (inventory *Inventory) Reconcile(ctx context.Context) error {
	inventory.reconcileMutex.Lock()
	defer inventory.reconcileMutex.Unlock()
	if err := inventory.openReconcileGap(); err != nil {
		return err
	}
	listed, err := inventory.docker.ContainerList(
		ctx,
		client.ContainerListOptions{All: false, Size: false},
	)
	if err != nil {
		return err
	}
	runningIDs := make([]string, 0, len(listed.Items))
	seen := make(map[string]struct{}, len(listed.Items))
	for _, summary := range listed.Items {
		if summary.State != container.StateRunning {
			continue
		}
		if !dockerIDPattern.MatchString(summary.ID) {
			return fmt.Errorf("invalid Docker list identity")
		}
		if _, duplicate := seen[summary.ID]; duplicate {
			return fmt.Errorf("duplicate Docker list identity")
		}
		seen[summary.ID] = struct{}{}
		runningIDs = append(runningIDs, summary.ID)
	}
	sort.Strings(runningIDs)
	nextRecords := make([]inventoryRecord, 0, len(runningIDs))
	for _, fullID := range runningIDs {
		if err := ctx.Err(); err != nil {
			return err
		}
		record, running, err := inventory.inspectRunningContainer(ctx, fullID)
		if err != nil {
			return err
		}
		if running {
			nextRecords = append(nextRecords, record)
		}
	}
	nextDockerNetworks, err := inventory.globalDockerNetworks(ctx)
	if err != nil {
		return err
	}

	inventory.mutex.Lock()
	defer inventory.mutex.Unlock()
	if inventory.state.Generation == math.MaxUint64 {
		return fmt.Errorf("Docker inventory generation exhausted")
	}
	nextGeneration := inventory.state.Generation + 1
	observedAt := inventory.now().UTC().Format(time.RFC3339Nano)
	nextLedger := append(
		[]inventoryRevisionLedgerEntry{},
		inventory.state.RevisionLedger...,
	)
	ledgerIndex := make(map[string]int, len(nextLedger))
	for index, entry := range nextLedger {
		ledgerIndex[entry.FullContainerID] = index
	}
	for index := range nextRecords {
		revisionSHA256, err := revisionHash(nextRecords[index])
		if err != nil {
			return err
		}
		fullID := nextRecords[index].Identity.FullContainerID
		revision := uint64(1)
		if priorIndex, ok := ledgerIndex[fullID]; ok {
			prior := nextLedger[priorIndex]
			revision = prior.InventoryRevision
			if prior.RevisionSHA256 != revisionSHA256 {
				if revision == math.MaxUint64 {
					return fmt.Errorf(
						"%w: per-container revision overflow",
						ErrInventoryRevisionLedgerExhausted,
					)
				}
				revision++
			}
			nextLedger[priorIndex].InventoryRevision = revision
			nextLedger[priorIndex].RevisionSHA256 = revisionSHA256
		} else {
			if len(nextLedger) >= inventoryRevisionLedgerMaxEntries {
				return fmt.Errorf(
					"%w: distinct container capacity",
					ErrInventoryRevisionLedgerExhausted,
				)
			}
			nextLedger = append(nextLedger, inventoryRevisionLedgerEntry{
				FullContainerID:   fullID,
				InventoryRevision: revision,
				RevisionSHA256:    revisionSHA256,
			})
			ledgerIndex[fullID] = len(nextLedger) - 1
		}
		nextRecords[index].RevisionSHA256 = revisionSHA256
		nextRecords[index].Identity.InventoryGeneration = nextGeneration
		nextRecords[index].Identity.InventoryRevision = revision
		nextRecords[index].Identity.ObservedAt = observedAt
	}
	sort.Slice(nextLedger, func(left, right int) bool {
		return nextLedger[left].FullContainerID <
			nextLedger[right].FullContainerID
	})
	next := inventoryDiskState{
		SchemaVersion:      inventorySchema,
		Generation:         nextGeneration,
		DockerReconcileGap: false,
		Records:            nextRecords,
		RevisionLedger:     nextLedger,
		DockerNetworks:     nextDockerNetworks,
	}
	return inventory.persistAndAdopt(next)
}

func (inventory *Inventory) SnapshotForCorrelation(
	fullContainerID string,
) (CorrelationInventorySnapshot, error) {
	inventory.mutex.RLock()
	defer inventory.mutex.RUnlock()
	if inventory.state.DockerReconcileGap {
		return CorrelationInventorySnapshot{}, ErrInventoryReconcileRequired
	}
	if !dockerIDPattern.MatchString(fullContainerID) {
		return CorrelationInventorySnapshot{}, ErrContainerNotFound
	}
	record, ok := inventory.records[fullContainerID]
	if !ok || !record.Identity.Running {
		return CorrelationInventorySnapshot{}, ErrContainerNotFound
	}
	if record.Identity.InventoryGeneration != inventory.state.Generation {
		return CorrelationInventorySnapshot{}, ErrInventoryStale
	}
	return CorrelationInventorySnapshot{
		Generation:     inventory.state.Generation,
		Identity:       cloneContainerIdentity(record.Identity),
		DockerNetworks: cloneDockerNetworks(inventory.state.DockerNetworks),
	}, nil
}

func (inventory *Inventory) resolve(
	matches func(string) bool,
) (ContainerIdentityV1, error) {
	inventory.mutex.RLock()
	defer inventory.mutex.RUnlock()
	if inventory.state.DockerReconcileGap {
		return ContainerIdentityV1{}, ErrInventoryReconcileRequired
	}
	var result ContainerIdentityV1
	count := 0
	for fullID, record := range inventory.records {
		if !record.Identity.Running || !matches(fullID) {
			continue
		}
		result = cloneContainerIdentity(record.Identity)
		count++
	}
	switch count {
	case 0:
		return ContainerIdentityV1{}, ErrContainerNotFound
	case 1:
		return result, nil
	default:
		return ContainerIdentityV1{}, ErrAmbiguousContainerPrefix
	}
}

func (inventory *Inventory) ResolvePrefix(
	prefix string,
) (ContainerIdentityV1, error) {
	if len(prefix) < 12 ||
		len(prefix) > 64 ||
		!regexp.MustCompile(`^[0-9a-f]+$`).MatchString(prefix) {
		return ContainerIdentityV1{}, ErrContainerNotFound
	}
	return inventory.resolve(func(fullID string) bool {
		return strings.HasPrefix(fullID, prefix)
	})
}

func (inventory *Inventory) LookupFullID(
	fullID string,
) (ContainerIdentityV1, error) {
	if !dockerIDPattern.MatchString(fullID) {
		return ContainerIdentityV1{}, ErrContainerNotFound
	}
	return inventory.resolve(func(candidate string) bool {
		return candidate == fullID
	})
}

func (inventory *Inventory) CheckNetNSUniqueness(
	ctx context.Context,
	fullID string,
	networkNamespaceInode uint64,
) (NetNSUniquenessV1, error) {
	if !dockerIDPattern.MatchString(fullID) || networkNamespaceInode == 0 {
		return NetNSUniquenessV1{}, ErrContainerNotFound
	}

	inventory.mutex.RLock()
	if inventory.state.DockerReconcileGap {
		inventory.mutex.RUnlock()
		return NetNSUniquenessV1{}, ErrInventoryReconcileRequired
	}
	generation := inventory.state.Generation
	target, ok := inventory.records[fullID]
	inventory.mutex.RUnlock()
	if !ok || !target.Identity.Running {
		return NetNSUniquenessV1{}, ErrContainerNotFound
	}
	if target.ProcessIdentity.NetworkNamespaceInode !=
		networkNamespaceInode {
		return NetNSUniquenessV1{}, ErrInventoryStale
	}

	listed, err := inventory.docker.ContainerList(
		ctx,
		client.ContainerListOptions{All: false, Size: false},
	)
	if err != nil {
		return NetNSUniquenessV1{}, errors.Join(ErrInventoryStale, err)
	}
	seen := make(map[string]struct{}, len(listed.Items))
	targetSeen := false
	for _, summary := range listed.Items {
		if err := ctx.Err(); err != nil {
			return NetNSUniquenessV1{}, err
		}
		if summary.State != container.StateRunning {
			continue
		}
		if !dockerIDPattern.MatchString(summary.ID) {
			return NetNSUniquenessV1{}, errors.Join(
				ErrInventoryStale,
				fmt.Errorf("invalid Docker list identity"),
			)
		}
		if _, duplicate := seen[summary.ID]; duplicate {
			return NetNSUniquenessV1{}, errors.Join(
				ErrInventoryStale,
				fmt.Errorf("duplicate Docker list identity"),
			)
		}
		seen[summary.ID] = struct{}{}
		inspected, err := inventory.docker.ContainerInspect(
			ctx,
			summary.ID,
			client.ContainerInspectOptions{Size: false},
		)
		if err != nil {
			return NetNSUniquenessV1{}, errors.Join(ErrInventoryStale, err)
		}
		if inspected.Container.ID != summary.ID ||
			inspected.Container.State == nil ||
			!inspected.Container.State.Running ||
			inspected.Container.State.Pid <= 0 {
			return NetNSUniquenessV1{}, errors.Join(
				ErrInventoryStale,
				ErrContainerIdentityMismatch,
			)
		}
		liveProcess, err := inventory.processes.ReadProcessIdentity(
			summary.ID,
			inspected.Container.State.Pid,
		)
		if err != nil {
			return NetNSUniquenessV1{}, errors.Join(
				ErrInventoryStale,
				err,
			)
		}
		if err := liveProcess.Validate(); err != nil {
			return NetNSUniquenessV1{}, errors.Join(
				ErrInventoryStale,
				err,
			)
		}
		inode := liveProcess.NetworkNamespaceInode
		if summary.ID == fullID {
			targetSeen = true
			if uint64(inspected.Container.State.Pid) !=
				target.Identity.InitPID ||
				inode != networkNamespaceInode ||
				liveProcess != target.ProcessIdentity {
				return NetNSUniquenessV1{}, ErrInventoryStale
			}
			continue
		}
		if inode == networkNamespaceInode {
			return NetNSUniquenessV1{}, ErrSharedNetworkNamespace
		}
	}
	if !targetSeen {
		return NetNSUniquenessV1{}, ErrInventoryStale
	}

	inventory.mutex.RLock()
	defer inventory.mutex.RUnlock()
	if inventory.state.DockerReconcileGap {
		return NetNSUniquenessV1{}, ErrInventoryReconcileRequired
	}
	if inventory.state.Generation != generation {
		return NetNSUniquenessV1{}, ErrInventoryStale
	}
	snapshotSHA256, err := hashCanonical(inventory.state)
	if err != nil {
		return NetNSUniquenessV1{}, err
	}
	return NetNSUniquenessV1{
		FullContainerID:         fullID,
		NetworkNamespaceInode:   networkNamespaceInode,
		InventoryGeneration:     generation,
		InventorySnapshotSHA256: snapshotSHA256,
		Unique:                  true,
		CheckedAt: inventory.now().UTC().Format(
			time.RFC3339Nano,
		),
	}, nil
}

func (inventory *Inventory) LoggingUnavailable() bool {
	inventory.mutex.RLock()
	defer inventory.mutex.RUnlock()
	for _, record := range inventory.records {
		if record.Identity.Running && !record.DockerLoggingVisible {
			return true
		}
	}
	return false
}

func (inventory *Inventory) Generation() uint64 {
	inventory.mutex.RLock()
	defer inventory.mutex.RUnlock()
	return inventory.state.Generation
}

func (inventory *Inventory) ReconcileGapOpen() bool {
	inventory.mutex.RLock()
	defer inventory.mutex.RUnlock()
	return inventory.state.DockerReconcileGap
}
