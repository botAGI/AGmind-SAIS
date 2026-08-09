package actuatord

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"agmind.local/sais/host/observerd"
	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/specialuse"
)

const (
	MinTTLSeconds                  = uint64(30)
	DefaultTTLSeconds              = uint64(120)
	MaxTTLSeconds                  = uint64(300)
	ApprovalTTL                    = 5 * time.Minute
	MaxPendingPlans                = 32
	maxAcceptedIntentAge           = 2 * time.Minute
	maxInventoryObservationAge     = 10 * time.Second
	maxIntegrityObservationAge     = 10 * time.Second
	maxUniquenessObservationAge    = 5 * time.Second
	PerMinuteIntents               = 3
	PerHourIntents                 = 20
	pinnedSpecialUseRegistrySHA256 = "e3e39e76d00b1677335db8e9a805c7b9480ea2f4dc9e33f0b93cd3a905128d73"
)

var (
	ErrIntentRejected     = errors.New("containment intent rejected")
	ErrIntentEquivocation = errors.New("intent ID equivocation")
	ErrObserverUnhealthy  = errors.New("observer is not healthy")
	ErrPendingLimit       = errors.New("pending plan limit reached")
	ErrIntentRateLimited  = errors.New("actuator intent rate limited")
	digestPattern         = regexp.MustCompile(`^[0-9a-f]{64}$`)
	intentIDPattern       = regexp.MustCompile(`^int_[0-9a-f]{32}$`)
)

type SafetySnapshot struct {
	SpecialUseRegistryRaw     []byte
	SpecialUseRegistrySHA256  string
	ManagementDeniedNetworks  []string
	ManagementDeniedAddresses []string
	ManagementDenylistSHA256  string
}

func (snapshot SafetySnapshot) validatedRegistry() (specialuse.Registry, error) {
	if len(snapshot.SpecialUseRegistryRaw) == 0 ||
		len(snapshot.SpecialUseRegistryRaw) > 65_536 ||
		snapshot.SpecialUseRegistrySHA256 != pinnedSpecialUseRegistrySHA256 ||
		snapshot.ManagementDeniedNetworks == nil ||
		snapshot.ManagementDeniedAddresses == nil ||
		!digestPattern.MatchString(snapshot.ManagementDenylistSHA256) {
		return nil, fmt.Errorf("%w: invalid safety snapshot", ErrIntentRejected)
	}
	sum := sha256.Sum256(snapshot.SpecialUseRegistryRaw)
	if fmt.Sprintf("%x", sum) != pinnedSpecialUseRegistrySHA256 {
		return nil, fmt.Errorf("%w: special-use registry pin mismatch", ErrIntentRejected)
	}
	registry, err := specialuse.Load(bytes.NewReader(snapshot.SpecialUseRegistryRaw))
	if err != nil || len(registry) == 0 {
		return nil, fmt.Errorf("%w: invalid special-use registry", ErrIntentRejected)
	}
	expected, err := contracts.PCCManagementDenylistSHA256(
		snapshot.ManagementDeniedNetworks,
		snapshot.ManagementDeniedAddresses,
	)
	if err != nil || expected != snapshot.ManagementDenylistSHA256 {
		return nil, fmt.Errorf("%w: management denylist binding", ErrIntentRejected)
	}
	return registry, nil
}

func parsedDeniedDestinations(snapshot SafetySnapshot) ([]netip.Prefix, []netip.Addr, error) {
	networks := make([]netip.Prefix, len(snapshot.ManagementDeniedNetworks))
	for index, raw := range snapshot.ManagementDeniedNetworks {
		value, err := netip.ParsePrefix(raw)
		if err != nil || !value.Addr().Is4() || value.Masked() != value || value.String() != raw {
			return nil, nil, fmt.Errorf("invalid management network")
		}
		networks[index] = value
	}
	addresses := make([]netip.Addr, len(snapshot.ManagementDeniedAddresses))
	for index, raw := range snapshot.ManagementDeniedAddresses {
		value, err := netip.ParseAddr(raw)
		if err != nil || !value.Is4() || value.String() != raw {
			return nil, nil, fmt.Errorf("invalid management address")
		}
		addresses[index] = value
	}
	return networks, addresses, nil
}

func configuredNamespaceMutationCapability(capabilities []string) bool {
	for _, capability := range capabilities {
		normalized := strings.TrimPrefix(strings.ToUpper(capability), "CAP_")
		if normalized == "NET_ADMIN" || normalized == "SYS_ADMIN" || normalized == "ALL" {
			return true
		}
	}
	return false
}

func supportedNetworkIdentity(identity observerd.ContainerIdentityV1) bool {
	if identity.NetworkMode == "host" || identity.NetworkMode == "none" ||
		strings.HasPrefix(identity.NetworkMode, "container:") ||
		strings.HasPrefix(identity.NetworkMode, "service:") ||
		identity.NetworkDriver != "bridge" || len(identity.AttachedNetworks) == 0 {
		return false
	}
	for _, network := range identity.AttachedNetworks {
		if network.Driver != "bridge" {
			return false
		}
	}
	return true
}

func destinationTouchesDocker(
	destination netip.Addr,
	networks []contracts.PCCDockerNetworkV1,
) (bool, error) {
	if _, err := contracts.PCCDockerNetworkSnapshotSHA256(networks); err != nil {
		return false, err
	}
	for _, network := range networks {
		for _, raw := range network.SubnetCIDRs {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return false, err
			}
			if prefix.Contains(destination) {
				return true, nil
			}
		}
		for _, raw := range network.GatewayAddresses {
			gateway, err := netip.ParseAddr(raw)
			if err != nil {
				return false, err
			}
			if gateway == destination {
				return true, nil
			}
		}
	}
	return false, nil
}

func attachedNetworksMatchGlobal(
	attached []observerd.AttachedNetworkV1,
	networks []contracts.PCCDockerNetworkV1,
) bool {
	for _, target := range attached {
		index, found := slices.BinarySearchFunc(
			networks,
			target.NetworkID,
			func(network contracts.PCCDockerNetworkV1, id string) int {
				return strings.Compare(network.NetworkID, id)
			},
		)
		if !found {
			return false
		}
		global := networks[index]
		if global.Driver != target.Driver ||
			!slices.Equal(global.SubnetCIDRs, target.SubnetCIDRs) ||
			!slices.Equal(global.GatewayAddresses, target.GatewayAddresses) {
			return false
		}
	}
	return true
}

func validateHardLimits(
	intent contracts.TemporaryEgressDenyIntentV1,
	identity observerd.ContainerIdentityV1,
	networks []contracts.PCCDockerNetworkV1,
	safety SafetySnapshot,
	now time.Time,
) error {
	return validateHardLimitsForPhase(intent, identity, networks, safety, now, true)
}

func validateApplyHardLimits(
	intent contracts.TemporaryEgressDenyIntentV1,
	identity observerd.ContainerIdentityV1,
	networks []contracts.PCCDockerNetworkV1,
	safety SafetySnapshot,
	now time.Time,
) error {
	return validateHardLimitsForPhase(intent, identity, networks, safety, now, false)
}

func validateHardLimitsForPhase(
	intent contracts.TemporaryEgressDenyIntentV1,
	identity observerd.ContainerIdentityV1,
	networks []contracts.PCCDockerNetworkV1,
	safety SafetySnapshot,
	now time.Time,
	requireFreshIntent bool,
) error {
	if err := intent.Validate(); err != nil {
		return errors.Join(ErrIntentRejected, err)
	}
	if err := identity.Validate(); err != nil {
		return errors.Join(ErrIntentRejected, err)
	}
	registry, err := safety.validatedRegistry()
	if err != nil {
		return err
	}
	created, err := time.Parse(time.RFC3339Nano, intent.CreatedAt)
	if err != nil || created.After(now) ||
		(requireFreshIntent && now.Sub(created) > maxAcceptedIntentAge) {
		return fmt.Errorf("%w: stale intent", ErrIntentRejected)
	}
	if intent.TTLSeconds < MinTTLSeconds || intent.TTLSeconds > MaxTTLSeconds ||
		!identity.Running || identity.Privileged ||
		configuredNamespaceMutationCapability(identity.ConfiguredCapAdd) ||
		identity.EffectiveCapNetAdmin || !supportedNetworkIdentity(identity) ||
		!attachedNetworksMatchGlobal(identity.AttachedNetworks, networks) {
		return fmt.Errorf("%w: target exceeds hard limits", ErrIntentRejected)
	}
	destination, err := netip.ParseAddr(intent.DestinationIPv4)
	if err != nil || !destination.Is4() || destination.String() != intent.DestinationIPv4 {
		return fmt.Errorf("%w: invalid destination", ErrIntentRejected)
	}
	deniedNetworks, deniedAddresses, err := parsedDeniedDestinations(safety)
	if err != nil || !specialuse.IsPermittedPublicIPv4(
		destination,
		registry,
		deniedNetworks,
		deniedAddresses,
	) {
		return fmt.Errorf("%w: destination is not permitted public IPv4", ErrIntentRejected)
	}
	touchesDocker, err := destinationTouchesDocker(destination, networks)
	if err != nil || touchesDocker {
		return fmt.Errorf("%w: Docker infrastructure destination", ErrIntentRejected)
	}
	return nil
}

func intentMatchesIdentity(
	intent contracts.TemporaryEgressDenyIntentV1,
	identity observerd.ContainerIdentityV1,
) bool {
	return intent.DockerContainerID == identity.FullContainerID &&
		intent.DockerStartedAt == identity.DockerStartedAt &&
		intent.ImageID == identity.ImageID &&
		slices.Equal(intent.RepoDigests, identity.RepoDigests) &&
		intent.ImmutableSpecSHA256 == identity.ImmutableSpecSHA256 &&
		intent.InventoryGeneration == identity.InventoryGeneration &&
		intent.InventoryRevision == identity.InventoryRevision
}
