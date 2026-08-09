package actuatord

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

const (
	nftOwnerMarker = "agmind:pcc:v1"
	nftTableName   = "agmind_pcc"
	nftChainName   = "output"
	nftSetName     = "blocked_v4"
)

var (
	ErrNoApprovedPlan       = errors.New("no approved plan is ready to apply")
	ErrKillSwitchActive     = errors.New("actuator mutation kill switch is active")
	ErrForeignNftCollision  = errors.New("foreign nftables object collision")
	ErrNftNotApplied        = errors.New("nftables mutation is proven absent")
	ErrNftMutationUncertain = errors.New("nftables mutation result is uncertain")
)

type NftApplySpec struct {
	PlanID           string
	DestinationIPv4  string
	TTL              time.Duration
	TargetNetNSInode uint64
}

func (spec NftApplySpec) validate() error {
	destination, err := netip.ParseAddr(spec.DestinationIPv4)
	if err != nil || !destination.Is4() || destination.String() != spec.DestinationIPv4 ||
		!planIDPattern.MatchString(spec.PlanID) || spec.TargetNetNSInode == 0 ||
		spec.TTL < time.Duration(MinTTLSeconds)*time.Second ||
		spec.TTL > time.Duration(MaxTTLSeconds)*time.Second {
		return fmt.Errorf("invalid fixed nft apply specification")
	}
	return nil
}

type ApplyObservation struct {
	TargetNetNSInode              uint64
	RulesetSHA256                 string
	ConfiguredTimeoutMilliseconds uint64
	RemainingTimeoutMilliseconds  uint64
	CounterPackets                uint64
	CounterBytes                  uint64
	HostNetNSBefore               uint64
	HostNetNSAfter                uint64
}

func (observation ApplyObservation) validate(spec NftApplySpec) error {
	configured := uint64(spec.TTL / time.Millisecond)
	if err := spec.validate(); err != nil ||
		observation.TargetNetNSInode != spec.TargetNetNSInode ||
		!digestPattern.MatchString(observation.RulesetSHA256) ||
		observation.ConfiguredTimeoutMilliseconds != configured ||
		observation.RemainingTimeoutMilliseconds == 0 ||
		observation.RemainingTimeoutMilliseconds > configured ||
		observation.HostNetNSBefore == 0 ||
		observation.HostNetNSBefore != observation.HostNetNSAfter {
		return fmt.Errorf("invalid nft apply observation")
	}
	return nil
}

type PreparedNftMutation interface {
	ExpectedRulesetSHA256() string
	FlushOnceAndVerify(context.Context) (ApplyObservation, error)
	Close() error
}

type NftBackend interface {
	// Prepare is read-only with respect to the kernel. It may stage an in-memory
	// batch, but the returned capability is the only object allowed to Flush it.
	Prepare(
		context.Context,
		ApplyTargetHandle,
		NftApplySpec,
	) (PreparedNftMutation, error)
}

type ExpiryObservation struct {
	TargetNetNSInode uint64
	RulesetSHA256    string
	ElementPresent   bool
	HostNetNSBefore  uint64
	HostNetNSAfter   uint64
}

func (observation ExpiryObservation) validate(spec NftApplySpec) error {
	if err := spec.validate(); err != nil ||
		observation.TargetNetNSInode != spec.TargetNetNSInode ||
		!digestPattern.MatchString(observation.RulesetSHA256) ||
		observation.HostNetNSBefore == 0 ||
		observation.HostNetNSBefore != observation.HostNetNSAfter {
		return fmt.Errorf("invalid nft expiry observation")
	}
	return nil
}

type NftExpiryBackend interface {
	// InspectExpiry is strictly read-only. It must never enqueue a netlink
	// mutation or call Flush, even when it finds an overstaying element.
	InspectExpiry(
		context.Context,
		ApplyTargetHandle,
		NftApplySpec,
	) (ExpiryObservation, error)
}

type NftRecoveryBackend interface {
	// InspectApplied classifies the exact element after a durable APPLY_INTENT.
	// present=false is a proof of absence; it never creates or extends state.
	InspectApplied(
		context.Context,
		ApplyTargetHandle,
		NftApplySpec,
	) (observation ApplyObservation, present bool, err error)
}
