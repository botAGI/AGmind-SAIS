package actuatord

import (
	"context"
	"errors"
	"fmt"
	"regexp"
)

var (
	ErrTargetStale         = errors.New("containment target is stale")
	ErrUnsupportedPlatform = errors.New("actuator requires Linux")
)

var fullDockerIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// PrepareTargetSnapshot contains only independently observed kernel facts.
// The caller-owned handle keeps pidfd/netns alive only through uniqueness and
// must be closed before nonce generation or durable PREPARED publication.
type PrepareTargetSnapshot struct {
	InitPID               uint64
	PIDStartTicks         uint64
	CgroupPathSHA256      string
	NetworkNamespaceInode uint64
	EffectiveCapNetAdmin  bool
}

func (snapshot PrepareTargetSnapshot) validate() error {
	if snapshot.InitPID == 0 ||
		snapshot.PIDStartTicks == 0 ||
		snapshot.NetworkNamespaceInode == 0 ||
		!digestPattern.MatchString(snapshot.CgroupPathSHA256) {
		return fmt.Errorf("%w: invalid kernel identity", ErrTargetStale)
	}
	return nil
}

type TargetResolver interface {
	ResolveForPrepare(
		context.Context,
		string,
		uint64,
	) (PrepareTargetHandle, error)
}

type PrepareTargetHandle interface {
	Snapshot() PrepareTargetSnapshot
	Close() error
}
