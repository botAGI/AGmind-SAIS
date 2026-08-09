//go:build !linux

package actuatord

import (
	"context"
	"time"
)

type unsupportedTargetResolver struct{}

func NewPlatformTargetResolver() TargetResolver {
	return unsupportedTargetResolver{}
}

func (unsupportedTargetResolver) ResolveForPrepare(
	context.Context,
	string,
	uint64,
) (PrepareTargetHandle, error) {
	return nil, ErrUnsupportedPlatform
}

func platformClockSample() (ClockSample, error) {
	return ClockSample{Wall: time.Now().UTC()}, ErrUnsupportedPlatform
}
