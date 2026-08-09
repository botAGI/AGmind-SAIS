//go:build !linux

package actuatord

import "context"

type unsupportedNftBackend struct{}

func NewPlatformNftBackend() NftBackend { return unsupportedNftBackend{} }

func (unsupportedNftBackend) Prepare(
	context.Context,
	ApplyTargetHandle,
	NftApplySpec,
) (PreparedNftMutation, error) {
	return nil, ErrUnsupportedPlatform
}
