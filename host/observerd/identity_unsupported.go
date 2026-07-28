//go:build !linux

package observerd

import "agmind.local/sais/internal/uds"

type unsupportedProcessIdentityReader struct{}

func newPlatformProcessIdentityReader() processIdentityReader {
	return unsupportedProcessIdentityReader{}
}

func (unsupportedProcessIdentityReader) ReadProcessIdentity(
	string,
	int,
) (processIdentity, error) {
	return processIdentity{}, uds.ErrUnsupportedPlatform
}

func (unsupportedProcessIdentityReader) NetworkNamespaceInode(
	int,
) (uint64, error) {
	return 0, uds.ErrUnsupportedPlatform
}
