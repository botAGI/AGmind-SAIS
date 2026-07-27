//go:build !linux

package uds

import (
	"net"
	"os"
)

func PeerCredentials(net.Conn) (Peer, error) {
	return Peer{}, ErrUnsupportedPlatform
}

func PeerInGroup(Peer, uint32) (bool, error) {
	return false, ErrUnsupportedPlatform
}

func listenOwned(string, os.FileMode, int) (*ownedListener, error) {
	return nil, ErrUnsupportedPlatform
}
