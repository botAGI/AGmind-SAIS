//go:build !linux

package uds_test

import (
	"errors"
	"net"
	"testing"

	"agmind.local/sais/internal/uds"
)

func TestPeerCredentialsFailClosedOnUnsupportedPlatform(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	if _, err := uds.PeerCredentials(left); !errors.Is(
		err,
		uds.ErrUnsupportedPlatform,
	) {
		t.Fatalf("got %v, want ErrUnsupportedPlatform", err)
	}
	if _, err := uds.PeerInGroup(
		uds.Peer{PID: 1},
		0,
	); !errors.Is(err, uds.ErrUnsupportedPlatform) {
		t.Fatalf("group lookup got %v, want ErrUnsupportedPlatform", err)
	}
}
