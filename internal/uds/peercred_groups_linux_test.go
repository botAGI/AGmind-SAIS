//go:build linux

package uds

import (
	"errors"
	"strings"
	"testing"
)

func TestPeerInGroupStatusRequiresMatchingKernelIdentity(t *testing.T) {
	peer := Peer{PID: 123, UID: 1001, GID: 1002}
	valid := "" +
		"Name:\ttest\n" +
		"Pid:\t123\n" +
		"Uid:\t1001\t1001\t1001\t1001\n" +
		"Gid:\t1002\t1002\t1002\t1002\n" +
		"Groups:\t1002 2000 3000\n"
	member, err := peerInGroupStatus(peer, 2000, []byte(valid))
	if err != nil || !member {
		t.Fatalf("valid supplementary group member=%v err=%v", member, err)
	}
	member, err = peerInGroupStatus(peer, 4000, []byte(valid))
	if err != nil || member {
		t.Fatalf("absent supplementary group member=%v err=%v", member, err)
	}

	for name, status := range map[string]string{
		"pid mismatch": strings.Replace(valid, "Pid:\t123", "Pid:\t124", 1),
		"uid mismatch": strings.Replace(
			valid,
			"1001\t1001\t1001\t1001",
			"1001\t1001\t1001\t9999",
			1,
		),
		"gid mismatch": strings.Replace(
			valid,
			"1002\t1002\t1002\t1002",
			"1002\t1002\t1002\t9999",
			1,
		),
		"missing groups": strings.Replace(
			valid,
			"Groups:\t1002 2000 3000\n",
			"",
			1,
		),
		"duplicate pid":   valid + "Pid:\t123\n",
		"malformed group": strings.Replace(valid, "2000", "-1", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := peerInGroupStatus(
				peer,
				2000,
				[]byte(status),
			); !errors.Is(err, ErrInvalidPeer) {
				t.Fatalf("got %v, want ErrInvalidPeer", err)
			}
		})
	}
}

func TestPeerInGroupStatusRejectsOversizedInput(t *testing.T) {
	if _, err := peerInGroupStatus(
		Peer{PID: 1, UID: 0, GID: 0},
		0,
		[]byte(strings.Repeat("x", peerStatusMaxBytes+1)),
	); !errors.Is(err, ErrInvalidPeer) {
		t.Fatalf("got %v, want ErrInvalidPeer", err)
	}
}
