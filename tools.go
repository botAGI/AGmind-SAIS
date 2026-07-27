//go:build tools

// Package sais pins dependencies used by the subsequent host-service tasks.
package sais

import (
	_ "github.com/google/nftables"
	_ "github.com/moby/moby/api/types"
	_ "github.com/moby/moby/client"
	_ "golang.org/x/sys/unix"
)
