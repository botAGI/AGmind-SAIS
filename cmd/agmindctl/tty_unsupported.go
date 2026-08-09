//go:build !darwin && !linux

package main

import "os"

func isTerminal(*os.File) bool {
	return false
}
