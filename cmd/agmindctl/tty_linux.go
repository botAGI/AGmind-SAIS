//go:build linux

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

func isTerminal(file *os.File) bool {
	if file == nil {
		return false
	}
	_, err := unix.IoctlGetTermios(int(file.Fd()), unix.TCGETS)
	return err == nil
}
