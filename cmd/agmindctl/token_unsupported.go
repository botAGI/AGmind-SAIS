//go:build !linux && !darwin

package main

import (
	"fmt"
	"io"
)

func rotateCoreAPITokenCommand(io.Writer) error {
	return fmt.Errorf("token rotation requires Linux")
}
