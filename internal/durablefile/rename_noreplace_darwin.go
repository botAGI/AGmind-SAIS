//go:build darwin

package durablefile

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func renameNoReplace(
	oldDirectory int,
	oldName string,
	newDirectory int,
	newName string,
) error {
	err := unix.RenameatxNp(
		oldDirectory,
		oldName,
		newDirectory,
		newName,
		unix.RENAME_EXCL,
	)
	if errors.Is(err, unix.EEXIST) {
		return os.ErrExist
	}
	return err
}
