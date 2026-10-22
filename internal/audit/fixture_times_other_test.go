//go:build !windows && !darwin

package audit

import (
	"os"
	"time"
)

// setFixtureFileTimes sets atime/mtime. Birth/creation is typically unavailable
// on Linux and cannot be rewritten via portable APIs — callers must not assume
// birth matches the requested value when fileBirthTimeUTC reports unavailable.
func setFixtureFileTimes(path string, atime, mtime, birth time.Time) error {
	_ = birth
	return os.Chtimes(path, atime, mtime)
}
