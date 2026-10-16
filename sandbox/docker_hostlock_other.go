//go:build !unix

package sandbox

import "os"

// holdHostDir has no lock to take where BSD locks do not exist; systemd-tmpfiles, the
// cleaner it guards against, runs only on Linux.
func holdHostDir(dir string) (*os.File, error) {
	return os.Open(dir)
}
