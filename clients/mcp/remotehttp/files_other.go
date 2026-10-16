//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package remotehttp

import (
	"errors"
	"os"
)

var errPlatform = errors.New("remote HTTP hosting requires a supported Unix host; stdio remains available on this platform")

func privateDir(string) error                                { return errPlatform }
func openPrivate(string, int, os.FileMode) (*os.File, error) { return nil, errPlatform }
func lockState(string) (*os.File, error)                     { return nil, errPlatform }
