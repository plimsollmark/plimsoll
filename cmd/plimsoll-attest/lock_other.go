//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package main

import (
	"os"
	"time"
)

// lockFile takes no lock on this platform: do not run two plimsoll-attest run
// commands on one bundle at once here (the usage text says so), or the second breaks
// the bundle's chain.
func lockFile(*os.File, time.Duration) (unlock func(), err error) { return func() {}, nil }
