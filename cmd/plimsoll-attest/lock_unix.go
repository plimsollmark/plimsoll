//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// lockFile takes an exclusive lock on f, waiting at most wait for another holder, held
// until unlock or the process ends, so two runs appending to one bundle take turns.
func lockFile(f *os.File, wait time.Duration) (unlock func(), err error) {
	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("locking the bundle: %w", err)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("another run has held the bundle's lock for %v", wait)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
