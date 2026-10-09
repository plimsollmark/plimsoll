//go:build unix

package main

import "syscall"

// descriptorLimit returns the process's soft open-file limit, or 0 if it cannot be read.
func descriptorLimit() uint64 {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 0
	}
	return uint64(rl.Cur)
}
