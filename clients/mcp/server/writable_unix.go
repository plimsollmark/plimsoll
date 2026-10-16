//go:build unix

package server

import "syscall"

// writable reports whether this user may make an entry in dir (access(2) with W_OK,
// which counts access-control lists as the kernel does).
func writable(dir string) bool {
	return syscall.Access(dir, 0x2) == nil
}
