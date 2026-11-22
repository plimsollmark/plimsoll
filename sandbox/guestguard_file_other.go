//go:build !linux

package sandbox

import "errors"

// guestGuardFolderNoExec cannot read mount flags here, so it refuses: the guard's filter is for
// Linux containers, and a docker daemon on another system runs them in a Linux machine of its
// own, whose folders this process cannot see.
var guestGuardFolderNoExec = func(string) (bool, error) {
	return false, errors.New("the guest guard is written only on Linux")
}
