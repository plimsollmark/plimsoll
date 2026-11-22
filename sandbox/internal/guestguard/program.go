package guestguard

import (
	"embed"
	"fmt"
)

// The guard program: program/guard.c with guest_filter.h, built by program/build.sh statically
// against musl, one file per machine, program/guard_<goarch>. program/guard.sha256 pins the
// inputs of the build (guard.c, guest_filter.h, build.sh) and each file it installed; the
// package's tests fail when the bytes and the pin disagree, and when an input changed without
// a rebuild. (The C source sits in its own folder because the go tool refuses C files in a
// package that does not use cgo.)
//
//go:embed program/guard_* program/guard.sha256
var programFiles embed.FS

// ProgramFile is the built guard's file name for goarch.
func ProgramFile(goarch string) string { return "program/guard_" + goarch }

// Program is the committed bytes of the guard program for goarch (amd64 today; arm64 is built
// by build.sh and compared across two builds, but not installed until it has run under the
// docker tests on an arm64 host). An error names a machine with no guard: no guest code may be
// started there behind a guard that does not exist.
func Program(goarch string) ([]byte, error) {
	b, err := programFiles.ReadFile(ProgramFile(goarch))
	if err != nil {
		return nil, fmt.Errorf("no guest guard program is built for %s (build.sh installs amd64 only until an arm64 build has run under its tests): %w", goarch, err)
	}
	return b, nil
}
