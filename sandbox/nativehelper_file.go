package sandbox

import (
	"runtime"

	"github.com/plimsollmark/plimsoll/sandbox/internal/nativehelper"
)

// NativeHelperPath is where plimsoll's native helper is in a sandbox whose image carries it.
const NativeHelperPath = nativehelper.InContainer

// NativeHelperFilesVersion is the version of the native helper's file commands
// (docs/session-files.md) this plimsolld carries.
const NativeHelperFilesVersion = nativehelper.FilesVersion

// dockerNativeHelperFile, when a test sets it, is a file on the docker host that every
// container this package starts gets as one read-only bind mount at nativehelper.InContainer
// (lockdownFlags), over the image's own project runner: another build of the native helper
// (plimsoll-helper), so the runner equivalence suite can be run against a changed helper
// (PLIMSOLL_TEST_NATIVE_HELPER_FILE) without rebuilding or retagging the images every
// working copy on a machine shares. dockerNativeHelperWant is then that file's SHA-256 and the
// line its identity command prints, which the startup test requires in their place. Nothing a
// daemon reads sets either.
var (
	dockerNativeHelperFile string
	dockerNativeHelperWant nativehelper.Want
)

// nativeHelperWant is what the startup test requires of a project image's runner
// (smokeNativeHelper): the native helper inside this plimsolld, built for its own machine
// (Preflight refuses a docker daemon or image for another), or the build a test handed in.
func nativeHelperWant() (nativehelper.Want, error) {
	if dockerNativeHelperWant.SHA256 != "" {
		return dockerNativeHelperWant, nil
	}
	return nativehelper.Pinned(runtime.GOARCH)
}
