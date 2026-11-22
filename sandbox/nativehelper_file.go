package sandbox

import (
	"runtime"

	"github.com/plimsollmark/plimsoll/sandbox/internal/nativehelper"
)

// dockerNativeHelperFile, when a test sets it, is a file on the docker host that every
// container this package starts gets as one read-only bind mount at nativehelper.InContainer
// (lockdownFlags), over the image's own project runner: another build of the native helper
// (plimsoll-helper), so the runner equivalence suite can be run against a changed helper
// (PLIMSOLL_TEST_NATIVE_HELPER_FILE) without rebuilding or retagging the images every
// working copy on a machine shares. dockerNativeHelperSum is then that file's SHA-256, the
// one the startup test requires in its place. Nothing a daemon reads sets either.
var (
	dockerNativeHelperFile string
	dockerNativeHelperSum  string
)

// nativeHelperWant is the SHA-256 the startup test requires of a project image's runner
// (smokeNativeHelper): the native helper inside this plimsolld, built for its own machine
// (Preflight refuses a docker daemon or image for another), or the build a test handed in.
func nativeHelperWant() (string, error) {
	if dockerNativeHelperSum != "" {
		return dockerNativeHelperSum, nil
	}
	return nativehelper.SHA256(runtime.GOARCH)
}
