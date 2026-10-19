// Package dockertest gives a test in any package under sandbox the docker provider the
// docker suite configures: the runtime and seccomp profile it selects, its two images.
// Without docker or the images the test skips, or fails when the suite requires docker
// (SANDBOX_TEST_REQUIRE_DOCKER=1, which make docker-suite sets), so a suite that was asked
// for proof cannot pass by skipping. Only tests import it.
package dockertest

import (
	"os"
	"os/exec"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// Sandbox returns the docker provider for a test, or ends the test as described above.
// It also skips in -short mode, which make audit's race pass uses: docker tests run only
// in the docker suite.
func Sandbox(t testing.TB) *sandbox.DockerSandbox {
	t.Helper()
	skip := func(format string, args ...any) {
		t.Helper()
		if os.Getenv("SANDBOX_TEST_REQUIRE_DOCKER") == "1" {
			t.Fatalf("docker coverage was required (SANDBOX_TEST_REQUIRE_DOCKER=1) but its infrastructure is missing: "+format, args...)
		}
		t.Skipf(format, args...)
	}
	if testing.Short() {
		skip("skipping docker test in -short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		skip("docker not available")
	}
	d := sandbox.DefaultDocker("")
	d.Runtime = os.Getenv("SANDBOX_DOCKER_RUNTIME")
	d.Seccomp = os.Getenv("SANDBOX_DOCKER_SECCOMP")
	for _, img := range []string{d.Image, d.ProjectImage} {
		if err := exec.Command("docker", "image", "inspect", img).Run(); err != nil {
			skip("image %s is not present (run `make docker-images`)", img)
		}
	}
	return d
}
