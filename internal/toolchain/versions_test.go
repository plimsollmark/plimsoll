package toolchain

import (
	"os"
	"regexp"
	"testing"
)

// pkgVersion matches "name@1.2.3" install pins (incl. scoped @scope/name@1.2.3) in a
// Dockerfile's `npm install -g` line. node:22 etc. have no @<semver> so won't match.
var pkgVersion = regexp.MustCompile(`([a-z@][a-z0-9@/-]*)@(\d+\.\d+\.\d+)`)

func dockerfilePins(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	pins := map[string]string{}
	for _, m := range pkgVersion.FindAllStringSubmatch(string(data), -1) {
		pins[m[1]] = m[2]
	}
	return pins
}

// TestToolchainVersionsInSync fails if the docker image or the e2b template pins a
// toolchain version that differs from toolchain.versions — the guard that keeps the
// two providers' toolchains from drifting apart.
func TestToolchainVersionsInSync(t *testing.T) {
	want, err := Load("../../toolchain.versions")
	if err != nil {
		t.Fatalf("load toolchain.versions: %v", err)
	}
	if len(want) == 0 {
		t.Fatal("toolchain.versions is empty")
	}

	for _, df := range []string{"../../docker/Dockerfile", "../../e2b/e2b.Dockerfile"} {
		pins := dockerfilePins(t, df)
		for name, version := range want {
			got, ok := pins[name]
			if !ok {
				t.Errorf("%s does not pin %q (expected %s@%s from toolchain.versions)", df, name, name, version)
				continue
			}
			if got != version {
				t.Errorf("%s pins %s@%s, want %s (sync with toolchain.versions)", df, name, got, version)
			}
		}
	}
}
