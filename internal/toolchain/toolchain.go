// Package toolchain exposes the single source of truth for the baked TypeScript
// toolchain versions (the repo-root toolchain.versions file), shared by the docker
// provider image and the e2b template so they cannot drift. The package test
// (versions_test.go) enforces that both Dockerfiles match the file.
package toolchain

import (
	"bufio"
	"os"
	"strings"
)

// Load parses a toolchain.versions file (name=version lines; blank lines and #
// comments ignored) into a name->version map.
func Load(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	versions := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, version, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		versions[strings.TrimSpace(name)] = strings.TrimSpace(version)
	}
	return versions, sc.Err()
}
