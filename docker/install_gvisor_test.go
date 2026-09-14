package docker

import (
	"crypto/sha512"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the installer without root, network access, or system writes. The
// fixture runtime refuses any attempt to enable downloads or register globally.
func TestInstallerVerifiesCompleteOfflineBundle(t *testing.T) {
	for _, tool := range []string{"bash", "tar", "zstd", "sha512sum"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("installer test requires %s", tool)
		}
	}
	script, err := os.ReadFile("install-gvisor.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		missing bool
		tamper  bool
		version string
		want    string
	}{
		{name: "complete", version: "20260907.0", want: "Verified gVisor"},
		{name: "tampered", tamper: true, version: "20260907.0", want: "FAILED"},
		{name: "missing sidecar", missing: true, version: "20260907.0", want: "bundle lacks executable gvisor-bin/sentry"},
		{name: "wrong version", version: "20260714.0", want: "bundle version differs from manifest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			installer := filepath.Join(dir, "docker", "install-gvisor.sh")
			put := func(path, value string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(value), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			put(installer, string(script))
			bundleDir := filepath.Join(dir, "bundle")
			put(filepath.Join(bundleDir, "runsc"), fmt.Sprintf(`#!/usr/bin/env bash
set -eu
if [[ "$1" == --version ]]; then echo 'runsc version release-%s'; exit; fi
[[ "$1" == install && "$2" == --download-sidecars=NEVER && "$3" == --require-sidecars=ALWAYS ]]
[[ "$4" == --config_file=*/tmp/gvisor-install.*/daemon.json ]]
[[ "$5" == -- && "$6" == --host-uds=open && $# -eq 6 ]]
`, tc.version))
			put(filepath.Join(bundleDir, "shim"), "fixture")
			if !tc.missing {
				put(filepath.Join(bundleDir, "gvisor-bin", "sentry"), "fixture")
			}
			archive := filepath.Join(dir, "bundle.tar.zstd")
			if out, err := exec.Command("tar", "--zstd", "-cf", archive, "-C", bundleDir, ".").CombinedOutput(); err != nil {
				t.Fatalf("fixture archive: %v: %s", err, out)
			}
			raw, err := os.ReadFile(archive)
			if err != nil {
				t.Fatal(err)
			}
			hash := fmt.Sprintf("%x", sha512.Sum512(raw))
			put(filepath.Join(dir, "docker", "gvisor.versions"), fmt.Sprintf("release=20260907.0\nsha512_x86_64=%s\nsha512_aarch64=%s\nexecutables=runsc shim gvisor-bin/sentry\n", hash, hash))
			if tc.tamper {
				put(archive, "tampered archive")
			}
			out, err := exec.Command("bash", installer, "--verify-only", "--archive", archive).CombinedOutput()
			if (err == nil) != (tc.name == "complete") || !strings.Contains(string(out), tc.want) {
				t.Fatalf("installer = %v, %s; want %q", err, out, tc.want)
			}
			stages, err := filepath.Glob(filepath.Join(dir, "tmp", "gvisor-install.*"))
			if err != nil || len(stages) != 0 {
				t.Fatalf("installer left staging files: %v, %v", stages, err)
			}
		})
	}
}
