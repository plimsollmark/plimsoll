package providerkit

import (
	"strings"
	"testing"
)

// TestPinnedDigest is the one table for what every provider accepts as a pinned image
// (docker, Docker Cloud's image and store image, openshell, agentsandbox, wslc). Before
// 2026-11-18 the providers answered it four ways: docker, Docker Cloud and openshell took
// upper-case hexadecimal and lower-cased it; agentsandbox and wslc took a reference with
// no name; all of them took a second '@'.
func TestPinnedDigest(t *testing.T) {
	lo := strings.Repeat("0123456789abcdef", 4)
	up := strings.ToUpper(lo)
	for _, tc := range []struct {
		ref    string
		pinned bool
		why    string
	}{
		{"img@sha256:" + lo, true, "a name and a lower-case sha256 digest"},
		{"registry.example:5000/ns/img:tag@sha256:" + lo, true, "a registry, a tag and a digest: the digest names the content"},
		{"tmpl_abc@sha256:" + lo, true, "a Docker Cloud store image ID"},
		{"img@sha256:" + up, false, "the OCI specification: [A-F] MUST NOT be used; docker refuses it too"},
		{"img@sha256:" + lo[:32] + up[32:], false, "mixed case is upper case"},
		{"img@SHA256:" + lo, false, "the algorithm is lower case"},
		{"img@sha256:" + lo[:63], false, "63 hex digits"},
		{"img@sha256:" + lo + "0", false, "65 hex digits"},
		{"img@sha256:" + lo[:63] + "g", false, "not hexadecimal"},
		{"img@sha256:" + lo + "\n", false, "a trailing newline"},
		{"img@sha256:" + lo + " ", false, "a trailing space"},
		{"img@sha512:" + lo + lo, false, "only sha256 is a pin here"},
		{"img:tag", false, "a tag can be repushed"},
		{"img", false, "no digest"},
		{"", false, "empty"},
		{"@sha256:" + lo, false, "no name before the digest"},
		{"a@b@sha256:" + lo, false, "a second '@'"},
		{"sha256:" + lo, false, "a digest alone is not a reference"},
	} {
		digest, pinned := PinnedDigest(tc.ref)
		if pinned != tc.pinned {
			t.Errorf("PinnedDigest(%q) pinned = %v, want %v (%s)", tc.ref, pinned, tc.pinned, tc.why)
		}
		if pinned && digest != tc.ref[strings.LastIndex(tc.ref, "@")+1:] {
			t.Errorf("PinnedDigest(%q) = %q, want the digest after the '@'", tc.ref, digest)
		}
		if !pinned && digest != "" {
			t.Errorf("PinnedDigest(%q) = %q for a reference that is not pinned", tc.ref, digest)
		}
	}
}

func TestValidDigestAndReportedDigest(t *testing.T) {
	lo := strings.Repeat("0123456789abcdef", 4)
	for d, want := range map[string]bool{
		"sha256:" + lo: true, "sha256:" + strings.ToUpper(lo): false, "sha256:" + lo[:63]: false, "sha256:": false,
		"sha512:" + lo + lo: false, lo: false, " sha256:" + lo: false,
	} {
		if ValidDigest(d) != want {
			t.Errorf("ValidDigest(%q) = %v, want %v", d, !want, want)
		}
	}
	for id, want := range map[string]string{
		"docker-pullable://img@sha256:" + lo:   "sha256:" + lo,
		"registry.example/img@sha256:" + lo:    "sha256:" + lo,
		"@sha256:" + lo:                        "sha256:" + lo,
		"img@sha256:" + strings.ToUpper(lo):    "",
		"img@sha256:" + lo + "@x":              "",
		"sha256:" + lo:                         "",
		"img:tag":                              "",
		"a@b@sha256:" + lo:                     "sha256:" + lo,
		"containerd://img@sha256:" + lo + "\n": "",
		"img@sha256:" + lo[:63]:                "",
	} {
		got, ok := ReportedDigest(id)
		if got != want || ok != (want != "") {
			t.Errorf("ReportedDigest(%q) = %q, %v; want %q", id, got, ok, want)
		}
	}
}
