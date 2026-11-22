package providerkit

import "strings"

// PinForm is how every provider's refusal names a pinned reference.
const PinForm = "name@sha256:<64 lower-case hex digits>"

// digestPrefix is the one algorithm a pin may name: every provider states a pin as
// "@sha256:" in its settings, its errors and its identities.
const digestPrefix = "sha256:"

// ValidDigest reports whether d is a SHA-256 content digest as the OCI image
// specification writes one (descriptor.md, "Digests"): "sha256:" and an encoded part that
// "MUST match /[a-f0-9]{64}/", where "[A-F] MUST NOT be used". Upper-case hexadecimal is
// refused: docker itself refuses it ("invalid checksum digest format", docker 29.1.3,
// measured 2026-11-18), so a reference written that way never named an image a run
// could use.
func ValidDigest(d string) bool {
	hex, ok := strings.CutPrefix(d, digestPrefix)
	if !ok || len(hex) != 64 {
		return false
	}
	for i := 0; i < len(hex); i++ {
		if c := hex[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// PinnedDigest returns the digest an image reference is pinned by, and whether it is
// pinned: a non-empty name, one '@', and a ValidDigest after it. A name may carry a tag
// (registry:5000/ns/img:tag@sha256:...): the digest is what names the content. Every
// provider and its settings check use this one rule (SANDBOX_REQUIRE_PINNED_IMAGES, the
// identity a pinned image states, the digest a booted sandbox is compared with).
func PinnedDigest(ref string) (string, bool) {
	name, digest, ok := strings.Cut(ref, "@")
	if !ok || name == "" || !ValidDigest(digest) {
		return "", false
	}
	return digest, true
}

// ReportedDigest returns the digest a reported image ID ends in ("<anything>@sha256:..."),
// as a container runtime states one (a Kubernetes pod's imageID, a repository digest), and
// whether it ends in a ValidDigest. It is read, not configured, so what comes before the
// last '@' is not checked.
func ReportedDigest(id string) (string, bool) {
	i := strings.LastIndex(id, "@")
	if i < 0 || !ValidDigest(id[i+1:]) {
		return "", false
	}
	return id[i+1:], true
}
