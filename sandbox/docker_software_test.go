package sandbox

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParseDockerSelectedManifest(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	manifest := `{"Id":"` + digest + `","Os":"linux","Architecture":"amd64","Descriptor":{"digest":"` + digest + `","mediaType":"application/vnd.oci.image.manifest.v1+json"}}`
	want := "oci-manifest:linux/amd64@" + digest
	if got := parseDockerSelectedManifest([]byte(manifest), "linux/amd64"); got != want {
		t.Fatalf("manifest = %q, want %q", got, want)
	}
	for _, raw := range []string{
		strings.Replace(manifest, `"Architecture":"amd64"`, `"Architecture":"arm64"`, 1),
		strings.Replace(manifest, `"digest":"`+digest+`"`, `"digest":"sha256:`+strings.Repeat("b", 64)+`"`, 1),
		strings.Replace(manifest, `image.manifest.v1+json`, `image.index.v1+json`, 1),
		strings.Replace(manifest, `"Descriptor":{`, `"Missing":{`, 1),
	} {
		if got := parseDockerSelectedManifest([]byte(raw), "linux/amd64"); got != "" {
			t.Fatalf("unproven manifest claimed %q", got)
		}
	}
}

func TestDockerDefaultPlatformOverridesDetection(t *testing.T) {
	t.Setenv("DOCKER_DEFAULT_PLATFORM", "linux/arm64")
	if got := dockerSelectedPlatform(context.Background(), ""); got != "linux/arm64" {
		t.Fatalf("selected platform = %q, want explicit override", got)
	}
}

func TestDockerDefaultPlatformCannotSilentlyFallBack(t *testing.T) {
	requireDocker(t)
	t.Setenv("DOCKER_DEFAULT_PLATFORM", "linux/plimsoll-invalid")
	d := testDocker()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := d.Preflight(ctx); err == nil {
		t.Fatal("an unavailable explicit platform passed Preflight")
	}
}

// The daemon reports linux/arm64 while an arm64 image reports variant v8: Docker
// treats them as one platform, so the identity must be established, and written
// the same way whichever form was asked for.
func TestParseDockerSelectedManifestNormalizesPlatform(t *testing.T) {
	digest := "sha256:" + strings.Repeat("c", 64)
	manifest := `{"Id":"` + digest + `","Os":"linux","Architecture":"arm64","Variant":"v8","Descriptor":{"digest":"` + digest + `","mediaType":"application/vnd.oci.image.manifest.v1+json"}}`
	want := "oci-manifest:linux/arm64@" + digest
	for _, platform := range []string{"linux/arm64", "linux/arm64/v8", "linux/aarch64"} {
		if got := parseDockerSelectedManifest([]byte(manifest), platform); got != want {
			t.Fatalf("platform %q: manifest = %q, want %q", platform, got, want)
		}
	}
	if got := parseDockerSelectedManifest([]byte(manifest), "linux/amd64"); got != "" {
		t.Fatalf("an arm64 manifest was claimed for linux/amd64: %q", got)
	}
	for in, want := range map[string]string{
		"linux/amd64": "linux/amd64", "linux/amd64/v1": "linux/amd64", "linux/x86_64": "linux/amd64",
		"linux/amd64/v3": "linux/amd64/v3", "linux/arm64/v8": "linux/arm64", "linux/arm64/v9": "linux/arm64/v9",
		"linux/arm": "linux/arm/v7", "linux/armhf": "linux/arm/v7", "linux/arm/v6": "linux/arm/v6",
	} {
		if got := normalizePlatform(in); got != want {
			t.Fatalf("normalizePlatform(%q) = %q, want %q", in, got, want)
		}
	}
}

// Only a positive signal from docker info selects the containerd store; the
// classic store's driver status has no snapshotter driver-type.
func TestContainerdStoreFromDriverStatus(t *testing.T) {
	for raw, want := range map[string]bool{
		`[["driver-type","io.containerd.snapshotter.v1"]]`:                                       true,
		`[["Backing Filesystem","extfs"],["Supports d_type","true"],["Using metacopy","false"]]`: false,
		`null`: false,
	} {
		got, err := containerdStoreFromDriverStatus([]byte(raw))
		if err != nil || got != want {
			t.Fatalf("%s: got %v, %v; want %v", raw, got, err, want)
		}
	}
	if _, err := containerdStoreFromDriverStatus([]byte("not json")); err == nil {
		t.Fatal("malformed driver status accepted")
	}
}

func TestDockerSoftwareRuleMatchesSelectedManifest(t *testing.T) {
	requireDocker(t)
	d := testDocker()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := d.Preflight(ctx); err != nil {
		infraSkip(t, "Docker preflight: %v", err)
	}
	env := d.Environments().JavaScript
	bad := SoftwareRule{Mode: SoftwareExact, Identities: []string{"oci-manifest:linux/amd64@sha256:" + strings.Repeat("b", 64)}}
	if env.SoftwareIdentity == "" {
		_, err := d.RunJavaScript(ctx, Request{Code: "console.log(42)", Software: bad})
		if !errors.Is(err, ErrSoftwareMismatch) {
			t.Fatalf("unknown selected image must refuse a required rule: %v", err)
		}
		return
	}
	if !strings.HasPrefix(env.SoftwareIdentity, "oci-manifest:linux/") {
		t.Fatalf("unexpected identity: %q", env.SoftwareIdentity)
	}
	good := SoftwareRule{Mode: SoftwareExact, Identities: []string{env.SoftwareIdentity}}
	res, err := d.RunJavaScript(ctx, Request{Code: "console.log(41)", Software: good})
	if err != nil || res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != "41" || res.SoftwareIdentity != env.SoftwareIdentity || res.EnvironmentIdentity != env.Identity {
		t.Fatalf("selected run: %+v, %v; described %+v", res, err, env)
	}
	_, err = d.RunJavaScript(ctx, Request{Code: "console.log(42)", Software: bad})
	if !errors.Is(err, ErrSoftwareMismatch) {
		t.Fatalf("mismatched run: %v", err)
	}
	if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalEnvironment {
		t.Fatalf("mismatched run has no environment refusal: %v, %v", reason, ok)
	}
}
