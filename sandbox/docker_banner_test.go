package sandbox

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The banner is a diagnostic. These tests pin the three properties that keep it
// one: it is read only under runsc, it is bounded and printable, and it can never
// move the isolation tier.

func TestSmokeProbeScriptReadsBannerOnlyWhenAsked(t *testing.T) {
	with, without := smokeProbeScript(true, false), smokeProbeScript(false, false)
	if !strings.Contains(with, "dmesg") {
		t.Fatal("banner script does not read dmesg")
	}
	if strings.Contains(without, "dmesg") || strings.Contains(without, "child_process") {
		t.Fatal("a probe built without the banner still contains the dmesg read")
	}
	for _, s := range []string{with, without} {
		for _, want := range []string{`/proc/mounts`, `/plimsoll-smoke`, `JSON.stringify({ rootWritable, mounts, writable, banner, socket })`} {
			if !strings.Contains(s, want) {
				t.Fatalf("probe lost %q", want)
			}
		}
	}
}

func TestBannerFirstLineIsBoundedAndPrintable(t *testing.T) {
	gvisor := "[    0.000000] Starting gVisor...\n[    0.354495] Daemonizing children...\n"
	cases := []struct{ in, want string }{
		{gvisor, "[    0.000000] Starting gVisor..."},
		{"dmesg: klogctl: Operation not permitted\n", "dmesg: klogctl: Operation not permitted"},
		{"", ""},
		{"\n\n", ""},
		{"line\r\nnext", "line"},
		{"tab\there\x1b[0m and é", "tab?here?[0m and ?"},
		{strings.Repeat("x", 500), strings.Repeat("x", 120)},
	}
	for _, c := range cases {
		if got := bannerFirstLine(c.in); got != c.want {
			t.Errorf("bannerFirstLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRuntimeBannerNeverAffectsIsolation(t *testing.T) {
	forged := "[    0.000000] Starting gVisor..."
	for _, runtime := range []string{"", "runc", "runsc"} {
		d := DefaultDocker("")
		d.Runtime = runtime
		d.runtimeBannerLine, d.runtimeBannerRead = forged, true
		if got := d.IsolationClass(); got != IsolationContainer {
			t.Fatalf("runtime %q with a forged banner and no verified preflight reports %s, want %s", runtime, got, IsolationContainer)
		}
		if line, read := d.RuntimeBanner(); !read || line != forged {
			t.Fatalf("RuntimeBanner did not return what was stored")
		}
	}
}

// TestDockerSmokeBannerFollowsRuntime runs the real smoke probe under the
// configured runtime. Under runc the banner must not be attempted at all; under
// runsc (SANDBOX_DOCKER_RUNTIME=runsc) the result is logged, and whether or not a
// line came back, readiness is unaffected. It does not assert that gVisor
// answers: an unavailable banner is a documented outcome, not a failure.
func TestDockerSmokeBannerFollowsRuntime(t *testing.T) {
	d := testDocker()
	requireSnippetImage(t, d)
	requireProjectImage(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := d.SmokeTest(ctx); err != nil {
		t.Fatalf("SmokeTest: %v", err)
	}
	line, read := d.RuntimeBanner()
	if d.Runtime != "runsc" {
		if read || line != "" {
			t.Fatalf("banner read under runtime %q: %q; the read must only be attempted under runsc", d.Runtime, line)
		}
		return
	}
	t.Logf("runsc banner read=%v line=%q", read, line)
	if read && (len(line) > 120 || line != bannerFirstLine(line)) {
		t.Fatalf("banner line is not bounded printable ASCII: %q", line)
	}
	if got := d.IsolationClass(); got != IsolationKernel {
		t.Fatalf("verified runsc reports %s after SmokeTest, want %s (the banner must not have changed admission either way)", got, IsolationKernel)
	}
}
