package sandbox

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// These tests create real, billable Docker Cloud sandboxes. They run only when
// DOCKER_SBX_TOKEN and SANDBOX_DOCKERCLOUD_API_URL are both set, and skip
// otherwise; the ordinary gate strips the token (Makefile NO_PAID_KEYS) so they
// cannot run by accident. `make dockercloud-suite` sets DOCKERCLOUD_LIVE_REQUIRED=1,
// under which missing configuration fails instead of skipping, so a green
// deliberate run means the live service was actually exercised.
//
// Each test creates one or two sandboxes for a few seconds; at the published
// rate (from $0.07 an hour) the whole suite costs well under one cent.
func dockerCloudLive(t *testing.T) *DockerCloud {
	t.Helper()
	token := os.Getenv("DOCKER_SBX_TOKEN")
	user := os.Getenv("DOCKER_SBX_USERNAME")
	apiURL := os.Getenv("SANDBOX_DOCKERCLOUD_API_URL")
	if token == "" || user == "" || apiURL == "" {
		if os.Getenv("DOCKERCLOUD_LIVE_REQUIRED") == "1" {
			t.Fatal("the live dockercloud suite was required but DOCKER_SBX_TOKEN, DOCKER_SBX_USERNAME or SANDBOX_DOCKERCLOUD_API_URL is not set")
		}
		t.Skip("DOCKER_SBX_TOKEN, DOCKER_SBX_USERNAME and SANDBOX_DOCKERCLOUD_API_URL not set")
	}
	image := os.Getenv("SANDBOX_DOCKERCLOUD_IMAGE")
	if image == "" {
		t.Fatal("SANDBOX_DOCKERCLOUD_IMAGE must name the toolchain image for the live suite")
	}
	return &DockerCloud{Token: token, Username: user, AuthURL: os.Getenv("SANDBOX_DOCKERCLOUD_AUTH_URL"), APIURL: apiURL, Image: image, DefaultTimeout: 60 * time.Second, MaxTimeout: 90 * time.Second,
		MaxVCPU: 1, MaxMemoryMB: 2048} // Micro, the smallest and cheapest size
}

// TestDockerCloudSmokeLive is the startup proof against the real service:
// capabilities, deny-all egress read back and probed from inside the guest, the
// wrapper's tools present, and the step working directory honored.
func TestDockerCloudSmokeLive(t *testing.T) {
	d := dockerCloudLive(t)
	start := time.Now()
	if err := d.SmokeTest(context.Background()); err != nil {
		t.Fatalf("SmokeTest: %v", err)
	}
	t.Logf("smoke passed in %v", time.Since(start))
}

func TestDockerCloudRunJavaScriptLive(t *testing.T) {
	d := dockerCloudLive(t)
	res, err := d.RunJavaScript(context.Background(), Request{Code: `console.log("dockercloud", 6*7)`})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "dockercloud 42") || res.Isolation != IsolationVM {
		t.Fatalf("got exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
	t.Logf("ok in %v", res.Duration)
}

func TestDockerCloudRunProjectLive(t *testing.T) {
	d := dockerCloudLive(t)
	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files: []File{
			{Path: "lib/util.mjs", Content: "export const add = (a, b) => a + b;\n"},
			{Path: "main.mjs", Content: "import { add } from './lib/util.mjs';\nimport { writeFileSync } from 'node:fs';\nwriteFileSync('out.txt', String(add(2, 3)));\nconsole.log('sum', add(2, 3));\n"},
		},
		Steps:     []string{"node main.mjs"},
		Artifacts: []string{"out.txt", "absent.txt"},
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 || !strings.Contains(res.Steps[0].Stdout, "sum 5") {
		t.Fatalf("got %+v", res)
	}
	if len(res.Artifacts) != 1 || res.Artifacts[0].Path != "out.txt" || string(res.Artifacts[0].Content) != "5" {
		t.Fatalf("artifacts = %+v", res.Artifacts)
	}
}

// TestDockerCloudBoundsLive proves the bounds the API does not provide: a flood is
// capped and reported as truncated, and a hung snippet is ended by the in-guest
// limit and reported as a timeout.
func TestDockerCloudBoundsLive(t *testing.T) {
	d := dockerCloudLive(t)
	d.MaxOutputBytes = 1024
	res, err := d.RunJavaScript(context.Background(), Request{Code: `process.stdout.write("x".repeat(1 << 20))`})
	if err != nil {
		t.Fatalf("flood: %v", err)
	}
	if !res.StdoutTruncated || len(res.Stdout) != 1024 {
		t.Fatalf("flood: truncated=%v len=%d", res.StdoutTruncated, len(res.Stdout))
	}
	res, err = d.RunJavaScript(context.Background(), Request{Code: `for (;;) {}`, Timeout: 8 * time.Second})
	if err != nil {
		t.Fatalf("hang: %v", err)
	}
	if !res.TimedOut || res.ExitCode != 124 {
		t.Fatalf("hang: %+v", res)
	}
}

func TestDockerCloudOrphanListingLive(t *testing.T) {
	d := dockerCloudLive(t)
	n, err := d.ReconcileOrphans(context.Background())
	if err != nil {
		t.Fatalf("ReconcileOrphans: %v", err)
	}
	if n != 0 {
		t.Fatalf("a fresh instance reaped %d sandboxes; it must only ever match its own name prefix", n)
	}
}
