package sandbox

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// noSandboxServer is a provider API that fails the test on any request: a warm-only
// open must be refused before the provider asks its service for anything.
func noSandboxServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("a warm-only open reached the provider's API: %s %s", r.Method, r.URL.Path)
		http.Error(w, "no", http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func wantNoWarmSandbox(t *testing.T, what string, err error) {
	t.Helper()
	if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalCapacity || !errors.Is(err, ErrNoWarmSandbox) || !errors.Is(err, ErrAtCapacity) {
		t.Fatalf("%s: a warm-only open = %v (reason %v, marked %v); want refused, capacity, no warm sandbox", what, err, reason, ok)
	}
}

// A provider without a pool refuses every warm-only open and makes nothing: a paid
// provider, which bills a sandbox by the second, never creates one for a caller that
// asked for a waiting one.
func TestWarmOnlyOpenOnAProviderWithoutAPoolMakesNothing(t *testing.T) {
	e := &E2B{APIKey: "not-a-key", APIBase: noSandboxServer(t)}
	_, err := e.OpenSession(context.Background(), SessionOptions{Lifetime: time.Minute, WarmOnly: true})
	wantNoWarmSandbox(t, "e2b", err)
}

// On docker a warm-only open with no pool, or with a pool that has no member to hand
// over, is refused before any container is made (no Preflight, no docker call), and
// leaves the pool's demand as it was: a refused warm-only open costs its caller
// nothing, so counted, a caller could steer every member to the languages it names
// (found in review, 2026-10-28; it was counted before the claim until then).
func TestDockerWarmOnlyOpenMakesNoContainer(t *testing.T) {
	d := DefaultDocker("")
	d.ready, d.daemonHost, d.verifiedRuntime, d.verifiedGuestUID = true, "unix:///var/run/docker.sock", d.Runtime, d.guestUID()
	d.verifiedImageIDs = map[string]string{d.Image: "sha256:snippet", d.ProjectImage: "sha256:project"}
	d.projectLanguages = []Language{LanguageJavaScript, LanguagePython}
	opts := SessionOptions{Lifetime: time.Minute, WarmOnly: true, Languages: []Language{LanguagePython}}
	_, err := d.OpenSession(context.Background(), opts)
	wantNoWarmSandbox(t, "docker without a pool", err)

	p := unstartedPool(t, d, "javascript", "python")
	for range 20 {
		_, err = d.OpenSession(context.Background(), opts)
		wantNoWarmSandbox(t, "docker with no member waiting", err)
	}
	if got := p.Demand(); !maps.Equal(got, map[string]float64{"javascript,python": 1}) {
		t.Fatalf("20 refused warm-only opens for Python moved the pool's demand to %v", got)
	}
}
