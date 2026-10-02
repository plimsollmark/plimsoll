package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox"
)

type failingPreflight struct{ sandbox.Sandbox }

func (failingPreflight) Preflight(context.Context) error {
	return errors.New("docker daemon is not ready: DOCKER_HOST=unix:///run/secret.sock image registry.internal/plimsoll@sha256:abc")
}

// /readyz is unauthenticated, so a failing Preflight answers with a fixed body and
// keeps its detail for the log (v0.15.0 review, M1).
func TestReadyzDoesNotEchoPreflightErrors(t *testing.T) {
	rec := httptest.NewRecorder()
	readyzHandler(failingPreflight{sandbox.Disabled{}})(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	body := rec.Body.String()
	if rec.Code != http.StatusServiceUnavailable || strings.TrimSpace(body) != "not ready" {
		t.Fatalf("readyz = %d %q; want 503 and a fixed body", rec.Code, body)
	}
}
