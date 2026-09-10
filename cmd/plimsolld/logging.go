package main

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// newLogHandler picks the audit stream's encoding. It defaults to JSON because
// the "code run" lines this daemon emits are an AUDIT STREAM before they are
// developer output: prospector-report and internal/report.Parse both consume
// newline-delimited JSON, and a metadata-only audit record that no tool can parse
// is not an audit record. Text is available for reading a local run by eye.
//
// Selection is case-insensitive and whitespace-tolerant, matching every other env
// read in this package, so "TEXT" from a k8s manifest picks what it looks like it
// picks. Anything unrecognized falls to JSON — the parseable default, not a
// surprise.
func newLogHandler(getenv func(string) string, w io.Writer) slog.Handler {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if strings.EqualFold(strings.TrimSpace(getenv("PLIMSOLL_LOG_FORMAT")), "text") {
		return slog.NewTextHandler(w, opts)
	}
	return slog.NewJSONHandler(w, opts)
}

// configureLogging installs the process logger. It sets slog.Default rather than
// threading a logger through: rpc.SandboxService falls back to slog.Default() when
// its Logger field is unset, and every other line in this package is a
// package-level slog call.
func configureLogging(getenv func(string) string) {
	slog.SetDefault(slog.New(newLogHandler(getenv, os.Stderr)))
}
