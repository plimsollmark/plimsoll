package main

import (
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/plimsollmark/plimsoll/internal/printable"
	"github.com/plimsollmark/plimsoll/internal/settings"
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
	opts := &slog.HandlerOptions{Level: slog.LevelInfo, ReplaceAttr: printableAttr}
	if strings.EqualFold(settings.LogFormat.Get(getenv), "text") {
		return slog.NewTextHandler(w, opts)
	}
	return slog.NewJSONHandler(w, opts)
}

// printableAttr writes each string a log line carries (a value, an error's text, a list
// of strings) through printable.Text, so no line can rewrite the
// screen of an operator who reads the stream on a terminal: a file's name or content, a
// provider's error text and a runner's error detail come from outside the daemon. JSON
// already escapes the characters below U+0020 and the text format quotes a value that
// holds one, but neither escapes DEL, the C1 range or the bidirectional controls (the
// security scan of 2026-11-20, F8). Text that holds none is unchanged, so a parser of
// the stream reads every ordinary line as before; an error is written as its text, as
// both handlers write one. A value of any other kind (a number, a time, a level, a struct)
// is left as it is: the handler encodes it, and a string type of its own is not cleaned.
func printableAttr(_ []string, a slog.Attr) slog.Attr {
	switch a.Value.Kind() {
	case slog.KindString:
		a.Value = slog.StringValue(printable.Text(a.Value.String()))
	case slog.KindAny:
		switch v := a.Value.Any().(type) {
		case error:
			a.Value = slog.StringValue(printable.Text(v.Error()))
		case []string:
			out := make([]string, len(v))
			for i, s := range v {
				out[i] = printable.Text(s)
			}
			a.Value = slog.AnyValue(out)
		}
	}
	return a
}

// configureLogging installs the process logger. It sets slog.Default rather than
// threading a logger through: rpc.SandboxService falls back to slog.Default() when
// its Logger field is unset, and every other line in this package is a
// package-level slog call.
func configureLogging(getenv func(string) string) {
	slog.SetDefault(slog.New(newLogHandler(getenv, os.Stderr)))
}
