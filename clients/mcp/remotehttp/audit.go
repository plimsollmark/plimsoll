package remotehttp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Audit is bounded metadata, separate from the signed evidence files, in two streams by
// kind, each a file and one preceding file, each rotated on its own, so a burst of one
// kind never pushes the other out. No HTTP access log is enabled: headers, URL queries,
// credentials and tool content are never recorded.
//
// The security stream (audit.jsonl) holds sign-in, consent, token, grant, enable and
// disable events and the refusals; the tool stream (tools.jsonl) holds the tool traffic
// (toolKinds). They were one stream, and at the meter's rate tool lines pushed the line
// recording a stolen credential's first use out of both files within two hours
// (hunt-security-26, 2026-11-20). How long each holds, from its line sizes and the
// transport's meters:
//
//   - Tools, 1 MiB a file: a run_code writes a tool_admission line (about 123 bytes) and
//     a checked_record line (about 199), and the shared meter admits two calls a second,
//     so the two files hold about 54 minutes at that rate, 108 at one grant's one a
//     second. Enough: they show the traffic now; what ran is in the signed receipts.
//   - Security, 4 MiB a file: its busiest writers are the anonymous refusals, at most one
//     line (about 100 bytes) every 2 seconds past a burst of 30 (Engine.refused), so the
//     two files hold about 46 hours of a sustained flood; and a refresh credential used at
//     its grant's refresh meter (one each 10 seconds past a burst of 4, takeRefresh)
//     writes a token_issued line of about 200 bytes, so about 4.8 days of that. A client
//     refreshes once an access lifetime (15 minutes), so the 16 grants the store holds at
//     most, refreshing that way, fill the two files in about four weeks.
//     Enough for the purpose it is kept for: a stolen refresh credential shows itself
//     within one access lifetime of the owner's own client, whose next refresh presents
//     the rotated credential and revokes the family (refresh_reuse), and the owner then
//     reads the first use well inside those bounds.
type auditLog struct {
	mu       sync.Mutex
	security auditStream
	tools    auditStream
	failed   bool
}

// auditStream is one stream: name.jsonl and name.previous.jsonl in dir, each at most max.
type auditStream struct {
	dir, name string
	max       int64
	file      *os.File
	size      int64
}

const (
	securityAuditMax = 4 << 20
	toolAuditMax     = 1 << 20
)

// toolKinds are the events of the tool stream; every other kind is a security event.
var toolKinds = map[string]bool{"tool_admission": true, "checked_record": true, "sandbox_background_warning": true}

func openAudit(dir string) (*auditLog, error) {
	a := &auditLog{security: auditStream{dir: dir, name: "audit", max: securityAuditMax}, tools: auditStream{dir: dir, name: "tools", max: toolAuditMax}}
	if err := a.security.open(); err != nil {
		return nil, err
	}
	if err := a.tools.open(); err != nil {
		_ = a.security.file.Close()
		return nil, err
	}
	return a, nil
}

func (s *auditStream) path(previous bool) string {
	if previous {
		return filepath.Join(s.dir, s.name+".previous.jsonl")
	}
	return filepath.Join(s.dir, s.name+".jsonl")
}

func (s *auditStream) open() error {
	previous, err := openPrivate(s.path(true), os.O_RDONLY, 0)
	if err == nil {
		st, statErr := previous.Stat()
		_ = previous.Close()
		if statErr != nil || st.Size() > s.max {
			return errors.New("previous audit file exceeds its limit")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := openPrivate(s.path(false), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil || st.Size() > s.max {
		_ = f.Close()
		return errors.New("audit file unreadable or exceeds its limit")
	}
	s.file, s.size = f, st.Size()
	return nil
}

// write appends b, first rotating the file when b would take it past max.
func (s *auditStream) write(b []byte) error {
	if s.size+int64(len(b)) > s.max {
		_ = s.file.Close()
		s.file = nil
		if err := os.Rename(s.path(false), s.path(true)); err != nil {
			return err
		}
		f, err := openPrivate(s.path(false), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		s.file, s.size = f, 0
	}
	n, err := s.file.Write(b)
	s.size += int64(n)
	if err == nil && n != len(b) {
		err = errors.New("short audit write")
	}
	return err
}

func (s *auditStream) close() error {
	if s.file == nil {
		return nil
	}
	err := errors.Join(s.file.Sync(), s.file.Close())
	s.file = nil
	return err
}

func (a *auditLog) event(kind, grant, record string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := &a.security
	if toolKinds[kind] {
		s = &a.tools
	}
	if a.failed || s.file == nil {
		return
	}
	b, _ := json.Marshal(struct {
		Time   string `json:"time"`
		Event  string `json:"event"`
		Grant  string `json:"grant,omitempty"`
		Record string `json:"record,omitempty"`
	}{time.Now().UTC().Format(time.RFC3339Nano), kind, grant, record})
	if s.write(append(b, '\n')) != nil {
		a.failed = true
	}
}
func (a *auditLog) healthy() bool { a.mu.Lock(); defer a.mu.Unlock(); return !a.failed }
func (a *auditLog) close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return errors.Join(a.security.close(), a.tools.close())
}

// Background library errors can contain remote response text. Record only their
// category, never the interpolated message or attributes.
type auditHandler struct{ audit *auditLog }

func (a auditHandler) Enabled(context.Context, slog.Level) bool { return true }
func (a auditHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		a.audit.event("sandbox_background_warning", "", "")
	}
	return nil
}
func (a auditHandler) WithAttrs([]slog.Attr) slog.Handler { return a }
func (a auditHandler) WithGroup(string) slog.Handler      { return a }
