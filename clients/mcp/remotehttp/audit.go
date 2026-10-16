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

// Audit is bounded metadata, separate from the signed evidence files. Each file
// is at most 1 MiB and only one preceding file is retained. No HTTP access log is
// enabled: headers, URL queries, credentials and tool content are never recorded.
type auditLog struct {
	mu     sync.Mutex
	dir    string
	file   *os.File
	size   int64
	failed bool
}

func openAudit(dir string) (*auditLog, error) {
	previous, err := openPrivate(filepath.Join(dir, "audit.previous.jsonl"), os.O_RDONLY, 0)
	if err == nil {
		st, statErr := previous.Stat()
		_ = previous.Close()
		if statErr != nil || st.Size() > 1<<20 {
			return nil, errors.New("previous audit file exceeds its limit")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, err := openPrivate(filepath.Join(dir, "audit.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || st.Size() > 1<<20 {
		_ = f.Close()
		return nil, errors.New("audit file unreadable or exceeds its limit")
	}
	return &auditLog{dir: dir, file: f, size: st.Size()}, nil
}
func (a *auditLog) event(kind, grant, record string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed || a.file == nil {
		return
	}
	b, _ := json.Marshal(struct {
		Time   string `json:"time"`
		Event  string `json:"event"`
		Grant  string `json:"grant,omitempty"`
		Record string `json:"record,omitempty"`
	}{time.Now().UTC().Format(time.RFC3339Nano), kind, grant, record})
	b = append(b, '\n')
	if a.size+int64(len(b)) > 1<<20 {
		_ = a.file.Close()
		if err := os.Rename(filepath.Join(a.dir, "audit.jsonl"), filepath.Join(a.dir, "audit.previous.jsonl")); err != nil {
			a.failed = true
			return
		}
		f, err := openPrivate(filepath.Join(a.dir, "audit.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			a.failed = true
			return
		}
		a.file = f
		a.size = 0
	}
	n, err := a.file.Write(b)
	a.size += int64(n)
	if err != nil || n != len(b) {
		a.failed = true
	}
}
func (a *auditLog) healthy() bool { a.mu.Lock(); defer a.mu.Unlock(); return !a.failed }
func (a *auditLog) close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return nil
	}
	err := errors.Join(a.file.Sync(), a.file.Close())
	a.file = nil
	return err
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
