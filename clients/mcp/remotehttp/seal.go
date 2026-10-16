package remotehttp

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// An approval is never stored before the owner proves a passkey. Its fields are
// sealed with a per-process HMAC key into the page; the passkey challenge is
// sealed into the options answer. Anonymous requests therefore allocate nothing,
// and a restart or a disable (a new generation) invalidates every open approval.
type approval struct {
	Generation                                  uint64
	Nonce, CookieHash, CSRF                     string
	Client                                      clientRecord
	Redirect, Resource, Scope, Challenge, State string
	Expires                                     time.Time
	Enrollment                                  bool
}

// ceremony binds one passkey challenge to the approval that asked for it.
type ceremony struct {
	ID, Approval string
	Enrollment   bool
	Expires      time.Time
	Session      webauthn.SessionData
}

const maxSealBytes = 16 << 10

type sealer struct{ key []byte }

func newSealer() sealer {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("secure random source unavailable")
	}
	return sealer{key}
}

func (s sealer) mac(kind string, payload []byte) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(kind))
	m.Write([]byte{0})
	m.Write(payload)
	return m.Sum(nil)
}

func (s sealer) seal(kind string, v any) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic("sealing a fixed structure failed")
	}
	payload := bytes.TrimSuffix(b.Bytes(), []byte("\n"))
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(s.mac(kind, payload))
}

func (s sealer) open(kind, token string, v any) error {
	if len(token) > maxSealBytes {
		return errors.New("sealed value too large")
	}
	body, tag, ok := strings.Cut(token, ".")
	if !ok {
		return errors.New("malformed sealed value")
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return err
	}
	sum, err := base64.RawURLEncoding.DecodeString(tag)
	if err != nil || !hmac.Equal(sum, s.mac(kind, payload)) {
		return errors.New("sealed value refused")
	}
	d := json.NewDecoder(bytes.NewReader(payload))
	d.DisallowUnknownFields()
	if err = d.Decode(v); err != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("sealed value is malformed")
	}
	return nil
}

// approvalCookie names one approval's browser binding, so two approvals in one
// browser (two tabs, or a client reopening its popup) do not overwrite each other.
func approvalCookie(nonce string) string { return "__Host-plimsoll-approval-" + nonce }

// marks remembers what only a verified owner creates: a used passkey challenge,
// an approval whose passkey was verified, an approval already answered. Entries
// last as long as the value they stand for, so the map cannot be filled anonymously.
type marks struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

const maxMarks = 256

// take consumes a live mark.
func (m *marks) take(key string, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	exp, ok := m.entries[key]
	delete(m.entries, key)
	return ok && now.Before(exp)
}

// claim marks key once: false if it is already marked or the table is full.
func (m *marks) claim(key string, expires, now time.Time) bool {
	return m.put(key, expires, now, false)
}

// mark sets key, keeping an existing mark: false only if the table is full.
func (m *marks) mark(key string, expires, now time.Time) bool {
	return m.put(key, expires, now, true)
}

func (m *marks) put(key string, expires, now time.Time, again bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if exp, ok := m.entries[key]; ok && now.Before(exp) {
		return again
	}
	if len(m.entries) >= maxMarks {
		for k, exp := range m.entries {
			if !now.Before(exp) {
				delete(m.entries, k)
			}
		}
		if len(m.entries) >= maxMarks {
			return false
		}
	}
	m.entries[key] = expires
	return true
}

// answered reports whether an approval was already approved: one approval
// yields at most one code, however many times a passkey verifies on its page.
func (m *marks) answered(nonce string, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	exp, ok := m.entries["answered:"+nonce]
	return ok && now.Before(exp)
}

func (m *marks) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = map[string]time.Time{}
}
