// Package remotehttp serves one owner's MCP tools over authenticated HTTP. OAuth
// credentials are separate from the daemon credential and the receipt signing key.
package remotehttp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	accessLifetime      = 15 * time.Minute
	familyLifetime      = 30 * 24 * time.Hour
	idleLifetime        = 7 * 24 * time.Hour
	codeLifetime        = time.Minute
	transactionLifetime = 5 * time.Minute
	maxStateBytes       = 16 << 20
	maxGrants           = 16
	maxClients          = 32
	maxCodes            = 64
	// A family rotates once per access lifetime: 30 days of 15-minute tokens is
	// 2,880 rotations, so 4,096 leaves room for retries. Sixteen full histories
	// (about 72 JSON bytes per entry) stay near 4.7 MB, inside maxStateBytes.
	maxRefreshHistory = 4096
	// refreshGrace lets a client that lost a rotation's answer retry with the
	// token it sent; Okta's documented default for the same window is 30 seconds.
	refreshGrace = 30 * time.Second
)

var errInactive = errors.New("authorization is not active")
var errInvalidGrant = errors.New("invalid grant")
var errInvalidScope = errors.New("invalid scope")
var errStateFull = errors.New("authorization state byte limit reached")
var errUnavailable = errors.New("authorization storage failed; restart required")

type clientRecord struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Redirects []string `json:"redirects"`
}

type grantRecord struct {
	ID          string          `json:"id"`
	Client      string          `json:"client"`
	Resource    string          `json:"resource"`
	Scope       string          `json:"scope"`
	Created     time.Time       `json:"created"`
	Expires     time.Time       `json:"expires"`
	LastUsed    time.Time       `json:"last_used"`
	Revoked     bool            `json:"revoked"`
	RefreshHash string          `json:"refresh_hash,omitempty"`
	UsedRefresh map[string]bool `json:"used_refresh"`
	// PrevRefresh is the token the last rotation consumed, accepted again until
	// Rotated plus refreshGrace. A retry inside it rotates the family once more.
	PrevRefresh string    `json:"prev_refresh,omitempty"`
	Rotated     time.Time `json:"rotated,omitzero"`
}

type accessRecord struct {
	Grant   string    `json:"grant"`
	Expires time.Time `json:"expires"`
}

type codeRecord struct {
	Client    clientRecord `json:"client"`
	Redirect  string       `json:"redirect"`
	Resource  string       `json:"resource"`
	Scope     string       `json:"scope"`
	Challenge string       `json:"challenge"`
	Expires   time.Time    `json:"expires"`
}

type stateData struct {
	Generation       uint64                  `json:"generation"`
	Version          int                     `json:"version"`
	Origin           string                  `json:"origin"`
	Disabled         bool                    `json:"disabled"`
	OwnerID          []byte                  `json:"owner_id"`
	Credentials      []webauthn.Credential   `json:"credentials"`
	BootstrapHash    string                  `json:"bootstrap_hash,omitempty"`
	BootstrapExpires time.Time               `json:"bootstrap_expires,omitempty"`
	Grants           map[string]*grantRecord `json:"grants"`
	Access           map[string]accessRecord `json:"access"`
	Codes            map[string]codeRecord   `json:"codes"`
	Clients          map[string]clientRecord `json:"clients"`
}

// store serializes each durable transaction. write is replaceable by tests to
// inject failures at the persistence boundary. A write failure poisons this open
// store: no authentication or mutation is accepted until an operator restarts it.
type store struct {
	mu     sync.Mutex
	dir    string
	lock   *os.File
	data   stateData
	failed bool
	now    func() time.Time
	write  func([]byte) error
	// recent holds each grant's last rotation answer in memory only, never on
	// disk, so a retry inside refreshGrace gets the same answer back.
	recent map[string]rotation
	// commit runs under mu once a transition is published, never after a failure.
	commit []func()
}

type rotation struct {
	from  string // digest of the refresh token the rotation consumed
	pair  tokenPair
	ends  time.Time
	until time.Time // access token expiry, for expires_in on a repeat
}

// errRepeat ends a transition that changes nothing because its answer exists.
var errRepeat = errors.New("repeat of a published answer")

func randomID(prefix string) string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("secure random source unavailable")
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b[:])
}

func digest(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }

func openStore(dir, origin string) (*store, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("state directory must be absolute")
	}
	if err := privateDir(dir); err != nil {
		return nil, err
	}
	lock, err := lockState(filepath.Join(dir, "writer.lock"))
	if err != nil {
		return nil, err
	}
	s := &store{dir: dir, lock: lock, now: time.Now, recent: map[string]rotation{}}
	s.write = s.replace
	f, err := openPrivate(filepath.Join(dir, "state.json"), os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		if origin == "" {
			_ = lock.Close()
			return nil, errors.New("authorization state is not initialized")
		}
		s.data = stateData{Version: 1, Origin: origin, Disabled: true, OwnerID: []byte(randomID("owner_")), Grants: map[string]*grantRecord{}, Access: map[string]accessRecord{}, Codes: map[string]codeRecord{}, Clients: map[string]clientRecord{}}
		b, _ := json.Marshal(s.data)
		if err = s.write(b); err != nil {
			_ = lock.Close()
			return nil, err
		}
	} else if err != nil {
		_ = lock.Close()
		return nil, err
	} else {
		b, e := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
		_ = f.Close()
		if e != nil || len(b) > maxStateBytes {
			_ = lock.Close()
			return nil, errors.New("authorization state unreadable or oversized")
		}
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if e = dec.Decode(&s.data); e != nil || dec.Decode(new(any)) != io.EOF {
			_ = lock.Close()
			return nil, errors.New("authorization state is corrupt")
		}
		if s.data.Version != 1 || s.data.Origin == "" || len(s.data.OwnerID) == 0 || s.data.Grants == nil || s.data.Access == nil || s.data.Codes == nil || s.data.Clients == nil {
			_ = lock.Close()
			return nil, errors.New("authorization state has an invalid schema")
		}
		if origin != "" && s.data.Origin != origin {
			_ = lock.Close()
			return nil, errors.New("public origin differs from persisted authorization state")
		}
		if len(s.data.Grants) > maxGrants || len(s.data.Clients) > maxClients || len(s.data.Codes) > maxCodes || len(s.data.Credentials) > 8 {
			_ = lock.Close()
			return nil, errors.New("authorization state exceeds its limits")
		}
		for id, g := range s.data.Grants {
			if g == nil || g.ID != id || g.UsedRefresh == nil || len(g.UsedRefresh) > maxRefreshHistory {
				_ = lock.Close()
				return nil, errors.New("authorization state has an invalid grant")
			}
		}
	}
	return s, nil
}

func (s *store) close() error { return s.lock.Close() }

func (s *store) replace(b []byte) error {
	if len(b) > maxStateBytes {
		return errStateFull
	}
	f, err := os.CreateTemp(s.dir, "state-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	if err = f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	n, err := f.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, filepath.Join(s.dir, "state.json")); err != nil {
		return err
	}
	d, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// update clones first, prunes expired authority, applies one transition, then
// persists it before publishing it in memory or returning a credential.
func (s *store) update(fn func(*stateData) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return errUnavailable
	}
	s.commit = nil
	b, _ := json.Marshal(s.data)
	var next stateData
	if err := json.Unmarshal(b, &next); err != nil {
		return err
	}
	now := s.now()
	for k, a := range next.Access {
		if !now.Before(a.Expires) {
			delete(next.Access, k)
		}
	}
	for k, c := range next.Codes {
		if !now.Before(c.Expires) {
			delete(next.Codes, k)
		}
	}
	live := liveAccess(&next)
	for id, g := range next.Grants {
		// A grant without a refresh token is spent once its last access token
		// expires; keeping it would hold a grant slot for the idle lifetime.
		spent := g.RefreshHash == "" && !live[id]
		if g.Revoked || spent || !now.Before(g.Expires) || !now.Before(g.LastUsed.Add(idleLifetime)) {
			delete(next.Grants, id)
			for h, a := range next.Access {
				if a.Grant == id {
					delete(next.Access, h)
				}
			}
		}
	}
	if err := fn(&next); err != nil {
		return err
	}
	b, err := json.Marshal(next)
	if err != nil {
		return err
	}
	// An oversized transition is refused before the write, so it cannot poison
	// the store the way a failed write does.
	if len(b) > maxStateBytes {
		return errStateFull
	}
	if err = s.write(b); err != nil {
		s.failed = true
		s.commit = nil
		return fmt.Errorf("persisting authorization state: %w", err)
	}
	s.data = next
	for _, f := range s.commit {
		f()
	}
	s.commit = nil
	return nil
}

func liveAccess(d *stateData) map[string]bool {
	live := map[string]bool{}
	for _, a := range d.Access {
		live[a.Grant] = true
	}
	return live
}

func activeGrant(d *stateData, g *grantRecord, now time.Time) bool {
	return !d.Disabled && g != nil && !g.Revoked && now.Before(g.Expires) && now.Before(g.LastUsed.Add(idleLifetime))
}

func (s *store) access(token, resource string) (grantRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed || !strings.HasPrefix(token, "a_") || len(token) != 45 {
		return grantRecord{}, errInactive
	}
	a, ok := s.data.Access[digest(token)]
	g := s.data.Grants[a.Grant]
	if !ok || !s.now().Before(a.Expires) || !activeGrant(&s.data, g, s.now()) || g.Resource != resource {
		return grantRecord{}, errInactive
	}
	return *g, nil
}

type tokenPair struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

func issue(d *stateData, g *grantRecord, now time.Time, refresh bool) tokenPair {
	// Only the newest access token for this grant is needed by these clients. Old
	// access tokens retain their original lifetime to permit in-flight requests.
	a := randomID("a_")
	expires := now.Add(accessLifetime)
	if g.Expires.Before(expires) {
		expires = g.Expires
	}
	d.Access[digest(a)] = accessRecord{Grant: g.ID, Expires: expires}
	p := tokenPair{AccessToken: a, TokenType: "Bearer", ExpiresIn: int(expires.Sub(now) / time.Second), Scope: g.Scope}
	if refresh {
		p.RefreshToken = randomID("r_")
		g.RefreshHash = digest(p.RefreshToken)
	}
	return p
}

// grantActive reads the grant alone: a storage fault refuses new authentication
// elsewhere, and is no reason to close a live grant's sandboxes.
func (s *store) grantActive(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return activeGrant(&s.data, s.data.Grants[id], s.now())
}

// lookupCode and lookupRefresh are read-only checks made before a transition,
// so a request carrying no valid credential never clones or writes the state.
// Both answer errUnavailable when storage has failed, which the token endpoint
// reports as a server fault rather than an invalid credential.
func (s *store) lookupCode(code string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return false, errUnavailable
	}
	_, ok := s.data.Codes[digest(code)]
	return ok, nil
}

// lookupRefresh finds the active grant a refresh token belongs to, current or
// used; a used one goes on to the transition, which decides retry or reuse.
func (s *store) lookupRefresh(token string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return "", errUnavailable
	}
	h := digest(token)
	now := s.now()
	for id, g := range s.data.Grants {
		if (g.RefreshHash == h || g.UsedRefresh[h]) && activeGrant(&s.data, g, now) {
			return id, nil
		}
	}
	return "", nil
}

// lookupToken finds the grant a revocation names, for one client.
func (s *store) lookupToken(token, client string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := digest(token)
	for id, g := range s.data.Grants {
		matches := g.RefreshHash == h || g.UsedRefresh[h]
		if a, ok := s.data.Access[h]; ok && a.Grant == id {
			matches = true
		}
		if matches && g.Client == client {
			return id
		}
	}
	return ""
}

// exchange returns the new grant and any grant it retired to make room.
func (s *store) exchange(code, client, redirect, resource, verifier string) (tokenPair, string, []string, error) {
	var pair tokenPair
	var id string
	var evicted []string
	err := s.update(func(d *stateData) error {
		c, ok := d.Codes[digest(code)]
		if !ok || !strings.HasPrefix(code, "c_") || d.Disabled || c.Client.ID != client || c.Redirect != redirect || c.Resource != resource || !s.now().Before(c.Expires) || !validVerifier(verifier) || challenge(verifier) != c.Challenge {
			return errInvalidGrant
		}
		if len(d.Grants) >= maxGrants {
			// The owner just approved this connection with a passkey. Make room by
			// retiring the least recently refreshed grant that holds no live access
			// token: a client that reconnected has abandoned it.
			live := liveAccess(d)
			var oldest *grantRecord
			for _, g := range d.Grants {
				if !live[g.ID] && (oldest == nil || g.LastUsed.Before(oldest.LastUsed)) {
					oldest = g
				}
			}
			if oldest == nil {
				return errors.New("connector grant limit reached; every grant is in use")
			}
			// Reported only once the transition is written: a failed write leaves
			// the old grant in force, and its workspace must stay too.
			retired := oldest.ID
			s.commit = append(s.commit, func() { evicted = append(evicted, retired) })
			delete(d.Grants, oldest.ID)
		}
		if len(d.Access) >= 4096 {
			return errors.New("access token limit reached; wait for expiry")
		}
		delete(d.Codes, digest(code))
		now := s.now()
		id = randomID("g_")
		g := &grantRecord{ID: id, Client: client, Resource: resource, Scope: c.Scope, Created: now, Expires: now.Add(familyLifetime), LastUsed: now, UsedRefresh: map[string]bool{}}
		d.Grants[id] = g
		pair = issue(d, g, now, strings.Contains(c.Scope, "offline_access"))
		return nil
	})
	return pair, id, evicted, err
}

// scopeWithin reports whether a refresh request's scope is one RFC 6749 section
// 6 allows: omitted, or any order of a subset of what the owner granted.
func scopeWithin(requested, granted string) bool {
	if requested == "" {
		return true
	}
	if !validScope(requested) {
		return false
	}
	return canonicalScope(requested) == "code:run" || granted == canonicalScope(requested)
}

// refresh rotates a family. revoked names why this request revoked the grant
// ("refresh_reuse" or "refresh_exhausted"); the caller then cancels its work.
func (s *store) refresh(token, client, resource, scope string) (tokenPair, string, string, error) {
	var pair tokenPair
	var id, revoked string
	err := s.update(func(d *stateData) error {
		if !strings.HasPrefix(token, "r_") || len(token) != 45 {
			return errInvalidGrant
		}
		h := digest(token)
		now := s.now()
		// Answers past their window are dropped, so no issued credential stays in
		// memory longer than it can be repeated.
		for k, r := range s.recent {
			if !now.Before(r.ends) {
				delete(s.recent, k)
			}
		}
		for _, g := range d.Grants {
			if g.RefreshHash != h && !g.UsedRefresh[h] {
				continue
			}
			if !activeGrant(d, g, now) || g.Client != client || resource != "" && resource != g.Resource {
				return errInvalidGrant
			}
			if !scopeWithin(scope, g.Scope) {
				return errInvalidScope
			}
			id = g.ID
			retry := g.UsedRefresh[h] && h == g.PrevRefresh && now.Before(g.Rotated.Add(refreshGrace))
			if g.UsedRefresh[h] && !retry {
				// Reported only once the revocation is written (see exchange).
				s.commit = append(s.commit, func() { revoked = "refresh_reuse" })
				revoke(d, g)
				return nil
			}
			if r, ok := s.recent[g.ID]; retry && ok && r.from == h && now.Before(r.ends) && digest(r.pair.RefreshToken) == g.RefreshHash {
				// A retry, or a refresh racing this one with the same token:
				// both get one answer, so neither holds a token the other retired.
				pair = r.pair
				pair.ExpiresIn = int(r.until.Sub(now) / time.Second)
				return errRepeat
			}
			if len(g.UsedRefresh) >= maxRefreshHistory {
				s.commit = append(s.commit, func() { revoked = "refresh_exhausted" })
				revoke(d, g)
				return nil
			}
			if len(d.Access) >= 4096 {
				return errors.New("access token limit reached; wait for expiry")
			}
			if retry {
				// The answer was lost with the process that gave it. Its token is
				// retired rather than revived: presenting it later is reuse.
				g.UsedRefresh[g.RefreshHash] = true
			} else {
				g.UsedRefresh[h] = true
				g.PrevRefresh = h
				g.Rotated = now
			}
			g.LastUsed = now
			pair = issue(d, g, now, true)
			grant, answer, ends := g.ID, pair, g.Rotated.Add(refreshGrace)
			s.commit = append(s.commit, func() {
				s.recent[grant] = rotation{from: h, pair: answer, ends: ends, until: now.Add(time.Duration(answer.ExpiresIn) * time.Second)}
			})
			return nil
		}
		return errInvalidGrant
	})
	if errors.Is(err, errRepeat) {
		err = nil
	}
	if err == nil && revoked != "" {
		err = errInvalidGrant
	}
	return pair, id, revoked, err
}

func revoke(d *stateData, g *grantRecord) {
	g.Revoked = true
	g.RefreshHash = ""
	for h, a := range d.Access {
		if a.Grant == g.ID {
			delete(d.Access, h)
		}
	}
}

func (s *store) revokeToken(token, client string) (string, error) {
	var id string
	err := s.update(func(d *stateData) error {
		h := digest(token)
		for _, g := range d.Grants {
			matches := g.RefreshHash == h || g.UsedRefresh[h]
			if a, ok := d.Access[h]; ok && a.Grant == g.ID {
				matches = true
			}
			if matches && g.Client == client {
				id = g.ID
				revoke(d, g)
				return nil
			}
		}
		return nil // RFC 7009 does not disclose whether a token exists.
	})
	return id, err
}

func (s *store) disable() ([]string, error) {
	var ids []string
	err := s.update(func(d *stateData) error {
		d.Disabled = true
		d.Generation++
		d.Codes = map[string]codeRecord{}
		d.BootstrapHash = ""
		d.BootstrapExpires = time.Time{}
		for id, g := range d.Grants {
			ids = append(ids, id)
			revoke(d, g)
		}
		d.Grants = map[string]*grantRecord{}
		return nil
	})
	return ids, err
}

func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func validVerifier(s string) bool {
	return len(s) >= 43 && len(s) <= 128 && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-._~", r))
	}) < 0
}
