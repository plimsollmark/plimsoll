package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

type grantContextKey struct{}

type connectorGrant struct {
	// group is the approved app the grant belongs to: grants of one app share its
	// part of the sandbox cap (connectionShare), so approving an app twice does not
	// double what it may hold.
	group      string
	ctx        context.Context
	cancel     context.CancelFunc
	revoked    bool // guarded by Server.mu, as are admissions to calls
	revokedAt  time.Time
	calls      sync.WaitGroup
	done       chan struct{}
	err        error
	cleanupErr error // first failed close, retained after it leaves s.closings
}

// grantRef is what a request's context carries: the workspace's ID and the very
// workspace it was issued for, so a request that authenticated before a revocation
// is never admitted into a later workspace registered under the same ID.
type grantRef struct {
	id string
	g  *connectorGrant
}

func grantID(ctx context.Context) string {
	r, _ := ctx.Value(grantContextKey{}).(grantRef)
	return r.id
}

// grantLocked returns the live workspace ctx was issued for: nil when it is revoked,
// gone, or replaced by another workspace with the same ID.
func (s *Server) grantLocked(ctx context.Context) *connectorGrant {
	r, _ := ctx.Value(grantContextKey{}).(grantRef)
	g := s.grants[r.id]
	if g == nil || g.revoked || g != r.g {
		return nil
	}
	return g
}

func recordKey(ctx context.Context, digest string) string {
	if id := grantID(ctx); id != "" {
		return id + "\x00" + digest
	}
	return digest
}

// RegisterGrant installs a connector workspace after the authorization layer has
// accepted its persisted grant. It is a local API, never an MCP tool or HTTP route.
// IDs are random internal identifiers, never OAuth credentials or user input; group
// names the approved app the grant belongs to (the authorization layer passes a
// digest of its OAuth client), fixed by the first registration of an ID.
func (s *Server) RegisterGrant(id, group string) error {
	label := func(v string) bool {
		return v != "" && len(v) <= 64 && strings.IndexFunc(v, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-')
		}) < 0
	}
	if !label(id) || !label(group) {
		return errors.New("invalid connector grant identifier or group")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return errors.New("server is stopping")
	}
	if g := s.grants[id]; g != nil {
		if g.revoked {
			return errors.New("connector grant was revoked")
		}
		return nil
	}
	// This bounds canceled contexts and tombstones as well as live workspaces.
	// The authorization layer separately bounds active persisted grants.
	if !s.roomLocked() {
		return errors.New("connector workspace limit reached: every place is a live workspace or one still being cleaned up")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.grants[id] = &connectorGrant{group: group, ctx: ctx, cancel: cancel}
	return nil
}

// maxGrantEntries bounds live workspaces plus tombstones; tombstoneHold is how
// long a finished tombstone is kept before room may be made from it.
const (
	maxGrantEntries = 256
	tombstoneHold   = time.Minute
)

// roomLocked makes room by forgetting tombstones revoked at least tombstoneHold ago
// whose cleanup has finished. Forgetting one cannot readmit a request: a request's
// context names the workspace it was issued for (grantRef), and a workspace later
// registered under the same ID is another one. The authorization layer also rechecks
// a grant after registering it, so a forgotten ID is not revived for long.
func (s *Server) roomLocked() bool {
	if len(s.grants) < maxGrantEntries {
		return true
	}
	now := time.Now()
	for id, g := range s.grants {
		if !g.revoked || now.Sub(g.revokedAt) < tombstoneHold {
			continue
		}
		select {
		case <-g.done:
			delete(s.grants, id)
		default:
		}
	}
	return len(s.grants) < maxGrantEntries
}

// Grants lists the workspaces registered and not revoked, so the authorization
// layer can cancel any whose grant it no longer holds active.
func (s *Server) Grants() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []string
	for id, g := range s.grants {
		if !g.revoked {
			ids = append(ids, id)
		}
	}
	return ids
}

// GrantContext binds an authenticated HTTP request to a registered workspace.
// Token validation and audience/scope checks must precede it. No client argument
// can set this context value, and RequireGrant fails closed if it is missing.
func (s *Server) GrantContext(ctx context.Context, id string) (context.Context, error) {
	s.mu.Lock()
	g := s.grants[id]
	valid := g != nil && !g.revoked && !s.stopped
	s.mu.Unlock()
	if !valid {
		return nil, errors.New("connector grant is not active")
	}
	return context.WithValue(ctx, grantContextKey{}, grantRef{id: id, g: g}), nil
}

func (s *Server) grantRevokedLocked(ctx context.Context) bool {
	return s.cfg.RequireGrant && s.grantLocked(ctx) == nil
}

// RevokeGrant stops admissions, cancels active calls, removes the grant's handles
// and records, and awaits its sandbox cleanup. Cleanup has one owner and continues
// if the caller's wait expires. The authorization layer must persist revocation
// before calling this method, so a process restart cannot restore the authority.
func (s *Server) RevokeGrant(ctx context.Context, id string) error {
	s.mu.Lock()
	g := s.grants[id]
	if g == nil {
		// A persisted grant may be revoked immediately after restart, before
		// its first request registers the workspace. Retain a tombstone so an
		// authentication already in progress cannot register it afterward.
		if !s.roomLocked() {
			s.mu.Unlock()
			return nil
		} // all new registrations already refuse
		grantCtx, cancel := context.WithCancel(context.Background())
		g = &connectorGrant{ctx: grantCtx, cancel: cancel}
		s.grants[id] = g
	}
	if !g.revoked {
		g.revoked = true
		g.revokedAt = time.Now()
		g.cancel()
		g.done = make(chan struct{})
		var closings []*closing
		for handle, b := range s.boxes {
			if b.grant == id {
				delete(s.boxes, handle)
				closings = append(closings, s.closeBoxLocked(b))
			}
		}
		prefix := id + "\x00"
		var kept []string
		for _, key := range s.order {
			if strings.HasPrefix(key, prefix) {
				s.recordBytes -= recordText(s.records[key])
				delete(s.records, key)
			} else {
				kept = append(kept, key)
			}
		}
		s.order = kept
		go func() {
			g.calls.Wait()
			var errs []error
			for _, c := range closings {
				<-c.done
				errs = append(errs, c.result.err)
			}
			// Opens admitted before revocation can return a sandbox after we removed
			// the existing boxes. Their close is registered before calls.Done.
			for {
				s.mu.Lock()
				var more []*closing
				for c := range s.closings {
					if c.grant == id {
						more = append(more, c)
					}
				}
				s.mu.Unlock()
				if len(more) == 0 {
					break
				}
				for _, c := range more {
					<-c.done
					errs = append(errs, c.result.err)
				}
			}
			s.mu.Lock()
			errs = append(errs, g.cleanupErr)
			s.mu.Unlock()
			g.err = errors.Join(errs...)
			close(g.done)
		}()
	}
	done := g.done
	s.mu.Unlock()
	select {
	case <-done:
		return g.err
	case <-ctx.Done():
		return fmt.Errorf("grant revoked; sandbox cleanup still pending: %w", ctx.Err())
	}
}
