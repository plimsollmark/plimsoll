package remotehttp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func testStore(t *testing.T) *store {
	t.Helper()
	s, err := openStore(filepath.Join(t.TempDir(), "state"), "https://mcp.example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.close() })
	if err = s.update(func(d *stateData) error { d.Disabled = false; return nil }); err != nil {
		t.Fatal(err)
	}
	return s
}

const testVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123456789"
const testRedirect = "https://claude.ai/api/mcp/auth_callback"

func seedCode(t *testing.T, s *store) string {
	t.Helper()
	code := randomID("c_")
	err := s.update(func(d *stateData) error {
		d.Codes[digest(code)] = codeRecord{Client: clientRecord{ID: "test-client"}, Redirect: testRedirect, Resource: d.Origin + "/mcp", Scope: "code:run offline_access", Challenge: challenge(testVerifier), Expires: s.now().Add(codeLifetime)}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return code
}
func firstPair(t *testing.T, s *store) (tokenPair, string) {
	t.Helper()
	p, id, _, err := s.exchange(seedCode(t, s), "test-client", testRedirect, s.data.Origin+"/mcp", testVerifier)
	if err != nil {
		t.Fatal(err)
	}
	return p, id
}

func TestDurableCodeTokenRotationAndLateReuse(t *testing.T) {
	s := testStore(t)
	code := seedCode(t, s)
	for _, args := range [][4]string{{"other", testRedirect, s.data.Origin + "/mcp", testVerifier}, {"test-client", testRedirect + "?bad=1", s.data.Origin + "/mcp", testVerifier}, {"test-client", testRedirect, "https://other.example/mcp", testVerifier}, {"test-client", testRedirect, s.data.Origin + "/mcp", strings.Repeat("z", 43)}} {
		if _, _, _, err := s.exchange(code, args[0], args[1], args[2], args[3]); err == nil {
			t.Fatal("substituted code binding accepted")
		}
	}
	p, id, _, err := s.exchange(code, "test-client", testRedirect, s.data.Origin+"/mcp", testVerifier)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = s.exchange(code, "test-client", testRedirect, s.data.Origin+"/mcp", testVerifier); err == nil {
		t.Fatal("code replay accepted")
	}
	raw, err := os.ReadFile(filepath.Join(s.dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), p.AccessToken) || strings.Contains(string(raw), p.RefreshToken) || strings.Contains(string(raw), code) {
		t.Fatal("raw credential was persisted")
	}
	if _, ok := s.data.Access[digest(p.AccessToken)]; !ok {
		t.Fatal("raw state lacks the hashed access row")
	}
	if err = s.close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openStore(s.dir, s.data.Origin)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	if _, _, _, err = reopened.exchange(code, "test-client", testRedirect, s.data.Origin+"/mcp", testVerifier); err == nil {
		t.Fatal("code replay survived restart")
	}
	p2, _, _, err := reopened.refresh(p.RefreshToken, "test-client", "", "")
	if err != nil {
		t.Fatal(err)
	}
	p3, _, _, err := reopened.refresh(p2.RefreshToken, "test-client", "", "")
	if err != nil {
		t.Fatal(err)
	}
	_, got, reuse, err := reopened.refresh(p.RefreshToken, "test-client", "", "")
	if !errors.Is(err, errInvalidGrant) || reuse != "refresh_reuse" || got != id {
		t.Fatal("late refresh reuse did not revoke family")
	}
	if _, err = reopened.access(p3.AccessToken, s.data.Origin+"/mcp"); err == nil {
		t.Fatal("reuse left newest access token active")
	}
	if _, _, _, err = reopened.refresh(p3.RefreshToken, "test-client", "", ""); err == nil {
		t.Fatal("revoked family refreshed")
	}
}

// Two refreshes racing with one token are what a client retrying a lost answer,
// or two calls that both met a 401, look like. Both get the same answer, so
// neither holds a token the other retired; reuse detection still holds after.
func TestConcurrentRefreshesShareOneAnswer(t *testing.T) {
	s := testStore(t)
	p, _ := firstPair(t, s)
	var wg sync.WaitGroup
	type result struct {
		p   tokenPair
		err error
	}
	results := make(chan result, 2)
	for range 2 {
		wg.Go(func() {
			p, _, _, e := s.refresh(p.RefreshToken, "test-client", "", "")
			results <- result{p, e}
		})
	}
	wg.Wait()
	close(results)
	var issued []tokenPair
	for r := range results {
		if r.err != nil {
			t.Fatalf("retry inside the grace window refused: %v", r.err)
		}
		issued = append(issued, r.p)
	}
	if issued[0].RefreshToken != issued[1].RefreshToken || issued[0].AccessToken != issued[1].AccessToken {
		t.Fatal("concurrent refreshes with one token got different answers")
	}
	next, _, _, err := s.refresh(issued[0].RefreshToken, "test-client", "", "")
	if err != nil {
		t.Fatalf("the shared answer could not rotate: %v", err)
	}
	if _, _, why, err := s.refresh(p.RefreshToken, "test-client", "", ""); err == nil || why != "refresh_reuse" {
		t.Fatal("a token two rotations old was accepted")
	}
	if _, err := s.access(next.AccessToken, s.data.Origin+"/mcp"); err == nil {
		t.Fatal("reuse left the family active")
	}
}

func TestStoredSignatureCounterNeverMovesBack(t *testing.T) {
	var d stateData
	newer := webauthn.Credential{ID: []byte("key")}
	newer.Authenticator.SignCount = 9
	if err := storeCredential(&d, &newer, true); err != nil {
		t.Fatal(err)
	}
	older := newer
	older.Authenticator.SignCount = 8
	if err := storeCredential(&d, &older, false); err != nil {
		t.Fatal(err)
	}
	if d.Credentials[0].Authenticator.SignCount != 9 {
		t.Fatal("a concurrent older login moved the signature counter back")
	}
}

func TestRefreshGraceEndsAndScopeMayBeReorderedOrNarrowed(t *testing.T) {
	s := testStore(t)
	p, _ := firstPair(t, s)
	next, _, _, err := s.refresh(p.RefreshToken, "test-client", "", "offline_access code:run")
	if err != nil {
		t.Fatalf("reordered scope refused: %v", err)
	}
	if next, _, _, err = s.refresh(next.RefreshToken, "test-client", "", "code:run"); err != nil || next.Scope != "code:run offline_access" {
		t.Fatalf("narrower scope refused: %v", err)
	}
	if _, _, _, err = s.refresh(next.RefreshToken, "test-client", "", "code:run admin"); !errors.Is(err, errInvalidScope) {
		t.Fatal("wider scope accepted")
	}
	later := time.Now().Add(refreshGrace + time.Second)
	s.now = func() time.Time { return later }
	if _, _, why, err := s.refresh(p.RefreshToken, "test-client", "", ""); err == nil || why != "refresh_reuse" {
		t.Fatal("an old token was accepted")
	}
}

// A grant without a refresh token is spent once its access token expires, and a
// full store retires the least recently refreshed idle grant for a new approval.
func TestSpentAndAbandonedGrantsReleaseTheirSlots(t *testing.T) {
	s := testStore(t)
	short := func() (string, error) {
		code := randomID("c_")
		err := s.update(func(d *stateData) error {
			d.Codes[digest(code)] = codeRecord{Client: clientRecord{ID: "test-client"}, Redirect: testRedirect, Resource: d.Origin + "/mcp", Scope: "code:run", Challenge: challenge(testVerifier), Expires: s.now().Add(codeLifetime)}
			return nil
		})
		if err != nil {
			return "", err
		}
		_, id, _, err := s.exchange(code, "test-client", testRedirect, s.data.Origin+"/mcp", testVerifier)
		return id, err
	}
	clock := time.Now()
	s.now = func() time.Time { return clock }
	for range maxGrants {
		if _, err := short(); err != nil {
			t.Fatal(err)
		}
	}
	clock = clock.Add(accessLifetime + time.Second)
	if _, err := short(); err != nil {
		t.Fatalf("spent grants kept their slots: %v", err)
	}
	clock = clock.Add(accessLifetime + time.Second)
	for range maxGrants {
		firstPair(t, s)
	}
	clock = clock.Add(accessLifetime + time.Second)
	_, id, evicted, err := s.exchange(seedCode(t, s), "test-client", testRedirect, s.data.Origin+"/mcp", testVerifier)
	if err != nil || len(evicted) != 1 || evicted[0] == id {
		t.Fatalf("a full store did not retire an idle grant: %v %v", evicted, err)
	}
}

func TestOversizedStateIsRefusedWithoutPoisoning(t *testing.T) {
	s := testStore(t)
	err := s.update(func(d *stateData) error {
		d.Clients["big"] = clientRecord{ID: "big", Name: strings.Repeat("x", maxStateBytes)}
		return nil
	})
	if !errors.Is(err, errStateFull) || s.failed {
		t.Fatalf("oversized transition: %v, poisoned %v", err, s.failed)
	}
	firstPair(t, s)
}

func TestAuthorizationPersistenceFailureFailsClosed(t *testing.T) {
	s := testStore(t)
	p, _ := firstPair(t, s)
	s.write = func([]byte) error { return errors.New("disk full") }
	if _, _, _, err := s.refresh(p.RefreshToken, "test-client", "", ""); err == nil {
		t.Fatal("failed persistence returned credentials")
	}
	if _, err := s.access(p.AccessToken, s.data.Origin+"/mcp"); err == nil {
		t.Fatal("storage failure left authentication active")
	}
	if err := s.update(func(*stateData) error { return nil }); err == nil {
		t.Fatal("poisoned store accepted another transition")
	}
}

func TestExpiryAudienceAndPersistentEmergencyStop(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	p, _ := firstPair(t, s)
	if _, err := s.access(p.AccessToken, "https://other.example/mcp"); err == nil {
		t.Fatal("wrong audience accepted")
	}
	if _, err := s.access(p.RefreshToken, s.data.Origin+"/mcp"); err == nil {
		t.Fatal("refresh used as access")
	}
	now = now.Add(accessLifetime)
	if _, err := s.access(p.AccessToken, s.data.Origin+"/mcp"); err == nil {
		t.Fatal("expired access accepted")
	}
	now = now.Add(idleLifetime)
	if _, _, _, err := s.refresh(p.RefreshToken, "test-client", "", ""); err == nil {
		t.Fatal("idle family refreshed")
	}
	p, _ = firstPair(t, s)
	if _, err := s.disable(); err != nil {
		t.Fatal(err)
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	r, err := openStore(s.dir, s.data.Origin)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	if !r.data.Disabled {
		t.Fatal("disable did not survive restart")
	}
	if _, err := r.access(p.AccessToken, r.data.Origin+"/mcp"); err == nil {
		t.Fatal("disabled access accepted")
	}
	if _, _, _, err := r.refresh(p.RefreshToken, "test-client", "", ""); err == nil {
		t.Fatal("disabled refresh accepted")
	}
}

func TestStateLockPermissionsOriginAndCorruption(t *testing.T) {
	s := testStore(t)
	if other, err := openStore(s.dir, s.data.Origin); err == nil {
		_ = other.close()
		t.Fatal("second writer accepted")
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	if other, err := openStore(s.dir, "https://changed.example"); err == nil {
		_ = other.close()
		t.Fatal("changed origin accepted")
	}
	p := filepath.Join(s.dir, "state.json")
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if other, err := openStore(s.dir, s.data.Origin); err == nil {
		_ = other.close()
		t.Fatal("readable state accepted")
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if other, err := openStore(s.dir, s.data.Origin); err == nil {
		_ = other.close()
		t.Fatal("corrupt schema accepted")
	}
}

// A failed directory sync may happen after rename committed the new state. The
// current process must stop authorizing, and restart must respect that consumed
// refresh, even though its successful response never reached a client.
func TestPersistenceFailureAfterRenameAndLostRefreshResponse(t *testing.T) {
	s := testStore(t)
	first, _ := firstPair(t, s)
	realWrite := s.write
	s.write = func(b []byte) error {
		if err := realWrite(b); err != nil {
			return err
		}
		return errors.New("directory sync failed after rename")
	}
	if _, _, _, err := s.refresh(first.RefreshToken, "test-client", "", ""); err == nil {
		t.Fatal("uncertain commit issued a successful refresh")
	}
	if _, err := s.access(first.AccessToken, s.data.Origin+"/mcp"); err == nil {
		t.Fatal("uncertain commit kept current process authorizing")
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := openStore(s.dir, s.data.Origin)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.close()
	// Inside the grace window the lost answer is retried; past it, the token is
	// reuse. Either way the restart honors the refresh committed before the loss.
	if _, _, why, err := restarted.refresh(first.RefreshToken, "test-client", "", ""); err != nil || why != "" {
		t.Fatalf("restart refused a retry inside the grace window: %v", err)
	}
	later := time.Now().Add(refreshGrace + time.Second)
	restarted.now = func() time.Time { return later }
	if _, _, why, err := restarted.refresh(first.RefreshToken, "test-client", "", ""); err == nil || why != "refresh_reuse" {
		t.Fatal("restart forgot the refresh committed before its response was lost")
	}
}

// A family that used its whole refresh history is revoked, not left failing.
func TestExhaustedRefreshHistoryRevokesTheFamily(t *testing.T) {
	s := testStore(t)
	p, id := firstPair(t, s)
	if err := s.update(func(d *stateData) error {
		for i := range maxRefreshHistory - 1 {
			d.Grants[id].UsedRefresh[fmt.Sprint(i)] = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	p, _, _, err := s.refresh(p.RefreshToken, "test-client", "", "")
	if err != nil {
		t.Fatal(err)
	}
	_, got, why, err := s.refresh(p.RefreshToken, "test-client", "", "")
	if !errors.Is(err, errInvalidGrant) || why != "refresh_exhausted" || got != id {
		t.Fatalf("exhausted history: %q %v", why, err)
	}
	if _, err = s.access(p.AccessToken, s.data.Origin+"/mcp"); err == nil {
		t.Fatal("an exhausted family stayed active")
	}
}

// A transition whose write fails reports no retired grant and no revocation: the old
// state stays in force, so the workspaces it names must stay too.
func TestFailedWritesReportNoRetirementOrRevocation(t *testing.T) {
	s := testStore(t)
	clock := time.Now()
	s.now = func() time.Time { return clock }
	for range maxGrants {
		firstPair(t, s)
	}
	clock = clock.Add(accessLifetime + time.Second)
	code := seedCode(t, s)
	s.write = func([]byte) error { return errors.New("disk full") }
	if _, _, evicted, err := s.exchange(code, "test-client", testRedirect, s.data.Origin+"/mcp", testVerifier); err == nil || len(evicted) != 0 {
		t.Fatalf("a failed exchange reported retired grants %v (%v)", evicted, err)
	}
	if len(s.data.Grants) != maxGrants {
		t.Fatalf("the failed exchange changed the durable grants: %d", len(s.data.Grants))
	}

	r := testStore(t)
	rclock := time.Now()
	r.now = func() time.Time { return rclock }
	p, _ := firstPair(t, r)
	if _, _, _, err := r.refresh(p.RefreshToken, "test-client", "", ""); err != nil {
		t.Fatal(err)
	}
	rclock = rclock.Add(refreshGrace + time.Second)
	r.write = func([]byte) error { return errors.New("disk full") }
	if _, _, revoked, err := r.refresh(p.RefreshToken, "test-client", "", ""); err == nil || revoked != "" {
		t.Fatalf("a reuse whose revocation was not written reported %q (%v)", revoked, err)
	}
}

// A lookup made after storage failed says so, rather than finding nothing: the token
// endpoint answers a server fault, not an invalid credential, even when the failure
// lands between its health check and the lookup.
func TestLookupsReportFailedStorage(t *testing.T) {
	s := testStore(t)
	p, _ := firstPair(t, s)
	code := seedCode(t, s)
	s.mu.Lock()
	s.failed = true
	s.mu.Unlock()
	if found, err := s.lookupCode(code); found || !errors.Is(err, errUnavailable) {
		t.Fatalf("code lookup on failed storage: %v, %v", found, err)
	}
	if id, err := s.lookupRefresh(p.RefreshToken); id != "" || !errors.Is(err, errUnavailable) {
		t.Fatalf("refresh lookup on failed storage: %q, %v", id, err)
	}
}
