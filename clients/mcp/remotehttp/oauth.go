package remotehttp

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
)

func parseJSON(r *http.Request, out any) error { return decodeJSON(r, out, true) }

func decodeJSON(r *http.Request, out any, strict bool) error {
	t, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || t != "application/json" {
		return errors.New("expected JSON")
	}
	d := json.NewDecoder(r.Body)
	if strict {
		d.DisallowUnknownFields()
	}
	if err = d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func parseForm(r *http.Request, keys ...string) (url.Values, error) {
	t, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || t != "application/x-www-form-urlencoded" {
		return nil, errors.New("expected form")
	}
	if err = r.ParseForm(); err != nil {
		return nil, err
	}
	for k, v := range r.PostForm {
		if len(v) != 1 || !slices.Contains(keys, k) {
			return nil, errors.New("unexpected or duplicate form field")
		}
	}
	return r.PostForm, nil
}
func constantEqual(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func (e *Engine) register(w http.ResponseWriter, r *http.Request) {
	if !e.active() {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	var in struct {
		Name      string   `json:"client_name"`
		Redirects []string `json:"redirect_uris"`
		Method    string   `json:"token_endpoint_auth_method"`
		Grants    []string `json:"grant_types"`
		Responses []string `json:"response_types"`
	}
	// RFC 7591 permits extension metadata. Unknown fields are ignored, never
	// stored, fetched or used as authority.
	if decodeJSON(r, &in, false) != nil || len(in.Name) > 80 || len(in.Redirects) == 0 || len(in.Redirects) > 2 || in.Method != "" && in.Method != "none" {
		oauthError(w, 400, "invalid_client_metadata")
		return
	}
	for _, s := range in.Redirects {
		if !approvedRedirect(s) {
			oauthError(w, 400, "invalid_redirect_uri")
			return
		}
	}
	for _, s := range in.Grants {
		if s != "authorization_code" && s != "refresh_token" {
			oauthError(w, 400, "invalid_client_metadata")
			return
		}
	}
	for _, s := range in.Responses {
		if s != "code" {
			oauthError(w, 400, "invalid_client_metadata")
			return
		}
	}
	// The public registration identity is the approved callback set. Do not
	// allocate a permanent row for every anonymous name or connection attempt.
	sort.Strings(in.Redirects)
	in.Redirects = slices.Compact(in.Redirects)
	var names []string
	for _, redirect := range in.Redirects {
		u, _ := url.Parse(redirect)
		names = append(names, u.Hostname())
	}
	c := clientRecord{ID: randomID("client_"), Name: strings.Join(names, ", "), Redirects: in.Redirects}
	// A repeat registration is answered from memory: only a new callback set,
	// of which the approved list allows few, writes the state.
	e.state.mu.Lock()
	for _, existing := range e.state.data.Clients {
		if slices.Equal(existing.Redirects, c.Redirects) {
			e.state.mu.Unlock()
			e.registered(w, existing)
			return
		}
	}
	e.state.mu.Unlock()
	err := e.state.update(func(d *stateData) error {
		if d.Disabled {
			return errInactive
		}
		for _, existing := range d.Clients {
			if slices.Equal(existing.Redirects, c.Redirects) {
				c = existing
				return nil
			}
		}
		if len(d.Clients) >= maxClients {
			return errors.New("registration cap")
		}
		d.Clients[c.ID] = c
		return nil
	})
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	e.audit.event("client_registered", "", digest(c.ID))
	e.registered(w, c)
}

func (e *Engine) registered(w http.ResponseWriter, c clientRecord) {
	jsonReply(w, 201, map[string]any{"client_id": c.ID, "client_name": c.Name, "redirect_uris": c.Redirects, "token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}})
}

func (e *Engine) resolveClient(r *http.Request, id string) (clientRecord, error) {
	if approvedMetadata(id) {
		return e.clients.resolve(r.Context(), id)
	}
	e.state.mu.Lock()
	c, ok := e.state.data.Clients[id]
	e.state.mu.Unlock()
	if !ok {
		return clientRecord{}, errors.New("unknown client")
	}
	return c, nil
}

func validScope(s string) bool {
	return s == "code:run" || s == "code:run offline_access" || s == "offline_access code:run"
}
func canonicalScope(s string) string {
	if strings.Contains(s, "offline_access") {
		return "code:run offline_access"
	}
	return "code:run"
}

func (e *Engine) authorize(w http.ResponseWriter, r *http.Request) {
	if !e.active() {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		reject(w, 400)
		return
	}
	keys := []string{"client_id", "redirect_uri", "response_type", "resource", "scope", "state", "code_challenge", "code_challenge_method"}
	for k, v := range q {
		if len(v) != 1 || !slices.Contains(keys, k) || len(v[0]) > 2048 {
			reject(w, 400)
			return
		}
	}
	c, err := e.resolveClient(r, q.Get("client_id"))
	redirect := q.Get("redirect_uri")
	if err != nil || !approvedRedirect(redirect) || !slices.Contains(c.Redirects, redirect) {
		oauthError(w, 400, "invalid_client")
		return
	}
	tx := &approval{Generation: e.generation(), Client: c, Redirect: redirect, State: q.Get("state"), Resource: q.Get("resource"), Scope: q.Get("scope"), Challenge: q.Get("code_challenge"), Expires: time.Now().Add(transactionLifetime)}
	if !validScope(tx.Scope) {
		e.redirect(w, r, tx, "", "invalid_scope")
		return
	}
	if tx.Resource != e.resource() {
		e.redirect(w, r, tx, "", "invalid_target")
		return
	}
	decoded, err := base64.RawURLEncoding.DecodeString(tx.Challenge)
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || err != nil || len(decoded) != 32 || len(tx.Challenge) != 43 || len(tx.State) > 1024 {
		e.redirect(w, r, tx, "", "invalid_request")
		return
	}
	tx.Scope = canonicalScope(tx.Scope)
	e.startApproval(w, tx)
}

// startApproval seals an approval into its page and binds it to this browser
// with a cookie of its own. Nothing is stored.
func (e *Engine) startApproval(w http.ResponseWriter, tx *approval) {
	tx.Nonce = randomID("")[:22]
	tx.CSRF = randomID("csrf_")
	cookie := randomID("browser_")
	tx.CookieHash = digest(cookie)
	http.SetCookie(w, &http.Cookie{Name: approvalCookie(tx.Nonce), Value: cookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(transactionLifetime.Seconds())})
	e.page(w, tx, e.seals.seal("approval", tx))
}

// openApproval checks a sealed approval against its browser, its CSRF value,
// its kind, its lifetime and the current generation.
func (e *Engine) openApproval(r *http.Request, sealed, csrf string, enrollment bool) *approval {
	var tx approval
	if e.seals.open("approval", sealed, &tx) != nil || tx.Enrollment != enrollment || tx.Generation != e.generation() || !time.Now().Before(tx.Expires) || !constantEqual(tx.CSRF, csrf) || !e.browserProof(r, &tx) {
		return nil
	}
	return &tx
}
func (e *Engine) redirect(w http.ResponseWriter, r *http.Request, tx *approval, code, kind string) {
	u, _ := url.Parse(tx.Redirect)
	q := u.Query()
	q.Set("iss", e.cfg.PublicURL)
	if tx.State != "" {
		q.Set("state", tx.State)
	}
	if kind != "" {
		q.Set("error", kind)
	} else {
		q.Set("code", code)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func (e *Engine) consent(w http.ResponseWriter, r *http.Request) {
	f, err := parseForm(r, "tx", "csrf", "decision")
	if err != nil {
		reject(w, 400)
		return
	}
	tx := e.openApproval(r, f.Get("tx"), f.Get("csrf"), false)
	if tx == nil || !e.active() {
		e.refused("consent_refused")
		reject(w, 403)
		return
	}
	switch f.Get("decision") {
	case "deny":
		// Denying a verified approval is final: it takes the verified mark that
		// approval needs and marks the approval answered, so an approve already on
		// its way cannot follow it (take is atomic, so one of the two wins). An
		// unverified approval's denial stores nothing; only the owner's passkey
		// could still verify it.
		now := time.Now()
		if e.marks.take("verified:"+tx.Nonce, now) {
			e.marks.claim("answered:"+tx.Nonce, tx.Expires, now)
		}
		e.endApproval(w, tx)
		e.redirect(w, r, tx, "", "access_denied")
		return
	case "approve":
	default:
		reject(w, 403)
		return
	}
	// Only a verified passkey creates the verified mark, and approval consumes
	// it and marks the approval answered, so one approval yields at most one code.
	now := time.Now()
	if !e.marks.take("verified:"+tx.Nonce, now) || !e.marks.claim("answered:"+tx.Nonce, tx.Expires, now) {
		e.refused("consent_refused")
		reject(w, 403)
		return
	}
	code := randomID("c_")
	err = e.state.update(func(d *stateData) error {
		if d.Disabled || d.Generation != tx.Generation || len(d.Codes) >= maxCodes {
			return errInactive
		}
		d.Codes[digest(code)] = codeRecord{Client: tx.Client, Redirect: tx.Redirect, Resource: tx.Resource, Scope: tx.Scope, Challenge: tx.Challenge, Expires: e.state.now().Add(codeLifetime)}
		return nil
	})
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	e.audit.event("consent_approved", "", digest(tx.Client.ID))
	e.endApproval(w, tx)
	e.redirect(w, r, tx, code, "")
}

func (e *Engine) endApproval(w http.ResponseWriter, tx *approval) {
	http.SetCookie(w, &http.Cookie{Name: approvalCookie(tx.Nonce), Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

// unavailable answers a fault on this side. invalid_grant would tell the client
// to discard a refresh token that is still valid; a 5xx tells it to retry.
func unavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "5")
	oauthError(w, 503, "temporarily_unavailable")
}

func (e *Engine) token(w http.ResponseWriter, r *http.Request) {
	f, err := parseForm(r, "grant_type", "client_id", "code", "redirect_uri", "resource", "code_verifier", "refresh_token", "scope")
	if err != nil {
		oauthError(w, 400, "invalid_request")
		return
	}
	if !e.healthy() {
		unavailable(w)
		return
	}
	// A disabled service has revoked every grant and code, so the transitions
	// below answer invalid_grant for it, which is then true.
	var pair tokenPair
	var id, revoked string
	var evicted []string
	switch f.Get("grant_type") {
	case "authorization_code":
		found, lookupErr := e.state.lookupCode(f.Get("code"))
		if lookupErr != nil {
			unavailable(w)
			return
		}
		if !found {
			oauthError(w, 400, "invalid_grant")
			return
		}
		pair, id, evicted, err = e.state.exchange(f.Get("code"), f.Get("client_id"), f.Get("redirect_uri"), f.Get("resource"), f.Get("code_verifier"))
	case "refresh_token":
		grant, lookupErr := e.state.lookupRefresh(f.Get("refresh_token"))
		if lookupErr != nil {
			unavailable(w)
			return
		}
		if grant == "" {
			oauthError(w, 400, "invalid_grant")
			return
		}
		if !e.takeRefresh(grant) {
			w.Header().Set("Retry-After", "10")
			oauthError(w, 429, "temporarily_unavailable")
			return
		}
		pair, id, revoked, err = e.state.refresh(f.Get("refresh_token"), f.Get("client_id"), f.Get("resource"), f.Get("scope"))
	default:
		oauthError(w, 400, "unsupported_grant_type")
		return
	}
	for _, old := range evicted {
		e.cancelGrant(r.Context(), old)
		e.audit.event("grant_retired", old, "")
	}
	if revoked != "" {
		e.cancelGrant(r.Context(), id)
		e.audit.event(revoked, id, "")
	}
	switch {
	case errors.Is(err, errInvalidGrant):
		oauthError(w, 400, "invalid_grant")
		return
	case errors.Is(err, errInvalidScope):
		oauthError(w, 400, "invalid_scope")
		return
	case err != nil:
		unavailable(w)
		return
	}
	if err = e.tools.RegisterGrant(id, digest(f.Get("client_id"))); err != nil {
		_, _ = e.state.revokeToken(pair.AccessToken, f.Get("client_id"))
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	e.audit.event("token_issued", id, digest(f.Get("client_id")))
	jsonReply(w, 200, pair)
}

func (e *Engine) revoke(w http.ResponseWriter, r *http.Request) {
	f, err := parseForm(r, "token", "client_id", "token_type_hint")
	if err != nil || f.Get("client_id") == "" {
		oauthError(w, 400, "invalid_request")
		return
	}
	// RFC 7009 answers 200 for an unknown token; finding none needs no write.
	if e.state.lookupToken(f.Get("token"), f.Get("client_id")) == "" {
		w.WriteHeader(200)
		return
	}
	id, err := e.state.revokeToken(f.Get("token"), f.Get("client_id"))
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	if id != "" {
		e.cancelGrant(r.Context(), id)
		e.audit.event("grant_revoked", id, "")
	}
	w.WriteHeader(200)
}
