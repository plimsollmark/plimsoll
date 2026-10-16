package remotehttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type owner struct {
	id          []byte
	credentials []webauthn.Credential
}

func (u owner) WebAuthnID() []byte                         { return u.id }
func (u owner) WebAuthnName() string                       { return "owner" }
func (u owner) WebAuthnDisplayName() string                { return "plimsoll owner" }
func (u owner) WebAuthnCredentials() []webauthn.Credential { return u.credentials }
func (e *Engine) owner() owner {
	e.state.mu.Lock()
	defer e.state.mu.Unlock()
	return owner{e.state.data.OwnerID, e.state.data.Credentials}
}

type ceremonyInput struct {
	TX         string          `json:"tx"`
	CSRF       string          `json:"csrf"`
	Code       string          `json:"code,omitempty"`
	Session    string          `json:"session,omitempty"`
	Credential json.RawMessage `json:"credential,omitempty"`
}

// EnrollmentCode opens one short-lived enrollment ceremony. Only the private
// local operator channel calls it; the raw code is returned once and never stored.
func (e *Engine) EnrollmentCode() (string, error) {
	code := randomID("enroll_")
	err := e.state.update(func(d *stateData) error {
		if len(d.Credentials) >= 8 {
			return errors.New("passkey limit reached")
		}
		d.BootstrapHash = digest(code)
		d.BootstrapExpires = e.state.now().Add(transactionLifetime)
		return nil
	})
	if err != nil {
		return "", err
	}
	e.audit.event("enrollment_enabled", "", "")
	return code, nil
}

func (e *Engine) enrollmentPage(w http.ResponseWriter, r *http.Request) {
	e.state.mu.Lock()
	available := e.state.data.BootstrapHash != "" && e.state.now().Before(e.state.data.BootstrapExpires) && !e.state.failed
	e.state.mu.Unlock()
	if !available {
		reject(w, 404)
		return
	}
	e.startApproval(w, &approval{Generation: e.generation(), Expires: time.Now().Add(transactionLifetime), Enrollment: true})
}

// ceremonyReply answers a ceremony's options with its challenge sealed beside
// them; the page returns the seal with the authenticator's answer.
func (e *Engine) ceremonyReply(w http.ResponseWriter, tx *approval, options any, session *webauthn.SessionData) {
	c := ceremony{ID: randomID("")[:22], Approval: tx.Nonce, Enrollment: tx.Enrollment, Expires: tx.Expires, Session: *session}
	b, err := json.Marshal(options)
	var reply map[string]any
	if err == nil {
		err = json.Unmarshal(b, &reply)
	}
	if err != nil {
		reject(w, 500)
		return
	}
	reply["session"] = e.seals.seal("ceremony", c)
	jsonReply(w, 200, reply)
}

func (e *Engine) beginEnrollment(w http.ResponseWriter, r *http.Request) {
	var in ceremonyInput
	if parseJSON(r, &in) != nil {
		reject(w, 400)
		return
	}
	tx := e.openApproval(r, in.TX, in.CSRF, true)
	e.state.mu.Lock()
	known := e.state.data.BootstrapHash != "" && constantEqual(e.state.data.BootstrapHash, digest(in.Code))
	e.state.mu.Unlock()
	if tx == nil || !known {
		e.refused("enrollment_refused")
		reject(w, 403)
		return
	}
	// The one-use local authorization is consumed durably before any challenge
	// is issued. A canceled enrollment requires another local enrollment code.
	err := e.state.update(func(d *stateData) error {
		if d.Generation != tx.Generation || d.BootstrapHash == "" || !constantEqual(d.BootstrapHash, digest(in.Code)) || !e.state.now().Before(d.BootstrapExpires) || len(d.Credentials) >= 8 {
			return errInactive
		}
		d.BootstrapHash = ""
		return nil
	})
	if err != nil {
		e.audit.event("enrollment_refused", "", "")
		reject(w, 403)
		return
	}
	// Excluding enrolled passkeys makes an authenticator that already holds one
	// refuse, instead of replacing it: a discoverable credential for the same
	// site and user handle overwrites the earlier one in the same provider.
	u := e.owner()
	creation, session, err := e.keys.BeginRegistration(u, webauthn.WithRegistrationOrigin(e.cfg.PublicURL), webauthn.WithExclusions(webauthn.Credentials(u.credentials).CredentialDescriptors()))
	if err != nil {
		reject(w, 500)
		return
	}
	e.ceremonyReply(w, tx, creation, session)
}

func (e *Engine) beginLogin(w http.ResponseWriter, r *http.Request) {
	var in ceremonyInput
	if parseJSON(r, &in) != nil {
		reject(w, 400)
		return
	}
	tx := e.openApproval(r, in.TX, in.CSRF, false)
	if tx == nil || !e.active() || e.marks.answered(tx.Nonce, time.Now()) {
		e.refused("login_refused")
		reject(w, 403)
		return
	}
	options, session, err := e.keys.BeginLogin(e.owner(), webauthn.WithLoginOrigin(e.cfg.PublicURL), webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		reject(w, 500)
		return
	}
	e.ceremonyReply(w, tx, options, session)
}

// finishCeremony holds no engine lock: the sealed challenge travels with the
// request, and the verified challenge is claimed once, so a replay fails.
func (e *Engine) finishCeremony(w http.ResponseWriter, r *http.Request, enroll bool) {
	var in ceremonyInput
	if parseJSON(r, &in) != nil {
		reject(w, 400)
		return
	}
	tx := e.openApproval(r, in.TX, in.CSRF, enroll)
	var c ceremony
	if tx == nil || e.seals.open("ceremony", in.Session, &c) != nil || c.Approval != tx.Nonce || c.Enrollment != enroll || !time.Now().Before(c.Expires) || !enroll && (!e.active() || e.marks.answered(tx.Nonce, time.Now())) {
		e.refused("passkey_refused")
		reject(w, 403)
		return
	}
	response := r.Clone(r.Context())
	response.Body = io.NopCloser(bytes.NewReader(in.Credential))
	u := e.owner()
	var credential *webauthn.Credential
	var err error
	if enroll {
		credential, err = e.keys.FinishRegistration(u, c.Session, response)
	} else {
		credential, err = e.keys.FinishLogin(u, c.Session, response)
	}
	if err != nil || credential == nil || !credential.Flags.UserVerified || credential.Authenticator.CloneWarning {
		e.refused("passkey_refused")
		reject(w, 403)
		return
	}
	// Only a verified passkey reaches here, so only the owner adds marks.
	now := time.Now()
	if !e.marks.claim("ceremony:"+c.ID, c.Expires, now) {
		e.refused("passkey_refused")
		reject(w, 403)
		return
	}
	err = e.state.update(func(d *stateData) error {
		if d.Generation != tx.Generation || !bytes.Equal(d.OwnerID, u.id) {
			return errInactive
		}
		return storeCredential(d, credential, enroll)
	})
	if err == nil && !enroll && !e.marks.mark("verified:"+tx.Nonce, tx.Expires, now) {
		err = errors.New("verification table full")
	}
	if err != nil {
		reject(w, 503)
		return
	}
	e.audit.event("passkey_verified", "", "")
	jsonReply(w, 200, map[string]bool{"verified": true})
}

// storeCredential records an enrolled passkey, or a verified login's updated
// copy. Logins verify concurrently, so an older answer never moves the signature
// counter back: clone detection compares the next assertion with it.
func storeCredential(d *stateData, credential *webauthn.Credential, enroll bool) error {
	for i, c := range d.Credentials {
		if bytes.Equal(c.ID, credential.ID) {
			if enroll {
				return errors.New("passkey already enrolled")
			}
			if credential.Authenticator.SignCount >= c.Authenticator.SignCount {
				d.Credentials[i] = *credential
			}
			return nil
		}
	}
	if !enroll || len(d.Credentials) >= 8 {
		return errInactive
	}
	d.Credentials = append(d.Credentials, *credential)
	return nil
}

func (e *Engine) cancelGrant(ctx context.Context, id string) bool {
	if id == "" || e.tools == nil {
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := e.tools.RevokeGrant(ctx, id)
	e.mu.Lock()
	delete(e.grantLimits, id)
	e.mu.Unlock()
	if err != nil {
		e.audit.event("cleanup_unconfirmed", id, "")
	}
	return err == nil
}

// Disable persists the emergency stop before canceling any grant's work. A
// persistence failure stops the tool server as well, and cannot be called success.
// It cancels every workspace the tool server holds, not only the grants the store
// still listed: one that expired before the last sweep still has its sandboxes.
func (e *Engine) Disable(ctx context.Context) (bool, error) {
	ids, err := e.state.disable()
	e.marks.reset()
	if err != nil {
		if e.tools != nil {
			e.tools.Shutdown()
		}
		return false, err
	}
	if e.tools != nil {
		ids = append(ids, e.tools.Grants()...)
	}
	slices.Sort(ids)
	complete := true
	for _, id := range slices.Compact(ids) {
		if !e.cancelGrant(ctx, id) {
			complete = false
		}
	}
	e.mu.Lock()
	e.grantLimits = map[string]*grantRate{}
	e.mu.Unlock()
	e.audit.event("disabled", "", "")
	return complete, nil
}

func (e *Engine) Enable() error {
	err := e.state.update(func(d *stateData) error {
		if len(d.Credentials) == 0 {
			return errors.New("owner passkey not enrolled")
		}
		d.Disabled = false
		return nil
	})
	if err == nil {
		e.audit.event("enabled", "", "")
	}
	return err
}
