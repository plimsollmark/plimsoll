package remotehttp

import (
	_ "embed"
	"html/template"
	"net/http"
)

//go:embed owner.html
var ownerHTML string
var ownerPage = template.Must(template.New("owner").Parse(ownerHTML))

func (e *Engine) page(w http.ResponseWriter, tx *approval, seal string) {
	nonce := randomID("n_")
	// Chromium applies form-action to an authorization form's redirect too.
	// Only the callback already checked against both policies is permitted.
	formActions := "'self'"
	if !tx.Enrollment {
		formActions += " " + tx.Redirect
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; form-action "+formActions+"; base-uri 'none'")
	_ = ownerPage.Execute(w, struct {
		Nonce  string
		TX     *approval
		Seal   string
		Origin string
	}{nonce, tx, seal, e.cfg.PublicURL})
}
