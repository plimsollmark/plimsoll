package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"html/template"
	"strings"
)

// publicPEM encodes the harness's public key as a PKIX PEM block, the form
// plimsoll-attest verify -pub reads.
func publicPEM(pub ed25519.PublicKey) ([]byte, []byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	return der, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// chainSVG draws the session's records left to right, each naming the one before
// it, and the close statement that fixes the chain's length.
func chainSVG(calls []call) template.HTML {
	const (
		w, h   = 150, 78
		gap    = 34
		top    = 26
		margin = 12
	)
	n := len(calls) + 1 // the records, then the close
	width := margin*2 + n*w + (n-1)*gap
	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" width="100%%" role="img" aria-label="The session's records as a chain: each record names the digest of the one before it, and the close states how many there are and which is last.">`, width, top+h+36)
	b.WriteString(`<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#5a5a5a"/></marker></defs>`)
	short := func(s string) string {
		if len(s) < 10 {
			if s == "" {
				return "(none)"
			}
			return s
		}
		return s[:10] + "…"
	}
	for i, c := range calls {
		x := margin + i*(w+gap)
		fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" rx="7" fill="#fff" stroke="#2a78d6" stroke-width="1.5"/>`, x, top, w, h)
		fmt.Fprintf(&b, `<text x="%d" y="%d" font-size="13" font-weight="600" fill="#1a1a1a">call %d · %s</text>`, x+10, top+20, c.N, template.HTMLEscapeString(c.Kind))
		fmt.Fprintf(&b, `<text x="%d" y="%d" font-size="11.5" fill="#5a5a5a">record</text>`, x+10, top+40)
		fmt.Fprintf(&b, `<text x="%d" y="%d" font-size="11.5" font-family="ui-monospace, Menlo, Consolas, monospace" fill="#1a1a1a">%s</text>`, x+56, top+40, template.HTMLEscapeString(short(c.Record)))
		fmt.Fprintf(&b, `<text x="%d" y="%d" font-size="11.5" fill="#5a5a5a">previous</text>`, x+10, top+60)
		fmt.Fprintf(&b, `<text x="%d" y="%d" font-size="11.5" font-family="ui-monospace, Menlo, Consolas, monospace" fill="#1a1a1a">%s</text>`, x+66, top+60, template.HTMLEscapeString(short(c.Previous)))
		if i > 0 {
			fmt.Fprintf(&b, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#5a5a5a" stroke-width="1.3" marker-end="url(#arrow)"/>`, x, top+h/2, x-gap+2, top+h/2)
		}
	}
	x := margin + len(calls)*(w+gap)
	last := ""
	if len(calls) > 0 {
		last = calls[len(calls)-1].Record
	}
	fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" rx="7" fill="#e6f4ea" stroke="#1baf7a" stroke-width="1.5"/>`, x, top, w, h)
	fmt.Fprintf(&b, `<text x="%d" y="%d" font-size="13" font-weight="600" fill="#1e6b2f">close</text>`, x+10, top+20)
	fmt.Fprintf(&b, `<text x="%d" y="%d" font-size="11.5" fill="#1e6b2f">%d calls</text>`, x+10, top+40, len(calls))
	fmt.Fprintf(&b, `<text x="%d" y="%d" font-size="11.5" fill="#1e6b2f">last </text><text x="%d" y="%d" font-size="11.5" font-family="ui-monospace, Menlo, Consolas, monospace" fill="#1e6b2f">%s</text>`, x+10, top+60, x+40, top+60, template.HTMLEscapeString(short(last)))
	fmt.Fprintf(&b, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#5a5a5a" stroke-width="1.3" marker-end="url(#arrow)"/>`, x, top+h/2, x-gap+2, top+h/2)
	fmt.Fprintf(&b, `<text x="%d" y="%d" font-size="12" fill="#5a5a5a">Each arrow: a record names the digest of the one before it. The close fixes how many there are, so a cut tail shows.</text>`, margin, top+h+26)
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}
