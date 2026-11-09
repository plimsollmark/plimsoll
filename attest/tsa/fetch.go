package tsa

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Authority is a time-stamp authority a requester trusts: a name, the URL that takes
// requests, and the lowercase hex SHA-256 of its root certificate's DER, which every
// token from it must chain to.
type Authority struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	RootSHA256 string `json:"root_sha256"`
}

// Fetch sends req to the authority and returns the response bytes, unverified.
func (a Authority) Fetch(ctx context.Context, client *http.Client, req Request) ([]byte, error) {
	if client == nil {
		// Not http.DefaultClient, which has no timeout (review, 2026-10-26).
		client = &http.Client{Timeout: 30 * time.Second}
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.URL, bytes.NewReader(req.DER))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	httpReq.Header.Set("Accept", "application/timestamp-reply")
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("tsa: %s: %w", a.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tsa: %s answered HTTP %d", a.Name, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
	if err != nil {
		return nil, fmt.Errorf("tsa: %s: %w", a.Name, err)
	}
	if len(body) > MaxResponse {
		return nil, fmt.Errorf("tsa: %s answered more than %d bytes", a.Name, MaxResponse)
	}
	return body, nil
}

// Witness asks the authority for a token over digest and verifies it: the token must
// cover the digest, echo the request's nonce and chain to the authority's pinned root
// among roots. It returns the verified token, the request and the response bytes to keep.
func Witness(ctx context.Context, client *http.Client, a Authority, digest []byte, roots []*x509.Certificate) (Token, Request, []byte, error) {
	req, err := NewRequest(digest)
	if err != nil {
		return Token{}, Request{}, nil, err
	}
	response, err := a.Fetch(ctx, client, req)
	if err != nil {
		return Token{}, Request{}, nil, err
	}
	tok, err := Verify(response, digest, req.Nonce, roots)
	if err != nil {
		return Token{}, Request{}, nil, fmt.Errorf("%s: %w", a.Name, err)
	}
	if tok.RootSHA256 != a.RootSHA256 {
		return Token{}, Request{}, nil, fmt.Errorf("tsa: %s's token chains to root %s, not the pinned %s", a.Name, tok.RootSHA256, a.RootSHA256)
	}
	return tok, req, response, nil
}
