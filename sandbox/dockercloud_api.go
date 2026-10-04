package sandbox

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ---- errors and the token exchange, shared by every transport ----

// dcRPCError is a Connect error from either endpoint. Code and Message are the
// vendor's text, kept as sent; Error scrubs them, so no construction site (a unary
// body, an end-of-stream frame) can put an echoed credential into an error string.
type dcRPCError struct {
	Procedure  string
	HTTPStatus int
	Code       string // Connect code: not_found, unimplemented, ...
	Message    string
}

func (e *dcRPCError) Error() string {
	return fmt.Sprintf("dockercloud %s: %s (HTTP %d): %s", e.Procedure, truncateForError(e.Code), e.HTTPStatus, truncateForError(e.Message))
}

func dcCodeIs(err error, code string) bool {
	var rpc *dcRPCError
	return errors.As(err, &rpc) && rpc.Code == code
}

// dcUnsentError is a call that failed before its request was handed to the HTTP
// client: the token exchange failed, or the context was already done.
type dcUnsentError struct{ err error }

func (e *dcUnsentError) Error() string { return e.err.Error() }
func (e *dcUnsentError) Unwrap() error { return e.err }

// dcUnsent reports whether a failed call proves its request never reached the
// service: it failed before it was sent (dcUnsentError) or before a connection was
// made (requestNeverLeft).
func dcUnsent(err error) bool {
	var unsent *dcUnsentError
	return errors.As(err, &unsent) || requestNeverLeft(err)
}

// dcRefused reports whether a failed call is the service refusing it, by a Connect
// code that says it did nothing. The codes that leave the outcome open (unknown,
// internal, unavailable, deadline_exceeded, aborted, canceled, data_loss),
// already_exists (something under that name exists), and any other error, a response
// that could not be read or parsed included, do not.
func dcRefused(err error) bool {
	var rpc *dcRPCError
	if !errors.As(err, &rpc) {
		return false
	}
	switch rpc.Code {
	case "unknown", "internal", "unavailable", "deadline_exceeded", "aborted", "canceled", "data_loss", "already_exists":
		return false
	}
	return true
}

// dcDefaultAuthURL is Docker Hub's documented token endpoint: POST
// {"identifier", "secret"} and receive {"access_token"}.
const dcDefaultAuthURL = "https://hub.docker.com/v2/auth/token"

// dcAuthRefreshMargin renews the bearer token this long before it expires, so a
// call never starts with a token about to lapse.
const dcAuthRefreshMargin = 60 * time.Second

func (d *DockerCloud) authURL() string {
	if u := strings.TrimSpace(d.AuthURL); u != "" {
		return u
	}
	return dcDefaultAuthURL
}

// bearer returns a current short-lived access token, exchanging the personal
// access token when none is cached or the cached one is within the refresh margin.
// The JWT's exp claim is read only to schedule the refresh; it is never trusted
// for anything else. Neither token is logged or included in an error.
func (d *DockerCloud) bearer(ctx context.Context) (string, error) {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	if d.access != "" && time.Until(d.accessExp) > dcAuthRefreshMargin {
		return d.access, nil
	}
	body, err := json.Marshal(map[string]string{"identifier": strings.TrimSpace(d.Username), "secret": strings.TrimSpace(d.Token)})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.authURL(), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("dockercloud: token exchange: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", fmt.Errorf("dockercloud: token exchange: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Classified like any Connect auth failure so callers treat it one way. The
		// response body is not echoed: it is the vendor's text about our credential.
		code := "unavailable"
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			code = "unauthenticated"
		}
		return "", &dcRPCError{Procedure: "token exchange", HTTPStatus: resp.StatusCode, Code: code,
			Message: fmt.Sprintf("token exchange refused: HTTP %d", resp.StatusCode)}
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.AccessToken == "" {
		return "", errors.New("dockercloud: token exchange returned no access_token")
	}
	d.access, d.accessExp = out.AccessToken, dcJWTExpiry(out.AccessToken, time.Now())
	return d.access, nil
}

// dcJWTExpiry reads the exp claim of an unverified JWT for refresh scheduling. An
// unreadable token is treated as expiring in five minutes.
func dcJWTExpiry(token string, now time.Time) time.Time {
	fallback := now.Add(5 * time.Minute)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fallback
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return fallback
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Exp <= 0 {
		return fallback
	}
	return time.Unix(claims.Exp, 0)
}

// ---- protojson helpers ----

// protoEnum holds a protojson enum value. Conforming servers emit the value name,
// but the encoding also allows the number, so both are accepted.
type protoEnum string

func (p *protoEnum) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*p = protoEnum(s)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*p = protoEnum(strconv.FormatInt(n, 10))
	return nil
}

func (p protoEnum) is(name string, number int) bool {
	return string(p) == name || string(p) == strconv.Itoa(number)
}

// protoUint holds a protojson unsigned integer, which the encoding writes as a
// string for 64-bit fields and as a number for 32-bit ones.
type protoUint uint64

func (p *protoUint) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		n, err := strconv.ParseUint(s, 10, 64)
		*p = protoUint(n)
		return err
	}
	var n uint64
	err := json.Unmarshal(b, &n)
	*p = protoUint(n)
	return err
}

func protoDuration(d time.Duration) string {
	secs := int64(math.Ceil(d.Seconds()))
	if secs < 1 {
		secs = 1
	}
	return strconv.FormatInt(secs, 10) + "s"
}
