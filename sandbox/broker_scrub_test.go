package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// scrubPieces runs pieces through a stream scrubber for credential and returns each
// call's output and the output of end.
func scrubPieces(credential string, pieces []string) (outs []string, tail string, hit bool) {
	s := newStreamScrubber(credentialCopies(&HostAPIGrant{}, credential))
	for _, p := range pieces {
		outs = append(outs, string(s.next([]byte(p))))
	}
	tail = string(s.end())
	return outs, tail, s.hit
}

// TestStreamScrubberMatchesTheWholeAnswerHoweverItIsCut: a streamed answer, cut into
// pieces at every position and into pieces of every size, is found to hold a copy exactly
// when the buffered path finds one in the whole answer; when it holds none, the pieces
// leave the scrubber as the answer itself. So a copy split across pieces, at any byte, is
// found, and nothing of the piece that completes it is sent.
func TestStreamScrubberMatchesTheWholeAnswerHoweverItIsCut(t *testing.T) {
	t.Parallel()
	copies := credentialCopies(&HostAPIGrant{}, plantedCredential)
	texts := []string{
		"data: {\"you_sent\":\"Bearer " + plantedCredential + "\"}\n\ndata: again " + plantedCredential + plantedCredential + " end\n\n",
		plantedCredential,
		"x" + plantedCredential[:len(plantedCredential)-1] + " " + plantedCredential + "y",
		strings.Repeat(plantedCredential[:5], 9) + plantedCredential + "\n",
		"no copy here, only CANARY-cred and a line\nand another\n\n",
		"x" + plantedCredential[:len(plantedCredential)-1] + " " + plantedCredential[1:] + "y",
		"",
	}
	judge := func(t *testing.T, what, text string, pieces []string) {
		t.Helper()
		want := holdsCopy([]byte(text), copies)
		outs, tail, hit := scrubPieces(plantedCredential, pieces)
		got := strings.Join(outs, "") + tail
		if hit != want {
			t.Fatalf("%s of %q: found a copy %v, the whole answer holds one %v", what, text, hit, want)
		}
		if strings.Contains(got, plantedCredential) {
			t.Fatalf("%s of %q: a copy was handed over: %q", what, text, got)
		}
		if !hit && got != text {
			t.Fatalf("%s of %q: an answer with no copy left as %q", what, text, got)
		}
		if hit && !strings.HasPrefix(text, got) {
			t.Fatalf("%s of %q: what was sent, %q, is not the answer's start", what, text, got)
		}
	}
	for _, text := range texts {
		for cut := 0; cut <= len(text); cut++ {
			judge(t, fmt.Sprintf("cut at %d", cut), text, []string{text[:cut], text[cut:]})
		}
		for size := 1; size <= len(text); size++ {
			var pieces []string
			for i := 0; i < len(text); i += size {
				pieces = append(pieces, text[i:min(i+size, len(text))])
			}
			judge(t, fmt.Sprintf("pieces of %d", size), text, pieces)
		}
	}
}

// TestStreamScrubberHoldsBackNothingThatDependsOnTheCredential: what waits between
// pieces is decided by the data alone. Were the end of a piece held because it matches
// the start of the credential, guest code able to shape an answer could learn the
// credential a byte at a time by watching which endings arrive late. So for answers
// that hold no whole copy, every piece leaves two scrubbers with different credentials
// at the same length, whatever part of either credential the pieces end with.
func TestStreamScrubberHoldsBackNothingThatDependsOnTheCredential(t *testing.T) {
	t.Parallel()
	const other = "ZZZZ-another-credential-0001"
	for k := 0; k < len(plantedCredential); k++ {
		for _, before := range []string{"data: ", "data: x", "", "line\n"} {
			pieces := []string{before + plantedCredential[:k], "tail of the line\n\n", "data: more"}
			a, tailA, hitA := scrubPieces(plantedCredential, pieces)
			b, tailB, hitB := scrubPieces(other, pieces)
			if hitA || hitB {
				t.Fatalf("prefix %d: a removal with no whole copy in %q", k, pieces)
			}
			for i := range pieces {
				if len(a[i]) != len(b[i]) {
					t.Fatalf("prefix of %d bytes after %q: piece %d left as %d bytes with the credential it starts and %d with another: the hold depends on the credential", k, before, i, len(a[i]), len(b[i]))
				}
			}
			if strings.Join(a, "")+tailA != strings.Join(pieces, "") || strings.Join(b, "")+tailB != strings.Join(pieces, "") {
				t.Fatalf("prefix %d: an answer with no copy was changed", k)
			}
		}
	}
}

// TestStreamScrubberSendsAFinishedEventAtOnce: a piece that ends on an event boundary
// (a blank line) leaves whole, so removal adds no delay to a stream of events; the
// unfinished last word of a piece is all that waits, and never more than the hold.
func TestStreamScrubberSendsAFinishedEventAtOnce(t *testing.T) {
	t.Parallel()
	event := "event: delta\ndata: {\"text\":\"hi\"}\n\n"
	outs, tail, _ := scrubPieces(plantedCredential, []string{event, "data: half a wor", "d\n\n", strings.Repeat("x", 3*scrubHold)})
	if outs[0] != event {
		t.Fatalf("a finished event left as %q", outs[0])
	}
	if outs[1] != "data: half a " || outs[2] != "word\n\n" {
		t.Fatalf("the unfinished word: %q then %q", outs[1], outs[2])
	}
	if len(outs[3]) != 2*scrubHold || len(tail) != scrubHold {
		t.Fatalf("a long unbroken run: %d sent and %d held, want %d and %d", len(outs[3]), len(tail), 2*scrubHold, scrubHold)
	}
}

// TestCredentialCopies: the copies are what applyCredential sends, longest first; a
// credential shorter than minScrubbedCredential is not looked for (a placeholder would match
// ordinary words and end the grant).
func TestCredentialCopies(t *testing.T) {
	t.Parallel()
	if got := credentialCopies(&HostAPIGrant{}, "tok"); got != nil {
		t.Fatalf("a 3-byte credential is listed: %q", got)
	}
	if got := credentialCopies(&HostAPIGrant{}, ""); got != nil {
		t.Fatalf("no credential, yet copies: %q", got)
	}
	if newStreamScrubber(nil) != nil {
		t.Fatal("a scrubber with nothing to look for")
	}
	if holdsCopy([]byte("stoked tokens"), credentialCopies(&HostAPIGrant{}, "tok")) {
		t.Fatal("a short credential matched an answer")
	}
	g := &HostAPIGrant{CredentialPlacement: CredentialPlacement{Kind: CredentialBasic, Username: "svc"}}
	h := http.Header{}
	g.applyCredential(h, plantedCredential)
	sent := strings.TrimPrefix(h.Get("Authorization"), "Basic ")
	copies := credentialCopies(g, plantedCredential)
	if len(copies) != 2 || string(copies[0]) != sent || string(copies[1]) != plantedCredential {
		t.Fatalf("basic copies = %q, want the header's value %q then the credential", copies, sent)
	}
}

// TestBrokerStreamCutsBeforeACopySplitAcrossPieces (finding hunt-security-32): over the
// broker's socket, an event stream that echoes the credential, split between two pieces the
// upstream sends a moment apart, is cut before the piece that completes the copy: the client
// gets the first event, which arrives before the upstream has written the last piece, and
// the start of the echo's line up to its unfinished last word, and never the event after it;
// the row records the call as not delivered with CredentialMatched, and the run's grant has
// ended.
func TestBrokerStreamCutsBeforeACopySplitAcrossPieces(t *testing.T) {
	t.Parallel()
	half := len(plantedCredential) / 2
	pieces := []string{"event: start\ndata: {}\n\n", "data: you sent Bearer " + plantedCredential[:half], plantedCredential[half:] + "\n\n", "event: stop\ndata: {}\n\n"}
	upstream, u := newSSEUpstream(t, pieces, 300*time.Millisecond, http.StatusOK)
	grant := &HostAPIGrant{BaseURL: upstream.URL, Allow: []HostRoute{{Method: "GET", Path: "/v1/echo"}}}
	b, err := startDockerBroker(grant, plantedCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	resp, conn := socketStream(t, b.sock, "GET", "/v1/echo")
	defer conn.Close()
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, err := resp.Body.Read(buf)
	if err != nil || string(buf[:n]) != pieces[0] {
		t.Fatalf("first read: %q, %v; want the first event whole", buf[:n], err)
	}
	firstAt := time.Now()
	rest, _ := io.ReadAll(resp.Body) // the cut ends the body, with or without an error
	got := string(buf[:n]) + string(rest)
	want := pieces[0] + "data: you sent Bearer "
	if got != want {
		t.Fatalf("the client read %q, want %q", got, want)
	}
	u.mu.Lock()
	lastSent := u.sent[len(u.sent)-1]
	u.mu.Unlock()
	if !firstAt.Before(lastSent) {
		t.Fatalf("the first event arrived at %v, after the last piece was written at %v: the scan held a finished event back", firstAt, lastSent)
	}
	trace := b.core.traceSnapshot()
	if trace == nil || len(trace.Calls) != 1 || !trace.Calls[0].CredentialMatched || trace.Calls[0].Delivered || trace.Calls[0].RespBytes != len(want) {
		t.Fatalf("trace = %+v", trace)
	}
	if next := b.core.Call(context.Background(), brokerCall{Method: "GET", RawTarget: "/v1/echo"}); next.Status != http.StatusServiceUnavailable {
		t.Fatalf("the next call got %d %q, want 503: the run's grant has ended", next.Status, next.Body)
	}
}

// TestBrokerStreamCutInsideACopyHandsOverNoPartOfIt: a flood whose echo of the
// credential straddles the byte cap is cut there, and the client gets nothing of the
// copy: the unfinished word at the cut is dropped, not sent. Sending it would hand over
// the credential less its last bytes to code that can size an answer.
func TestBrokerStreamCutInsideACopyHandsOverNoPartOfIt(t *testing.T) {
	t.Parallel()
	const inside = 9 // bytes of the copy before the cap
	lead := "data: " + strings.Repeat("x", 4000) + "\n"
	var body strings.Builder
	for body.Len()+len(lead) < maxHostResponseBytes-inside-1 {
		body.WriteString(lead)
	}
	body.WriteString(strings.Repeat("y", maxHostResponseBytes-inside-1-body.Len()))
	body.WriteString(" " + plantedCredential + "\n\n" + strings.Repeat(lead, 40))
	text := body.String()
	if text[maxHostResponseBytes-inside:maxHostResponseBytes] != plantedCredential[:inside] {
		t.Fatalf("the test's own layout is off: %q at the cap", text[maxHostResponseBytes-inside:maxHostResponseBytes])
	}
	var pieces []string
	for i := 0; i < len(text); i += 60 << 10 {
		pieces = append(pieces, text[i:min(i+60<<10, len(text))])
	}
	upstream, _ := newSSEUpstream(t, pieces, 0, http.StatusOK)
	grant := &HostAPIGrant{BaseURL: upstream.URL, Allow: []HostRoute{{Method: "GET", Path: "/v1/echo"}}}
	b, err := startDockerBroker(grant, plantedCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	resp, conn := socketStream(t, b.sock, "GET", "/v1/echo")
	defer conn.Close()
	got, _ := io.ReadAll(resp.Body) // the cut ends the body, with or without an error
	resp.Body.Close()
	if len(got) != maxHostResponseBytes-inside {
		t.Fatalf("client received %d bytes, want the cap less the %d bytes of the cut word (%d)", len(got), inside, maxHostResponseBytes-inside)
	}
	if bytes.Contains(got, []byte(plantedCredential[:4])) {
		t.Fatalf("the client's answer ends %q: part of the credential crossed the cut", got[len(got)-32:])
	}
	trace := b.core.traceSnapshot()
	if trace == nil || len(trace.Calls) != 1 || trace.Calls[0].Delivered || trace.Calls[0].RespBytes != len(got) {
		t.Fatalf("trace = %+v", trace)
	}
}

// TestBrokerStreamWithholdsAnAnswerWhoseContentTypeHoldsACopy: a streamed answer's
// Content-Type reaches the guest before its body, so one that holds a copy gets the broker's
// fixed error in place of the whole stream, as a buffered answer does, and ends the grant.
func TestBrokerStreamWithholdsAnAnswerWhoseContentTypeHoldsACopy(t *testing.T) {
	t.Parallel()
	upstream := newEchoTypeUpstream(t)
	grant := &HostAPIGrant{BaseURL: upstream, Allow: []HostRoute{{Method: "GET", Path: "/v1/echo"}}}
	b, err := startDockerBroker(grant, plantedCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	resp, conn := socketStream(t, b.sock, "GET", "/v1/echo")
	defer conn.Close()
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, plantedCredential) || strings.Contains(ct, "event-stream") {
		t.Fatalf("Content-Type = %q, want the broker's own", ct)
	}
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), errCredentialMatched) || strings.Contains(string(body), "data: ok") {
		t.Fatalf("the client got %d %q, want the broker's fixed error and nothing of the stream", resp.StatusCode, body)
	}
	trace := b.core.traceSnapshot()
	if trace == nil || len(trace.Calls) != 1 || !trace.Calls[0].CredentialMatched || trace.Calls[0].Delivered {
		t.Fatalf("trace = %+v", trace)
	}
	if next := b.core.Call(context.Background(), brokerCall{Method: "GET", RawTarget: "/v1/echo"}); next.Status != http.StatusServiceUnavailable {
		t.Fatalf("the next call got %d %q, want 503: the run's grant has ended", next.Status, next.Body)
	}
}

// newEchoTypeUpstream serves one event stream whose Content-Type carries the request's
// Authorization value as a parameter, and returns its URL.
func newEchoTypeUpstream(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; note="+strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		_, _ = io.WriteString(w, "data: ok\n\n")
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestStreamScrubberMatchesTheWholeAnswerInARunLongerThanTheHold: where the unfinished
// last word is longer than the hold, only its last scrubHold bytes wait, and a copy
// anywhere in the run, cut anywhere, is still found.
func TestStreamScrubberMatchesTheWholeAnswerInARunLongerThanTheHold(t *testing.T) {
	t.Parallel()
	for _, lead := range []int{0, 1, scrubHold - len(plantedCredential), scrubHold - 1, scrubHold, scrubHold + 1, 2*scrubHold + 7} {
		for _, copied := range []bool{true, false} {
			middle := plantedCredential
			if !copied {
				middle = plantedCredential[1:]
			}
			text := strings.Repeat("x", lead) + middle + strings.Repeat("y", scrubHold+50) + plantedCredential[:7]
			for cut := 0; cut <= len(text); cut++ {
				outs, tail, hit := scrubPieces(plantedCredential, []string{text[:cut], text[cut:]})
				got := strings.Join(outs, "") + tail
				if hit != copied || strings.Contains(got, plantedCredential) || (!copied && got != text) {
					t.Fatalf("lead %d, copy %v, cut at %d: found %v, %d bytes out of %d", lead, copied, cut, hit, len(got), len(text))
				}
			}
			for _, size := range []int{1, 2, 3, 5, 17, len(plantedCredential) - 1, len(plantedCredential), scrubHold - 1, scrubHold, scrubHold + 1} {
				var pieces []string
				for i := 0; i < len(text); i += size {
					pieces = append(pieces, text[i:min(i+size, len(text))])
				}
				outs, tail, hit := scrubPieces(plantedCredential, pieces)
				got := strings.Join(outs, "") + tail
				if hit != copied || strings.Contains(got, plantedCredential) || (!copied && got != text) {
					t.Fatalf("lead %d, copy %v, pieces of %d: found %v, %d bytes out of %d", lead, copied, size, hit, len(got), len(text))
				}
				if !copied {
					for i := range outs {
						if held := len(strings.Join(pieces[:i+1], "")) - len(strings.Join(outs[:i+1], "")); held > scrubHold+len(plantedCredential) {
							t.Fatalf("lead %d, pieces of %d: %d bytes waiting after piece %d", lead, size, held, i)
						}
					}
				}
			}
		}
	}
}
