package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// seal writes entries through a harness signing with s, as a bundle is written,
// ending with a checkpoint, and reads the lines back.
func seal(t *testing.T, s *Signer, entries ...Entry) []Entry {
	t.Helper()
	var buf bytes.Buffer
	h := NewHarness(s, &buf)
	for _, e := range entries {
		if err := h.write(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	out, err := ReadBundle(&buf)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// traced is a signed single run whose request carries trace_id id.
func traced(t *testing.T, s *Signer, id string) Entry {
	t.Helper()
	return tracedAs(t, s, tracedCode(id), id)
}

// tracedCode is the code traced runs for id, so each id's call has its own request.
func tracedCode(id string) string { return "console.log(" + strconv.Quote(id) + ")" }

// requests is the request digests of the calls traced makes for ids.
func requests(ids ...string) []string {
	var out []string
	for _, id := range ids {
		req, _ := exchange(tracedCode(id), "1\n", sandbox.RunRecord{})
		out = append(out, record.RunRequestDigest(req))
	}
	return out
}

// tracedAs is one signed call running code under trace_id id.
func tracedAs(t *testing.T, s *Signer, code, id string) Entry {
	t.Helper()
	req, resp := exchange(code, "1\n", sandbox.RunRecord{})
	req.TraceId = id
	r := record.FromWire(resp.GetRecord())
	r.RequestSHA256 = record.RunRequestDigest(req)
	r.SHA256 = record.Digest(r)
	resp.Record = record.ToWire(r)
	e, err := s.Call(req, resp)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// A bundle shows it is the whole file its harness wrote:
// every line is linked to the one before it, and the last line is a checkpoint. A
// line deleted, moved, inserted, duplicated or changed, a cut tail, and a bundle
// without links all fail; a bundle cut back to an earlier checkpoint verifies, which
// only the caller's own count (VerifyExpected) can catch.
func TestBundleLinksProveTheWholeFile(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	v := NewVerifier(key.Public().(ed25519.PublicKey))
	runs := []Entry{traced(t, s, "a"), traced(t, s, "b"), traced(t, s, "c")}
	good := seal(t, s, runs...)
	if rep, err := VerifyBundle(good, v); err != nil || rep.Runs != 3 {
		t.Fatalf("a whole bundle: %+v, %v", rep, err)
	}
	changed := append([]Entry(nil), good...)
	resp := &plimsollv1.RunResponse{}
	if err := proto.Unmarshal(changed[1].Response, resp); err != nil {
		t.Fatal(err)
	}
	resp.GetJavascript().Stdout = []byte("2\n")
	changed[1].Response, _ = proto.Marshal(resp)
	foreign := seal(t, NewSigner(newKey(t)), runs...)
	for name, c := range map[string]struct {
		lines []Entry
		want  error
	}{
		"a line deleted":             {[]Entry{good[0], good[2], good[3]}, ErrLink},
		"two lines swapped":          {[]Entry{good[1], good[0], good[2], good[3]}, ErrLink},
		"a line duplicated":          {[]Entry{good[0], good[1], good[1], good[2], good[3]}, ErrLink},
		"a line changed":             {changed, ErrLink},
		"the checkpoint cut":         {good[:3], ErrIncomplete},
		"the last run and its end":   {good[:2], ErrIncomplete},
		"no links at all":            {runs, ErrLink},
		"an empty bundle":            {nil, ErrIncomplete},
		"links by another key":       {foreign, ErrSignature},
		"a line from another bundle": {[]Entry{good[0], foreign[1], good[2], good[3]}, ErrSignature},
	} {
		if _, err := VerifyBundle(c.lines, v); !errors.Is(err, c.want) {
			t.Errorf("%s: %v; want %v", name, err, c.want)
		}
	}

	// A harness resumed on a whole bundle continues its chain after the checkpoint;
	// cut back to the first checkpoint, the bundle still verifies (the stated limit).
	var more bytes.Buffer
	h, err := ResumeHarness(s, good, &more)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.write(traced(t, s, "d")); err != nil {
		t.Fatal(err)
	}
	if err := h.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	tail, err := ReadBundle(&more)
	if err != nil {
		t.Fatal(err)
	}
	both := append(append([]Entry(nil), good...), tail...)
	if rep, err := VerifyBundle(both, v); err != nil || rep.Runs != 4 {
		t.Fatalf("a resumed bundle: %+v, %v", rep, err)
	}
	if _, err := VerifyBundle(both[:len(both)-1], v); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("a resumed bundle without its last checkpoint: %v", err)
	}
	if _, err := VerifyBundle(good, v); err != nil {
		t.Fatalf("cut back to the first checkpoint: %v (verifies by design; VerifyExpected catches it)", err)
	}
	if err := VerifyExpected(good, requests("a", "b", "c", "d")); !errors.Is(err, ErrExpected) {
		t.Fatalf("cut back to the first checkpoint, against the caller's four calls: %v", err)
	}
	if _, err := ResumeHarness(s, good[:3], &more); err == nil {
		t.Fatal("a harness resumed on a bundle without its checkpoint")
	}
}

// The caller's own list of request digests names every expected call, each as many
// times as it ran. A call whose trace_id the caller expected but whose request is not
// the one it sent fails; identical requests are counted, not refused.
func TestVerifyExpected(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	bundle := seal(t, s, traced(t, s, "a"), traced(t, s, "b"), traced(t, s, "c"))
	if err := VerifyExpected(bundle, requests("c", "a", "b")); err != nil {
		t.Fatal(err)
	}
	if CountCalls(bundle) != 3 {
		t.Fatalf("CountCalls = %d", CountCalls(bundle))
	}
	for name, want := range map[string][]string{
		"a call missing":    requests("a", "b", "c", "d"),
		"a call unexpected": requests("a", "b"),
		"another call":      requests("a", "b", "x"),
		"nothing expected":  nil,
		"a call twice":      requests("a", "b", "c", "c"),
		"not a digest":      append(requests("a", "b"), "c"),
		"upper-case hex":    append(requests("a", "b"), strings.ToUpper(requests("c")[0])),
	} {
		if err := VerifyExpected(bundle, want); !errors.Is(err, ErrExpected) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The caller's call b sent one request; the bundle holds another under b's
	// trace_id. A list of trace_ids could not tell them apart.
	substituted := seal(t, s, traced(t, s, "a"), tracedAs(t, s, tracedCode("x"), "b"), traced(t, s, "c"))
	if err := VerifyExpected(substituted, requests("a", "b", "c")); !errors.Is(err, ErrExpected) {
		t.Errorf("a request substituted under the expected trace_id: %v; want refused", err)
	}
	// The same request sent twice is two calls with one digest: listed twice it
	// verifies, listed once it does not.
	repeated := seal(t, s, traced(t, s, "a"), traced(t, s, "b"), tracedAs(t, s, tracedCode("b"), "b-again"))
	if err := VerifyExpected(repeated, requests("a", "b", "b")); err != nil {
		t.Errorf("one request sent twice, listed twice: %v", err)
	}
	if err := VerifyExpected(repeated, requests("a", "b")); !errors.Is(err, ErrExpected) {
		t.Errorf("one request sent twice, listed once: %v; want refused", err)
	}
}

// A bundle's bytes are exactly what the harness wrote: a line with anything added or
// re-encoded is refused, however Go's decoder would read it (the R7 review of F7: a
// second signed call hidden after a line's object, a repeated key another parser reads
// differently, blank lines); so is a link or checkpoint changed after signing.
func TestBundleBytesAreExactlyTheHarnesss(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	v := NewVerifier(key.Public().(ed25519.PublicKey))
	var buf bytes.Buffer
	h := NewHarness(s, &buf)
	for _, id := range []string{"a", "b"} {
		if err := h.write(traced(t, s, id)); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	join := func(ls []string) string { return strings.Join(ls, "\n") + "\n" }
	with := func(i int, line string) string {
		out := append([]string(nil), lines...)
		out[i] = line
		return join(out)
	}
	if entries, err := ReadBundle(strings.NewReader(buf.String())); err != nil {
		t.Fatal(err)
	} else if _, err := VerifyBundle(entries, v); err != nil {
		t.Fatal(err)
	}
	extra := traced(t, s, "hidden")
	hidden, _ := json.Marshal(extra)
	lastLink := lines[len(lines)-1]
	for name, text := range map[string]string{
		"a signed call after a line's object":  with(0, lines[0]+string(hidden)),
		"garbage after a line's object":        with(0, lines[0]+" not json"),
		"a blank line":                         join(append([]string{lines[0], ""}, lines[1:]...)),
		"a repeated key":                       with(1, `{"request":"AAAA",`+lines[1][1:]),
		"a key in another case":                with(1, strings.Replace(lines[1], `"request":`, `"Request":`, 1)),
		"surrounding spaces":                   with(1, " "+lines[1]),
		"an escaped character":                 with(1, strings.Replace(lines[1], `"request"`, `"\u0072equest"`, 1)),
		"a line break inside the link payload": with(2, strings.Replace(lastLink, `"payload":"`, `"payload":"\n`, 1)),
		"a signature added to the last link":   with(2, strings.Replace(lastLink, `"signatures":[`, `"signatures":[{"keyid":"evil","sig":"AAAA"},`, 1)),
		"an envelope on the checkpoint":        with(2, strings.Replace(lastLink, `{"link":`, `{"envelope":{"payloadType":"x","payload":"","signatures":null},"link":`, 1)),
		"a line break inside the last link's signature": with(2, func() string {
			i := strings.LastIndex(lastLink, `"sig":"`) + len(`"sig":"`)
			return lastLink[:i] + `\n` + lastLink[i:]
		}()),
		"Windows line endings":           strings.ReplaceAll(buf.String(), "\n", "\r\n"),
		"no newline after the last line": strings.TrimSuffix(buf.String(), "\n"),
	} {
		entries, err := ReadBundle(strings.NewReader(text))
		if err == nil {
			_, err = VerifyBundle(entries, v)
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
