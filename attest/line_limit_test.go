package attest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// An entry too long for a bundle line is refused with its own error before anything is
// written, and the harness goes on: the next entry is written and the bundle verifies. The
// old refusal wrapped ErrLine ("not exactly the harness's encoding") and poisoned the
// harness as if a partial line had been written, with zero bytes written
// (hunt-quality-25). A write that fails part way still poisons it
// (TestHarnessAppendsNothingAfterAFailedWrite).
func TestATooLongEntryLeavesTheHarnessUsable(t *testing.T) {
	s, v := newKeyPair(t)
	var buf bytes.Buffer
	h := NewHarness(s, &buf)
	small := traced(t, s, "small")
	b, err := json.Marshal(small)
	if err != nil {
		t.Fatal(err)
	}
	defer func(limit int) { writeLimit = limit }(writeLimit)
	writeLimit = len(b) + 4096 // the small entry and its link fit; the big one does not

	big := traced(t, s, "big")
	big.Request = append(big.Request, make([]byte, 8192)...) // too long, whatever its content
	err = h.write(big)
	if !errors.Is(err, ErrLineTooLong) || errors.Is(err, ErrLine) || strings.Contains(err.Error(), "partial line") {
		t.Fatalf("a too-long entry: %v, want ErrLineTooLong alone", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("a refused entry wrote %d bytes", buf.Len())
	}
	if err := h.write(small); err != nil {
		t.Fatalf("the entry after a too-long one: %v", err)
	}
	if err := h.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	lines, err := ReadBundle(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := VerifyBundle(lines, v); err != nil || rep.Runs != 1 {
		t.Fatalf("the bundle after a refused entry: %+v, %v", rep, err)
	}
}

// MaxLineBytes holds the largest call line the official daemon and client can produce: the
// largest request plimsolld reads (maxRequestBytes, read here from cmd/plimsolld's source,
// since it is unexported in a main package) and the largest response the client reads
// (client.MaxResponseBytes), each in base64, with a signed record's envelope, the link and
// the JSON around them. It fails when either cap grows, or MaxLineBytes shrinks, past
// what the other holds (hunt-quality-25).
func TestMaxLineBytesHoldsTheLargestExchange(t *testing.T) {
	maxRequest := daemonConstant(t, "../cmd/plimsolld/main.go", "maxRequestBytes")
	if maxRequest <= 0 || client.MaxResponseBytes <= 0 {
		t.Fatalf("caps %d and %d", maxRequest, client.MaxResponseBytes)
	}
	// A call line with a one-byte request and response, sealed as a harness writes it:
	// everything but the two messages.
	s, _ := newKeyPair(t)
	req, resp := exchange("1", "", sandbox.RunRecord{})
	e, err := s.Call(req, resp)
	if err != nil {
		t.Fatal(err)
	}
	line := seal(t, s, e)[0]
	line.Request, line.Response = []byte{1}, []byte{1}
	b, err := json.Marshal(line)
	if err != nil {
		t.Fatal(err)
	}
	// The envelope's own size depends on the record's free-text fields; this allows a
	// megabyte of them beside the measured line.
	const envelopeAllowance = 1 << 20
	rest := len(b) - 2*base64.StdEncoding.EncodedLen(1) + envelopeAllowance
	need := base64.StdEncoding.EncodedLen(maxRequest) + base64.StdEncoding.EncodedLen(client.MaxResponseBytes) + rest + 1
	if need > MaxLineBytes {
		t.Fatalf("the largest call line is %d bytes (a request of %d and a response of %d, in base64, and %d for the rest); MaxLineBytes is %d",
			need, maxRequest, client.MaxResponseBytes, rest, MaxLineBytes)
	}
	t.Logf("the largest call line: %d of %d bytes, %d to spare", need, MaxLineBytes, MaxLineBytes-need)
}

// daemonConstant evaluates the integer constant name declared in the Go file at path.
func daemonConstant(t *testing.T, path, name string) int {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, spec := range g.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, id := range vs.Names {
				if id.Name != name || i >= len(vs.Values) {
					continue
				}
				var src strings.Builder
				if err := printer.Fprint(&src, fset, vs.Values[i]); err != nil {
					t.Fatal(err)
				}
				tv, err := types.Eval(token.NewFileSet(), nil, token.NoPos, src.String())
				if err != nil || tv.Value == nil {
					t.Fatalf("%s in %s is %s, not a constant this test can evaluate: %v", name, path, src.String(), err)
				}
				n, ok := constant.Int64Val(tv.Value)
				if !ok {
					t.Fatalf("%s in %s is not an integer", name, path)
				}
				return int(n)
			}
		}
	}
	t.Fatalf("no constant %s in %s", name, path)
	return 0
}
