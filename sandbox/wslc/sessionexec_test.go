package wslc

import (
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// formatArg builds one argument as WSL's FormatCommandLine does (the rules
// windowsCommandLineLen counts), so the count can be checked against a string.
func formatArg(a string) string {
	if a != "" && !strings.ContainsAny(a, " \t\r\n\"") {
		return a
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for _, r := range a {
		switch r {
		case '\\':
			slashes++
		case '"':
			b.WriteString(strings.Repeat(`\`, slashes*2+1) + `"`)
			slashes = 0
		default:
			b.WriteString(strings.Repeat(`\`, slashes))
			b.WriteRune(r)
			slashes = 0
		}
	}
	b.WriteString(strings.Repeat(`\`, slashes*2) + `"`)
	return b.String()
}

// parseArgs splits a command line by the C runtime's rules for arguments after the
// program name (backslashes are literal unless a quote follows; 2n backslashes and a
// quote are n backslashes and a quote mark; 2n+1 are n and a literal quote).
func parseArgs(line string) []string {
	var out []string
	rs := []rune(line)
	for i := 0; i < len(rs); {
		for i < len(rs) && (rs[i] == ' ' || rs[i] == '\t') {
			i++
		}
		if i == len(rs) {
			break
		}
		var b strings.Builder
		quoted := false
		for i < len(rs) && (quoted || (rs[i] != ' ' && rs[i] != '\t')) {
			slashes := 0
			for i < len(rs) && rs[i] == '\\' {
				slashes++
				i++
			}
			if i < len(rs) && rs[i] == '"' {
				b.WriteString(strings.Repeat(`\`, slashes/2))
				if slashes%2 == 1 {
					b.WriteRune('"')
				} else {
					quoted = !quoted
				}
				i++
				continue
			}
			b.WriteString(strings.Repeat(`\`, slashes))
			if i < len(rs) && (quoted || (rs[i] != ' ' && rs[i] != '\t')) {
				b.WriteRune(rs[i])
				i++
			}
		}
		out = append(out, b.String())
	}
	return out
}

var hostileArgs = []string{"plain", "", " ", "two words", "tab\there", `a"q`, `back\slash`, `bs before quote\"x`, `trail\`, `trail2\\`,
	`""`, `\"`, `\\server\share`, "-x", "--", "--user", "new\nline", "cr\rx", "café 漢字 \U0001F600", "%PATH%", "^&|<>()", "'s'"}

func TestFormatArgRoundTripsThroughTheCRule(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	alphabet := []rune{'a', ' ', '\t', '"', '\\', '\n', 'é', '\U0001F600', '-'}
	cases := slices.Clone(hostileArgs)
	for range 2000 {
		var b strings.Builder
		for range r.IntN(12) {
			b.WriteRune(alphabet[r.IntN(len(alphabet))])
		}
		cases = append(cases, b.String())
	}
	for _, a := range cases {
		f := formatArg(a)
		if got := parseArgs(f); len(got) != 1 || got[0] != a {
			t.Fatalf("%q formats as %q, which parses back as %q", a, f, got)
		}
		if n := quotedLen(a); n != len(utf16.Encode([]rune(f))) {
			t.Fatalf("%q: quotedLen %d, the formatted %q is %d UTF-16 units", a, n, f, len(utf16.Encode([]rune(f))))
		}
	}
	if got := parseArgs(strings.Join(func() []string {
		var f []string
		for _, a := range hostileArgs {
			f = append(f, formatArg(a))
		}
		return f
	}(), " ")); !slices.Equal(got, hostileArgs) {
		t.Fatalf("the joined line parses as %q", got)
	}
}

func TestWindowsCommandLineLenCountsTheBaseName(t *testing.T) {
	// The line measured on 2026-11-21: "wslc.exe container exec plimsoll-argv-probe printf %s" and
	// 32,712 a's started (32,766 characters); one more a did not.
	args := []string{"container", "exec", "plimsoll-argv-probe", "printf", "%s", strings.Repeat("a", 32712)}
	if n := windowsCommandLineLen("/mnt/c/Program Files/WSL/wslc.exe", args); n != maxCommandLine {
		t.Fatalf("windowsCommandLineLen = %d, want %d", n, maxCommandLine)
	}
}

func TestCheckForwarded(t *testing.T) {
	for _, a := range hostileArgs {
		if err := checkForwarded(a); err != nil {
			t.Errorf("checkForwarded(%q) = %v, want it to cross", a, err)
		}
	}
	for _, a := range []string{"\xff", "a\x00b", "\xed\xa0\x80"} { // invalid UTF-8, a NUL, an encoded surrogate
		if !errors.Is(checkForwarded(a), errUnsafeForwarded) {
			t.Errorf("checkForwarded(%q) let it through", a)
		}
	}
}

func TestSessionExecCallLayout(t *testing.T) {
	c, err := sessionExecCall("plimsoll-run-1", "plimsoll-wslc-2", "61000:61000", []string{"/bin/sh", "-c", `echo "$A"`, ""}, []string{"A=1", "a=two words", "-u=x"})
	if err != nil {
		t.Fatal(err)
	}
	wantArgs := []string{"--session", "plimsoll-run-1", "container", "exec", "--interactive", "--user", "61000:61000", "--workdir", "/work", "plimsoll-wslc-2"}
	wantForwarded := []string{"/usr/bin/env", "-i", "--", "A=1", "a=two words", "-u=x", "/bin/sh", "-c", `echo "$A"`, ""}
	if !slices.Equal(c.args, wantArgs) || !slices.Equal(c.forwarded, wantForwarded) {
		t.Fatalf("got %q then %q", c.args, c.forwarded)
	}
	cmd := startHost(context.Background(), "/mnt/c/Program Files/WSL/wslc.exe", c)
	if cmd.Err != nil {
		t.Fatal(cmd.Err)
	}
	if len(cmd.Env) != 1 || !strings.HasPrefix(cmd.Env[0], "PATH=") {
		t.Fatalf("environment %q, want PATH alone", cmd.Env)
	}
	if got := cmd.Args[1:]; !slices.Equal(got, slices.Concat(wantArgs, wantForwarded)) {
		t.Fatalf("argv %q", got)
	}
}

func TestSessionExecRefusesBeforeDispatch(t *testing.T) {
	p := &Provider{cfg: Config{Path: "/mnt/c/Program Files/WSL/wslc.exe"}}
	long := strings.Repeat("a", maxCommandLine)
	for _, tc := range []struct {
		name    string
		session string
		argv    []string
		env     []string
		want    error
	}{
		{"no command", "s", nil, nil, nil},
		{"a relative command", "s", []string{"sh"}, nil, nil},
		{"a command holding =", "s", []string{"/bin/a=b"}, nil, nil},
		{"an environment string with no =", "s", []string{"/bin/true"}, []string{"A"}, nil},
		{"an environment string with no name", "s", []string{"/bin/true"}, []string{"=1"}, nil},
		{"invalid UTF-8 in an argument", "s", []string{"/bin/echo", "\xff"}, nil, errUnsafeForwarded},
		{"a NUL in an argument", "s", []string{"/bin/echo", "a\x00"}, nil, errUnsafeForwarded},
		{"invalid UTF-8 in a value", "s", []string{"/bin/true"}, []string{"A=\xff"}, errUnsafeForwarded},
		{"a command line past the limit", "s", []string{"/bin/echo", long}, nil, errCommandLineTooLong},
		{"an environment past the limit", "s", []string{"/bin/true"}, []string{"A=" + long}, errCommandLineTooLong},
		{"a space in the session name", "a b", []string{"/bin/true"}, nil, errUnsafeArg},
	} {
		cmd, err := p.sessionExec(context.Background(), tc.session, "c", "61000:61000", tc.argv, tc.env)
		if reason, ok := sandbox.NotDispatchedReason(err); cmd != nil || !ok || reason != sandbox.RefusalRequest || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s: cmd %v, err %v; want no command and a not-dispatched refusal (%v)", tc.name, cmd, err, tc.want)
		}
	}
	// The largest call that fits starts; one more character is refused.
	c, err := sessionExecCall("s", "c", "61000:61000", []string{"/bin/echo", ""}, nil)
	if err != nil {
		t.Fatal(err)
	}
	room := maxCommandLine - windowsCommandLineLen(p.cfg.Path, slices.Concat(c.args, c.forwarded)) + 2 // the empty argument's quotes
	if cmd, err := p.sessionExec(context.Background(), "s", "c", "61000:61000", []string{"/bin/echo", strings.Repeat("a", room)}, nil); err != nil || cmd.Err != nil {
		t.Fatalf("a call of exactly %d characters: %v", maxCommandLine, err)
	}
	if _, err := p.sessionExec(context.Background(), "s", "c", "61000:61000", []string{"/bin/echo", strings.Repeat("a", room+1)}, nil); !errors.Is(err, errCommandLineTooLong) {
		t.Fatalf("one character more: %v", err)
	}
}
