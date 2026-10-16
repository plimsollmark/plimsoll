// Command tour records the examples of the MCP trainer page (docs/trainers): it starts
// the plimsoll MCP server binary over stdio, plays the model's part with scripted calls,
// made the way a model makes them, against a real plimsolld, and writes everything it
// sent and got back as one JavaScript file that sets window.MCP_TOUR.
//
// It builds nothing: it is given the server and plimsoll-attest binaries. It makes a
// demo signing key and a receipts directory in a temporary directory, deletes both when
// it ends, and writes only the public half of the key. The caller token is read from a
// file and handed to the server's environment; it is never printed or written. See
// README.md for the command that reruns it.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/plimsollmark/plimsoll/attest"
)

// settings are the server's PLIMSOLL_* settings for the recording, beside its URL, token
// and receipt paths. The test builds a server from them too, so the surface digest it
// compares is that of a server configured as the recorded one was.
var settings = []string{
	"PLIMSOLL_MAX_SANDBOXES=3",
	"PLIMSOLL_TIMEOUT_MS=3000",
	"PLIMSOLL_CALL_TIMEOUT_MS=15000",
}

// prefix and suffix wrap the JSON in the file the page loads.
const (
	prefix = "window.MCP_TOUR = "
	suffix = ";\n"
)

type options struct {
	server, attest, daemon, tokenFile, out string
}

func main() {
	var o options
	flag.StringVar(&o.server, "server", "", "the plimsoll-mcp binary, started over stdio")
	flag.StringVar(&o.attest, "attest", "", "the plimsoll-attest binary, run as verify-entry on a receipt")
	flag.StringVar(&o.daemon, "daemon", "", "plimsolld's URL")
	flag.StringVar(&o.tokenFile, "token-file", "", "a file holding the caller token (omit for an open development daemon)")
	flag.StringVar(&o.out, "out", "", "the JavaScript file to write")
	flag.Parse()
	if o.server == "" || o.attest == "" || o.daemon == "" || o.out == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "tour: needs -server PATH -attest PATH -daemon URL -out PATH, and -token-file PATH unless the daemon is open")
		os.Exit(2)
	}
	failed, err := run(o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tour:", err)
		os.Exit(1)
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "tour: wrote %s, but %d claims did not hold; the file records them as not held\n", o.out, failed)
		os.Exit(3)
	}
	fmt.Fprintln(os.Stderr, "tour: wrote", o.out)
}

// Tour is what the page reads.
type Tour struct {
	Generator     string          `json:"generator"`
	Generated     string          `json:"generated"`
	Method        string          `json:"method"`
	Server        serverMeta      `json:"server"`
	Daemon        json.RawMessage `json:"daemon"`
	Settings      []string        `json:"settings"`
	Tools         []string        `json:"tools"`
	SurfaceDigest string          `json:"surfaceDigest"`
	ToolList      json.RawMessage `json:"toolList"`
	Scenarios     []*Scenario     `json:"scenarios"`
	ServerInfo    *Step           `json:"serverInfo"`
}

type serverMeta struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	ProtocolVersion string `json:"protocolVersion"`
	Instructions    string `json:"instructions"`
}

// Scenario is one example: what the user wants, the calls made for it, and what the
// results showed, with each claim of the plan checked against them.
type Scenario struct {
	ID       string   `json:"id"`
	Number   int      `json:"number"`
	Kind     string   `json:"kind"` // "use", or "safety" for the scene that is not a use case
	Title    string   `json:"title"`
	Ask      string   `json:"ask"`
	Shows    string   `json:"shows"`
	Steps    []*Step  `json:"steps"`
	Observed string   `json:"observed"`
	Claims   []Claim  `json:"claims"`
	Receipt  *Receipt `json:"receipt,omitempty"`
}

// Claim is one expectation of the plan and whether the real result met it.
type Claim struct {
	Claim string `json:"claim"`
	Held  bool   `json:"held"`
}

// Step is one tool call as the host sent it and the server answered it.
type Step struct {
	Intent    string          `json:"intent"`
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
	IsError   bool            `json:"isError"`
	// Result is the structured result, or for a tool error the failure value: in both
	// cases the one text block the server sent, which is that JSON.
	Result json.RawMessage `json:"result"`
	WallMs int64           `json:"wallMs"`
}

// Receipt is the signed line of one run, with what a browser needs to check it.
type Receipt struct {
	Of           string          `json:"of"`
	RecordSHA256 string          `json:"recordSha256"`
	File         string          `json:"file"`
	LineNumber   int             `json:"lineNumber"`
	Line         string          `json:"line"`
	LineSHA256   string          `json:"lineSha256"`
	KeyID        string          `json:"keyId"`
	PublicKeyPEM string          `json:"publicKeyPem"`
	PublicKeyRaw string          `json:"publicKeyRaw"`
	Statement    json.RawMessage `json:"statement"`
	Signed       signedBytes     `json:"signed"`
	NotCovered   string          `json:"notCovered"`
	VerifyEntry  cliRun          `json:"verifyEntry"`
}

// signedBytes says exactly which bytes the record's signature covers.
type signedBytes struct {
	Algorithm  string      `json:"algorithm"`
	PublicKey  string      `json:"publicKey"`
	Signature  source      `json:"signature"`
	Message    messageSpec `json:"message"`
	AlsoSigned string      `json:"alsoSigned"`
}

type source struct {
	From     string `json:"from"`
	Encoding string `json:"encoding"`
	Bytes    int    `json:"bytes,omitempty"`
}

type messageSpec struct {
	Scheme      string   `json:"scheme"`
	Parts       []string `json:"parts"`
	Separator   string   `json:"separator"`
	Lengths     string   `json:"lengths"`
	PayloadType source   `json:"payloadType"`
	Payload     source   `json:"payload"`
	Bytes       int      `json:"bytes"`
	SHA256      string   `json:"sha256"`
}

type cliRun struct {
	Command  string `json:"command"`
	ExitCode int    `json:"exitCode"`
	Output   string `json:"output"`
}

type file struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type runArgs struct {
	Code     string `json:"code"`
	Language string `json:"language,omitempty"`
	Files    []file `json:"files,omitempty"`
	Sandbox  string `json:"sandbox,omitempty"`
}

type handleArgs struct {
	Sandbox string `json:"sandbox"`
}

type recordArgs struct {
	RecordSHA256 string `json:"recordSha256"`
}

type noArgs struct{}

// session is the host's side of the MCP connection.
type session struct {
	ctx context.Context
	cs  *mcp.ClientSession
}

// call makes one tool call and records it. A tool error is a result, recorded as one;
// only a failure of the connection itself is an error.
func (s *session) call(intent, tool string, args any) (*Step, map[string]any, error) {
	raw, err := json.Marshal(args)
	if err != nil {
		return nil, nil, err
	}
	start := time.Now()
	res, err := s.cs.CallTool(s.ctx, &mcp.CallToolParams{Name: tool, Arguments: json.RawMessage(raw)})
	wall := time.Since(start)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", tool, err)
	}
	if len(res.Content) != 1 {
		return nil, nil, fmt.Errorf("%s: %d content blocks, the server sends one", tool, len(res.Content))
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		return nil, nil, fmt.Errorf("%s: the content block is not text", tool)
	}
	var value map[string]any
	if err := json.Unmarshal([]byte(text.Text), &value); err != nil {
		return nil, nil, fmt.Errorf("%s: the text block is not a JSON object: %w", tool, err)
	}
	if !res.IsError {
		b, err := json.Marshal(res.StructuredContent)
		if err != nil {
			return nil, nil, err
		}
		var structured map[string]any
		if err := json.Unmarshal(b, &structured); err != nil || !reflect.DeepEqual(value, structured) {
			return nil, nil, fmt.Errorf("%s: the text block is not the structured result", tool)
		}
	}
	return &Step{Intent: intent, Tool: tool, Arguments: raw, IsError: res.IsError, Result: json.RawMessage(text.Text), WallMs: wall.Milliseconds()}, value, nil
}

func run(o options) (int, error) {
	token := ""
	if o.tokenFile != "" {
		b, err := os.ReadFile(o.tokenFile)
		if err != nil {
			return 0, err
		}
		token = strings.TrimSpace(string(b))
	}
	tmp, err := os.MkdirTemp("", "plimsoll-tour-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(tmp)
	priv, pubPEM, err := attest.GenerateKey()
	if err != nil {
		return 0, err
	}
	keyFile, pubFile, receipts := filepath.Join(tmp, "demo.key"), filepath.Join(tmp, "demo.pub"), filepath.Join(tmp, "receipts")
	if err := os.WriteFile(keyFile, priv, 0o600); err != nil {
		return 0, err
	}
	if err := os.WriteFile(pubFile, pubPEM, 0o600); err != nil {
		return 0, err
	}
	secrets := [][]byte{priv}
	if key, err := attest.ParsePrivateKey(priv); err == nil {
		secrets = append(secrets, []byte(base64.StdEncoding.EncodeToString(key.Seed())), []byte(base64.StdEncoding.EncodeToString(key)))
	}
	if token != "" {
		// As written, and as JSON writes it inside a string.
		quoted, _ := json.Marshal(token)
		secrets = append(secrets, []byte(token), bytes.Trim(quoted, `"`))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.Command(o.server)
	cmd.Env = append([]string{
		"PLIMSOLL_URL=" + o.daemon,
		"PLIMSOLL_TOKEN=" + token,
		"PLIMSOLL_SIGNING_KEY_FILE=" + keyFile,
		"PLIMSOLL_RECEIPTS_DIR=" + receipts,
	}, settings...)
	cmd.Stderr = os.Stderr
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "plimsoll-tour", Version: "1"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		return 0, fmt.Errorf("starting %s: %w", o.server, err)
	}
	defer cs.Close()
	s := &session{ctx: ctx, cs: cs}

	hello := cs.InitializeResult()
	t := &Tour{
		Generator: "clients/mcp/examples/tour",
		Generated: time.Now().UTC().Format(time.RFC3339),
		Method: "Scripted calls, made the way a model makes them: this program plays the model's part, sending each tool call over the same " +
			"stdio connection an MCP host opens, to the real server binary, which ran the code on a real plimsolld. No model chose these calls. " +
			"Receipts were signed with a demo key made for this recording; its private half was deleted when the recording ended, and only its public half is here.",
		Server:   serverMeta{Name: hello.ServerInfo.Name, Version: hello.ServerInfo.Version, ProtocolVersion: hello.ProtocolVersion, Instructions: hello.Instructions},
		Settings: settings,
	}
	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		return 0, err
	}
	if t.ToolList, err = json.Marshal(list.Tools); err != nil {
		return 0, err
	}

	first, firstResult, err := checkDontGuess(s)
	if err != nil {
		return 0, err
	}
	t.Scenarios = append(t.Scenarios, first)
	for _, f := range []func(*session) (*Scenario, error){yourFile, notebook, debugLoop, noNetwork, twoLanguages, runawayLoop} {
		sc, err := f(s)
		if err != nil {
			return 0, err
		}
		t.Scenarios = append(t.Scenarios, sc)
	}
	proof, err := proveItLater(s, o, tmp, firstResult)
	if err != nil {
		return 0, err
	}
	t.Scenarios = append(t.Scenarios, proof)
	safety, err := capScene(s)
	if err != nil {
		return 0, err
	}
	t.Scenarios = append(t.Scenarios, safety)

	st, info, err := s.call("Ask the server what it is and what its daemon states.", "server_info", noArgs{})
	if err != nil {
		return 0, err
	}
	if st.IsError {
		return 0, fmt.Errorf("server_info failed: %s", st.Result)
	}
	t.ServerInfo = st
	t.Tools = strs(info["tools"])
	t.SurfaceDigest = str(info, "surfaceDigest")
	daemon, _ := info["daemon"].(map[string]any)
	if daemon == nil {
		return 0, fmt.Errorf("server_info names no daemon: %s", str(info, "daemonError"))
	}
	if t.Daemon, err = json.Marshal(daemon); err != nil {
		return 0, err
	}

	data, err := encode(t, str(daemon, "provider"), str(daemon, "isolation"))
	if err != nil {
		return 0, err
	}
	for _, secret := range secrets {
		if len(secret) > 0 && bytes.Contains(data, secret) {
			return 0, errors.New("the output holds the caller token or the demo private key; nothing was written")
		}
	}
	if bytes.Contains(data, []byte(tmp)) {
		return 0, errors.New("the output names this run's temporary directory; nothing was written")
	}
	if err := os.WriteFile(o.out, data, 0o644); err != nil {
		return 0, err
	}
	failed := 0
	for _, sc := range t.Scenarios {
		for _, c := range sc.Claims {
			if !c.Held {
				failed++
				fmt.Fprintf(os.Stderr, "tour: %d. %s: did not hold: %s\n", sc.Number, sc.Title, c.Claim)
			}
		}
	}
	return failed, nil
}

// encode is the file: a header saying where it comes from, then the one global.
func encode(t *Tour, provider, isolation string) ([]byte, error) {
	body, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "// Generated by clients/mcp/examples/tour at %s. Do not edit it by hand: rerun the\n", t.Generated)
	fmt.Fprintf(&b, "// program (clients/mcp/examples/tour/README.md). Recorded through the %s MCP server %s\n", t.Server.Name, t.Server.Version)
	fmt.Fprintf(&b, "// against a plimsolld running provider %s at the %q isolation tier, as server_info reported.\n", provider, isolation)
	b.WriteString(prefix)
	b.Write(body)
	b.WriteString(suffix)
	return b.Bytes(), nil
}

// decode reads a file encode wrote.
func decode(data []byte) (*Tour, error) {
	s := string(data)
	for strings.HasPrefix(s, "//") {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			return nil, errors.New("the file is only comments")
		}
		s = s[i+1:]
	}
	if !strings.HasPrefix(s, prefix) || !strings.HasSuffix(s, suffix) {
		return nil, fmt.Errorf("the file is not %q followed by JSON and %q", prefix, suffix)
	}
	var t Tour
	dec := json.NewDecoder(strings.NewReader(strings.TrimSuffix(strings.TrimPrefix(s, prefix), suffix)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("data after the JSON value")
	}
	return &t, nil
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }
func num(m map[string]any, k string) int    { f, _ := m[k].(float64); return int(f) }
func yes(m map[string]any, k string) bool   { b, _ := m[k].(bool); return b }

// strs is a JSON array of strings; anything else in it is skipped.
func strs(v any) []string {
	var out []string
	list, _ := v.([]any)
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func (sc *Scenario) claim(text string, held bool) { sc.Claims = append(sc.Claims, Claim{text, held}) }

func (sc *Scenario) add(st *Step) { sc.Steps = append(sc.Steps, st) }

// lines is output on one line, its lines joined by " / ".
func lines(out string) string {
	return strings.Join(strings.Split(strings.TrimRight(out, "\n"), "\n"), " / ")
}

func lastLine(out string) string {
	parts := strings.Split(strings.TrimRight(out, "\n"), "\n")
	return parts[len(parts)-1]
}

// ran says how a run_code call ended, in a clause.
func ran(st *Step, r map[string]any) string {
	if st.IsError {
		return fmt.Sprintf("was a tool error (ran: %s): %s", str(r, "ran"), str(r, "summary"))
	}
	if yes(r, "timedOut") {
		return fmt.Sprintf("timed out after %d ms of wall time (exit %d)", st.WallMs, num(r, "exitCode"))
	}
	return fmt.Sprintf("exited %d in %d ms", num(r, "exitCode"), st.WallMs)
}

func exited(st *Step, r map[string]any, code int) bool {
	return !st.IsError && !yes(r, "timedOut") && num(r, "exitCode") == code
}

func checkDontGuess(s *session) (*Scenario, map[string]any, error) {
	sc := &Scenario{ID: "check-dont-guess", Number: 1, Kind: "use", Title: "Check, don't guess",
		Ask:   "The user asks whether 2,305,843,009,213,693,951 is prime. A model answering from memory could guess; this one runs a test and reads the answer.",
		Shows: "A fresh run: run_code without a sandbox handle runs once in a new sandbox and keeps nothing."}
	st, r, err := s.call("Run a Miller-Rabin test on 2**61 - 1, and on 2**61 + 1 beside it, in a fresh sandbox.", "run_code",
		runArgs{Code: primeCode, Language: "python"})
	if err != nil {
		return nil, nil, err
	}
	sc.add(st)
	out := str(r, "stdout")
	sc.claim("the run exited 0", exited(st, r, 0))
	sc.claim("it says 2**61 - 1 is prime", strings.Contains(out, "2305843009213693951 = 2**61 - 1: prime"))
	sc.claim("it says 2**61 + 1 is not prime", strings.Contains(out, "2305843009213693953 = 2**61 + 1: not prime"))
	sc.claim("the result names its isolation tier and its run record", !st.IsError && str(r, "isolation") != "" && str(r, "recordSha256") != "")
	sc.Observed = fmt.Sprintf("The run %s behind the %q tier and printed: %s.", ran(st, r), str(r, "isolation"), lines(out))
	return sc, r, nil
}

func yourFile(s *session) (*Scenario, error) {
	sc := &Scenario{ID: "your-file", Number: 2, Kind: "use", Title: "Your file, analyzed",
		Ask:   "The user hands over a CSV of daily bike rentals at three stations (made-up data for this example, 12 rows) and asks for summary figures.",
		Shows: "Data goes in files, not pasted into the code: the server writes each file into the sandbox's working directory before the code runs."}
	st, r, err := s.call("Pass the CSV as data/rides.csv and summarize it with Python's csv and statistics modules.", "run_code",
		runArgs{Code: ridesCode, Language: "python", Files: []file{{Path: "data/rides.csv", Content: ridesCSV}}})
	if err != nil {
		return nil, err
	}
	sc.add(st)
	out := str(r, "stdout")
	sc.claim("the run exited 0", exited(st, r, 0))
	sc.claim("the code read all 12 rows from the file", strings.Contains(out, "rows: 12"))
	sc.claim("it computed the total", strings.Contains(out, "total rides: 2186"))
	sc.Observed = fmt.Sprintf("The run %s and printed: %s.", ran(st, r), lines(out))
	return sc, nil
}

func open(s *session, sc *Scenario, intent string) (string, error) {
	st, r, err := s.call(intent, "open_sandbox", noArgs{})
	if err != nil {
		return "", err
	}
	sc.add(st)
	if st.IsError {
		return "", fmt.Errorf("%s: open_sandbox failed: %s", sc.Title, st.Result)
	}
	return str(r, "sandbox"), nil
}

func closeBox(s *session, sc *Scenario, handle string) (map[string]any, error) {
	st, r, err := s.call("Close the sandbox: its files and interpreter state are deleted.", "close_sandbox", handleArgs{Sandbox: handle})
	if err != nil {
		return nil, err
	}
	sc.add(st)
	sc.claim("close_sandbox reports the daemon deleted the sandbox", !st.IsError && yes(r, "deleted"))
	return r, nil
}

func notebook(s *session) (*Scenario, error) {
	sc := &Scenario{ID: "notebook", Number: 3, Kind: "use", Title: "A notebook that remembers",
		Ask:   "The user shares a fortnight of daily highs (made-up data, 14 rows) and then asks two follow-up questions about them.",
		Shows: "open_sandbox gives a handle; calls with it run in one interpreter, so what one call defines is there for the next (stateKept)."}
	h, err := open(s, sc, "Open a sandbox that keeps state between calls.")
	if err != nil {
		return nil, err
	}
	st1, r1, err := s.call("Load the readings into a variable once; the last line's value is shown, as in a notebook.", "run_code",
		runArgs{Code: loadReadings, Language: "python", Files: []file{{Path: "readings.csv", Content: readingsCSV}}, Sandbox: h})
	if err != nil {
		return nil, err
	}
	sc.add(st1)
	st2, r2, err := s.call("Which day was warmest? Use the variable the first call made.", "run_code", runArgs{Code: warmestDay, Language: "python", Sandbox: h})
	if err != nil {
		return nil, err
	}
	sc.add(st2)
	st3, r3, err := s.call("How many days were above 25 C? Same variable, third call.", "run_code", runArgs{Code: daysAbove25, Language: "python", Sandbox: h})
	if err != nil {
		return nil, err
	}
	sc.add(st3)
	sc.claim("the first call loaded 14 readings", exited(st1, r1, 0) && strings.TrimSpace(str(r1, "stdout")) == "14")
	sc.claim("the follow-up calls used the variable without reloading it", exited(st2, r2, 0) && exited(st3, r3, 0) &&
		!yes(r2, "freshInterpreter") && !yes(r3, "freshInterpreter"))
	sc.claim("every call reports stateKept", yes(r1, "stateKept") && yes(r2, "stateKept") && yes(r3, "stateKept"))
	sc.claim("the warmest day is 2026-06-09 at 27.4 C", strings.TrimSpace(str(r2, "stdout")) == "('2026-06-09', 27.4)")
	sc.claim("six days were above 25 C", strings.TrimSpace(str(r3, "stdout")) == "6")
	if _, err := closeBox(s, sc, h); err != nil {
		return nil, err
	}
	sc.Observed = fmt.Sprintf("The load %s and showed %s (freshInterpreter %t: the sandbox's first Python call); the follow-ups showed %s and %s (freshInterpreter %t and %t), and stateKept was %t on every call.",
		ran(st1, r1), strings.TrimSpace(str(r1, "stdout")), yes(r1, "freshInterpreter"),
		strings.TrimSpace(str(r2, "stdout")), strings.TrimSpace(str(r3, "stdout")), yes(r2, "freshInterpreter"), yes(r3, "freshInterpreter"),
		yes(r1, "stateKept") && yes(r2, "stateKept") && yes(r3, "stateKept"))
	return sc, nil
}

func debugLoop(s *session) (*Scenario, error) {
	sc := &Scenario{ID: "debug-loop", Number: 4, Kind: "use", Title: "The debug loop",
		Ask:   "The model writes a median function and a check for it. The check fails; the model reads the traceback, fixes the function, and runs the check again.",
		Shows: "A failing program is a result, not a tool error: its exit code and traceback come back for the model to read, as a test run would for a person."}
	h, err := open(s, sc, "Open a sandbox to work in.")
	if err != nil {
		return nil, err
	}
	st1, r1, err := s.call("Define median and check it on an odd and an even list.", "run_code", runArgs{Code: medianBuggy, Language: "python", Sandbox: h})
	if err != nil {
		return nil, err
	}
	sc.add(st1)
	st2, r2, err := s.call("The traceback says the even case returned the upper middle value: average the two middle values and check again.", "run_code",
		runArgs{Code: medianFixed, Language: "python", Sandbox: h})
	if err != nil {
		return nil, err
	}
	sc.add(st2)
	sc.claim("the first check failed with a non-zero exit and a traceback", !st1.IsError && num(r1, "exitCode") != 0 && strings.Contains(str(r1, "stderr"), "Traceback"))
	sc.claim("the traceback names the failed assertion", strings.Contains(str(r1, "stderr"), "AssertionError"))
	sc.claim("the fixed version passed with exit 0", exited(st2, r2, 0) && strings.Contains(str(r2, "stdout"), "all checks pass"))
	if _, err := closeBox(s, sc, h); err != nil {
		return nil, err
	}
	sc.Observed = fmt.Sprintf("The first run %s, its stderr ending %q; the fixed run %s and printed %q.",
		ran(st1, r1), lastLine(str(r1, "stderr")), ran(st2, r2), strings.TrimSpace(str(r2, "stdout")))
	return sc, nil
}

func noNetwork(s *session) (*Scenario, error) {
	sc := &Scenario{ID: "no-network", Number: 5, Kind: "use", Title: "Untrusted code, no network",
		Ask:   "Code the model did not write itself (from a web page, say) tries to fetch a URL. The user wants to know it cannot phone home.",
		Shows: "A sandbox has no network: the request fails inside the sandbox, and the result names the isolation tier it ran behind. The URL names a server by address, so the failure is the network itself, not a name lookup."}
	st, r, err := s.call("List the network interfaces, then fetch https://1.1.1.1/ with a 2 second timeout, printing what happens.", "run_code",
		runArgs{Code: networkCode, Language: "python"})
	if err != nil {
		return nil, err
	}
	sc.add(st)
	out := str(r, "stdout")
	sc.claim("the run exited 0 (the code catches the failure and prints it)", exited(st, r, 0))
	sc.claim("the request did not reach the internet", strings.Contains(out, "no network:") && !strings.Contains(out, "reached the internet"))
	sc.claim("the result names its isolation tier", !st.IsError && str(r, "isolation") != "")
	sc.Observed = fmt.Sprintf("The run %s behind the %q tier and printed: %s.", ran(st, r), str(r, "isolation"), lines(out))
	return sc, nil
}

func twoLanguages(s *session) (*Scenario, error) {
	sc := &Scenario{ID: "two-languages", Number: 6, Kind: "use", Title: "Two languages, one sandbox",
		Ask:   "Python prepares some data (made-up figures) and a JavaScript step reads it, as a pipeline might.",
		Shows: "A sandbox keeps an interpreter per language and one working directory, so a file Python writes is there for JavaScript."}
	h, err := open(s, sc, "Open a sandbox; it runs both languages.")
	if err != nil {
		return nil, err
	}
	st1, r1, err := s.call("Write trip.json from Python.", "run_code", runArgs{Code: writeJSON, Language: "python", Sandbox: h})
	if err != nil {
		return nil, err
	}
	sc.add(st1)
	st2, r2, err := s.call("Read trip.json from JavaScript in the same sandbox.", "run_code", runArgs{Code: readJSON, Language: "javascript", Sandbox: h})
	if err != nil {
		return nil, err
	}
	sc.add(st2)
	sc.claim("Python wrote the file (exit 0)", exited(st1, r1, 0))
	sc.claim("JavaScript read it (exit 0, the city and mean printed)", exited(st2, r2, 0) && strings.Contains(str(r2, "stdout"), "Lisbon: mean daily high 23.0 C"))
	sc.claim("the second call ran in JavaScript", str(r2, "language") == "javascript")
	if _, err := closeBox(s, sc, h); err != nil {
		return nil, err
	}
	sc.Observed = fmt.Sprintf("Python %s and printed %q; JavaScript %s and printed %q.",
		ran(st1, r1), strings.TrimSpace(str(r1, "stdout")), ran(st2, r2), strings.TrimSpace(str(r2, "stdout")))
	return sc, nil
}

func runawayLoop(s *session) (*Scenario, error) {
	sc := &Scenario{ID: "runaway-loop", Number: 7, Kind: "use", Title: "A runaway loop",
		Ask:   "The model's code never ends. The user should get an answer anyway, and the sandbox should still be there for the next step.",
		Shows: "Every run has a time budget (3 seconds in this recording): a loop past it is stopped and reported as timedOut, and the sandbox answers the next call."}
	h, err := open(s, sc, "Open a sandbox.")
	if err != nil {
		return nil, err
	}
	st1, r1, err := s.call("Define a variable first.", "run_code", runArgs{Code: setAnswer, Language: "python", Sandbox: h})
	if err != nil {
		return nil, err
	}
	sc.add(st1)
	st2, r2, err := s.call("Run a loop that never ends.", "run_code", runArgs{Code: runaway, Language: "python", Sandbox: h})
	if err != nil {
		return nil, err
	}
	sc.add(st2)
	st3, r3, err := s.call("Ask the same sandbox for something small, and whether the variable is still there.", "run_code", runArgs{Code: stillThere, Language: "python", Sandbox: h})
	if err != nil {
		return nil, err
	}
	sc.add(st3)
	sc.claim("the first call defined the variable (exit 0)", exited(st1, r1, 0))
	sc.claim("the loop was stopped and reported as timedOut", !st2.IsError && yes(r2, "timedOut"))
	sc.claim("the sandbox answered the next call (exit 0)", exited(st3, r3, 0) && strings.Contains(str(r3, "stdout"), "still answering"))
	if _, err := closeBox(s, sc, h); err != nil {
		return nil, err
	}
	kept := "the variable survived"
	switch {
	case strings.Contains(str(r3, "stdout"), "answer is still 42"):
	case yes(r3, "freshInterpreter"):
		kept = "the variable did not survive, since stopping the loop ended the interpreter that held it and this call ran in a new one"
	default:
		kept = "the variable did not survive"
	}
	sc.Observed = fmt.Sprintf("The loop %s; the next call %s, printed %q (freshInterpreter %t, freshSandbox %t): %s.",
		ran(st2, r2), ran(st3, r3), lines(str(r3, "stdout")), yes(r3, "freshInterpreter"), yes(r3, "freshSandbox"), kept)
	return sc, nil
}

func proveItLater(s *session, o options, tmp string, first map[string]any) (*Scenario, error) {
	sc := &Scenario{ID: "prove-it-later", Number: 8, Kind: "use", Title: "Prove it later",
		Ask:   "Later, someone asks: did that primality check really run, behind which tier, with what code and output?",
		Shows: "Every run has a checked run record, and with receipts on, a line signed with the user's key that anyone holding the public key can check on its own."}
	digest := str(first, "recordSha256")
	st, r, err := s.call("Fetch the run record of example 1 by its sha256.", "get_record", recordArgs{RecordSHA256: digest})
	if err != nil {
		return nil, err
	}
	sc.add(st)
	rec, _ := r["record"].(map[string]any)
	sc.claim("get_record returned example 1's record", !st.IsError && str(rec, "sha256") == digest)

	receipt, _ := first["receipt"].(map[string]any)
	name, n := str(receipt, "file"), num(receipt, "line")
	if str(receipt, "status") != "stored" || name == "" || n < 1 || strings.ContainsAny(name, "/\\") {
		return nil, fmt.Errorf("example 1 has no stored receipt: %v", receipt)
	}
	raw, err := os.ReadFile(filepath.Join(tmp, "receipts", name))
	if err != nil {
		return nil, err
	}
	all := strings.Split(string(raw), "\n")
	if len(all) <= n {
		return nil, fmt.Errorf("%s has fewer than %d lines", name, n)
	}
	line := all[n-1]
	sum := sha256.Sum256([]byte(line))
	var entry attest.Entry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil, fmt.Errorf("line %d of %s: %w", n, name, err)
	}
	pubPEM, err := os.ReadFile(filepath.Join(tmp, "demo.pub"))
	if err != nil {
		return nil, err
	}
	pub, err := attest.ParsePublicKey(pubPEM)
	if err != nil {
		return nil, err
	}
	payload, err := base64.StdEncoding.DecodeString(entry.Envelope.Payload)
	if err != nil {
		return nil, err
	}
	pae := attest.PAE(entry.Envelope.PayloadType, payload)
	paeSum := sha256.Sum256(pae)
	var sig []byte
	if len(entry.Envelope.Signatures) == 1 {
		sig, _ = base64.StdEncoding.DecodeString(entry.Envelope.Signatures[0].Sig)
	}
	var statement map[string]any
	if err := json.Unmarshal(payload, &statement); err != nil {
		return nil, err
	}
	subject := ""
	if subjects, _ := statement["subject"].([]any); len(subjects) == 1 {
		digests, _ := subjects[0].(map[string]any)["digest"].(map[string]any)
		subject, _ = digests["sha256"].(string)
	}
	sc.claim("the line's SHA-256 is the one the result named", hex.EncodeToString(sum[:]) == str(receipt, "lineSha256"))
	sigOK := len(sig) == ed25519.SignatureSize && ed25519.Verify(pub, pae, sig)
	sc.claim("the record's Ed25519 signature verifies over the PAE with the demo public key", sigOK)
	sc.claim("the signed statement's subject is example 1's record", subject == digest)
	sc.claim("the key ID is the one the result named", attest.KeyID(pub) == str(receipt, "keyId"))

	rel := filepath.Join("receipts", name)
	cmd := exec.Command(o.attest, "verify-entry", "-pub", "demo.pub", "-line", strconv.Itoa(n), rel)
	cmd.Dir = tmp
	cmd.Env = []string{}
	out, err := cmd.CombinedOutput()
	exit := 0
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		exit = exitErr.ExitCode()
	case err != nil:
		return nil, fmt.Errorf("running %s: %w", o.attest, err)
	}
	verified := strings.TrimSpace(string(out))
	sc.claim("plimsoll-attest verify-entry accepted the line", exit == 0 && strings.HasPrefix(verified, "entry verified"))

	sc.Receipt = &Receipt{
		Of: "check-dont-guess", RecordSHA256: digest, File: name, LineNumber: n, Line: line, LineSHA256: hex.EncodeToString(sum[:]),
		KeyID: attest.KeyID(pub), PublicKeyPEM: string(pubPEM), PublicKeyRaw: base64.StdEncoding.EncodeToString(pub), Statement: payload,
		Signed: signedBytes{
			Algorithm: "Ed25519",
			PublicKey: "publicKeyRaw: the 32-byte public key, base64; publicKeyPem is the same key as PKIX",
			Signature: source{From: "envelope.signatures[0].sig", Encoding: "base64", Bytes: ed25519.SignatureSize},
			Message: messageSpec{
				Scheme:      "DSSE v1 pre-authentication encoding (PAE)",
				Parts:       []string{"DSSEv1", "len(payloadType)", "payloadType", "len(payload)", "payload"},
				Separator:   " ",
				Lengths:     "byte counts as ASCII decimal",
				PayloadType: source{From: "envelope.payloadType", Encoding: "utf-8"},
				Payload:     source{From: "envelope.payload", Encoding: "base64", Bytes: len(payload)},
				Bytes:       len(pae),
				SHA256:      hex.EncodeToString(paeSum[:]),
			},
			AlsoSigned: "link: the same scheme over link.payloadType and link.payload, signing the line's place in its file",
		},
		NotCovered: "A signature check proves the demo key signed this statement and nothing in it changed. It does not recompute the record from the request and " +
			"response stored in the line, check the line's link, or check the file around it: plimsoll-attest verify-entry checks the first two, " +
			"plimsoll-attest verify the whole file. It never shows that what the code printed is true.",
		VerifyEntry: cliRun{Command: fmt.Sprintf("plimsoll-attest verify-entry -pub demo.pub -line %d %s", n, rel), ExitCode: exit, Output: verified},
	}
	sc.Observed = fmt.Sprintf("get_record %s. The record's signature on line %d of %s (%d bytes) %s with the demo public key, and plimsoll-attest verify-entry (exit %d) said: %s",
		map[bool]string{true: "returned the record", false: "failed"}[!st.IsError], n, name, len(line),
		map[bool]string{true: "verified", false: "did not verify"}[sigOK], exit, strings.TrimSuffix(verified, ".")+".")
	return sc, nil
}

func capScene(s *session) (*Scenario, error) {
	sc := &Scenario{ID: "cap", Number: 9, Kind: "safety", Title: "A fourth sandbox, refused",
		Ask:   "With three sandboxes open, the model asks for a fourth. This server allows three at once.",
		Shows: "Opening never deletes anything to make room: the refusal says nothing ran, and names the idle sandboxes the model could close itself."}
	var handles []string
	for i := 1; i <= 3; i++ {
		h, err := open(s, sc, fmt.Sprintf("Open sandbox %d of 3.", i))
		if err != nil {
			return nil, err
		}
		handles = append(handles, h)
	}
	st, r, err := s.call("Open a fourth.", "open_sandbox", noArgs{})
	if err != nil {
		return nil, err
	}
	sc.add(st)
	idle := strs(r["idleSandboxes"])
	slices.Sort(idle)
	want := slices.Sorted(slices.Values(handles))
	sc.claim("the fourth open was refused", st.IsError)
	sc.claim("the refusal says nothing ran, for want of capacity", str(r, "ran") == "no" && str(r, "refusal") == "capacity")
	sc.claim("it names the three idle sandboxes", slices.Equal(idle, want))
	closedAll := true
	for _, h := range handles {
		cr, err := closeBox(s, sc, h)
		if err != nil {
			return nil, err
		}
		closedAll = closedAll && yes(cr, "deleted")
	}
	how := "a success"
	if st.IsError {
		how = fmt.Sprintf("a tool error with ran %q and refusal %q, naming %d idle sandboxes", str(r, "ran"), str(r, "refusal"), len(idle))
	}
	confirmed := "the daemon confirmed each deletion"
	if !closedAll {
		confirmed = "the daemon did not confirm every deletion"
	}
	sc.Observed = fmt.Sprintf("The fourth open_sandbox was %s. Closing the three, %s.", how, confirmed)
	return sc, nil
}
