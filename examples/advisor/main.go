// Command advisor shows the efficiency advisor end to end: the same question asked
// of a small inventory API twice, first the way an agent tends to write it (list the
// ids, then one call per item, then add the column up in its own code) and then the
// way the advice that came back suggests. Both runs print the same answer; the API
// counts the requests and bytes each one cost, so the finding's predictions can be
// read next to a measurement.
//
// Run it from the repository root, because it builds the daemon from source:
//
//	go run ./examples/advisor
//	go run ./examples/advisor -report out.html   # the same run as a self-contained page
//
// It needs no docker, no credentials and no model. The daemon is started with
// SANDBOX_PROVIDER=wasm and a grants file whose one profile opts in with
// "advice": "caller", so the agent-fixable findings ride back on the run result and
// the official client exposes them as Result.Advice. The findings are computed after
// the run over the broker's metadata-only call trace, so nothing about execution
// changes when they are on: same output, same exit code, same isolation tier.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/sandbox"
)

const (
	callerID = "example-client"
	profile  = "inventory"
	tokenEnv = "INVENTORY_TOKEN"
)

// Where the published copy of the report lives, and what it links back to. The
// page is served from the repository's docs/ tree on GitHub Pages, so the links are
// absolute: the same file must read correctly from a local path.
const (
	pageURL    = "https://plimsollmark.github.io/plimsoll/examples/advisor/report.html"
	cardURL    = "https://plimsollmark.github.io/plimsoll/social/cards/advisor-example.png"
	repoURL    = "https://github.com/plimsollmark/plimsoll"
	sourceURL  = repoURL + "/blob/main/examples/advisor/main.go"
	readmeURL  = repoURL + "#efficiency-advisor"
	lessonURL  = "https://plimsollmark.github.io/plimsoll/trainers/advisor.html"
	lessonsURL = "https://plimsollmark.github.io/plimsoll/trainers/"
	homeURL    = "https://plimsollmark.github.io/plimsoll/"
)

// perItemLoop is the agent's first attempt. It is not wrong, and that is the point:
// it returns the right number. It costs one request per item because the agent
// assumed the collection route returns summaries and did not check.
const perItemLoop = `host.get("/items").then(function (list) {
  return Promise.all(list.items.map(function (it) { return host.get("/items/" + it.id); }));
}).then(function (rows) {
  var total = rows.reduce(function (a, r) { return a + r.onHand; }, 0);
  console.log(JSON.stringify({ total: total, rows: rows.length }));
});`

// collectionRead is the same question written the way the finding suggests: the
// collection route the profile already grants carries the column.
const collectionRead = `host.get("/items").then(function (list) {
  var total = list.items.reduce(function (a, r) { return a + r.onHand; }, 0);
  console.log(JSON.stringify({ total: total, rows: list.items.length }));
});`

func main() {
	reportPath := flag.String("report", "", "write a self-contained HTML page of this run to the given path")
	flag.Parse()
	if err := run(context.Background(), *reportPath); err != nil {
		fmt.Fprintln(os.Stderr, "example failed:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, reportPath string) error {
	workDir, err := os.MkdirTemp("", "plimsoll-advisor-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)

	// The inventory API the agent code will call. It logs every request it serves,
	// which is the one measurement the advisor's numbers can be checked against from
	// outside the sandbox.
	api := newInventory()
	upstream := httptest.NewServer(api)
	defer upstream.Close()

	token, clientsPath, err := writeClientsFile(workDir)
	if err != nil {
		return err
	}
	grantsPath, err := writeGrantsFile(workDir, upstream.URL)
	if err != nil {
		return err
	}
	fmt.Printf("profile   | %q grants GET /items and GET /items/*, advice=caller, advice_retention=detailed\n", profile)
	fmt.Printf("profile   | the API credential is read by the daemon from $%s and never enters the guest\n", tokenEnv)

	binary, err := buildDaemon(ctx, workDir)
	if err != nil {
		return err
	}
	addr, err := freeAddr()
	if err != nil {
		return err
	}
	sink := &lineSink{}
	daemon, err := startDaemon(ctx, binary, addr, clientsPath, grantsPath, api.token, sink)
	if err != nil {
		return err
	}
	defer stop(daemon)

	baseURL := "http://" + addr
	if err := waitForReady(ctx, baseURL); err != nil {
		return err
	}
	fmt.Printf("daemon    | ready at %s (wasm, process tier; the advisor is provider-independent)\n\n", baseURL)

	remote, err := client.New(baseURL,
		client.WithToken(token),
		client.WithInsecureHTTP(), // loopback only; a real deployment serves TLS
		client.WithJavaScriptGrantProfile(profile),
	)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	first, err := show(ctx, remote, api, sink, 1, "1. the agent's first attempt: list the ids, then one call per item", perItemLoop)
	if err != nil {
		return err
	}
	second, err := show(ctx, remote, api, sink, 2, "2. the same question, written the way the advice suggests", collectionRead)
	if err != nil {
		return err
	}

	// The example checks its own claims rather than asserting them in prose.
	if first.stdout != second.stdout {
		return fmt.Errorf("the two runs disagree: %q vs %q", first.stdout, second.stdout)
	}
	if first.exitCode != 0 || second.exitCode != 0 {
		return fmt.Errorf("a run failed: exit %d and %d", first.exitCode, second.exitCode)
	}
	finding, ok := first.suggestion("fan_out", "/items")
	if !ok {
		return errors.New("the per-item loop did not come back with a fan_out finding suggesting GET /items")
	}
	if len(second.advice) != 0 {
		return fmt.Errorf("the collection read came back with advice: %+v", second.advice)
	}
	if first.audit.AgentFixable != 1 || second.audit.AgentFixable != 0 {
		return fmt.Errorf("audit lines disagree with the results: agent_fixable %d then %d", first.audit.AgentFixable, second.audit.AgentFixable)
	}
	// One observation, one finding: the twelve per-item reads are reported once, as
	// the fan-out, with eleven calls beyond one. A second finding over the same rows
	// would double the audit line's totals.
	if first.audit.AdviceFindings != 1 || first.audit.ExtraCalls != 11 {
		return fmt.Errorf("run 1's audit line should carry exactly the fan-out finding with 11 extra calls, got %d finding(s) and %d extra calls", first.audit.AdviceFindings, first.audit.ExtraCalls)
	}
	// The twelve per-item reads fetched twelve distinct items, and several of those
	// responses are the same size. The trace holds the route template and the size,
	// not the item, so it cannot tell same-size from same-item; the repeated-read
	// detector therefore leaves wildcard routes alone, and a finding here would be a
	// claim the evidence does not support.
	sameSize, perItem := first.largestSameSizeGroup("/items/*")
	if d, ok := first.audit.finding("repeated_read"); ok {
		return fmt.Errorf("the per-item loop was flagged as a repeated read of %s %s, but it fetched %d distinct items", d.Method, d.Route, perItem)
	}

	rows := compare(finding, first, second)
	fmt.Println("predicted vs measured")
	for _, r := range rows {
		fmt.Printf("   %-9s| %-44s | %s\n", r.Field, r.Predicted, r.Measured)
	}
	fmt.Println()
	fmt.Println("summary   | same answer both times; the second run cost the API", second.requestCount(), "request instead of", first.requestCount())
	fmt.Println("summary   | the finding named the granted route to switch to, so the fix needed no API change")
	fmt.Println("summary   | the audit line is the operator's view: the same finding with its costs and, at advice_retention=detailed,")
	fmt.Println("summary   | one metadata-only record per finding; nothing was withheld from the caller here, since the one finding was agent-fixable")
	fmt.Printf("summary   | %d of the %d per-item responses were the same size, and none was flagged as a repeated read:\n", sameSize, perItem)
	fmt.Println("summary   | the trace holds the template and the size, not the item, so it cannot tell same-size from same-item")

	if reportPath != "" {
		if err := writeReport(reportPath, []outcome{first, second}, rows); err != nil {
			return err
		}
		fmt.Printf("report    | written to %s\n", reportPath)
	}
	return nil
}

// outcome is what one run produced, from four vantage points: the guest's output,
// the API's request log, the advice on the result, and the daemon's audit line.
type outcome struct {
	title    string
	code     string
	stdout   string
	exitCode int
	wall     time.Duration
	requests []apiRequest
	advice   []sandbox.AdviceFinding
	audit    auditLine
}

func (o outcome) requestCount() int { return len(o.requests) }

func (o outcome) bytesServed() int {
	n := 0
	for _, r := range o.requests {
		n += r.ReqBytes + r.RespBytes
	}
	return n
}

func (o outcome) suggestion(pattern, route string) (sandbox.AdviceFinding, bool) {
	for _, f := range o.advice {
		if f.Pattern == pattern && f.SuggestedRoute == route {
			return f, true
		}
	}
	return sandbox.AdviceFinding{}, false
}

// largestSameSizeGroup returns, among the requests the API served under one route
// template, the size of the largest set sharing a response byte count, and the
// total. It is the measurement behind the example's repeated-read claim: the API
// knows these were distinct paths, and the trace knows only the template and the
// sizes.
func (o outcome) largestSameSizeGroup(template string) (sameSize, total int) {
	bySize := make(map[int]int)
	for _, r := range o.requests {
		if r.Template != template {
			continue
		}
		total++
		bySize[r.RespBytes]++
		sameSize = max(sameSize, bySize[r.RespBytes])
	}
	return sameSize, total
}

// show dispatches one snippet over the wire and prints what came back from each
// vantage point.
func show(ctx context.Context, remote *client.Remote, api *inventory, sink *lineSink, n int, title, code string) (outcome, error) {
	fmt.Println(title)
	api.snapshot()
	result, err := remote.RunJavaScript(ctx, sandbox.Request{Code: code, Timeout: 10 * time.Second})
	if err != nil {
		return outcome{}, fmt.Errorf("run: %w", err)
	}
	audit, err := sink.waitForAudit(n)
	if err != nil {
		return outcome{}, err
	}
	o := outcome{
		title:    title,
		code:     code,
		stdout:   strings.TrimSpace(result.Stdout),
		exitCode: result.ExitCode,
		wall:     result.Duration,
		requests: api.snapshot(),
		advice:   result.Advice,
		audit:    audit,
	}
	fmt.Printf("   guest  | %s\n", o.stdout)
	if errOut := strings.TrimSpace(result.Stderr); errOut != "" {
		fmt.Printf("   guest !| %s\n", errOut)
	}
	fmt.Printf("   api    | %d request(s) served, %d bytes; exit=%d isolation=%s wall=%s\n",
		o.requestCount(), o.bytesServed(), o.exitCode, result.Isolation, o.wall.Round(time.Millisecond))
	fmt.Printf("   audit  | host_calls=%d advice_findings=%d agent_fixable=%d (the daemon's own log line)\n",
		audit.HostCalls, audit.AdviceFindings, audit.AgentFixable)
	for _, d := range audit.Details {
		if !d.AgentFixable {
			fmt.Printf("   audit  | operator-only: %s on %s %s (remedy %s)\n", d.Pattern, d.Method, d.Route, d.Remedy)
		}
	}
	if len(o.advice) == 0 {
		fmt.Println("   advice | none returned to the caller")
	}
	for _, f := range o.advice {
		fmt.Printf("   advice | %s (%s, remedy %s) on %s %s; suggested %s %s, already granted\n",
			f.Pattern, f.Severity, f.Remedy, f.Method, f.Route, f.SuggestedMethod, f.SuggestedRoute)
		fmt.Printf("   advice | %d calls beyond one (measured count); about %s beyond one call (modelled); %d bytes moved in total (gross)\n",
			f.ExtraCalls, f.AddedLatency.Round(time.Millisecond), f.BytesMoved)
		fmt.Printf("   advice | %s\n", f.Detail)
	}
	fmt.Println()
	return o, nil
}

// compareRow puts one of the finding's numbers next to what the API measured.
type compareRow struct {
	Field     string
	Predicted string
	Measured  string
}

func compare(f sandbox.AdviceFinding, first, second outcome) []compareRow {
	return []compareRow{
		{
			Field:     "calls",
			Predicted: fmt.Sprintf("%d beyond one on %s %s (measured count minus one)", f.ExtraCalls, f.Method, f.Route),
			Measured:  fmt.Sprintf("the API served %d requests, then %d: %d fewer", first.requestCount(), second.requestCount(), first.requestCount()-second.requestCount()),
		},
		{
			Field:     "latency",
			Predicted: fmt.Sprintf("about %s beyond one call (a model, not wall time)", f.AddedLatency.Round(time.Millisecond)),
			Measured:  fmt.Sprintf("guest wall time %s, then %s (includes engine start; not the same quantity)", first.wall.Round(time.Millisecond), second.wall.Round(time.Millisecond)),
		},
		{
			Field:     "bytes",
			Predicted: fmt.Sprintf("%d moved in total by the flagged calls (gross)", f.BytesMoved),
			Measured:  fmt.Sprintf("the API moved %d bytes, then %d: %d fewer", first.bytesServed(), second.bytesServed(), first.bytesServed()-second.bytesServed()),
		},
	}
}

// inventory is the host API: twelve items behind a bearer the daemon injects. The
// handler checks the bearer, so a request that reached it proves the credential was
// attached host-side; the guest never saw it. It logs what it served, as it saw it,
// which is precisely what plimsoll's own trace does not hold.
type inventory struct {
	token string
	items []item
	mu    sync.Mutex
	log   []apiRequest
}

type item struct {
	ID     string `json:"id"`
	SKU    string `json:"sku"`
	OnHand int    `json:"onHand"`
}

// apiRequest is one request as the API saw it. Template is the route template the
// profile grants for that path, filled in for the report's comparison view.
type apiRequest struct {
	Method    string
	Path      string
	Template  string
	ReqBytes  int
	RespBytes int
}

func newInventory() *inventory {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	inv := &inventory{token: hex.EncodeToString(raw)}
	for i := 1; i <= 12; i++ {
		inv.items = append(inv.items, item{ID: fmt.Sprintf("i-%d", i), SKU: fmt.Sprintf("SKU-%03d", i), OnHand: (i * 7) % 23})
	}
	return inv
}

// snapshot returns the requests served since the previous snapshot and clears the log.
func (inv *inventory) snapshot() []apiRequest {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	out := inv.log
	inv.log = nil
	return out
}

func (inv *inventory) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+inv.token {
		http.Error(w, "missing or wrong bearer", http.StatusUnauthorized)
		return
	}
	var body bytes.Buffer
	status := http.StatusOK
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/items":
		_ = json.NewEncoder(&body).Encode(map[string]any{"items": inv.items})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/items/"):
		id := strings.TrimPrefix(r.URL.Path, "/items/")
		status = http.StatusNotFound
		for _, it := range inv.items {
			if it.ID == id {
				_ = json.NewEncoder(&body).Encode(it)
				status = http.StatusOK
			}
		}
	default:
		status = http.StatusNotFound
	}
	inv.mu.Lock()
	inv.log = append(inv.log, apiRequest{
		Method: r.Method, Path: r.URL.Path, Template: templateFor(r.URL.Path),
		ReqBytes: int(max(r.ContentLength, 0)), RespBytes: body.Len(),
	})
	inv.mu.Unlock()
	if status != http.StatusOK {
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body.Bytes())
}

// templateFor maps a path to the route template the profile grants for it. This is
// the report's reconstruction of what the trace holds; the trace itself never leaves
// the daemon, and the audit line's host_calls count is what confirms it.
func templateFor(path string) string {
	if strings.HasPrefix(path, "/items/") {
		return "/items/*"
	}
	return path
}

// lineSink captures the daemon's stderr so the audit lines can be read back. Each
// audit line is one JSON object; the fields below are the ones this example reads.
type lineSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lineSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

type auditLine struct {
	HostCalls      int           `json:"host_calls"`
	AdviceFindings int           `json:"advice_findings"`
	AgentFixable   int           `json:"advice_agent_fixable"`
	ExtraCalls     int           `json:"advice_extra_calls"`
	Details        []auditDetail `json:"advice_finding_details"`
}

// finding returns the audit line's record for one detector, if it emitted one.
func (a auditLine) finding(pattern string) (auditDetail, bool) {
	for _, d := range a.Details {
		if d.Pattern == pattern {
			return d, true
		}
	}
	return auditDetail{}, false
}

type auditDetail struct {
	Pattern        string `json:"pattern"`
	Severity       string `json:"severity"`
	Remedy         string `json:"remedy"`
	Method         string `json:"method"`
	Route          string `json:"route"`
	Detail         string `json:"detail"`
	AgentFixable   bool   `json:"agent_fixable"`
	ExtraCalls     int    `json:"extra_calls"`
	AddedLatencyMs int64  `json:"added_latency_ms"`
	BytesMoved     int64  `json:"bytes_moved"`
}

// waitForAudit returns the n-th "code run" audit line, waiting briefly for the
// daemon's stderr to catch up with the response the client already has.
func (l *lineSink) waitForAudit(n int) (auditLine, error) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		l.mu.Lock()
		lines := strings.Split(l.buf.String(), "\n")
		l.mu.Unlock()
		seen := 0
		for _, line := range lines {
			if !strings.Contains(line, `"msg":"code run"`) {
				continue
			}
			seen++
			if seen == n {
				var a auditLine
				if err := json.Unmarshal([]byte(line), &a); err != nil {
					return auditLine{}, fmt.Errorf("audit line %d is not JSON: %w", n, err)
				}
				return a, nil
			}
		}
		if time.Now().After(deadline) {
			return auditLine{}, fmt.Errorf("audit line %d did not appear on the daemon's stderr", n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// writeGrantsFile creates the one-profile grants file. The profile is selected by
// name over the wire; its base URL, routes and credential source all stay here, on
// the server side. Loopback HTTP is accepted for the base URL; anything else must be
// HTTPS.
func writeGrantsFile(dir, baseURL string) (string, error) {
	body := fmt.Sprintf(`{"profiles":{%q:{
  "base_url": %q,
  "allow": ["GET /items", "GET /items/*"],
  "allowed_callers": [%q],
  "token": {"type": "static", "env": %q},
  "advice": "caller",
  "advice_retention": "detailed"
}}}`, profile, baseURL, callerID, tokenEnv)
	path := filepath.Join(dir, "grants.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// writeClientsFile creates the multi-client auth file. Tokens are stored as SHA-256
// hex, never in the clear.
func writeClientsFile(dir string) (token, path string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	path = filepath.Join(dir, "clients.json")
	body := fmt.Sprintf(`{"clients":[{"id":%q,"token_sha256":%q,"scopes":["code:run"]}]}`,
		callerID, hex.EncodeToString(sum[:]))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return "", "", err
	}
	return token, path, nil
}

// buildDaemon compiles plimsolld from the checkout so the example runs the code in
// this tree rather than whatever happens to be installed.
func buildDaemon(ctx context.Context, dir string) (string, error) {
	binary := filepath.Join(dir, "plimsolld")
	cmd := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/plimsolld")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("build plimsolld (run this from the repository root): %w", err)
	}
	return binary, nil
}

func startDaemon(ctx context.Context, binary, addr, clientsPath, grantsPath, apiToken string, sink io.Writer) (*exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, binary)
	cmd.Env = append(os.Environ(),
		"SANDBOX_PROVIDER=wasm",
		"PLIMSOLL_ADDR="+addr,
		"PLIMSOLL_CLIENTS_FILE="+clientsPath,
		"PLIMSOLL_GRANTS_FILE="+grantsPath,
		tokenEnv+"="+apiToken,
	)
	// The daemon's structured audit line goes to stderr: one record per run, with
	// the advice counts and, at advice_retention=detailed, one metadata-only record
	// per finding. It never carries the code, the token, or a request path. The
	// example tees it so the operator's view can be printed beside the caller's.
	out := io.MultiWriter(os.Stderr, sink)
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start plimsolld: %w", err)
	}
	return cmd, nil
}

func stop(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
}

// waitForReady polls /readyz, which the daemon serves outside auth.
func waitForReady(ctx context.Context, baseURL string) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/readyz", nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("plimsolld did not become ready within 30s")
}

// freeAddr reserves a loopback port by binding it and handing back the address.
func freeAddr() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := listener.Addr().String()
	return addr, listener.Close()
}

// writeReport renders the run as one self-contained page: no scripts or styles are
// fetched, and nothing in it identifies the machine (no ports, no token).
func writeReport(path string, runs []outcome, rows []compareRow) error {
	type runView struct {
		N            int
		Title        string
		Code         string
		Stdout       string
		Requests     []apiRequest
		RequestCount int
		BytesServed  int
		WallMs       int64
		Advice       []sandbox.AdviceFinding
		Audit        auditLine
	}
	var views []runView
	for i, o := range runs {
		views = append(views, runView{
			N: i + 1, Title: o.title, Code: o.code, Stdout: o.stdout, Requests: o.requests,
			RequestCount: o.requestCount(), BytesServed: o.bytesServed(), WallMs: o.wall.Milliseconds(),
			Advice: o.advice, Audit: o.audit,
		})
	}
	sameSize, perItem := runs[0].largestSameSizeGroup("/items/*")
	data := struct {
		Generated  string
		Runs       []runView
		Rows       []compareRow
		SameSize   int
		PerItem    int
		PageURL    string
		CardURL    string
		RepoURL    string
		SourceURL  string
		ReadmeURL  string
		LessonURL  string
		LessonsURL string
		HomeURL    string
	}{time.Now().Format("2006-01-02"), views, rows, sameSize, perItem, pageURL, cardURL, repoURL, sourceURL, readmeURL, lessonURL, lessonsURL, homeURL}
	var buf bytes.Buffer
	if err := reportTemplate.Execute(&buf, data); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

var reportTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"ms": func(d time.Duration) int64 { return d.Milliseconds() },
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>13 requests became 1: plimsoll's efficiency advisor on one measured run</title>
<meta name="description" content="An agent spent 13 requests on one number. plimsoll's efficiency advisor named the granted route to use instead, and the rewrite cost 1. Every number is measured, or labelled as a model.">
<link rel="canonical" href="{{.PageURL}}">
<meta property="og:type" content="article">
<meta property="og:site_name" content="plimsoll">
<meta property="og:title" content="13 requests became 1: plimsoll's efficiency advisor on one measured run">
<meta property="og:description" content="An agent spent 13 requests on one number. plimsoll's efficiency advisor named the granted route to use instead, and the rewrite cost 1. Every number is measured, or labelled as a model.">
<meta property="og:url" content="{{.PageURL}}">
<meta property="og:image" content="{{.CardURL}}">
<meta property="og:image:width" content="1280">
<meta property="og:image:height" content="640">
<meta name="twitter:card" content="summary_large_image">
<style>
:root{color-scheme:light}
body{margin:0;padding:24px 16px;background:#fff;color:#1f2328;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:1100px;margin:0 auto}
nav{display:flex;flex-wrap:wrap;gap:6px 18px;align-items:baseline;padding-bottom:12px;border-bottom:1px solid #d1d9e0;margin-bottom:20px}
nav .brand{font-weight:700;color:#0f4a85;font-size:1.1em}
a{color:#0969da} a:hover{text-decoration-thickness:2px}
h1{font-size:1.7em;line-height:1.2;margin:0 0 8px} h2{font-size:1.2em;margin:32px 0 8px} h3{font-size:1em;margin:18px 0 6px}
p{max-width:80ch} .muted{color:#59636e}
.tiles{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.tile{border:1px solid #d1d9e0;border-radius:8px;padding:10px 14px;min-width:150px;background:#f6f8fa}
.tile b{display:block;font-size:1.5em}
.tabs{display:flex;flex-wrap:wrap;gap:6px;margin:12px 0 0}
.tabs button{border:1px solid #d1d9e0;border-bottom:none;border-radius:8px 8px 0 0;background:#f6f8fa;padding:8px 14px;font:inherit;cursor:pointer;text-align:left}
.tabs button[aria-selected=true]{background:#fff;font-weight:600}
.panel{border:1px solid #d1d9e0;border-radius:0 8px 8px 8px;padding:16px}
.panel[hidden]{display:none}
pre{background:#f6f8fa;border:1px solid #d1d9e0;border-radius:6px;padding:12px;overflow:auto;font-size:13px;line-height:1.45}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%} td,th{border:1px solid #d1d9e0;padding:5px 8px;text-align:left;vertical-align:top;font-size:.92em} th{background:#f6f8fa}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.card{border-left:4px solid #bf8700;background:#fff8c5;padding:10px 14px;border-radius:0 6px 6px 0;margin:10px 0}
.card.ok{border-left-color:#1a7f37;background:#dafbe1}
.card.op{border-left-color:#0969da;background:#ddf4ff}
.toggle{margin:8px 0}
.toggle button{font:inherit;padding:6px 12px;border:1px solid #d1d9e0;border-radius:6px;background:#fff;cursor:pointer}
.toggle button[aria-pressed=true]{background:#ddf4ff;border-color:#0969da}
.hide{display:none}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px} dt{color:#59636e}
ul{max-width:80ch;padding-left:1.2em} li{margin:4px 0}
footer{margin-top:40px;padding-top:12px;border-top:1px solid #d1d9e0;color:#59636e;font-size:.92em}
</style></head><body><main>
<nav><a class="brand" href="{{.HomeURL}}">plimsoll home</a>
<a href="{{.RepoURL}}">EXTERNAL · source repo ↗</a>
<a href="{{.LessonURL}}">INTERNAL · trainer site → the advisor lesson</a>
<a href="{{.LessonsURL}}">INTERNAL · trainer site → all lessons</a></nav>

<h1>13 requests became 1, and the sandbox is what said so</h1>
<p class="muted">One run of plimsoll's efficiency advisor, generated {{.Generated}} by <code>go run ./examples/advisor -report</code>. Every number on this page was measured by the API or read from the daemon's own log, or is labelled as a model.</p>

<p><b>plimsoll</b> is an open source sandbox service for running code that an AI agent wrote. Its broker authorizes every call that code makes to your API, keeps the credential outside the sandbox, and records only route templates, verbs, status codes, byte counts and timings. A <b>route template</b> is the granted route with its variable segment left as a <code>*</code>, so a call to <code>/items/i-7</code> is recorded as <code>/items/*</code>: which route the code used, never which item it asked for. There is no field for a path, a body or a credential, so none can be recorded by accident.</p>
<p><b>The efficiency advisor</b> reads that record after a run and reports where the call pattern cost the API more than the question needed. When the profile already grants a better route, the finding names it and comes back to the caller, who can rewrite. When it does not, the finding stays with the operator, because the agent cannot call a route that does not exist. plimsoll never calls a model to do any of this. It is a work in progress, and it is off unless a profile asks for it: a profile that does not set <code>advice</code> has its traffic left unanalyzed, and nothing is computed.</p>
<p><b>This page</b> is one real run of the repository's advisor example: a fake inventory API with twelve items, a plimsoll daemon on the WASM provider, and one grant profile with <code>advice: caller</code>. The same question is asked twice, first the way an agent tends to write it, then the way the advice suggests.</p>

<div class="tiles">
{{range .Runs}}<div class="tile"><span class="muted">run {{.N}} requests</span><b>{{.RequestCount}}</b></div>{{end}}
{{range .Runs}}<div class="tile"><span class="muted">run {{.N}} answer</span><b style="font-size:1em">{{.Stdout}}</b></div>{{end}}
</div>

<div class="tabs" role="tablist">
{{range .Runs}}<button role="tab" data-run="{{.N}}" aria-selected="{{if eq .N 1}}true{{else}}false{{end}}">{{.Title}}</button>{{end}}
</div>
{{range .Runs}}
<section class="panel" id="run-{{.N}}" role="tabpanel" {{if ne .N 1}}hidden{{end}}>
<h3>What the agent's code did</h3>
<pre>{{.Code}}</pre>
<h3>What came back</h3>
<dl><dt>guest output</dt><dd><code>{{.Stdout}}</code></dd>
<dt>guest wall time</dt><dd>{{.WallMs}} ms, engine start included</dd>
<dt>advice on the result</dt><dd>{{if .Advice}}{{len .Advice}} finding(s), below{{else}}none{{end}}</dd></dl>
{{range .Advice}}
<div class="card">detected an unnecessary <b>{{.Pattern}}</b> on {{.Method}} {{.Route}} (severity {{.Severity}}, remedy {{.Remedy}})<br>
suggested: <b>{{.SuggestedMethod}} {{.SuggestedRoute}}</b>, already granted<br>
{{.ExtraCalls}} calls beyond one <span class="muted">(measured count minus one)</span> ·
about {{ms .AddedLatency}} ms beyond one call <span class="muted">(modelled, not wall time)</span> ·
{{.BytesMoved}} bytes moved in total <span class="muted">(gross, not a saving)</span><br>
<span class="muted">{{.Detail}}</span><br>
<span class="muted"><b>severity</b> ranks nothing but the size of the pattern, for display: <b>low</b> under 25 calls, <b>medium</b> from 25, <b>high</b> from 100. A low finding is the same mistake as a high one over a smaller collection, so it is worth the same rewrite. Severity never gates a run or changes a result.</span></div>
{{else}}<div class="card ok">No finding. The collection route carried the column, so one request answered the question.</div>{{end}}

<h3>What the API saw, and what plimsoll's trace holds</h3>
<div class="toggle"><button type="button" class="trace-toggle" aria-pressed="false">Show what plimsoll's trace holds instead</button>
<span class="muted">Toggling swaps the path column for the route template the trace actually holds, so a path like <code>/items/i-7</code> collapses to <code>/items/*</code>: the record says which route the code called, never which item it asked for. The trace never leaves the daemon, so this view is reconstructed from the profile's route templates, and the audit line's <code>host_calls={{.Audit.HostCalls}}</code> is what confirms the count.</span></div>
<div class="scroll"><table><thead><tr><th>#</th><th>method</th><th class="path">path as the API saw it</th><th class="tmpl hide">route template in the trace</th><th class="num">request bytes</th><th class="num">response bytes</th></tr></thead>
<tbody>{{range $i, $r := .Requests}}<tr><td class="num">{{$i}}</td><td>{{$r.Method}}</td><td class="path"><code>{{$r.Path}}</code></td><td class="tmpl hide"><code>{{$r.Template}}</code></td><td class="num">{{$r.ReqBytes}}</td><td class="num">{{$r.RespBytes}}</td></tr>{{end}}
<tr><th colspan="4">{{.RequestCount}} requests</th><th class="num" colspan="2">{{.BytesServed}} bytes</th></tr></tbody></table></div>

<h3>The operator's view: the daemon's audit line</h3>
<div class="card op">host_calls={{.Audit.HostCalls}} · advice_findings={{.Audit.AdviceFindings}} · advice_agent_fixable={{.Audit.AgentFixable}}
{{range .Audit.Details}}<br>detected <b>{{.Pattern}}</b> on {{.Method}} {{.Route}} (severity {{.Severity}}, remedy {{.Remedy}}), and the finding was {{if .AgentFixable}}returned to the caller{{else}}kept operator only{{end}}{{end}}
<br><span class="muted">A finding the agent could not act on (no granted route to switch to) would stay here, operator only, with a prompt the API owner can paste into their own AI. {{if .Audit.Details}}This run produced none of those: the profile already granted the collection route, so its one finding went back to the caller.{{else}}This run produced no finding at all, so there is nothing here for either audience.{{end}}</span></div>
</section>
{{end}}

<h2>Predicted next to measured</h2>
<p>The finding's numbers compare the measured pattern with an assumed ideal of one call. The ideal is never measured, so the second run is the measurement.</p>
<div class="scroll"><table><thead><tr><th>number</th><th>the finding said</th><th>the API measured</th></tr></thead><tbody>
{{range .Rows}}<tr><td>{{.Field}}</td><td>{{.Predicted}}</td><td>{{.Measured}}</td></tr>{{end}}
</tbody></table></div>
<p class="muted">Bytes matched here only because the collection call was already being made in run 1; in general the replacement call moves bytes of its own, which is why the number is a gross total and not a saving.</p>

<h2>Run it yourself</h2>
<p>From a checkout of the repository, with Go installed. No docker, no credentials, no model, and nothing leaves your machine:</p>
<pre>git clone {{.RepoURL}}.git && cd plimsoll
go run ./examples/advisor                    # the run, in the terminal
go run ./examples/advisor -report out.html   # the same run as a page like this one</pre>
<p>The program checks its own claims: it fails if the two answers differ, if the loop does not come back with a fan-out finding naming the granted route, if the rewrite comes back with any finding at all, if the per-item loop is flagged as a repeated read, or if the audit line carries anything but that one finding with its 11 calls beyond one. Source: <a href="{{.SourceURL}}">EXTERNAL · source repo ↗ examples/advisor/main.go</a>. How the advisor fits the rest: <a href="{{.ReadmeURL}}">EXTERNAL · source repo ↗ README, efficiency advisor</a>.</p>

<h2>What this page claims, and what it does not</h2>
<ul>
<li><b>Advice never changes a run.</b> It is computed after the result is final, over metadata the broker already held. A run with advice is byte-identical in execution to one without; advice cannot gate admission or change an exit code, an output byte or the isolation tier.</li>
<li><b>The trace is metadata only.</b> Route templates, verbs, status codes, byte counts, latency. The toggle above shows what that leaves out.</li>
<li><b>No model is involved.</b> Two deterministic detectors (a fan-out over a per-item route, and repeated reads of one fixed route), counting only calls the broker delivered with a 2xx status, and one question against the granted routes. The paste-ready prompt for an API-change finding is text the operator may choose to hand to their own AI.</li>
<li><b>The numbers are what they say.</b> The call count is measured. The latency and byte figures are a model of the pattern against an ideal of one call, and the table above puts them next to what the API measured.</li>
<li><b>A finding claims only what the trace can support.</b> In run 1, {{.SameSize}} of the {{.PerItem}} per-item responses were the same size, and the API's log shows they were {{.PerItem}} distinct items. The trace holds the route template and the size, not the item, so it cannot tell same-size from same-item, and the repeated-read detector does not read a wildcard route at all. It reads only a route without a wildcard, where the broker admits exactly one path and every call is the same request; an unchanged size there is evidence the data did not change, and the finding says evidence, not proof.</li>
<li><b>This run used the WASM provider</b>, which is process-tier isolation and fine for an example. The advisor is provider-independent: the same broker core records the trace under Docker, E2B and WASM, so the findings do not depend on the tier.</li>
<li><b>The advisor is a work in progress, and off by default.</b> A profile that does not set <code>advice</code> has its traffic left unanalyzed and nothing computed at all; this page had to opt in with <code>advice: caller</code> to produce anything. Two detectors ship today and the rule set is not settled: two earlier ones were removed once it was clear the trace could not support them, because it holds no call start times (so it cannot tell serial calls from concurrent ones) and no guest content (so it cannot tell a client-side reduce from any other loop). Expect the detectors to change.</li>
<li><b>Status:</b> pre-1.0, single author, no external users yet, no third-party security audit. The lesson <a href="{{.LessonURL}}">INTERNAL · trainer site → API Efficiency Advisor</a> walks the same ground with a 128-call example.</li>
</ul>

<footer>Apache-2.0 · This page loads nothing from anywhere: no scripts, styles, fonts or images beyond what is inline. · <a href="{{.LessonsURL}}">INTERNAL · trainer site → plimsollmark.github.io/plimsoll/trainers</a></footer>

<script>
(function () {
  var tabs = document.querySelectorAll('.tabs button');
  tabs.forEach(function (t) {
    t.addEventListener('click', function () {
      tabs.forEach(function (o) { o.setAttribute('aria-selected', o === t ? 'true' : 'false'); });
      document.querySelectorAll('.panel').forEach(function (p) { p.hidden = p.id !== 'run-' + t.dataset.run; });
    });
  });
  document.querySelectorAll('.trace-toggle').forEach(function (b) {
    b.addEventListener('click', function () {
      var on = b.getAttribute('aria-pressed') !== 'true';
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
      b.textContent = on ? 'Show the paths the API saw instead' : "Show what plimsoll's trace holds instead";
      var panel = b.closest('.panel');
      panel.querySelectorAll('.path').forEach(function (c) { c.classList.toggle('hide', on); });
      panel.querySelectorAll('.tmpl').forEach(function (c) { c.classList.toggle('hide', !on); });
    });
  });
})();
</script>
</main></body></html>
`))
