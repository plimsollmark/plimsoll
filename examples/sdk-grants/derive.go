package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/plimsollmark/plimsoll/attest"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// derive reads the published raw files in dir, checks the signatures and digests that
// bind them, and computes everything the page states. The run calls it on what it just
// wrote and -verify calls it again, so the page has one source.
func derive(dir string) (*evidence, error) {
	read := func(name string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, name)) }
	pubPEM, err := read(filePub)
	if err != nil {
		return nil, err
	}
	pub, err := attest.ParsePublicKey(pubPEM)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filePub, err)
	}
	v := attest.NewVerifier(pub)
	bundleRaw, err := read(fileBundle)
	if err != nil {
		return nil, err
	}
	entries, err := attest.ReadBundle(bytes.NewReader(bundleRaw))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fileBundle, err)
	}
	rep, err := attest.VerifyBundle(entries, v)
	if err != nil {
		return nil, fmt.Errorf("%s does not verify: %w", fileBundle, err)
	}
	type call struct {
		rec  sandbox.RunRecord
		req  *plimsollv1.RunRequest
		resp *plimsollv1.RunResponse
		raw  [][]byte
	}
	calls := map[string]call{}
	for _, e := range entries {
		if len(e.Request) == 0 {
			continue
		}
		rec, err := v.Verify(e.Envelope)
		if err != nil {
			return nil, err
		}
		req, resp, err := e.Messages()
		if err != nil {
			return nil, err
		}
		calls[rec.SHA256] = call{rec: rec, req: req, resp: resp, raw: [][]byte{e.Request, e.Response}}
	}

	envRaw, err := read(fileObserved)
	if err != nil {
		return nil, err
	}
	var env attest.Envelope
	if err := json.Unmarshal(envRaw, &env); err != nil {
		return nil, fmt.Errorf("%s: %w", fileObserved, err)
	}
	var obs observations
	subjects, err := v.OpenStatement(env, observationsType, &obs)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fileObserved, err)
	}
	if len(subjects) != len(obs.Runs) || rep.Runs != len(obs.Runs) || len(calls) != len(obs.Runs) {
		return nil, fmt.Errorf("the statement names %d records for %d runs; the bundle holds %d runs", len(subjects), len(obs.Runs), rep.Runs)
	}
	for i, r := range obs.Runs {
		if subjects[i].Digest["sha256"] != r.Record {
			return nil, fmt.Errorf("the statement's subject %d is not run %s's record", i+1, r.Name)
		}
		if _, ok := calls[r.Record]; !ok {
			return nil, fmt.Errorf("run %s's record %s is not in the bundle", r.Name, r.Record)
		}
	}
	raw := map[string][]byte{}
	ev := &evidence{Date: obs.Date, Commit: obs.Commit, KeyID: attest.KeyID(pub), Daemon: obs.Daemon, Image: obs.Image, Pins: obs.Pins}
	for _, name := range []string{fileBundle, filePub, fileObserved, fileStub, fileGrants, fileDefault, fileVariant} {
		b, err := read(name)
		if err != nil {
			return nil, err
		}
		raw[name] = b
		ev.Files = append(ev.Files, fileView{Name: name, Bytes: len(b), SHA256: sha256Hex(b)})
	}
	for _, name := range hashedFiles {
		if got := sha256Hex(raw[name]); got != obs.Files[name] {
			return nil, fmt.Errorf("%s has SHA-256 %s; the signed statement names %s", name, got, obs.Files[name])
		}
	}

	profiles, err := readProfiles(raw[fileGrants])
	if err != nil {
		return nil, err
	}
	ev.Profiles = profiles
	byProfile := map[string]profileView{}
	for _, p := range profiles {
		byProfile[p.Name] = p
	}
	if ev.Seccomp, err = diffSeccomp(raw[fileDefault], raw[fileVariant], obs.Daemon.Policy); err != nil {
		return nil, err
	}
	var stubReqs []stubRequest
	dec := json.NewDecoder(bytes.NewReader(raw[fileStub]))
	dec.DisallowUnknownFields()
	for dec.More() {
		var r stubRequest
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("%s: %w", fileStub, err)
		}
		stubReqs = append(stubReqs, r)
	}
	ev.Stub = summarizeStub(stubReqs, byProfile, obs.Keys)

	byAPI := map[string][]stubRequest{}
	for _, r := range stubReqs {
		byAPI[r.API] = append(byAPI[r.API], r)
	}
	for _, rf := range obs.Runs {
		c := calls[rf.Record]
		if err := checkGuestCode(rf.Name, c.req); err != nil {
			return nil, fmt.Errorf("run %s: %w", rf.Name, err)
		}
		rv, err := deriveRun(rf, c.rec, c.resp, c.raw, byProfile[rf.Profile], byAPI[rf.Profile], obs)
		if err != nil {
			return nil, fmt.Errorf("run %s: %w", rf.Name, err)
		}
		ev.Runs = append(ev.Runs, rv)
	}
	ev.Checks = checks(ev, rep)
	return ev, nil
}

// guestDoc is what a guest program printed (report.py).
type guestDoc struct {
	Python      string            `json:"python"`
	SDKs        map[string]string `json:"sdks"`
	Environment map[string]string `json:"environment"`
	Processes   []struct {
		PID     int      `json:"pid"`
		Cmdline string   `json:"cmdline"`
		Environ []string `json:"environ"`
		Error   string   `json:"error"`
	} `json:"processes"`
	Sockets map[string]string    `json:"sockets"`
	Calls   map[string]guestCall `json:"calls"`
}

type guestCall struct {
	URL         string      `json:"url"`
	Sent        [][2]string `json:"sent"`
	Status      int         `json:"status"`
	Answer      string      `json:"answer"`
	ContentType string      `json:"content_type"`
	StartedMs   float64     `json:"started_ms"`
	Pieces      []struct {
		AtMs float64 `json:"at_ms"`
		Text *string `json:"text"`
		Type string  `json:"type"`
	} `json:"pieces"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256"`
	FileID      string `json:"file_id"`
	APIBytes    int64  `json:"api_bytes"`
	Error       string `json:"error"`
	ShouldRetry string `json:"x_should_retry"`
	Body        string `json:"body"`
}

var runTitles = map[string]string{
	"openai":    "The OpenAI library",
	"anthropic": "The Anthropic library",
	"plain":     "The control run: no grant",
}

// callPlan is the calls each run makes, in order, and the title the page gives each.
var callPlan = map[string][][2]string{
	"openai":    {{"chat", "A chat call"}, {"stream", "The same call, streamed"}, {"upload", "An 8 MiB file upload"}, {"refused", "A route the profile does not allow"}},
	"anthropic": {{"messages", "A messages call"}, {"stream", "The same call, streamed"}},
	"plain":     {},
}

// checkGuestCode: the request a run's record signs carries exactly this program's guest
// code, main.py and report.py byte for byte, and its one step. The page's socket, version,
// stream timing and sent-header claims are that code's report from inside the sandbox, so
// a run of other code must not derive (release review, 2026-10-29).
func checkGuestCode(name string, req *plimsollv1.RunRequest) error {
	i := slices.IndexFunc(guestRuns, func(g guestRun) bool { return g.name == name })
	if i < 0 {
		return fmt.Errorf("no guest run is named %q", name)
	}
	want := map[string]string{"main.py": guestRuns[i].main, "report.py": guestReport}
	files := req.GetProject().GetFiles()
	if len(files) != len(want) {
		return fmt.Errorf("the signed request carries %d files; this program sends %d", len(files), len(want))
	}
	for _, f := range files {
		if w, ok := want[f.GetPath()]; !ok || f.GetContent() != w {
			return fmt.Errorf("the signed request's %s is not this program's guest code", f.GetPath())
		}
		delete(want, f.GetPath())
	}
	if steps := req.GetProject().GetSteps(); !slices.Equal(steps, guestSteps) {
		return fmt.Errorf("the signed request's steps are %q; this program's are %q", steps, guestSteps)
	}
	return nil
}

func deriveRun(rf runFacts, rec sandbox.RunRecord, resp *plimsollv1.RunResponse, stored [][]byte, prof profileView, stubbed []stubRequest, obs observations) (runView, error) {
	rv := runView{Name: rf.Name, Title: runTitles[rf.Name], Profile: rf.Profile, TraceID: rf.TraceID, Audit: rf.Audit,
		Record: recordView{SHA256: rec.SHA256, Request: rec.RequestSHA256, Result: rec.ResultSHA256, Provider: rec.Provider,
			Isolation: rec.Isolation, Environment: rec.Environment, Policy: rec.Policy,
			StartedMs: rec.Started.UnixMilli(), EndedMs: rec.Ended.UnixMilli()}}
	pr := resp.GetProject()
	if pr == nil || len(pr.GetSteps()) != 1 {
		return rv, errors.New("the stored answer is not a one-step project result")
	}
	step := pr.GetSteps()[0]
	rv.Outcome, rv.ExitCode = pr.GetOutcome().String(), int(step.GetExitCode())
	var g guestDoc
	if err := json.Unmarshal(bytes.TrimSpace(step.GetStdout()), &g); err != nil {
		return rv, fmt.Errorf("the guest's output is not its JSON report: %w", err)
	}
	rv.Python, rv.SDKs, rv.Sockets = g.Python, g.SDKs, g.Sockets
	for _, k := range sortedKeys(g.Environment) {
		rv.Environment = append(rv.Environment, [2]string{k, g.Environment[k]})
	}
	for _, kv := range prof.SDKEnv {
		rv.SDKEnv = append(rv.SDKEnv, [2]string{kv[0], g.Environment[kv[0]]})
	}
	for _, p := range g.Processes {
		if p.Error != "" {
			rv.Unreadable++
			words := strings.Fields(p.Cmdline)
			if len(words) > 2 {
				words = words[:2]
			}
			rv.Refused = append(rv.Refused, fmt.Sprintf("pid %d, %s (%s)", p.PID, strings.Join(words, " "), p.Error))
		} else {
			rv.Processes++
		}
	}
	for _, k := range obs.Keys {
		for _, b := range stored {
			rv.KeyInGuest += bytes.Count(b, []byte(k))
		}
	}
	for _, m := range obs.Metrics {
		if m.Profile == rf.Profile && rf.Profile != "" {
			rv.Metrics = append(rv.Metrics, m)
		}
	}
	switch rec.Policy {
	case strings.Fields(obs.Daemon.Policy)[0]:
		rv.PolicyIs = "default"
	case strings.TrimPrefix(strings.Fields(obs.Daemon.Policy)[1], "sdk_env:"):
		rv.PolicyIs = "variant"
	default:
		rv.PolicyIs = "neither"
	}
	rv.StubRequests = len(stubbed)
	next := 0
	for _, c := range callPlan[rf.Name] {
		gc, ok := g.Calls[c[0]]
		if !ok {
			return rv, fmt.Errorf("the guest reported no %s call", c[0])
		}
		cv := callView{Name: c[0], Title: c[1], URL: gc.URL, Status: gc.Status, Answer: gc.Answer}
		u, err := url.Parse(gc.URL)
		if err != nil {
			return rv, err
		}
		var got *stubRequest
		for i := next; i < len(stubbed); i++ {
			if strings.SplitN(stubbed[i].Target, "?", 2)[0] == u.Path {
				got, next = &stubbed[i], i+1
				break
			}
		}
		if got != nil && (got.ReceivedMs < float64(rec.Started.UnixMilli()) || got.ReceivedMs > float64(rec.Ended.UnixMilli())+1) {
			return rv, fmt.Errorf("the stub's request for %s was received outside the run's record times", c[0])
		}
		var received [][2]string
		if got != nil {
			cv.Reached, cv.Target, received = true, got.Target, got.Headers
		}
		cv.Headers = headerRows(gc.Sent, received, prof.PassHeaders)
		switch {
		case c[0] == "stream":
			sv := pairStream(gc, got)
			cv.Stream = &sv
		case c[0] == "upload":
			up := &uploadView{Bytes: gc.Bytes, GuestSHA256: gc.SHA256, FileID: gc.FileID, RouteLimit: prof.RouteBytes["POST /v1/files"]}
			if got != nil {
				up.BodyBytes, up.Parts = got.BodyBytes, got.Parts
				for _, p := range got.Parts {
					if p.Name == "file" {
						up.StubSHA256 = p.SHA256
					}
				}
			}
			cv.Upload = up
		case c[0] == "refused":
			ref := &refusalView{Error: gc.Error, Status: gc.Status, ShouldRetry: gc.ShouldRetry, Body: gc.Body, RetryCount: headerValue(gc.Sent, "x-stainless-retry-count")}
			for _, s := range stubbed {
				if strings.SplitN(s.Target, "?", 2)[0] == u.Path {
					ref.StubAtRoute++
				}
			}
			cv.Refusal = ref
		}
		rv.Calls = append(rv.Calls, cv)
	}
	return rv, nil
}

// pairStream pairs each piece the guest's library handed over with the stub's write of
// it, times measured from the stub's first write (one clock: the guest and the stub run on
// the same Linux kernel, whose wall clock a container shares).
func pairStream(gc guestCall, got *stubRequest) streamView {
	sv := streamView{ContentType: gc.ContentType}
	if got == nil || len(got.Stream) == 0 {
		return sv
	}
	t0 := got.Stream[0].WrittenMs
	for i, p := range gc.Pieces {
		pv := pieceView{N: i + 1, ArrivedMs: p.AtMs - t0}
		// What the library handed over, labeled as the stub labels its write: the chunk's
		// text (OpenAI), or the event's type and any text (Anthropic).
		label := p.Type
		if p.Text != nil && *p.Text != "" {
			if label != "" {
				label += ": "
			}
			label += *p.Text
		}
		if i < len(got.Stream) {
			pv.WrittenMs, pv.Event = got.Stream[i].WrittenMs-t0, got.Stream[i].Event
			if label == pv.Event {
				sv.Matched++
			}
		}
		if i+1 < len(got.Stream) {
			pv.NextMs = got.Stream[i+1].WrittenMs - t0
			sv.Compared++
			if pv.ArrivedMs < pv.NextMs {
				sv.BeforeNext++
			}
		}
		if d := pv.ArrivedMs - pv.WrittenMs; d > sv.MaxDelay {
			sv.MaxDelay = d
		}
		sv.Pieces = append(sv.Pieces, pv)
	}
	if n := len(sv.Pieces); n > 0 {
		sv.FirstToLast = sv.Pieces[n-1].ArrivedMs - sv.Pieces[0].ArrivedMs
	}
	sv.WrittenSpan = got.Stream[len(got.Stream)-1].WrittenMs - t0
	for i := len(gc.Pieces); i < len(got.Stream); i++ {
		sv.Unpaired = append(sv.Unpaired, pieceView{N: i + 1, Event: got.Stream[i].Event, WrittenMs: got.Stream[i].WrittenMs - t0})
	}
	return sv
}

// brokerOwned are the headers the broker or its transport sets on every request it makes,
// whatever the guest sent: the library's value is replaced, or matched by coincidence.
var brokerOwned = map[string]bool{"host": true, "authorization": true, "content-type": true, "content-length": true,
	"accept": true, "accept-encoding": true, "user-agent": true, "transfer-encoding": true, "connection": true}

func headerRows(sent, received [][2]string, pass []string) []headerRow {
	passed := map[string]bool{}
	for _, p := range pass {
		passed[strings.ToLower(p)] = true
	}
	type vals struct {
		name string
		v    []string
	}
	collect := func(hs [][2]string) (map[string]*vals, []string) {
		m := map[string]*vals{}
		var order []string
		for _, h := range hs {
			k := strings.ToLower(h[0])
			if m[k] == nil {
				m[k] = &vals{name: h[0]}
				order = append(order, k)
			}
			m[k].v = append(m[k].v, h[1])
		}
		return m, order
	}
	s, sOrder := collect(sent)
	r, rOrder := collect(received)
	var rows []headerRow
	add := func(k string) {
		row := headerRow{}
		if s[k] != nil {
			row.Name, row.Sent = s[k].name, strings.Join(s[k].v, ", ")
		}
		if r[k] != nil {
			if row.Name == "" {
				row.Name = r[k].name
			}
			row.Received = strings.Join(r[k].v, ", ")
		}
		switch {
		case s[k] != nil && r[k] != nil && passed[k]:
			row.Fate = "passed"
			if row.Sent != row.Received {
				row.Fate = "altered"
			}
		case s[k] != nil && r[k] != nil && brokerOwned[k]:
			row.Fate = "replaced"
			if row.Sent == row.Received {
				row.Fate = "same"
			}
		case s[k] != nil && r[k] != nil:
			row.Fate = "leaked"
		case s[k] != nil && passed[k]:
			row.Fate = "lost"
		case s[k] != nil:
			row.Fate = "dropped"
		default:
			row.Fate = "added"
		}
		rows = append(rows, row)
	}
	for _, k := range sOrder {
		add(k)
	}
	for _, k := range rOrder {
		if s[k] == nil {
			add(k)
		}
	}
	return rows
}

func headerValue(hs [][2]string, name string) string {
	for _, h := range hs {
		if strings.EqualFold(h[0], name) {
			return h[1]
		}
	}
	return ""
}

func summarizeStub(reqs []stubRequest, profiles map[string]profileView, keys map[string]string) stubSummary {
	var s stubSummary
	var dummies []string
	for _, p := range profiles {
		for _, kv := range p.SDKEnv {
			if strings.HasSuffix(kv[0], "_API_KEY") {
				dummies = append(dummies, kv[1])
			}
		}
	}
	sort.Strings(dummies)
	for _, r := range reqs {
		s.Requests++
		for _, d := range dummies {
			for _, h := range r.Headers {
				s.DummyKeyHits += strings.Count(h[0]+": "+h[1], d)
			}
			s.DummyKeyHits += strings.Count(r.Body, d) + strings.Count(r.Target, d)
			if r.Body == "" {
				s.DummyKeyHits += r.Markers[d]
			}
		}
		if headerValue(r.Headers, "Authorization") == "Bearer "+keys[r.API] {
			s.BrokerKeyOK++
		}
		allowed := false
		for _, a := range profiles[r.API].Allow {
			if a == r.Method+" "+strings.SplitN(r.Target, "?", 2)[0] {
				allowed = true
			}
		}
		if !allowed {
			s.Undeclared++
		}
	}
	return s
}

// readProfiles reads grants.json into the fields the page shows, in a fixed order.
func readProfiles(raw []byte) ([]profileView, error) {
	var file struct {
		Profiles map[string]struct {
			BaseURL     string              `json:"base_url"`
			Allow       []string            `json:"allow"`
			PassHeaders []string            `json:"pass_headers"`
			SDKEnv      map[string]string   `json:"sdk_env"`
			RouteBytes  map[string]int64    `json:"route_max_request_bytes"`
			RouteTypes  map[string][]string `json:"route_content_types"`
			MaxRequest  int64               `json:"max_request_bytes"`
			Callers     []string            `json:"allowed_callers"`
			Token       struct {
				Type string `json:"type"`
				Env  string `json:"env"`
			} `json:"token"`
		} `json:"profiles"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("%s: %w", fileGrants, err)
	}
	var out []profileView
	for _, name := range sortedKeys(file.Profiles) {
		p := file.Profiles[name]
		pv := profileView{Name: name, BaseURL: p.BaseURL, Allow: p.Allow, PassHeaders: p.PassHeaders, RouteBytes: p.RouteBytes, RouteTypes: p.RouteTypes, MaxRequest: p.MaxRequest, TokenEnv: p.Token.Env, Callers: p.Callers}
		for _, k := range sortedKeys(p.SDKEnv) {
			pv.SDKEnv = append(pv.SDKEnv, [2]string{k, p.SDKEnv[k]})
		}
		out = append(out, pv)
	}
	return out, nil
}

// diffSeccomp names both profiles by digest, checks them against the daemon's stated
// policy, and lists the allow rules the variant adds and removes, one syscall at a time.
func diffSeccomp(defaultRaw, variantRaw []byte, policy string) (seccompView, error) {
	sv := seccompView{Default: "seccomp:sha256:" + sha256Hex(defaultRaw), Variant: "seccomp:sha256:" + sha256Hex(variantRaw), DefaultBytes: len(defaultRaw), VariantBytes: len(variantRaw)}
	if want := sv.Default + " sdk_env:" + sv.Variant; policy != want {
		return sv, fmt.Errorf("the daemon's policy %q is not the two published profiles' (%s)", policy, want)
	}
	flatten := func(raw []byte) (map[string]seccompRule, error) {
		var doc struct {
			Syscalls []map[string]any `json:"syscalls"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
		out := map[string]seccompRule{}
		for _, rule := range doc.Syscalls {
			names, _ := rule["names"].([]any)
			comment, _ := rule["//"].(string)
			rest := map[string]any{}
			for k, v := range rule {
				if k != "names" && !strings.HasPrefix(k, "//") && k != "comment" { // comments are "//", "//1", ...
					rest[k] = v
				}
			}
			canon, err := json.Marshal(rest)
			if err != nil {
				return nil, err
			}
			action, _ := rule["action"].(string)
			for _, n := range names {
				name, _ := n.(string)
				out[name+" "+string(canon)] = seccompRule{Syscall: name, Action: action, Args: describeArgs(rule), Comment: comment}
			}
		}
		return out, nil
	}
	def, err := flatten(defaultRaw)
	if err != nil {
		return sv, fmt.Errorf("%s: %w", fileDefault, err)
	}
	vari, err := flatten(variantRaw)
	if err != nil {
		return sv, fmt.Errorf("%s: %w", fileVariant, err)
	}
	for _, k := range sortedKeys(vari) {
		if _, ok := def[k]; ok {
			sv.Unchanged++
		} else {
			sv.Added = append(sv.Added, vari[k])
		}
	}
	for _, k := range sortedKeys(def) {
		if _, ok := vari[k]; !ok {
			r := def[k]
			r.Comment = ""
			sv.Removed = append(sv.Removed, r)
		}
	}
	return sv, nil
}

func describeArgs(rule map[string]any) string {
	args, _ := rule["args"].([]any)
	var parts []string
	for _, a := range args {
		m, _ := a.(map[string]any)
		idx, _ := m["index"].(float64)
		val, _ := m["value"].(float64)
		two, _ := m["valueTwo"].(float64)
		switch m["op"] {
		case "SCMP_CMP_EQ":
			parts = append(parts, fmt.Sprintf("arg%d == %d", int(idx), uint64(val)))
		case "SCMP_CMP_MASKED_EQ":
			parts = append(parts, fmt.Sprintf("arg%d & 0x%x == %d", int(idx), uint64(val), uint64(two)))
		default:
			parts = append(parts, fmt.Sprintf("arg%d %v %d", int(idx), m["op"], uint64(val)))
		}
	}
	for _, k := range []string{"includes", "excludes", "errnoRet"} {
		if x, ok := rule[k]; ok {
			b, _ := json.Marshal(x)
			parts = append(parts, k+" "+string(b))
		}
	}
	return strings.Join(parts, ", ")
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// The claims the page makes, each computed from the evidence. A rerun whose evidence does
// not support one fails the program, and the test fails on a published page whose
// evidence does not.
func checks(ev *evidence, rep attest.Report) []check {
	run := func(name string) *runView {
		for i := range ev.Runs {
			if ev.Runs[i].Name == name {
				return &ev.Runs[i]
			}
		}
		return &runView{}
	}
	callOf := func(r *runView, name string) *callView {
		for i := range r.Calls {
			if r.Calls[i].Name == name {
				return &r.Calls[i]
			}
		}
		return &callView{}
	}
	oa, an, pl := run("openai"), run("anthropic"), run("plain")
	var out []check
	add := func(id, says string, pass bool, detail string, args ...any) {
		out = append(out, check{ID: id, Says: says, Pass: pass, Detail: fmt.Sprintf(detail, args...)})
	}
	add("records", "Every run's record is signed by the harness and checks against the request and answer stored with it.",
		rep.Runs == 3 && len(rep.Sessions) == 0, "%d single runs verified, %d sessions", rep.Runs, len(rep.Sessions))
	add("dummy-key", "No request the API received carried the guest's dummy key, in a header or in a body.",
		ev.Stub.DummyKeyHits == 0 && ev.Stub.Requests > 0, "%d occurrences in %d requests", ev.Stub.DummyKeyHits, ev.Stub.Requests)
	add("broker-key", "Every request the API received carried the key the daemon holds for that API.",
		ev.Stub.BrokerKeyOK == ev.Stub.Requests && ev.Stub.Requests > 0, "%d of %d requests", ev.Stub.BrokerKeyOK, ev.Stub.Requests)
	keyHits, procs := 0, 0
	for _, r := range ev.Runs {
		keyHits += r.KeyInGuest
		procs += r.Processes
	}
	add("key-not-in-guest", "The keys the daemon holds appear nowhere in what each run was sent or answered: not in its environment, not in any process environment the guest could read, not in its output.",
		keyHits == 0 && procs > 0, "%d occurrences; %d process environments read", keyHits, procs)
	var bad []string
	for _, r := range ev.Runs {
		for _, c := range r.Calls {
			for _, h := range c.Headers {
				if h.Fate == "leaked" || h.Fate == "altered" || h.Fate == "lost" {
					bad = append(bad, r.Name+" "+c.Name+" "+h.Name+" "+h.Fate)
				}
			}
		}
	}
	org, beta, version := fate(callOf(oa, "chat"), "openai-organization"), fate(callOf(an, "messages"), "anthropic-beta"), fate(callOf(an, "messages"), "anthropic-version")
	add("headers", "Of the guest's headers, only the one the profile passes reached the API; the broker set its own credential and transport headers.",
		len(bad) == 0 && org == "dropped" && beta == "dropped" && version == "passed",
		"OpenAI-Organization %s, anthropic-beta %s, anthropic-version %s; %d headers leaked, altered or lost%s", org, beta, version, len(bad), listed(bad))
	streamOK, streamDetail := true, ""
	for _, r := range []*runView{oa, an} {
		s := callOf(r, "stream").Stream
		if s == nil || s.Compared == 0 || s.BeforeNext != s.Compared || s.Matched != len(s.Pieces) || !strings.HasPrefix(s.ContentType, "text/event-stream") {
			streamOK = false
		}
		if s != nil {
			streamDetail += fmt.Sprintf("%s: %d of %d pieces before the next was written, %d of %d matching the stub's, first to last %.0f ms; ", r.Name, s.BeforeNext, s.Compared, s.Matched, len(s.Pieces), s.FirstToLast)
		}
	}
	add("stream", "Each piece of both streamed answers reached the guest's library before the stub wrote the next one.", streamOK, "%s", strings.TrimSuffix(streamDetail, "; "))
	up := callOf(oa, "upload").Upload
	upOK := up != nil && up.GuestSHA256 != "" && up.GuestSHA256 == up.StubSHA256 && up.Bytes == 8<<20 && up.Bytes > 1<<20
	add("upload", "The 8 MiB upload reached the API byte for byte, on a route raised above the 1 MiB default.", upOK, "guest %s, stub %s", shortHex(upSHA(up, true)), shortHex(upSHA(up, false)))
	ref := callOf(oa, "refused")
	refOK := ref.Refusal != nil && !ref.Reached && ref.Refusal.Status == 403 && ref.Refusal.ShouldRetry == "false" && ref.Refusal.StubAtRoute == 0 && oa.Audit.HostCallsDenied == 1 && ref.Refusal.RetryCount == "0"
	add("refusal", "The call to a route the profile does not allow was refused by the broker, marked not to retry, made once, and never reached the API.", refOK,
		"status %d, X-Should-Retry %q, retry count %q, %d requests at the route, %d denied on the audit line", refStatus(ref), refField(ref, "retry"), refField(ref, "count"), refAt(ref), oa.Audit.HostCallsDenied)
	add("policy", "The two runs whose grant sets sdk_env ran under the derived variant, the control run under the default, each named by digest in its record.",
		oa.PolicyIs == "variant" && an.PolicyIs == "variant" && pl.PolicyIs == "default" && oa.Record.Policy == ev.Seccomp.Variant && pl.Record.Policy == ev.Seccomp.Default,
		"openai %s, anthropic %s, plain %s", oa.PolicyIs, an.PolicyIs, pl.PolicyIs)
	sockOK := true
	for _, r := range []*runView{oa, an} {
		sockOK = sockOK && r.Sockets["ipv4_tcp"] == "allowed" && strings.HasPrefix(r.Sockets["ipv4_udp"], "PermissionError") &&
			strings.HasPrefix(r.Sockets["ipv6_tcp"], "PermissionError") && strings.Contains(r.Sockets["outside_address"], "errno 101")
	}
	sockOK = sockOK && strings.HasPrefix(pl.Sockets["ipv4_tcp"], "PermissionError") && strings.HasPrefix(pl.Sockets["outside_address"], "PermissionError")
	add("sockets", "Under the variant an IPv4 TCP socket opens and a UDP or IPv6 socket does not, and an outside address is unreachable; under the default no IPv4 socket opens.",
		sockOK, "openai %s; anthropic %s; control %s", sockSummary(oa.Sockets), sockSummary(an.Sockets), sockSummary(pl.Sockets))
	pins := map[string]string{}
	for _, p := range ev.Pins {
		pins[p.Name] = p.Version
	}
	add("versions", "The guest imported the pinned versions of both libraries.",
		oa.SDKs["openai"] != "" && oa.SDKs["openai"] == pins["openai"] && an.SDKs["anthropic"] != "" && an.SDKs["anthropic"] == pins["anthropic"],
		"openai %s (pinned %s), anthropic %s (pinned %s)", oa.SDKs["openai"], pins["openai"], an.SDKs["anthropic"], pins["anthropic"])
	add("stub-routes", "The stub received only calls on routes the profiles allow: three from the OpenAI run, two from the Anthropic run, none from the control run.",
		ev.Stub.Undeclared == 0 && oa.StubRequests == 3 && an.StubRequests == 2 && pl.StubRequests == 0,
		"%d off the allow lists; %d, %d and %d", ev.Stub.Undeclared, oa.StubRequests, an.StubRequests, pl.StubRequests)
	add("audit", "The daemon's audit line for each run counts the calls the stub received, and the one refusal.",
		oa.Audit.HostCalls == oa.StubRequests && an.Audit.HostCalls == an.StubRequests && oa.Audit.HostCallsDenied == 1 && an.Audit.HostCallsDenied == 0 && pl.Audit.HostCalls == 0,
		"openai %d calls %d denied; anthropic %d and %d; plain %d", oa.Audit.HostCalls, oa.Audit.HostCallsDenied, an.Audit.HostCalls, an.Audit.HostCallsDenied, pl.Audit.HostCalls)
	return out
}

// sockSummary writes what one guest's socket attempts got, in a fixed order.
func sockSummary(m map[string]string) string {
	var parts []string
	for _, k := range [][2]string{{"ipv4_tcp", "IPv4 TCP"}, {"ipv4_udp", "UDP"}, {"ipv6_tcp", "IPv6"}, {"outside_address", "outside address"}} {
		v := m[k[0]]
		if i := strings.Index(v, "errno "); i >= 0 {
			v = strings.SplitN(v[i:], ",", 2)[0]
		}
		parts = append(parts, k[1]+" "+v)
	}
	return strings.Join(parts, ", ")
}

func listed(items []string) string {
	if len(items) == 0 {
		return ""
	}
	return ": " + strings.Join(items, "; ")
}

func fate(c *callView, name string) string {
	for _, h := range c.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Fate
		}
	}
	return "absent"
}

func upSHA(u *uploadView, guest bool) string {
	if u == nil {
		return ""
	}
	if guest {
		return u.GuestSHA256
	}
	return u.StubSHA256
}

func shortHex(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

func refStatus(c *callView) int {
	if c.Refusal == nil {
		return 0
	}
	return c.Refusal.Status
}

func refAt(c *callView) int {
	if c.Refusal == nil {
		return -1
	}
	return c.Refusal.StubAtRoute
}

func refField(c *callView, which string) string {
	if c.Refusal == nil {
		return ""
	}
	if which == "retry" {
		return c.Refusal.ShouldRetry
	}
	return c.Refusal.RetryCount
}
