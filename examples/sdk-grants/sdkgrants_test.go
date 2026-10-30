package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
)

const published = "../../docs/examples/sdk-grants"

// The published directory rechecks: the bundle and the statement verify, every file is
// the one the statement names, evidence.json is what they give, every claim the page
// makes holds, and index.html is what the evidence renders.
func TestPublishedFilesVerify(t *testing.T) {
	if err := verifyPublished(published); err != nil {
		t.Fatalf("%v; run go run ./examples/sdk-grants, or -render", err)
	}
	ev, err := loadEvidence(published)
	if err != nil {
		t.Fatal(err)
	}
	// The page's fixed sentences assume these; a rerun that changes one fails here, so
	// the text is reread before it is published.
	want := []string{"records", "dummy-key", "broker-key", "key-not-in-guest", "headers", "stream", "upload", "refusal", "policy", "sockets", "versions", "stub-routes", "audit"}
	if len(ev.Checks) != len(want) {
		t.Fatalf("%d checks, want %d", len(ev.Checks), len(want))
	}
	for i, c := range ev.Checks {
		if c.ID != want[i] || !c.Pass {
			t.Errorf("check %d is %q pass=%v (%s); want %q to pass", i, c.ID, c.Pass, c.Detail, want[i])
		}
	}
	if ev.Stub.Requests != 5 || ev.Stub.DummyKeyHits != 0 || ev.Stub.BrokerKeyOK != 5 {
		t.Errorf("stub summary %+v", ev.Stub)
	}
	d := newPageData(ev)
	if d.Upload.Upload == nil || d.Upload.Upload.Bytes != 8<<20 || d.Upload.Upload.RouteLimit != 16<<20 {
		t.Errorf("upload %+v: the page says 8 MiB on a route raised to 16 MiB", d.Upload.Upload)
	}
	for _, s := range []*streamView{d.OStream.Stream, d.AStream.Stream} {
		if s == nil || s.Compared < 8 || s.FirstToLast < float64(s.Compared-1)*float64(streamGap.Milliseconds())*0.8 {
			t.Errorf("stream %+v: the page says its pieces arrived spread out, one by one", s)
		}
	}

	page, err := os.ReadFile(filepath.Join(published, filePage))
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, m := range regexp.MustCompile(`\sid="([^"]+)"`).FindAllSubmatch(page, -1) {
		if ids[string(m[1])] {
			t.Errorf("id %q appears twice", m[1])
		}
		ids[string(m[1])] = true
	}
	if bytes.Contains(page, []byte("prefers-color-scheme")) {
		t.Error("the page has a dark-mode block")
	}
	if regexp.MustCompile("[\u2013\u2014]| -- ").Match(page) {
		t.Error("the page has a dash used as punctuation")
	}
	// Every link off the site says so in its text, and every glossary link says where it goes.
	for _, m := range regexp.MustCompile(`<a href="([^"]+)">(.*?)</a>`).FindAllSubmatch(page, -1) {
		href, text := string(m[1]), string(m[2])
		switch {
		case strings.HasPrefix(href, "../../trainers/glossary.html#"):
			if !strings.Contains(text, "(INTERNAL · glossary →)") {
				t.Errorf("glossary link %s reads %q", href, text)
			}
		case strings.HasPrefix(href, "https://plimsollmark.github.io/"), !strings.Contains(href, "://"):
		default:
			if !strings.Contains(text, "EXTERNAL · ") || !strings.Contains(text, "↗") {
				t.Errorf("outside link %s reads %q, with no EXTERNAL label", href, text)
			}
		}
	}
}

// A copy with one byte changed anywhere fails to verify: the stub's log, a stored answer
// in the bundle, the evidence, the page.
func TestPublishedFilesRefuseAnyChange(t *testing.T) {
	names := []string{fileBundle, filePub, fileObserved, fileStub, fileGrants, fileDefault, fileVariant, fileEvidence, filePage}
	for _, target := range []string{fileStub, fileBundle, fileVariant, fileGrants, fileEvidence, filePage} {
		dir := t.TempDir()
		for _, name := range names {
			raw, err := os.ReadFile(filepath.Join(published, name))
			if err != nil {
				t.Fatal(err)
			}
			if name == target {
				raw = flipOne(t, raw, target)
			}
			if err := os.WriteFile(filepath.Join(dir, name), raw, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := verifyPublished(dir); err == nil {
			t.Errorf("a copy with one byte of %s changed verified", target)
		}
	}
}

// flipOne changes one byte inside a value the file states, so the file still parses.
func flipOne(t *testing.T, raw []byte, name string) []byte {
	t.Helper()
	marker := map[string]string{
		fileStub: `"body_sha256":"`, fileBundle: `"payload":"`, fileVariant: `"SCMP_ACT_`, fileGrants: `"base_url": "`,
		fileEvidence: `"sha256": "`, filePage: `<h1>`,
	}[name]
	i := bytes.Index(raw, []byte(marker))
	if i < 0 {
		t.Fatalf("%s has no %q", name, marker)
	}
	i += len(marker) + 2
	out := append([]byte{}, raw...)
	if out[i] == 'a' {
		out[i] = 'b'
	} else {
		out[i] = 'a'
	}
	return out
}

// The stream check says no to a stream buffered whole: every piece arriving after the
// stub wrote the last one.
func TestStreamCheckRefusesABufferedStream(t *testing.T) {
	got := &stubRequest{Stream: []streamWrite{{N: 1, WrittenMs: 1000}, {N: 2, WrittenMs: 1400}, {N: 3, WrittenMs: 1800}}}
	var piecewise, buffered guestCall
	for _, at := range []float64{1003, 1404, 1802} {
		piecewise.Pieces = append(piecewise.Pieces, struct {
			AtMs float64 `json:"at_ms"`
			Text *string `json:"text"`
			Type string  `json:"type"`
		}{AtMs: at})
	}
	for _, at := range []float64{1805, 1805.5, 1806} {
		buffered.Pieces = append(buffered.Pieces, struct {
			AtMs float64 `json:"at_ms"`
			Text *string `json:"text"`
			Type string  `json:"type"`
		}{AtMs: at})
	}
	if s := pairStream(piecewise, got); s.Compared != 2 || s.BeforeNext != 2 {
		t.Errorf("piece by piece: %d of %d before the next", s.BeforeNext, s.Compared)
	}
	if s := pairStream(buffered, got); s.BeforeNext != 0 {
		t.Errorf("buffered whole: %d of %d counted as before the next", s.BeforeNext, s.Compared)
	}
}

// The header comparison calls each fate by its name, and a header that reached the API
// without the profile passing it is a finding.
func TestHeaderRowsNameEachFate(t *testing.T) {
	sent := [][2]string{{"Authorization", "Bearer dummy"}, {"anthropic-version", "2026-10-21"}, {"anthropic-beta", "x"}, {"X-Stainless-Lang", "python"}, {"Accept", "application/json"}, {"X-Smuggled", "1"}, {"OpenAI-Project", "p"}}
	received := [][2]string{{"Authorization", "Bearer real"}, {"Anthropic-Version", "2026-10-21"}, {"Accept", "application/json"}, {"X-Smuggled", "1"}, {"Accept-Encoding", "gzip"}}
	want := map[string]string{"authorization": "replaced", "anthropic-version": "passed", "anthropic-beta": "dropped", "x-stainless-lang": "dropped",
		"accept": "same", "x-smuggled": "leaked", "openai-project": "lost", "accept-encoding": "added"}
	rows := headerRows(sent, received, []string{"anthropic-version", "OpenAI-Project"})
	if len(rows) != len(want) {
		t.Fatalf("%d rows: %+v", len(rows), rows)
	}
	for _, r := range rows {
		if got := want[strings.ToLower(r.Name)]; got != r.Fate {
			t.Errorf("%s: fate %q, want %q", r.Name, r.Fate, got)
		}
	}
	altered := headerRows([][2]string{{"anthropic-version", "a"}}, [][2]string{{"Anthropic-Version", "b"}}, []string{"anthropic-version"})
	if altered[0].Fate != "altered" {
		t.Errorf("a passed header changed on the way is %q", altered[0].Fate)
	}
}

// The stub summary finds a dummy key in a header or a body, and refuses a request whose
// credential is not the daemon's.
func TestStubSummaryFindsTheDummyKey(t *testing.T) {
	profiles := map[string]profileView{"openai": {Name: "openai", Allow: []string{"POST /v1/chat/completions"}, SDKEnv: [][2]string{{"OPENAI_API_KEY", "dummy-1"}, {"OPENAI_BASE_URL", "{origin}/v1"}}}}
	keys := map[string]string{"openai": "real-1"}
	clean := stubRequest{API: "openai", Method: "POST", Target: "/v1/chat/completions", Headers: [][2]string{{"Authorization", "Bearer real-1"}}, Body: "{}"}
	if s := summarizeStub([]stubRequest{clean}, profiles, keys); s.DummyKeyHits != 0 || s.BrokerKeyOK != 1 || s.Undeclared != 0 {
		t.Errorf("clean request: %+v", s)
	}
	inHeader := clean
	inHeader.Headers = [][2]string{{"Authorization", "Bearer dummy-1"}}
	inBody := clean
	inBody.Body = `{"key":"dummy-1"}`
	inUpload := clean
	inUpload.Body, inUpload.Markers = "", map[string]int{"dummy-1": 1}
	offList := clean
	offList.Target = "/v1/embeddings"
	s := summarizeStub([]stubRequest{inHeader, inBody, inUpload, offList}, profiles, keys)
	if s.DummyKeyHits != 3 || s.BrokerKeyOK != 3 || s.Undeclared != 1 {
		t.Errorf("leaky requests: %+v; want 3 dummy key hits, 3 of 4 with the daemon's key, 1 off the allow list", s)
	}
}

// The seccomp comparison of the two published profiles finds the IPv4 socket rules and
// the narrowed socket options, and refuses a policy that names other profiles.
func TestSeccompDiffOfThePublishedProfiles(t *testing.T) {
	def, err := os.ReadFile(filepath.Join(published, fileDefault))
	if err != nil {
		t.Fatal(err)
	}
	vari, err := os.ReadFile(filepath.Join(published, fileVariant))
	if err != nil {
		t.Fatal(err)
	}
	policy := "seccomp:sha256:" + sha256Hex(def) + " sdk_env:seccomp:sha256:" + sha256Hex(vari)
	sv, err := diffSeccomp(def, vari, policy)
	if err != nil {
		t.Fatal(err)
	}
	added := map[string]int{}
	for _, r := range sv.Added {
		added[r.Syscall]++
	}
	if added["socket"] != 2 || added["setsockopt"] != 6 || added["getsockopt"] != 2 || len(sv.Added) != 10 {
		t.Errorf("added %v (%d rules)", added, len(sv.Added))
	}
	removed := map[string]string{}
	for _, r := range sv.Removed {
		removed[r.Syscall] = r.Args
	}
	if len(removed) != 2 || removed["setsockopt"] != "" || removed["getsockopt"] != "" {
		t.Errorf("removed %v; want setsockopt and getsockopt with any arguments", removed)
	}
	if _, err := diffSeccomp(def, vari, "seccomp:sha256:"+sha256Hex(def)); err == nil {
		t.Error("a policy naming no variant was accepted")
	}
	if _, err := diffSeccomp(def, def, policy); err == nil {
		t.Error("the default published as the variant was accepted")
	}
}

// TestDeriveRefusesOtherGuestCode: the page's socket, version, stream and sent-header
// claims are the guest code's own report, so derive takes a run only when its signed
// request carries this program's main.py and report.py byte for byte and its one step: a
// report.py edited to print what the reader wants to see must not derive (release
// release review, 2026-10-29).
func TestDeriveRefusesOtherGuestCode(t *testing.T) {
	req := func(files map[string]string, steps []string) *plimsollv1.RunRequest {
		var fs []*plimsollv1.ProjectFile
		for _, name := range []string{"main.py", "report.py", "extra.py"} {
			if body, ok := files[name]; ok {
				fs = append(fs, &plimsollv1.ProjectFile{Path: name, Content: body})
			}
		}
		return &plimsollv1.RunRequest{Payload: &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{Files: fs, Steps: steps}}}
	}
	own := map[string]string{"main.py": guestOpenAI, "report.py": guestReport}
	if err := checkGuestCode("openai", req(own, guestSteps)); err != nil {
		t.Fatalf("this program's own code: %v", err)
	}
	for name, r := range map[string]*plimsollv1.RunRequest{
		"report.py one byte off":    req(map[string]string{"main.py": guestOpenAI, "report.py": guestReport + " "}, guestSteps),
		"another run's main.py":     req(map[string]string{"main.py": guestAnthropic, "report.py": guestReport}, guestSteps),
		"a file more":               req(map[string]string{"main.py": guestOpenAI, "report.py": guestReport, "extra.py": ""}, guestSteps),
		"report.py missing":         req(map[string]string{"main.py": guestOpenAI}, guestSteps),
		"another step":              req(own, []string{"python3 -c 'print(1)'"}),
		"no project in the request": {},
	} {
		if err := checkGuestCode("openai", r); err == nil {
			t.Errorf("%s: derived", name)
		}
	}
}
