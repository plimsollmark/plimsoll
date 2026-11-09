package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Every test here uses the local stub and canary keys. realAPIs reach no test: the only caller
// that passes them is main, behind the -live flag.

// The budget arithmetic is the plan's, and a run that could pass it starts nothing, not even
// the look at its keys.
func TestLiveBudgetRefusesBeforeAnythingStarts(t *testing.T) {
	if got := liveWorstCase(realAPIs); math.Abs(got-0.00012672) > 1e-9 {
		t.Errorf("worst case $%.8f; the plan's arithmetic gives $0.00012672", got)
	}
	if err := checkLiveBudget(realAPIs); err != nil {
		t.Fatal(err)
	}
	dear := append([]liveAPI{}, realAPIs...)
	dear[0].PriceOut = 1e5 // 2 calls of 64 tokens at $100,000 a million is $12.80
	work := filepath.Join(t.TempDir(), "work")
	t.Setenv("NEBIUS_API_KEY", "")
	err := runLive(context.Background(), liveConfig{work: work, apis: dear, console: os.Stdout})
	if err == nil || !strings.Contains(err.Error(), "over the $0.25 budget") {
		t.Fatalf("a run over budget: %v", err)
	}
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Error("a run over budget touched its work directory")
	}
}

// A missing key starts nothing.
func TestLiveNeedsBothKeys(t *testing.T) {
	t.Setenv("NEBIUS_API_KEY", "a")
	t.Setenv("ANTHROPIC_API_KEY", "")
	work := filepath.Join(t.TempDir(), "work")
	err := runLive(context.Background(), liveConfig{work: work, apis: realAPIs, console: os.Stdout})
	if err == nil || !strings.Contains(err.Error(), "ANTHROPIC_API_KEY is not set") {
		t.Fatalf("no key: %v", err)
	}
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Error("a run with no key touched its work directory")
	}
}

// The guest code is held to the numbers the budget check uses: a higher token limit, a retry, a
// third paid call or another model in the guest fails here.
func TestLiveGuestCodeIsHeldToTheBudget(t *testing.T) {
	limit := regexp.MustCompile(`(?m)^MAX_TOKENS = (\d+)$`)
	prompt := regexp.MustCompile(`(?m)^PROMPT = "([^"]*)"$`)
	model := regexp.MustCompile(`(?m)^MODEL = "([^"]*)"$`)
	for _, a := range realAPIs {
		if n, _ := strconv.Atoi(limit.FindStringSubmatch(a.Main)[1]); n != liveMaxTokens {
			t.Errorf("%s: MAX_TOKENS is %d, the check uses %d", a.Name, n, liveMaxTokens)
		}
		if p := prompt.FindStringSubmatch(a.Main)[1]; len(p) >= 30 {
			t.Errorf("%s: the prompt is %d bytes", a.Name, len(p))
		}
		if m := model.FindStringSubmatch(a.Main)[1]; m != a.Model {
			t.Errorf("%s: the guest calls %q, the check prices %q", a.Name, m, a.Model)
		}
		if !strings.Contains(a.Main, "(max_retries=0, timeout=60)") {
			t.Errorf("%s: the client may retry", a.Name)
		}
		if got := strings.Count(a.Main, "max_tokens=MAX_TOKENS"); got != a.Calls {
			t.Errorf("%s: %d calls with the limit, the check prices %d", a.Name, got, a.Calls)
		}
		paid := regexp.MustCompile(`\.(chat\.completions|messages)(\.with_raw_response)?\.create\(`).FindAllString(a.Main, -1)
		if len(paid) != a.Calls {
			t.Errorf("%s: %d paid calls, the check prices %d: %v", a.Name, len(paid), a.Calls, paid)
		}
	}
}

// A profile holds the key's variable name and never a value, caps its one paid route, and
// allows nothing the refused calls use.
func TestLiveGrantsHoldNoKey(t *testing.T) {
	t.Setenv("NEBIUS_API_KEY", "canary-nebius")
	t.Setenv("ANTHROPIC_API_KEY", "canary-anthropic")
	raw, err := json.Marshal(liveGrants(realAPIs, ""))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("canary-")) || bytes.Contains(raw, []byte("workspace")) {
		t.Errorf("the grants file: %s", raw)
	}
	profiles, err := readProfiles(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 {
		t.Fatalf("%d profiles", len(profiles))
	}
	for _, p := range profiles {
		if len(p.Allow) != 1 || strings.Contains(p.Allow[0], "embeddings") || strings.Contains(p.Allow[0], "count_tokens") {
			t.Errorf("%s allows %v", p.Name, p.Allow)
		}
		if p.TokenEnv != map[string]string{"openai": "NEBIUS_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}[p.Name] {
			t.Errorf("%s reads its key from %s", p.Name, p.TokenEnv)
		}
	}
	withWorkspace, err := json.Marshal(liveGrants(realAPIs, "wrkspc_1"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(withWorkspace), "wrkspc_1") != 1 {
		t.Errorf("the workspace id belongs on the Anthropic profile alone: %s", withWorkspace)
	}
}

// The scan finds a key's bytes from its salted digest alone, and nothing else.
func TestScanWindowsFindsAKeyByItsDigest(t *testing.T) {
	key := []byte("canary-key-0123456789abcdef")
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	spec := scanSpec{Salt: hex.EncodeToString(salt), Keys: []keyDigest{{Name: "x", Length: len(key), SHA256: saltedDigest(salt, key)}}}
	data := []byte("some output before " + string(key) + " and after")
	if hits, windows, err := scanWindows(data, spec); err != nil || hits != 1 || windows != len(data)-len(key)+1 {
		t.Errorf("planted: %d hits in %d windows, %v", hits, windows, err)
	}
	if hits, _, err := scanWindows([]byte("nothing here but ordinary words, long enough"), spec); err != nil || hits != 0 {
		t.Errorf("clean: %d hits, %v", hits, err)
	}
	other := spec
	other.Salt = hex.EncodeToString(make([]byte, 16))
	if hits, _, _ := scanWindows(data, other); hits != 0 {
		t.Error("the digest matched under another salt")
	}
	if hits, _, _ := scanWindows([]byte(base64.StdEncoding.EncodeToString(data)), spec); hits != 0 {
		t.Error("the scan claims only exact bytes, and the page says so")
	}
}

func madeUpLive() *liveResults {
	calls := func(in, out int) []liveCallView {
		return []liveCallView{
			{Name: "plain", Title: "A plain call", Status: 200, Model: "m", Answer: "Hello there, friend.", Input: in, Output: out, UsageGiven: true},
			{Name: "stream", Title: "The same call, streamed", Status: 200, Pieces: 12, Span: 310, LargestGap: 40, Input: in, Output: out, UsageGiven: true, ContentType: "text/event-stream"},
			{Name: "refused", Title: "A route the profile does not allow", Status: 403, Error: "PermissionDeniedError", ShouldRetry: "false", Body: "forbidden by sandbox capability allowlist"},
		}
	}
	return &liveResults{Upstream: "real", Date: "2026-10-30", KeyID: "abc", Budget: 0.25, WorstCase: 0.00012672, CostUSD: 0.00002,
		APIs: []liveAPIView{
			{Profile: "openai", Vendor: "Nebius Token Factory", Model: "nvidia/Nemotron-3_5-Lightning", Library: "openai 3.41.0", Calls: calls(20, 30)},
			{Profile: "anthropic", Vendor: "Anthropic", Model: "claude-haiku-5-5", Library: "anthropic 2.3.0", Calls: calls(15, 12)},
		},
		Checks: []check{{ID: "api-answered", Says: "Each API answered.", Pass: true, Detail: "x"}}}
}

// The live section renders from its results alone, says what it cannot show, and stands apart
// from the stub's claims; with no results the page is the published page.
func TestLiveSectionRenders(t *testing.T) {
	ev, err := loadEvidence(published)
	if err != nil {
		t.Fatal(err)
	}
	without, err := render(ev, nil)
	if err != nil {
		t.Fatal(err)
	}
	stated, err := os.ReadFile(filepath.Join(published, filePage))
	if err != nil {
		t.Fatal(err)
	}
	if published, err := loadLive(published); err != nil {
		t.Fatal(err)
	} else if published == nil && !bytes.Equal(without, stated) {
		t.Error("with no live results, the page is not byte for byte the published page")
	}
	with, err := render(ev, madeUpLive())
	if err != nil {
		t.Fatal(err)
	}
	page := string(with)
	for _, want := range []string{
		`id="live"`,
		"The same libraries against the real APIs",
		"Apart from the <a href=\"#live\">section on the real APIs</a>, no real model API is called",
		"Nemotron-3_5-Lightning",
		"What the API received.",
		"are the stub run's, not this one's",
		"When the API wrote each piece.",
		"A key in another form.",
		"It is arithmetic, not an invoice.",
		"12 pieces over 310 ms",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not say %q", want)
		}
	}
	if strings.Contains(page, "neither vendor's API was called") {
		t.Error("the page still says neither vendor's API was called")
	}
	if regexp.MustCompile("[–—]| -- ").MatchString(page) {
		t.Error("the section has a dash used as punctuation")
	}
	ids := map[string]bool{}
	for _, m := range regexp.MustCompile(`\sid="([^"]+)"`).FindAllStringSubmatch(page, -1) {
		if ids[m[1]] {
			t.Errorf("id %q appears twice", m[1])
		}
		ids[m[1]] = true
	}
}

// A stub run's results must never read as a real run's: not on the page, not in -verify.
func TestLoadLiveRefusesWhatIsNotARealRun(t *testing.T) {
	dir := t.TempDir()
	if lr, err := loadLive(dir); lr != nil || err != nil {
		t.Fatalf("no file: %v, %v", lr, err)
	}
	if err := os.MkdirAll(filepath.Join(dir, liveDir), 0o755); err != nil {
		t.Fatal(err)
	}
	lr := madeUpLive()
	lr.Upstream = "stub"
	raw, err := marshalLive(lr)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, liveDir, fileLive), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLive(dir); err == nil {
		t.Error("a stub run's results loaded as a real run's")
	}
}

// The whole -live path against the local stub, with canary keys, under docker. It is off by
// default: it needs docker and the image sdk.Dockerfile builds, and takes about a minute.
//
//	PLIMSOLL_SDK_GRANTS_LIVE_STUB=1 go test ./examples/sdk-grants -run TestLivePlumbing -v
func TestLivePlumbing(t *testing.T) {
	if os.Getenv("PLIMSOLL_SDK_GRANTS_LIVE_STUB") != "1" {
		t.Skip("set PLIMSOLL_SDK_GRANTS_LIVE_STUB=1 to run it; it needs docker and the example's image")
	}
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repo)
	canary := map[string]string{}
	for _, a := range realAPIs {
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		canary[a.Name] = "canary-live-" + a.Name + "-" + hex.EncodeToString(b)
	}
	run := func(t *testing.T, change func([]liveAPI)) (liveConfig, *stub, *bytes.Buffer, error) {
		t.Helper()
		t.Setenv("NEBIUS_API_KEY", canary["openai"])
		t.Setenv("ANTHROPIC_API_KEY", canary["anthropic"])
		st, err := startStub(nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(st.close)
		apis := append([]liveAPI{}, realAPIs...)
		for i := range apis {
			apis[i].BaseURL = st.urls[apis[i].Name]
		}
		if change != nil {
			change(apis)
		}
		var console bytes.Buffer
		root := t.TempDir()
		c := liveConfig{repo: repo, work: filepath.Join(root, "work"), out: filepath.Join(root, "out"), apis: apis, upstream: "stub", console: &console}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		return c, st, &console, runLive(ctx, c)
	}
	mustHoldNoCanary := func(t *testing.T, c liveConfig, console []byte) {
		t.Helper()
		for name, key := range canary {
			if bytes.Contains(console, []byte(key)) {
				t.Errorf("the %s canary is in the console", name)
			}
			for _, root := range []string{c.work, c.out} {
				hits, err := filesHolding(root, key)
				if err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
				if len(hits) != 0 {
					t.Errorf("the %s canary is in %v", name, hits)
				}
			}
		}
	}

	t.Run("a clean run", func(t *testing.T) {
		c, st, console, err := run(t, nil)
		if err != nil {
			t.Fatalf("%v\n%s", err, console)
		}
		t.Logf("%s", console)
		// The keys did reach the API, so the check below is not passing because they went nowhere.
		reqs := st.requests()
		if len(reqs) != 4 {
			t.Fatalf("the stub received %d requests, want 4", len(reqs))
		}
		for _, r := range reqs {
			if got := headerValue(r.Headers, "Authorization"); got != "Bearer "+canary[r.API] {
				t.Errorf("%s %s carried the wrong credential", r.API, r.Target)
			}
			if strings.Contains(r.Body, "dummy") {
				t.Errorf("%s: a dummy key in the body", r.Target)
			}
			if !strings.Contains(r.Body, `"max_tokens":64`) && !strings.Contains(r.Body, `"max_tokens": 64`) {
				t.Errorf("%s: no 64-token limit in %s", r.Target, r.Body)
			}
		}
		mustHoldNoCanary(t, c, console.Bytes())
		lr, err := deriveLive(c.out)
		if err != nil {
			t.Fatal(err)
		}
		if lr.Upstream != "stub" {
			t.Errorf("upstream %q", lr.Upstream)
		}
		for _, ch := range lr.Checks {
			if !ch.Pass {
				t.Errorf("check %s: %s", ch.ID, ch.Detail)
			}
		}
		for _, a := range lr.APIs {
			if a.Scan.Places == 0 || a.Scan.Bytes == 0 || a.OutputScan.Windows == 0 {
				t.Errorf("%s scanned nothing: %+v, %+v", a.Vendor, a.Scan, a.OutputScan)
			}
		}
		if err := verifyLive(c.out, lr); err != nil {
			t.Error(err)
		}
		if _, err := loadLive(c.out); err == nil {
			t.Error("the page accepted a stub run's results")
		}
		// One byte changed in a raw file fails -verify; the results file too.
		for _, target := range []string{fileBundle, fileGrants, fileObserved, fileLive} {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, liveDir), 0o755); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{fileBundle, filePub, fileObserved, fileGrants, fileLive} {
				raw, err := os.ReadFile(filepath.Join(c.out, liveDir, name))
				if err != nil {
					t.Fatal(err)
				}
				if name == target {
					i := bytes.Index(raw, []byte(map[string]string{fileBundle: `"payload":"`, fileGrants: `"allow"`, fileObserved: `"payload"`, fileLive: `"sha256": "`}[name]))
					if i < 0 {
						t.Fatalf("%s: nothing to change", name)
					}
					i += 13
					raw = append([]byte{}, raw...)
					if raw[i] == 'a' {
						raw[i] = 'b'
					} else {
						raw[i] = 'a'
					}
				}
				if err := os.WriteFile(filepath.Join(dir, liveDir, name), raw, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := verifyLive(dir, lr); err == nil {
				t.Errorf("a copy with one byte of %s changed verified", target)
			}
		}
	})

	// The mistake the documentation warns about, put back on purpose: the real key in sdk_env,
	// so it enters the sandbox. The run must fail, and publish nothing.
	t.Run("the key put in the sandbox", func(t *testing.T) {
		c, _, console, err := run(t, func(apis []liveAPI) {
			apis[0].SDKEnv = map[string]string{"OPENAI_BASE_URL": "{origin}/v1", "OPENAI_API_KEY": canary["openai"]}
		})
		if err == nil {
			t.Fatalf("a run with the key in the sandbox passed\n%s", console)
		}
		if !strings.Contains(err.Error(), "KEY IS IN") && !strings.Contains(err.Error(), "key-not-in") {
			t.Errorf("failed for another reason: %v", err)
		}
		if entries, err := os.ReadDir(filepath.Join(c.out, liveDir)); err == nil && len(entries) != 0 {
			t.Errorf("published %d files", len(entries))
		}
		if bytes.Contains(console.Bytes(), []byte(canary["openai"])) || strings.Contains(err.Error(), canary["openai"]) {
			t.Error("the failure printed the key")
		}
		// Both digest scans saw it too, with no file check to lean on: the guest's report of
		// its own environment, and the guest's scan of its processes.
		raw, err := os.ReadFile(filepath.Join(c.work, "staged", liveDir, fileLive))
		if err != nil {
			t.Fatal(err)
		}
		var lr liveResults
		if err := json.Unmarshal(raw, &lr); err != nil {
			t.Fatal(err)
		}
		for _, ch := range lr.Checks {
			if strings.HasPrefix(ch.ID, "key-not-in") && ch.Pass {
				t.Errorf("the check %s passed with the key in the sandbox: %s", ch.ID, ch.Detail)
			}
		}
	})

	// And the digest scan alone, with the file check out of the way: the bundle of a run that
	// held the key shows hits, which is what -verify rests on.
	t.Run("the digest scan sees the key in a guest's output", func(t *testing.T) {
		raw := []byte(fmt.Sprintf(`{"environment":{"OPENAI_API_KEY":%q}}`, canary["openai"]))
		salt := make([]byte, 16)
		spec := scanSpec{Salt: hex.EncodeToString(salt), Keys: []keyDigest{{Name: "openai", Length: len(canary["openai"]), SHA256: saltedDigest(salt, []byte(canary["openai"]))}}}
		if hits, _, err := scanWindows(raw, spec); err != nil || hits != 1 {
			t.Errorf("%d hits, %v", hits, err)
		}
	})
}
