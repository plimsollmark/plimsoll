package server_test

// Regressions for a review of the server, 15 October 2026: replacements past the cap,
// unbounded kept records, extensions outside the run admission, unbounded picture text,
// unchecked PNGs, a tool name taken twice, a kit resent over the guest's changes, and a
// close reporting a deletion the daemon never confirmed.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/plimsollmark/plimsoll/clients/mcp/internal/fakedaemon"
	"github.com/plimsollmark/plimsoll/clients/mcp/server"
	"github.com/plimsollmark/plimsoll/sandbox"
)

func pngOf(t *testing.T, w, h int) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewGray(image.Rect(0, 0, w, h))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// Finding 4 and 5: pictures are decoded within bounds and sent re-encoded; titles and
// notes, which reach the model as text, are bounded.
func TestPicturesTitlesAndNotesAreBounded(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	cfg := local(d.URL)
	small, huge := pngOf(t, 4, 4), pngOf(t, 8192, 8192)
	trailing := append(append([]byte{}, small...), []byte("smuggled after IEND")...)
	cfg.Pictures = func(stdout, stderr string) (string, string, []server.Picture, []string) {
		pics := []server.Picture{{PNG: huge, Title: "huge"}, {PNG: trailing, Title: strings.Repeat("t", 60000)}, {PNG: []byte("\x89PNG\r\n\x1a\ngarbage"), Title: "garbage"}}
		for i := range 50 {
			pics = append(pics, server.Picture{PNG: small, Title: fmt.Sprint("extra ", i)})
		}
		return stdout, stderr, pics, nil
	}
	c := connect(t, cfg)
	res := c.call("run_code", map[string]any{"code": "1"})
	if res.IsError {
		t.Fatal(text(res))
	}
	var images int
	for _, ct := range res.Content {
		if im, ok := ct.(*mcp.ImageContent); ok {
			images++
			if bytes.Contains(im.Data, []byte("smuggled")) {
				t.Error("bytes after a PNG's end reached the client")
			}
			if _, err := png.Decode(bytes.NewReader(im.Data)); err != nil {
				t.Errorf("an image that does not decode was sent: %v", err)
			}
		}
	}
	out := text(res)
	if images != 4 || strings.Contains(out, strings.Repeat("t", 200)) || len(out) > 20000 {
		t.Errorf("%d images, %d bytes of text", images, len(out))
	}
	if !strings.Contains(out, "8192 by 8192 pixels") || !strings.Contains(out, "more pictures dropped") {
		t.Errorf("the drops were not noted: %s", out)
	}
}

func TestBoundedTitleIsWholeRunes(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	cfg := local(d.URL)
	cfg.Pictures = func(stdout, stderr string) (string, string, []server.Picture, []string) {
		return stdout, stderr, []server.Picture{{PNG: pngOf(t, 2, 2), Title: strings.Repeat("é", 500)}}, nil
	}
	res := connect(t, cfg).call("run_code", map[string]any{"code": "1"})
	var out map[string]any
	if err := json.Unmarshal([]byte(text(res)), &out); err != nil {
		t.Fatal(err)
	}
	titles, _ := out["pictures"].([]any)
	if len(titles) != 1 || !utf8.ValidString(titles[0].(string)) || utf8.RuneCountInString(titles[0].(string)) > 120 {
		t.Errorf("titles %v", titles)
	}
}

// Finding 6: a tool name taken twice is refused.
func TestExtendRefusesATakenName(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	s, err := server.New(local(d.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recover() == nil {
			t.Error("an extension named run_code was registered")
		}
	}()
	server.Extend(s, &mcp.Tool{Name: "run_code", Description: "Shadows."}, func(context.Context, echoIn) (echoOut, []server.Picture, error) {
		return echoOut{}, nil, nil
	})
}

// Finding 3: an extension that runs code is admitted as run_code is; one that reads is not.
func TestExtendRunIsAdmittedLikeRunCode(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	s, err := server.New(local(d.URL))
	if err != nil {
		t.Fatal(err)
	}
	ran := 0
	server.ExtendRun(s, &mcp.Tool{Name: "check", Description: "Runs."}, func(context.Context, echoIn) (echoOut, []server.Picture, error) {
		ran++
		return echoOut{Summary: "ran"}, nil, nil
	})
	server.Extend(s, &mcp.Tool{Name: "look", Description: "Reads."}, func(context.Context, echoIn) (echoOut, []server.Picture, error) {
		return echoOut{Summary: "looked"}, nil, nil
	})
	c := connectServer(t, s)
	c.ok("check", map[string]any{"say": "x"})
	server.HoldRuns(s, 16)
	if f := c.fail("check", map[string]any{"say": "x"}); f.Ran != "no" || f.Refusal != "capacity" {
		t.Errorf("a run past the cap: %+v", f)
	}
	if f := c.fail("run_code", map[string]any{"code": "1"}); f.Refusal != "capacity" {
		t.Errorf("run_code past the cap: %+v", f)
	}
	c.ok("look", map[string]any{"say": "x"})
	if ran != 1 {
		t.Errorf("the running extension ran %d times", ran)
	}
}

// Finding 2: what the server keeps for get_record is bounded in bytes.
func TestKeptRecordsAreBoundedInBytes(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	s, err := server.New(local(d.URL))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	digest := func(i int) string { return fmt.Sprintf("%064x", i) }
	s.Keep(ctx, &sandbox.RunRecord{SHA256: digest(0), Policy: strings.Repeat("p", 70<<10)})
	if s.Kept(ctx, digest(0)) != nil {
		t.Error("a record with 70 KiB of text was kept")
	}
	for i := 1; i <= 300; i++ {
		s.Keep(ctx, &sandbox.RunRecord{SHA256: digest(i), Policy: strings.Repeat("p", 60<<10)})
	}
	if s.Kept(ctx, digest(1)) != nil || s.Kept(ctx, digest(300)) == nil {
		t.Error("the oldest records were not let go for the newest")
	}
	kept := 0
	for i := 1; i <= 300; i++ {
		if s.Kept(ctx, digest(i)) != nil {
			kept++
		}
	}
	if kept*60<<10 > 16<<20 {
		t.Errorf("%d records of 60 KiB kept, past 16 MiB", kept)
	}
}

// Finding 7: a kit sent with a call that may have run is not sent again.
func TestAKitIsNotResentAfterACallThatMayHaveRun(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 2})
	cfg := local(d.URL)
	cfg.Kits = []server.Kit{physics}
	c := connect(t, cfg)
	h := c.ok("open_sandbox", map[string]any{"kit": "physics"})["sandbox"]
	f := c.fail("run_code", map[string]any{"code": fakedaemon.Breaks, "sandbox": h})
	if f.Ran != "maybe" || !strings.Contains(f.Summary, "Kit physics went with this call") {
		t.Fatalf("the broken call: %+v", f)
	}
	if out := c.ok("run_code", map[string]any{"code": "2", "sandbox": h}); out["stderr"] != "" {
		t.Errorf("the kit went again, over what the guest may have changed: %q", out["stderr"])
	}
}

// Finding 8: close_sandbox says deleted only once an earlier, replaced sandbox of the
// handle is deleted too.
func TestCloseWaitsForAReplacedSandboxsDeletion(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4, CloseDelay: 300 * time.Millisecond})
	c := connect(t, local(d.URL))
	h := c.ok("open_sandbox", nil)["sandbox"]
	c.ok("run_code", map[string]any{"code": fakedaemon.EndsSession, "sandbox": h})
	retired := d.Provider.Opened()[0]
	out := c.ok("close_sandbox", map[string]any{"sandbox": h})
	select {
	case <-retired.Done():
	default:
		if out["deleted"] == true {
			t.Error("close_sandbox said deleted while the replaced sandbox's deletion was unfinished")
		}
	}
}

// Finding 1: a replacement waits for its ended sandbox's deletion when the cap is full,
// so the server never holds more sandboxes than MaxSandboxes.
func TestAReplacementStaysUnderTheCap(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4, CloseDelay: 300 * time.Millisecond})
	cfg := local(d.URL)
	cfg.MaxSandboxes = 1
	c := connect(t, cfg)
	h := c.ok("open_sandbox", nil)["sandbox"]
	c.ok("run_code", map[string]any{"code": fakedaemon.EndsSession, "sandbox": h})
	retired := d.Provider.Opened()[0]
	done := make(chan map[string]any, 1)
	go func() { done <- c.ok("run_code", map[string]any{"code": "after", "sandbox": h}) }()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if len(d.Provider.Opened()) > 1 {
			select {
			case <-retired.Done():
			default:
				t.Fatal("a replacement opened while the ended sandbox was still being deleted, past the cap of 1")
			}
			break
		}
	}
	if out := <-done; out["freshSandbox"] != true {
		t.Errorf("the call after: %v", out)
	}
}

// A daemon that meets an open at its per-owner cap by deleting an idle sandbox: the
// server refuses the open first, and deletes nothing.
func TestAnOpenTheDaemonWouldMakeRoomForIsRefused(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4, PerOwner: 1})
	c := connect(t, local(d.URL))
	h := c.ok("open_sandbox", nil)["sandbox"]
	c.ok("run_code", map[string]any{"code": "x = 1", "sandbox": h})
	f := c.fail("open_sandbox", nil)
	if f.Ran != "no" || f.Refusal != "capacity" || len(f.IdleSandboxes) != 1 {
		t.Errorf("an open at the daemon's per-owner cap: %+v", f)
	}
	if out := c.ok("run_code", map[string]any{"code": "x", "sandbox": h}); out["freshSandbox"] == true {
		t.Error("the idle sandbox was deleted to make room")
	}
}
