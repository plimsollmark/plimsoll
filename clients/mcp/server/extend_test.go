package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/png"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/plimsollmark/plimsoll/clients/mcp/internal/fakedaemon"
	"github.com/plimsollmark/plimsoll/clients/mcp/server"
	"github.com/plimsollmark/plimsoll/sandbox"
)

func tinyPNG(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewGray(image.Rect(0, 0, 2, 2))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// picturesFrom turns each output line "PIC <title>" into a picture, and a line "BAD
// <title>" into a picture that is not a PNG.
func picturesFrom(t *testing.T) server.PicturesFunc {
	img := tinyPNG(t)
	return func(stdout, stderr string) (string, string, []server.Picture, []string) {
		var keep []string
		var pics []server.Picture
		for _, line := range strings.Split(stdout, "\n") {
			switch {
			case strings.HasPrefix(line, "PIC "):
				pics = append(pics, server.Picture{PNG: img, Title: strings.TrimPrefix(line, "PIC ")})
			case strings.HasPrefix(line, "BAD "):
				pics = append(pics, server.Picture{PNG: []byte("GIF89a"), Title: strings.TrimPrefix(line, "BAD ")})
			default:
				keep = append(keep, line)
			}
		}
		return strings.Join(keep, "\n"), stderr, pics, nil
	}
}

var physics = server.Kit{Name: "physics", Description: "A library.", Files: []sandbox.File{
	{Path: "lib/__init__.py", Content: "x = 1\n"}, {Path: "lib/envs/a.json", Content: "{}"},
}}

var motor = server.Kit{Name: "motor", Description: "The same library, another environment.", Files: []sandbox.File{
	{Path: "lib/__init__.py", Content: "x = 1\n"}, {Path: "lib/envs/motor.json", Content: "{}"},
}}

func inputProperties(t *testing.T, c *conn, tool string) map[string]any {
	t.Helper()
	return schemaProperties(t, c, tool, false)
}

func outputProperties(t *testing.T, c *conn, tool string) map[string]any {
	t.Helper()
	return schemaProperties(t, c, tool, true)
}

func schemaProperties(t *testing.T, c *conn, tool string, output bool) map[string]any {
	t.Helper()
	list, err := c.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range list.Tools {
		if tl.Name == tool {
			var b []byte
			if output {
				b, _ = json.Marshal(tl.OutputSchema)
			} else {
				b, _ = json.Marshal(tl.InputSchema)
			}
			var schema struct {
				Properties map[string]any `json:"properties"`
			}
			_ = json.Unmarshal(b, &schema)
			return schema.Properties
		}
	}
	t.Fatalf("no tool %s", tool)
	return nil
}

// Without an embedder's configuration nothing changes: no kit in either schema.
func TestKitsAreOffOnlyWhenNoneAreConfigured(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 2})
	plain := connect(t, local(d.URL))
	for _, tool := range []string{"run_code", "open_sandbox"} {
		if _, ok := inputProperties(t, plain, tool)["kit"]; ok {
			t.Errorf("%s offers kit with no kits configured", tool)
		}
	}
	cfg := local(d.URL)
	cfg.Kits = []server.Kit{physics, motor}
	cfg.KitsNote = "Read lib/README.md first."
	withKits := connect(t, cfg)
	// The kits' text is said once, under run_code; open_sandbox names the same kits and
	// points there (both tools travel in every tool list).
	for tool, want := range map[string]string{"run_code": "Read lib/README.md first. physics: A library.", "open_sandbox": "run_code's kit says what each kit holds"} {
		kit, _ := inputProperties(t, withKits, tool)["kit"].(map[string]any)
		if fmt.Sprint(kit["enum"]) != "[physics motor]" || !strings.Contains(fmt.Sprint(kit["description"]), want) {
			t.Errorf("%s kit: %v", tool, kit)
		}
	}
}

func TestAKitIsWrittenBeforeTheCallsFiles(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 2})
	cfg := local(d.URL)
	cfg.Kits = []server.Kit{physics, motor}
	c := connect(t, cfg)
	out := c.ok("run_code", map[string]any{"code": "1", "kit": "physics", "files": []any{map[string]any{"path": "mine.txt", "content": "m"}}})
	if out["stderr"] != "lib/__init__.py\nlib/envs/a.json\nmine.txt\n" {
		t.Errorf("fresh call with a kit wrote %q", out["stderr"])
	}
	// An unknown kit never reaches the server: the schema's enum refuses it.
	if res := c.call("run_code", map[string]any{"code": "1", "kit": "nope"}); !res.IsError {
		t.Errorf("an unknown kit ran: %s", text(res))
	}
	if f := c.fail("run_code", map[string]any{"code": "1", "kit": "physics", "files": []any{map[string]any{"path": "lib/__init__.py", "content": "other"}}}); f.Ran != "no" || !strings.Contains(f.Summary, "is a file of kit physics") {
		t.Errorf("a call file replacing a kit file: %+v", f)
	}
	if res := c.call("open_sandbox", map[string]any{"kit": "nope"}); !res.IsError || d.OpenSessions() != 0 {
		t.Errorf("open_sandbox with an unknown kit: %s, %d open", text(res), d.OpenSessions())
	}

	opened := c.ok("open_sandbox", map[string]any{"kit": "physics"})
	h := opened["sandbox"]
	if opened["kit"] != "physics" || !strings.Contains(opened["summary"].(string), "Kit physics is written into it with the first run_code call") {
		t.Errorf("open_sandbox with a kit: %v", opened)
	}
	first := c.ok("run_code", map[string]any{"code": "1", "sandbox": h})
	second := c.ok("run_code", map[string]any{"code": "2", "sandbox": h})
	if first["stderr"] != "lib/__init__.py\nlib/envs/a.json\n" || second["stderr"] != "" {
		t.Errorf("the kit goes with the first call only: %q then %q", first["stderr"], second["stderr"])
	}
	// Another kit sharing the library: the shared file goes once.
	third := c.ok("run_code", map[string]any{"code": "3", "sandbox": h, "kit": "motor"})
	if third["stderr"] != "lib/__init__.py\nlib/envs/motor.json\n" {
		t.Errorf("a second kit in the sandbox wrote %q", third["stderr"])
	}
}

func TestAKitGoesAgainIntoAReplacedSandbox(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 2})
	cfg := local(d.URL)
	cfg.Kits = []server.Kit{physics}
	c := connect(t, cfg)
	h := c.ok("open_sandbox", map[string]any{"kit": "physics"})["sandbox"]
	c.ok("run_code", map[string]any{"code": fakedaemon.EndsSession, "sandbox": h})
	again := c.ok("run_code", map[string]any{"code": "x", "sandbox": h})
	if again["freshSandbox"] != true || again["stderr"] != "lib/__init__.py\nlib/envs/a.json\n" {
		t.Errorf("the replacing sandbox gets the kit: %v", again)
	}
}

// With PictureLink set, a result lists where each sent picture can be opened, in order, and
// the PNG the hook is given is the one sent.
func TestPictureLinksFollowTheSentPictures(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 2})
	cfg := local(d.URL)
	cfg.Pictures = picturesFrom(t)
	var seen [][]byte
	cfg.PictureLink = func(png []byte, title string) string {
		seen = append(seen, png)
		return "http://127.0.0.1:8752/pictures/" + title + ".png"
	}
	c := connect(t, cfg)
	res := c.call("run_code", map[string]any{"code": "a\nPIC first\nPIC second"})
	var out struct {
		PictureLinks []string `json:"pictureLinks"`
		Summary      string   `json:"summary"`
	}
	if err := json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &out); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(out.PictureLinks) != "[http://127.0.0.1:8752/pictures/first.png http://127.0.0.1:8752/pictures/second.png]" || !strings.Contains(out.Summary, "pictureLinks") {
		t.Errorf("value: %+v", out)
	}
	if len(seen) != 2 || !bytes.Equal(seen[0], res.Content[1].(*mcp.ImageContent).Data) {
		t.Errorf("the hook was given %d pictures, the first not the one sent", len(seen))
	}
	// Without the hook the field is not in the schema at all.
	plain := connect(t, local(d.URL))
	if _, ok := outputProperties(t, plain, "run_code")["pictureLinks"]; ok {
		t.Error("pictureLinks is in the schema with no PictureLink configured")
	}
}

func TestPicturesTravelAsImagesAfterTheValue(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 2})
	cfg := local(d.URL)
	cfg.Pictures = picturesFrom(t)
	c := connect(t, cfg)
	res := c.call("run_code", map[string]any{"code": "a\nPIC first\nb\nBAD broken\nPIC second\nPIC third\nPIC fourth\nPIC fifth"})
	if res.IsError || len(res.Content) != 5 {
		t.Fatalf("want the value and four images, got %d blocks: %s", len(res.Content), text(res))
	}
	var out struct {
		Stdout       string   `json:"stdout"`
		Pictures     []string `json:"pictures"`
		PictureNotes []string `json:"pictureNotes"`
		Summary      string   `json:"summary"`
	}
	if err := json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &out); err != nil {
		t.Fatal(err)
	}
	if out.Stdout != "fresh python: a\nb" || fmt.Sprint(out.Pictures) != "[first second third fourth]" || len(out.PictureNotes) != 2 || !strings.Contains(out.Summary, "4 pictures are attached as images") {
		t.Errorf("value: %+v", out)
	}
	for _, block := range res.Content[1:] {
		if img, ok := block.(*mcp.ImageContent); !ok || img.MIMEType != "image/png" || !bytes.HasPrefix(img.Data, []byte("\x89PNG")) {
			t.Errorf("block %T is not a PNG image", block)
		}
	}
	// In a sandbox too, and a run without pictures is the plain value.
	h := c.ok("open_sandbox", nil)["sandbox"]
	if res := c.call("run_code", map[string]any{"code": "x\nPIC cell", "sandbox": h}); len(res.Content) != 2 {
		t.Errorf("a cell's picture: %d blocks", len(res.Content))
	}
	c.ok("run_code", map[string]any{"code": "plain"})
}

type echoIn struct {
	Say string `json:"say"`
}

type echoOut struct {
	Summary string `json:"summary"`
}

func TestExtendRegistersAToolLikeTheServers(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	s, err := server.New(local(d.URL))
	if err != nil {
		t.Fatal(err)
	}
	img := tinyPNG(t)
	server.Extend(s, &mcp.Tool{Name: "echo", Description: "Echoes."}, func(_ context.Context, in echoIn) (echoOut, []server.Picture, error) {
		switch in.Say {
		case "refuse":
			return echoOut{}, nil, sandbox.NotDispatched(sandbox.RefusalRequest, errors.New("no"))
		case "lost":
			return echoOut{}, nil, errors.New("the answer was lost")
		}
		return echoOut{Summary: in.Say}, []server.Picture{{PNG: img, Title: "p"}}, nil
	})
	c := connectServer(t, s)
	if res := c.call("echo", map[string]any{"say": "hi"}); res.IsError || len(res.Content) != 2 || !strings.Contains(text(res), `"summary":"hi"`) {
		t.Errorf("echo: %v", res.Content)
	}
	if f := c.fail("echo", map[string]any{"say": "refuse"}); f.Ran != "no" || f.Refusal != "request" {
		t.Errorf("a refusal: %+v", f)
	}
	if f := c.fail("echo", map[string]any{"say": "lost"}); f.Ran != "maybe" {
		t.Errorf("an unmarked error: %+v", f)
	}
	info := c.ok("server_info", nil)
	if !strings.Contains(fmt.Sprint(info["tools"]), "echo") {
		t.Errorf("server_info does not list the extension: %v", info["tools"])
	}
}

func TestKitsAreChecked(t *testing.T) {
	for _, k := range []server.Kit{
		{Name: "Bad Name", Files: physics.Files},
		{Name: "empty"},
		{Name: "reserved", Files: []sandbox.File{{Path: ".plimsoll/x", Content: ""}}},
		{Name: "absolute", Files: []sandbox.File{{Path: "/etc/x", Content: ""}}},
		{Name: "twice", Files: []sandbox.File{{Path: "a", Content: ""}, {Path: "a", Content: ""}}},
		{Name: "huge", Files: []sandbox.File{{Path: "a", Content: strings.Repeat("x", sandbox.MaxProjectBytes)}}},
	} {
		cfg := local("http://127.0.0.1:1")
		cfg.Kits = []server.Kit{k}
		if _, err := server.New(cfg); err == nil {
			t.Errorf("kit %q was accepted", k.Name)
		}
	}
}

// Kept finds what get_record finds, as a copy.
func TestKeptIsWhatGetRecordFinds(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	s, err := server.New(local(d.URL))
	if err != nil {
		t.Fatal(err)
	}
	c := connectServer(t, s)
	out := c.ok("run_code", map[string]any{"code": "1+1", "language": "javascript"})
	digest, _ := out["recordSha256"].(string)
	r := s.Kept(context.Background(), digest)
	if digest == "" || r == nil || r.SHA256 != digest {
		t.Fatalf("Kept(%q) = %+v", digest, r)
	}
	r.Provider = "changed"
	if got := c.ok("get_record", map[string]any{"recordSha256": digest}); strings.Contains(fmt.Sprint(got), "changed") {
		t.Error("changing Kept's answer changed the kept record")
	}
	if s.Kept(context.Background(), strings.Repeat("0", 64)) != nil {
		t.Error("Kept found a record the server never checked")
	}
}

// A panel is served as a ui:// resource and declares the UI extension; without one the
// server declares neither.
func TestPanelsAreServedOnlyWhenConfigured(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	plain := connect(t, local(d.URL))
	if caps := plain.cs.InitializeResult().Capabilities; caps.Resources != nil || caps.Extensions != nil {
		t.Errorf("a server without panels declares %+v", caps)
	}
	cfg := local(d.URL)
	cfg.Panels = []server.Panel{{URI: "ui://test/replay.html", Name: "replay", HTML: "<!doctype html><p>hi</p>"}}
	c := connect(t, cfg)
	caps := c.cs.InitializeResult().Capabilities
	if caps.Extensions["io.modelcontextprotocol/ui"] == nil || caps.Logging == nil {
		t.Errorf("a server with a panel declares %+v", caps)
	}
	res, err := c.cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "ui://test/replay.html"})
	if err != nil || len(res.Contents) != 1 || res.Contents[0].MIMEType != server.PanelMIME || res.Contents[0].Text != "<!doctype html><p>hi</p>" {
		t.Errorf("the panel resource: %+v, %v", res, err)
	}
	bad := local(d.URL)
	bad.Panels = []server.Panel{{URI: "https://elsewhere/page.html", Name: "x", HTML: "x"}}
	if _, err := server.New(bad); err == nil {
		t.Error("a panel outside ui:// was accepted")
	}
}
