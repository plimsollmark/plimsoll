package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io/fs"
	"net"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// Name is the server's name in initialize and server_info.
const Name = "plimsoll"

const tierNote = "the tier is the daemon's configuration and provider evidence plus its startup smoke tests, not hardware attestation"

// Server holds the daemon client, the sandboxes open_sandbox opened and the records
// get_record returns. One per process; its MCP server can be served on any transport.
type Server struct {
	cfg    Config
	remote *client.Remote
	mcp    *mcp.Server
	tools  []*mcp.Tool
	// receipts, when configured, signs every checked exchange (nil otherwise).
	receipts *Receipts

	// stop cancels every tool call in progress; Shutdown calls it.
	stopCtx context.Context
	stop    context.CancelFunc

	mu           sync.Mutex
	info         *client.Info
	grants       map[string]*connectorGrant
	records      map[string]*sandbox.RunRecord
	order        []string // record digests, oldest first
	recordBytes  int      // the text the kept records hold, against maxKeptRecordBytes
	boxes        map[string]*box
	closings     map[*closing]struct{} // closes not yet finished, each holding a place
	opening      int                   // opens in progress, each holding a place
	openingBy    map[string]int        // the same, per approved app (connectorGrant.group)
	openingGrant map[string]int        // the same, per connector grant ("" over stdio)
	outstanding  int                   // run_code calls in progress

	// calls counts the tool calls in progress, which Close waits for; one is added
	// under mu with stopped false, so none is added once Close waits.
	calls sync.WaitGroup

	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
	stopped   bool // Shutdown was called: no new work
}

// New builds the server. It does not contact the daemon: a host starts the server
// before any tool is called, and a daemon that is down is reported per call.
func New(cfg Config) (*Server, error) {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	opts := []client.Option{}
	if cfg.Token != "" {
		opts = append(opts, client.WithToken(cfg.Token))
	}
	if cfg.InsecureHTTP {
		opts = append(opts, client.WithInsecureHTTP())
	}
	if cfg.HTTPClient != nil {
		opts = append(opts, client.WithHTTPClient(cfg.HTTPClient))
	}
	if cfg.Recorder != nil {
		opts = append(opts, client.WithRecorder(cfg.Recorder))
	}
	var receipts *Receipts
	if cfg.ReceiptsDir != "" {
		if cfg.Recorder != nil {
			return nil, errors.New("receipts and a Recorder of the embedder's are each a recorder: configure one")
		}
		if receipts, err = OpenReceipts(cfg.ReceiptsDir, cfg.SigningKeyFile, cfg.ReceiptsMaxBytes); err != nil {
			return nil, fmt.Errorf("receipts: %w", err)
		}
		opts = append(opts, client.WithRecorder(receipts))
	}
	remote, err := client.New(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("PLIMSOLL_URL: %w", err)
	}
	s := &Server{cfg: cfg, remote: remote, receipts: receipts, grants: map[string]*connectorGrant{}, records: map[string]*sandbox.RunRecord{}, boxes: map[string]*box{}, closings: map[*closing]struct{}{}, openingBy: map[string]int{}, openingGrant: map[string]int{}}
	s.stopCtx, s.stop = context.WithCancel(context.Background())
	mopts := &mcp.ServerOptions{
		Instructions: "Runs code in plimsoll, a sandbox for untrusted code, and returns its output with a checked run record. " +
			"run_code without sandbox runs fresh; open_sandbox gives a handle whose run_code calls keep files and interpreter state. " +
			"Each result names the isolation tier the code ran behind and the run record's sha256; get_record returns the record.",
	}
	if len(cfg.Panels) > 0 {
		// Capabilities replaces the SDK's defaults, so logging, its one default, is kept.
		mopts.Capabilities = &mcp.ServerCapabilities{Logging: &mcp.LoggingCapabilities{}}
		mopts.Capabilities.AddExtension("io.modelcontextprotocol/ui", map[string]any{"mimeTypes": []string{PanelMIME}})
	}
	s.mcp = mcp.NewServer(&mcp.Implementation{Name: Name, Version: Version}, mopts)
	s.mcp.AddReceivingMiddleware(schemaRefusals)
	for _, p := range cfg.Panels {
		page := p
		s.mcp.AddResource(&mcp.Resource{URI: page.URI, Name: page.Name, Title: page.Title, MIMEType: PanelMIME, Meta: mcp.Meta{"ui": map[string]any{"prefersBorder": true}}},
			func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
				return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: page.URI, MIMEType: PanelMIME, Text: page.HTML}}}, nil
			})
	}
	s.register()
	return s, nil
}

// MCP is the server to serve: mcp.StdioTransport for a local host.
// A tool an embedder registers on the returned server directly must write its failures as
// JSON objects: schemaRefusals reads any plain-text error result as a schema refusal that
// ran nothing (review, 2026-10-26).
func (s *Server) MCP() *mcp.Server { return s.mcp }

// failure is a tool error as the model reads it: what happened in one sentence, then
// whether anything ran, and what is known about it.
type failure struct {
	Summary string `json:"summary"`
	// Ran is "no" when the daemon or this server refused before any code was sent,
	// and "maybe" when the code may have run without an answer that checked.
	Ran string `json:"ran"`
	// Refusal is why nothing ran, when the daemon said: request, permission, protocol,
	// unsupported, isolation, environment or capacity.
	Refusal string `json:"refusal,omitempty"`
	// SandboxEnded is why the sandbox ended, when it did.
	SandboxEnded string `json:"sandboxEnded,omitempty"`
	// RecordSHA256 is the checked record of a call that may have run; get_record returns it.
	RecordSHA256 string `json:"recordSha256,omitempty"`
	// SandboxUsable says, when a handle was used, whether the sandbox it had is still
	// there with its files and state; when false the handle still works, its next call
	// starting a new sandbox.
	SandboxUsable *bool `json:"sandboxUsable,omitempty"`
	// Receipt is what became of the record of a call that may have run.
	Receipt *Receipt `json:"receipt,omitempty"`
	// IdleSandboxes, when open_sandbox is refused at the cap, are the handles with no call
	// running or waiting: what close_sandbox could delete to make room, not what is safe to.
	IdleSandboxes []string `json:"idleSandboxes,omitempty"`
}

// answered reports whether a call's error still leaves a checked answer: none, or only
// a failure to keep the record of an answer that checked. An unanswered session call is
// never answered, whatever its recorder did.
func answered(err error, rec *sandbox.RunRecord) bool {
	if err == nil {
		return true
	}
	var unanswered *client.UnansweredCallError
	return errors.Is(err, client.ErrNotRecorded) && !errors.As(err, &unanswered) && rec != nil
}

func refused(reason sandbox.Refusal, format string, args ...any) *failure {
	return &failure{Summary: "Nothing ran: " + fmt.Sprintf(format, args...), Ran: "no", Refusal: reason.String()}
}

// shown is err's text as the model may see it. A transport failure names the daemon's
// address and a receipt failure the receipts directory's path, and over serve-http the
// model is claude.ai's or chatgpt.com's, so those are told by kind: the operation and what
// went wrong, never the address or the path (review, 2026-10-26).
func shown(err error) string {
	var oe *net.OpError
	var de *net.DNSError
	var ue *url.Error
	var pe *fs.PathError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &de):
		return "the daemon's name could not be resolved"
	case errors.As(err, &oe):
		if oe.Err != nil {
			return fmt.Sprintf("the daemon could not be reached (%s: %v)", oe.Op, oe.Err)
		}
		return "the daemon could not be reached (" + oe.Op + ")"
	case errors.As(err, &ue):
		return fmt.Sprintf("the %s request to the daemon failed: %v", ue.Op, ue.Err)
	case errors.As(err, &pe):
		return fmt.Sprintf("%s of a receipt file failed: %v", pe.Op, pe.Err)
	}
	return err.Error()
}

// failed describes err: nothing ran only when it carries the not-dispatched mark, or
// failed in this server before any request carried code.
func (s *Server) failed(ctx context.Context, err error) *failure {
	f := &failure{Ran: "maybe"}
	switch reason, ok := sandbox.NotDispatchedReason(err); {
	case ok:
		f.Ran, f.Refusal = "no", reason.String()
		f.Summary = fmt.Sprintf("Nothing ran (%s): %s", reason, shown(err))
	case errors.Is(err, errNotSent):
		f.Ran = "no"
		f.Summary = "Nothing ran: " + err.Error()
	case errors.Is(err, context.DeadlineExceeded):
		f.Summary = fmt.Sprintf("The call reached this server's %s deadline; the code may have run, and there is no checked answer for it. It was not retried; running it again could repeat what it did.", s.cfg.CallTimeout)
	default:
		f.Summary = fmt.Sprintf("The code may have run, and there is no checked answer for it: %s. It was not retried; running it again could repeat what it did.", shown(err))
	}
	var ended *sandbox.SessionEndedError
	if errors.As(err, &ended) {
		f.SandboxEnded = ended.Reason.String()
	}
	var unanswered *client.UnansweredCallError
	if errors.As(err, &unanswered) && unanswered.Record != nil {
		s.keep(ctx, unanswered.Record)
		f.RecordSHA256 = unanswered.Record.SHA256
		var notKept error
		if errors.Is(err, client.ErrNotRecorded) {
			notKept = err
		}
		f.Receipt = s.receiptFor(unanswered.Record, notKept)
	}
	return f
}

// errNotSent marks a failure of this server's own before any request carried code.
var errNotSent = errors.New("not sent")

// A checked record's digests are its own, but the daemon writes its other text
// (provider, environment, policy, ...), and a record checks however long that is: so the
// records kept are bounded in bytes as well as in number, and a record whose text alone
// is past maxRecordText is not kept at all (its receipt, when receipts are on, still is).
const (
	maxRecordText      = 64 << 10
	maxKeptRecordBytes = 16 << 20
)

func recordText(r *sandbox.RunRecord) int {
	return len(r.RequestSHA256) + len(r.ResultSHA256) + len(r.Provider) + len(r.Isolation) + len(r.Environment) +
		len(r.SoftwareIdentity) + len(r.SoftwareRuleID) + len(r.Policy) + len(r.Session) + len(r.PreviousSHA256) + len(r.Unanswered) + len(r.Instance) + len(r.SHA256)
}

// keep stores a checked record for get_record, evicting the oldest past KeptRecords or
// maxKeptRecordBytes.
func (s *Server) keep(ctx context.Context, r *sandbox.RunRecord) {
	if r == nil || r.SHA256 == "" {
		return
	}
	size := recordText(r)
	if size > maxRecordText {
		s.cfg.Logger.Warn("a checked record was not kept for get_record: its text is too long", "bytes", size, "record", r.SHA256)
		return
	}
	s.mu.Lock()
	key := recordKey(ctx, r.SHA256)
	if s.grantRevokedLocked(ctx) {
		s.mu.Unlock()
		return
	}
	if old, ok := s.records[key]; ok {
		s.recordBytes -= recordText(old)
	} else {
		s.order = append(s.order, key)
	}
	s.records[key] = r
	s.recordBytes += size
	for len(s.order) > KeptRecords || s.recordBytes > maxKeptRecordBytes {
		s.recordBytes -= recordText(s.records[s.order[0]])
		delete(s.records, s.order[0])
		s.order = s.order[1:]
	}
	s.mu.Unlock()
	if s.cfg.RecordObserver != nil {
		s.cfg.RecordObserver(grantID(ctx), r.SHA256)
	}
}

// describe returns the daemon's Describe, read once and again after a refusal that
// says the daemon may have changed (restarted with another image, tier or sessions).
func (s *Server) describe(ctx context.Context) (*client.Info, error) {
	s.mu.Lock()
	info := s.info
	s.mu.Unlock()
	if info != nil {
		return info, nil
	}
	got, err := s.remote.Describe(ctx)
	if err != nil {
		return nil, fmt.Errorf("the daemon did not answer Describe: %w: %w", err, errNotSent)
	}
	s.mu.Lock()
	s.info = &got
	s.mu.Unlock()
	return &got, nil
}

func (s *Server) forgetDescribe() {
	s.mu.Lock()
	s.info = nil
	s.mu.Unlock()
}

func (s *Server) forgetDescribeOn(err error) {
	switch reason, _ := sandbox.NotDispatchedReason(err); reason {
	case sandbox.RefusalUnsupported, sandbox.RefusalIsolation, sandbox.RefusalEnvironment, sandbox.RefusalProtocol:
		s.mu.Lock()
		s.info = nil
		s.mu.Unlock()
	}
}

// offered is the server's languages that env runs. Every daemon this server talks to
// states them (protocol 4), so an env that states none proved none and is offered none;
// it used to be let try, which sent calls a provider had proved it cannot run (review
// B9, 2026-10-23).
func (s *Server) offered(env sandbox.PayloadEnvironment) []sandbox.Language {
	var out []sandbox.Language
	for _, l := range s.cfg.Languages {
		if slices.Contains(env.Languages, l) {
			out = append(out, l)
		}
	}
	return out
}

func names(ls []sandbox.Language) []string {
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = string(l)
	}
	return out
}

// cut keeps at most max bytes of out, on a rune boundary: a rune cut in two is
// dropped whole. A rune is at most utf8.UTFMax bytes, so the cut moves back at most
// that far; guest output is arbitrary bytes, and a long run of continuation bytes
// (never a rune's start) would otherwise walk the cut back to the start of the
// output and hide everything before it behind "truncated".
func cut(out string, max int) (string, bool) {
	if len(out) <= max {
		return out, false
	}
	i := max
	for i > 0 && i > max-utf8.UTFMax && !utf8.RuneStart(out[i]) {
		i--
	}
	return out[:i], true
}

func newHandle() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "sbx_" + base64.RawURLEncoding.EncodeToString(b[:])
}

// SurfaceDigest is a short hash of the server's name, version and every tool as a host
// receives it (name, title, description, schemas, annotations), in canonical JSON and
// name order, so a host whose cached tool list differs gets a different digest.
func SurfaceDigest(tools []*mcp.Tool) string {
	sorted := slices.Clone(tools)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	h := sha256.New()
	fmt.Fprintf(h, "%s\x1f%s\x1e", Name, Version)
	for _, t := range sorted {
		h.Write(canonical(t))
		h.Write([]byte{0x1e})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// canonical is v's JSON with object keys sorted, whatever Go type produced it.
func canonical(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var generic any
	if json.Unmarshal(b, &generic) != nil {
		return nil
	}
	b, _ = json.Marshal(generic)
	return b
}

// Limits on the pictures one result carries: each goes to the model as an image, so it
// must be a PNG whose header and pixels decode within these bounds (a small file can
// declare an image that takes gigabytes to decode), and is sent re-encoded, so nothing
// rides along after its last chunk or in its text chunks.
const (
	maxPictures     = 4
	maxPictureBytes = 1 << 20
	maxPictureSide  = 4096
	maxPixels       = 4 << 20
	maxTitleRunes   = 120
	maxNotes        = 8
	maxNoteRunes    = 300
)

// pngMagic opens every PNG file.
const pngMagic = "\x89PNG\r\n\x1a\n"

// keepPictures keeps the first maxPictures pictures that are valid PNGs within the
// limits, re-encoded, noting each one dropped, and returns them with their titles. The
// titles and the notes reach the model as text, so both are bounded.
// pictureLinks asks the embedder's PictureLink, when set, where the user can open each kept
// picture.
func (s *Server) pictureLinks(pics []Picture) []string {
	if s.cfg.PictureLink == nil || len(pics) == 0 {
		return nil
	}
	links := make([]string, len(pics))
	for i, p := range pics {
		links[i] = s.cfg.PictureLink(p.PNG, p.Title)
	}
	return links
}

// PictureLinks is where the user can open each picture, from Config.PictureLink (nil when it
// is unset), for an embedder's own tool to put in its result; keep its pictures the way the
// server keeps them first, so the links match what is sent.
func (s *Server) PictureLinks(pics []Picture) []string { return s.pictureLinks(pics) }

// Caller names the caller a tool call belongs to: the owner, or one approved app over the
// remote transport. An embedder keeps per-caller state under it, as the server keeps sandboxes.
func (s *Server) Caller(ctx context.Context) string { return s.owner(ctx) }

func keepPictures(pics []Picture, notes *[]string) ([]Picture, []string) {
	var kept []Picture
	var titles []string
	extra := 0
	for i, p := range pics {
		title := clipRunes(p.Title, maxTitleRunes)
		if len(kept) == maxPictures {
			extra++
			continue
		}
		b, why := cleanPNG(p.PNG)
		if why != "" {
			*notes = append(*notes, fmt.Sprintf("picture %d (%s) dropped: %s", i+1, title, why))
			continue
		}
		kept = append(kept, Picture{PNG: b, Title: title})
		titles = append(titles, title)
	}
	if extra > 0 {
		*notes = append(*notes, fmt.Sprintf("%d more pictures dropped: a result carries at most %d", extra, maxPictures))
	}
	*notes = boundNotes(*notes)
	return kept, titles
}

// cleanPNG decodes b within the limits and encodes it again; why says why it would not.
func cleanPNG(b []byte) ([]byte, string) {
	if len(b) > maxPictureBytes || !strings.HasPrefix(string(b), pngMagic) {
		return nil, fmt.Sprintf("not a PNG of at most %d bytes", maxPictureBytes)
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		return nil, "not a PNG that decodes"
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > maxPictureSide || cfg.Height > maxPictureSide || cfg.Width*cfg.Height > maxPixels {
		return nil, fmt.Sprintf("%d by %d pixels; at most %d a side and %d in all", cfg.Width, cfg.Height, maxPictureSide, maxPixels)
	}
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		return nil, "not a PNG that decodes"
	}
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil || out.Len() > 4*maxPictureBytes {
		return nil, "could not be encoded again within the size limit"
	}
	return out.Bytes(), ""
}

// boundNotes keeps at most maxNotes notes of at most maxNoteRunes each, the rest counted.
func boundNotes(notes []string) []string {
	out := make([]string, 0, min(len(notes), maxNotes))
	for i, n := range notes {
		if i == maxNotes-1 && len(notes) > maxNotes {
			out = append(out, fmt.Sprintf("%d more notes dropped", len(notes)-i))
			break
		}
		out = append(out, clipRunes(n, maxNoteRunes))
	}
	return out
}

func clipRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// Extend registers an embedder's tool on s, with the admission, call deadline,
// shutdown and connector handling of the server's own tools, and lists it in
// server_info. h returns its output and the pictures to send beside it, or an error:
// one marked not dispatched (sandbox.NotDispatchedError) says nothing ran, and any
// other that the code may have run. Call it before serving; a name already taken
// panics.
func Extend[In, Out any](s *Server, t *mcp.Tool, h func(context.Context, In) (Out, []Picture, error)) {
	extend(s, t, false, h)
}

// ExtendRun registers an embedder's tool that runs code: Extend, plus run_code's
// admission (the receipts' disk cap, and the cap on calls holding the daemon at once,
// which counts both), so work through an embedder's tool is refused exactly when the
// same work through run_code would be. A tool that only reads uses Extend.
func ExtendRun[In, Out any](s *Server, t *mcp.Tool, h func(context.Context, In) (Out, []Picture, error)) {
	extend(s, t, true, h)
}

func extend[In, Out any](s *Server, t *mcp.Tool, runs bool, h func(context.Context, In) (Out, []Picture, error)) {
	addToolWith(s, t, func(ctx context.Context, in In) (Out, []Picture, *failure) {
		var zero Out
		if runs {
			release, f := s.admitRun()
			if f != nil {
				return zero, nil, f
			}
			defer release()
		}
		out, pics, err := h(ctx, in)
		if err != nil {
			return zero, nil, s.failed(ctx, err)
		}
		var notes []string
		kept, _ := keepPictures(pics, &notes)
		for _, n := range notes {
			s.cfg.Logger.Warn("picture dropped", "tool", t.Name, "why", n)
		}
		return out, kept, nil
	})
}

// Keep stores a checked record for get_record, as the server's own tools do; an
// embedder's tool calls it for each record its daemon client checked.
func (s *Server) Keep(ctx context.Context, r *sandbox.RunRecord) { s.keep(ctx, r) }

// Kept returns a copy of a checked record this server still keeps, found as get_record
// finds it (in remote mode, only among the calling connector's), or nil.
func (s *Server) Kept(ctx context.Context, recordSHA256 string) *sandbox.RunRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.records[recordKey(ctx, recordSHA256)]
	if r == nil {
		return nil
	}
	c := *r
	return &c
}

// Recorder is what records every checked exchange (the receipts, or the embedder's
// Recorder), or nil: an embedder's own daemon client records through it, so its runs
// get receipts like the server's.
func (s *Server) Recorder() client.Recorder {
	if s.receipts != nil {
		return s.receipts
	}
	return s.cfg.Recorder
}

// ReceiptFor says what became of a checked record, given the error its result came
// with (nil, or client.ErrNotRecorded); nil when nothing records.
func (s *Server) ReceiptFor(r *sandbox.RunRecord, err error) *Receipt { return s.receiptFor(r, err) }

// Settings is the configuration the server runs with, defaults filled in.
func (s *Server) Settings() Config { return s.cfg }

// schemaRefusals gives the SDK's own refusals the shape of this server's: arguments the tool's
// input schema refuses are answered by the SDK before any handler runs, as an error result in
// plain text. Every failure this server writes is a JSON object, and the SDK reports a failure
// after a handler (an output that does not fit its schema) as a protocol error, not a result, so
// an error result whose text is not a JSON object is a refusal that ran nothing.
func schemaRefusals(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		res, err := next(ctx, method, req)
		call, ok := res.(*mcp.CallToolResult)
		if err != nil || !ok || !call.IsError || len(call.Content) != 1 {
			return res, err
		}
		text, ok := call.Content[0].(*mcp.TextContent)
		if !ok || json.Valid([]byte(text.Text)) && strings.HasPrefix(strings.TrimSpace(text.Text), "{") {
			return res, err
		}
		b, _ := json.Marshal(refused(sandbox.RefusalRequest, "the arguments do not fit the tool's input schema (%s); fix them and call again", clipRunes(text.Text, 300)))
		// A copy of the SDK's result, its content replaced: the SDK has set what the
		// negotiated revision requires on it (2026-07-28's resultType, in a field this
		// package cannot set), which a new result would lack.
		retold := *call
		retold.Content = []mcp.Content{&mcp.TextContent{Text: string(b)}}
		return &retold, nil
	}
}

// addTool registers a tool whose output schema is Out's, and whose failures are tool
// errors carrying a failure as JSON (never structured output, which would have to
// conform to Out). Every tool is registered through it, so server_info lists exactly
// what tools/list sends; a test compares the two over the wire. An output with
// pictures (runOutput's) sends them as image content after its JSON.
func addTool[In, Out any](s *Server, t *mcp.Tool, h func(context.Context, In) (Out, *failure)) {
	addToolWith(s, t, func(ctx context.Context, in In) (Out, []Picture, *failure) {
		out, f := h(ctx, in)
		var pics []Picture
		if a, ok := any(out).(interface{ attached() []Picture }); ok && f == nil {
			pics = a.attached()
		}
		return out, pics, f
	})
}

func addToolWith[In, Out any](s *Server, t *mcp.Tool, h func(context.Context, In) (Out, []Picture, *failure)) {
	if t.OutputSchema == nil {
		schema, err := jsonschema.For[Out](nil)
		if err != nil {
			panic(fmt.Sprintf("tool %s: output schema: %v", t.Name, err))
		}
		t.OutputSchema = schema
	}
	if t.InputSchema == nil {
		schema, err := jsonschema.For[In](nil)
		if err != nil {
			panic(fmt.Sprintf("tool %s: input schema: %v", t.Name, err))
		}
		t.InputSchema = schema
	}
	// The SDK would replace a tool of the same name, leaving server_info listing both:
	// a name taken twice is a programming error, refused as http.ServeMux refuses a
	// pattern registered twice.
	for _, have := range s.tools {
		if have.Name == t.Name {
			panic(fmt.Sprintf("tool %s is registered twice", t.Name))
		}
	}
	s.tools = append(s.tools, t)
	mcp.AddTool(s.mcp, t, func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		// Admission and Shutdown share the lock: a call is either counted before
		// shutdown, which then waits for it, or refused.
		s.mu.Lock()
		if s.stopped {
			s.mu.Unlock()
			b, _ := json.Marshal(shuttingDown)
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
		}
		var grant *connectorGrant
		if s.cfg.RequireGrant {
			grant = s.grantLocked(ctx)
			if grant == nil {
				s.mu.Unlock()
				b, _ := json.Marshal(refused(sandbox.RefusalPermission, "connector authorization is absent or revoked"))
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
			}
			grant.calls.Add(1)
		}
		s.calls.Add(1)
		s.mu.Unlock()
		if grant != nil {
			defer grant.calls.Done()
		}
		defer s.calls.Done()
		ctx, cancel := context.WithTimeout(ctx, s.cfg.CallTimeout)
		defer cancel()
		if grant != nil {
			defer context.AfterFunc(grant.ctx, cancel)()
			if grant.ctx.Err() != nil {
				cancel()
			}
		}
		// Shutdown cancels every call in progress, so a signal need not wait for them.
		defer context.AfterFunc(s.stopCtx, cancel)()
		out, pics, f := h(ctx, in)
		if f != nil {
			b, _ := json.Marshal(f)
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
		}
		if len(pics) == 0 {
			return nil, out, nil
		}
		// With Content set the SDK adds no text block of its own, so the value's JSON
		// goes first, as the only text: a host that drops images keeps the result.
		b, err := json.Marshal(out)
		if err != nil {
			return nil, nil, err
		}
		content := []mcp.Content{&mcp.TextContent{Text: string(b)}}
		for _, p := range pics {
			content = append(content, &mcp.ImageContent{Data: p.PNG, MIMEType: "image/png"})
		}
		return &mcp.CallToolResult{Content: content}, out, nil
	})
}

func ptr[T any](v T) *T { return &v }

func timeString(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func joinNames(ls []sandbox.Language) string { return strings.Join(names(ls), " and ") }
