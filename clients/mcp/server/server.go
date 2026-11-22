package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
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
	"sync/atomic"
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
	// granted is the client a run_code call without a sandbox uses when the server was
	// installed with a grant: remote's settings with the grant profile selected for
	// snippets and projects. plan is what the daemon's Describe said the grant can do.
	// Both nil without a grant.
	granted *client.Remote
	plan    *grantPlan
	mcp     *mcp.Server
	tools   []*mcp.Tool
	// receipts, when configured, signs every checked exchange (nil otherwise).
	receipts *Receipts
	// opts are remote's options without its recorder, and shares the daemon clients of
	// each approved app, whose recorder counts its receipts against its share (clientsFor).
	opts   []client.Option
	shares map[string]shareClients

	// callFiles, when set (SetCallFiles), gives files every run_code call writes first.
	callFiles func() []sandbox.File

	// stop cancels every tool call in progress; Shutdown calls it.
	stopCtx context.Context
	stop    context.CancelFunc

	mu           sync.Mutex
	info         *client.Info
	grants       map[string]*connectorGrant
	records      map[string]keptRecord   // by recordKey
	held         map[string]*heldRecords // what each connection keeps, by grantID ("" over stdio)
	recordCount  int                     // the records kept, against keptPool
	recordBytes  int                     // the text they hold, against keptBytesPool
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

// New builds the server. Without a grant it does not contact the daemon: a host starts
// the server before any tool is called, and a daemon that is down is reported per call.
// With one (Config.GrantProfile) it reads the daemon's Describe once, because what
// run_code's description tells the model it can call depends on the daemon, and fails
// when the daemon is unreachable or cannot carry the grant.
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
		// In remote mode each approved app has its share of the directory (Full); over
		// stdio there is one caller, the owner, whose calls may fill the whole limit.
		receipts.shared = cfg.RequireGrant
	}
	s := &Server{cfg: cfg, receipts: receipts, opts: opts, shares: map[string]shareClients{}, grants: map[string]*connectorGrant{}, records: map[string]keptRecord{}, held: map[string]*heldRecords{}, boxes: map[string]*box{}, closings: map[*closing]struct{}{}, openingBy: map[string]int{}, openingGrant: map[string]int{}}
	local, err := s.newClients("")
	if err != nil {
		return nil, fmt.Errorf("PLIMSOLL_URL: %w", err)
	}
	s.remote = local.remote
	if cfg.GrantProfile != "" {
		if s.plan, err = describeGrant(s.remote, cfg); err != nil {
			return nil, err
		}
		s.granted = local.granted
	}
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
	s.mcp.AddReceivingMiddleware(s.schemaRefusals)
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

// shareClients are the daemon clients one share's calls use: remote, and granted when
// the server was installed with a grant.
type shareClients struct{ remote, granted *client.Remote }

// newClients builds the daemon clients of a share ("" for calls of no approved app),
// recording into its share of the receipts when there are receipts.
func (s *Server) newClients(share string) (shareClients, error) {
	opts := s.opts
	switch {
	case s.receipts != nil && share == "":
		opts = append(slices.Clip(opts), client.WithRecorder(s.receipts))
	case s.receipts != nil:
		opts = append(slices.Clip(opts), client.WithRecorder(shareRecorder{r: s.receipts, share: share}))
	}
	var c shareClients
	var err error
	if c.remote, err = client.New(s.cfg.URL, opts...); err != nil {
		return c, err
	}
	if s.cfg.GrantProfile != "" {
		c.granted, err = client.New(s.cfg.URL, append(slices.Clip(opts), client.WithProjectGrantProfile(s.cfg.GrantProfile), client.WithJavaScriptGrantProfile(s.cfg.GrantProfile))...)
	}
	return c, err
}

// shareOfCall is the share a call's receipts count against: the approved app its grant
// belongs to (so approving an app twice does not double its share, as with sandboxes),
// or "" for a call of no app.
func (s *Server) shareOfCall(ctx context.Context) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g := s.grantLocked(ctx); g != nil {
		return g.group
	}
	return ""
}

// clientsFor is the daemon clients of a share: those built for it when its first grant
// was registered (RegisterGrant), or the server's own for "", and for a share with none.
func (s *Server) clientsFor(share string) shareClients {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.shares[share]; ok {
		return c
	}
	return shareClients{remote: s.remote, granted: s.granted}
}

// MCP is the server to serve: mcp.StdioTransport for a local host.
// A tool an embedder registers on the returned server directly is not one of this server's:
// it gets none of their admission, deadline or answer writing, and its answers pass as it
// writes them, with nothing of this server's saying whether anything ran. Register a tool
// through Extend or ExtendRun instead.
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
	var he x509.HostnameError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &he):
		// Its standard text names every name on the daemon's certificate and the name
		// dialed, which are the daemon's address as much as the address itself is.
		return "the daemon's TLS certificate is not valid for the name this server connects to"
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

// notedError is an error with a sentence its failed call's answer ends with (WithNote).
type notedError struct {
	err  error
	note string
}

func (e *notedError) Error() string { return e.err.Error() }
func (e *notedError) Unwrap() error { return e.err }

// WithNote returns err with a sentence the answer of the failed call ends with, kept
// whatever the answer makes of err itself: an embedder's tool saying what the failure
// did not cost, for one (a lab that gives back a run it counts under a limit says so,
// since a model told only that the code may have run cannot tell). errors.Is and
// errors.As see through it; the outermost note is the one shown.
func WithNote(err error, note string) error {
	if err == nil || note == "" {
		return err
	}
	return &notedError{err: err, note: note}
}

// failed describes err: nothing ran only when it carries the not-dispatched mark, or
// failed in this server before any request carried code.
func (s *Server) failed(ctx context.Context, err error) *failure {
	f := &failure{Ran: "maybe"}
	var own *notSentError
	switch reason, ok := sandbox.NotDispatchedReason(err); {
	case ok:
		f.Ran, f.Refusal = "no", reason.String()
		f.Summary = fmt.Sprintf("Nothing ran (%s): %s", reason, shown(err))
	case errors.As(err, &own):
		f.Ran = "no"
		f.Summary = "Nothing ran: " + own.what + ": " + shown(own.err)
	case errors.Is(err, context.DeadlineExceeded):
		f.Summary = fmt.Sprintf("The call reached this server's %s deadline; the code may have run, and there is no checked answer for it. It was not retried; running it again could repeat what it did.", s.cfg.CallTimeout)
	default:
		f.Summary = fmt.Sprintf("The code may have run, and there is no checked answer for it: %s. It was not retried; running it again could repeat what it did.", shown(err))
	}
	var noted *notedError
	if errors.As(err, &noted) {
		f.Summary += " " + noted.note
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

// notSentError marks a failure of this server's own before any request carried code:
// what failed, and why. The mark is not words for the model: it once added ": not sent" to
// the answer (hunt-quality-49, 2026-11-20).
type notSentError struct {
	what string
	err  error
}

func (e *notSentError) Error() string { return e.what + ": " + e.err.Error() }
func (e *notSentError) Unwrap() error { return e.err }

// A checked record's digests are its own, but the daemon writes its other text
// (provider, environment, policy, ...), and a record checks however long that is: so the
// records kept are bounded in bytes as well as in number, and a record whose text alone
// is past maxRecordText is not kept at all (its receipt, when receipts are on, still is).
//
// The records kept are shared by every connection, and each keeps its own: a connection
// holds at most shareOf the pool, KeptRecords records and maxKeptRecordBytes of their
// text, its own oldest going first past either, so one connection's calls never push out
// another's records (hunt-security-25, 2026-11-20). The pool is twice a share so that a
// connection at its share leaves exactly a share for the others, and a share is what
// get_record's description promises and what the server kept before it had shares. Past
// the pool, which takes three connections or more, the oldest record of the connection
// holding the most goes.
const (
	maxRecordText      = 64 << 10
	maxKeptRecordBytes = 16 << 20
	keptPool           = 2 * KeptRecords
	keptBytesPool      = 2 * maxKeptRecordBytes
)

// heldRecords is what one connection keeps: its record keys, oldest first, and their text.
type heldRecords struct {
	order []string
	bytes int
}

func recordText(r *sandbox.RunRecord) int {
	return len(r.RequestSHA256) + len(r.ResultSHA256) + len(r.Provider) + len(r.Isolation) + len(r.Environment) +
		len(r.SoftwareIdentity) + len(r.SoftwareRuleID) + len(r.Policy) + len(r.Session) + len(r.PreviousSHA256) + len(r.Unanswered) + len(r.Instance) +
		len(r.IsolationQualification) + len(r.DaemonVersion) + len(r.SHA256)
}

// keptRecord is a record get_record returns, with its receipt's line as the receipt store
// knew it when the record was kept. The store's index of lines is bounded too, and holds
// lines get_record never sees (records too long to keep, an embedder's client's), so the
// two forgot in different orders and get_record called a line on disk and synced "failed"
// (hunt-quality-45, 2026-11-20). One entry holding both, they cannot disagree: the line
// lives exactly as long as the record. The pointer is the store's own, so the session's
// state it reads (open, closed, incomplete) is the current one.
type keptRecord struct {
	rec  *sandbox.RunRecord
	line *kept // nil when no line was stored (its write failed), or with no receipts
}

// keep stores a checked record for get_record, evicting the connection's own oldest past
// its share, and the oldest of the connection holding the most past the pool.
func (s *Server) keep(ctx context.Context, r *sandbox.RunRecord) {
	if r == nil || r.SHA256 == "" {
		return
	}
	size := recordText(r)
	if size > maxRecordText {
		s.cfg.Logger.Warn("a checked record was not kept for get_record: its text is too long", "bytes", size, "record", r.SHA256)
		return
	}
	line := s.receipts.lineOf(r.SHA256)
	s.mu.Lock()
	key := recordKey(ctx, r.SHA256)
	if s.grantRevokedLocked(ctx) {
		s.mu.Unlock()
		return
	}
	g := grantID(ctx)
	h := s.held[g]
	if h == nil {
		h = &heldRecords{}
		s.held[g] = h
	}
	if old, ok := s.records[key]; ok {
		h.bytes -= recordText(old.rec)
		s.recordBytes -= recordText(old.rec)
	} else {
		h.order = append(h.order, key)
		s.recordCount++
	}
	s.records[key] = keptRecord{rec: r, line: line}
	h.bytes += size
	s.recordBytes += size
	for len(h.order) > int(shareOf(keptPool)) || h.bytes > int(shareOf(keptBytesPool)) {
		s.evictLocked(g)
	}
	for s.recordCount > keptPool || s.recordBytes > keptBytesPool {
		s.evictLocked(s.largestHolderLocked())
	}
	s.mu.Unlock()
	if s.cfg.RecordObserver != nil {
		s.cfg.RecordObserver(grantID(ctx), r.SHA256)
	}
}

// evictLocked forgets the oldest record connection g keeps.
func (s *Server) evictLocked(g string) {
	h := s.held[g]
	key := h.order[0]
	h.order = h.order[1:]
	size := recordText(s.records[key].rec)
	h.bytes -= size
	s.recordBytes -= size
	s.recordCount--
	delete(s.records, key)
	if len(h.order) == 0 {
		delete(s.held, g)
	}
}

// largestHolderLocked is the connection keeping the most records (then the most text,
// then the least ID, so the choice does not depend on map order).
func (s *Server) largestHolderLocked() string {
	var best string
	var top *heldRecords
	for g, h := range s.held {
		if top == nil || len(h.order) > len(top.order) || len(h.order) == len(top.order) && (h.bytes > top.bytes || h.bytes == top.bytes && g < best) {
			best, top = g, h
		}
	}
	return best
}

// forgetRecordsLocked forgets every record connection g keeps (its grant was revoked).
func (s *Server) forgetRecordsLocked(g string) {
	for s.held[g] != nil {
		s.evictLocked(g)
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
		return nil, &notSentError{what: "the daemon did not answer Describe", err: err}
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

// SetCallFiles makes f's files part of every run_code call on s, fresh or in a sandbox,
// written into the working directory before the call's own: data an embedder's other
// tools make during a session (recordings, say) that code should read without the model
// copying it into the call. A call file at one of their paths is refused. f is called once
// per call and must return promptly; its files count against the call's limits, so an
// embedder keeps them well inside the daemon's, and keeps their paths apart from its kits'.
// Call it before serving.
func SetCallFiles(s *Server, f func() []sandbox.File) {
	s.callFiles = f
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
			// An embedder's client built on Recorder writes into the share of calls of no
			// app, so that share is checked too; one built on RecorderFor writes into its
			// caller's app's share, which admitRun checks.
			if s.shareOfCall(ctx) != "" {
				if f := s.full(""); f != nil {
					return zero, nil, f
				}
			}
			release, f := s.admitRun(ctx)
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
	r := s.records[recordKey(ctx, recordSHA256)].rec
	if r == nil {
		return nil
	}
	c := *r
	return &c
}

// Recorder is what records every checked exchange (the receipts, or the embedder's
// Recorder), or nil: an embedder's own daemon client records through it, so its runs
// get receipts like the server's. In remote mode its receipts count against the share of
// calls of no approved app; an embedder whose tool builds its client per call uses
// RecorderFor, so they count against the calling app's.
func (s *Server) Recorder() client.Recorder {
	if s.receipts != nil {
		return s.receipts
	}
	return s.cfg.Recorder
}

// RecorderFor is Recorder as the calls of ctx's caller reach it: in remote mode with
// receipts, the receipt store counting what it writes against the approved app of the
// call's grant (Receipts.Full); otherwise Recorder.
func (s *Server) RecorderFor(ctx context.Context) client.Recorder {
	if share := s.shareOfCall(ctx); s.receipts != nil && share != "" {
		return shareRecorder{r: s.receipts, share: share}
	}
	return s.Recorder()
}

// ReceiptFor says what became of a checked record, given the error its result came
// with (nil, or client.ErrNotRecorded); nil when nothing records.
func (s *Server) ReceiptFor(r *sandbox.RunRecord, err error) *Receipt { return s.receiptFor(r, err) }

// Settings is the configuration the server runs with, defaults filled in.
func (s *Server) Settings() Config { return s.cfg }

// started marks, on a tools/call's context, that the call reached the server's handler:
// schemaRefusals sets it, and answer stores true in it first thing.
type startedKey struct{}

// schemaRefusals gives the SDK's own refusals the shape of this server's: arguments the tool's
// input schema refuses are answered by the SDK before any handler runs, as an error result in
// plain text. It rewrites only those: a call to one of this server's tools whose handler never
// started. A handler that started writes its own answer (answer), and that answer is never
// read as a refusal, whatever its text: a call whose code ran was once told "Nothing ran"
// when its output could not be written as JSON (hunt-quality-43, 2026-11-20). A tool an
// embedder registered on MCP() directly is not this server's, so its answers pass as written.
func (s *Server) schemaRefusals(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		callReq, isCall := req.(*mcp.CallToolRequest)
		if !isCall || callReq.Params == nil || !s.isTool(callReq.Params.Name) {
			return next(ctx, method, req)
		}
		started := new(atomic.Bool)
		res, err := next(context.WithValue(ctx, startedKey{}, started), method, req)
		if started.Load() {
			return res, err
		}
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

// isTool reports whether name is one of the tools registered through addToolWith. The tools
// are registered before serving, so the list is read without the lock, as server_info reads it.
func (s *Server) isTool(name string) bool {
	return slices.ContainsFunc(s.tools, func(t *mcp.Tool) bool { return t.Name == name })
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

// addToolWith registers every tool, the server's and each embedder's (Extend, ExtendRun):
// the SDK reads and checks the arguments, and everything after that is answer's. A test
// fails if a tool is registered, or a tool result made, anywhere else.
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
	fit := resolveOutput(t)
	s.tools = append(s.tools, t)
	mcp.AddTool(s.mcp, t, func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		// The result is complete, its output already checked against the schema
		// (StructuredContent set and no value returned), so the SDK adds nothing to it.
		return s.answer(ctx, t.Name, fit, func(ctx context.Context) (any, []Picture, *failure) {
			return h(ctx, in)
		}), nil, nil
	})
}

// resolveOutput is t's output schema resolved as the SDK resolves it, for answer to check
// each output against before it is sent.
func resolveOutput(t *mcp.Tool) *jsonschema.Resolved {
	schema, ok := t.OutputSchema.(*jsonschema.Schema)
	if !ok {
		schema = new(jsonschema.Schema)
		b, err := json.Marshal(t.OutputSchema)
		if err == nil {
			err = json.Unmarshal(b, schema)
		}
		if err != nil {
			panic(fmt.Sprintf("tool %s: output schema: %v", t.Name, err))
		}
	}
	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{ValidateDefaults: true})
	if err != nil {
		panic(fmt.Sprintf("tool %s: output schema: %v", t.Name, err))
	}
	return resolved
}

// answer is the one place every tool call's answer is made once the SDK has read its
// arguments: admission, the call's deadline, the handler, and the writing of its output or
// its failure. The server writes each output itself, as JSON checked against the tool's
// output schema, rather than leaving that to the SDK, which answers an output it cannot
// write with a protocol error that says nothing of whether anything ran; with pictures the
// output was marshaled here, and a failure to do so went back as plain text that
// schemaRefusals read as "nothing ran" (hunt-quality-43, 2026-11-20). The handler has
// returned by then, so whatever code it sent may have run: such a failure is ran "maybe".
func (s *Server) answer(ctx context.Context, tool string, fit *jsonschema.Resolved, h func(context.Context) (any, []Picture, *failure)) *mcp.CallToolResult {
	if started, ok := ctx.Value(startedKey{}).(*atomic.Bool); ok {
		started.Store(true)
	}
	// Admission and Shutdown share the lock: a call is either counted before
	// shutdown, which then waits for it, or refused.
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return toolError(shuttingDown)
	}
	var grant *connectorGrant
	if s.cfg.RequireGrant {
		grant = s.grantLocked(ctx)
		if grant == nil {
			s.mu.Unlock()
			return toolError(refused(sandbox.RefusalPermission, "connector authorization is absent or revoked"))
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
	out, pics, f := h(ctx)
	if f != nil {
		return toolError(f)
	}
	b, err := writeOutput(out, fit)
	if err != nil {
		s.cfg.Logger.Warn("a tool's output could not be written; the call is answered as one that may have run", "tool", tool, "error", err)
		return toolError(undelivered(tool, err))
	}
	// The value's JSON goes first, as the only text: a host that drops images keeps the result.
	content := []mcp.Content{&mcp.TextContent{Text: string(b)}}
	for _, p := range pics {
		content = append(content, &mcp.ImageContent{Data: p.PNG, MIMEType: "image/png"})
	}
	return &mcp.CallToolResult{Content: content, StructuredContent: json.RawMessage(b)}
}

// undelivered is the answer to a call whose handler returned an output this server could
// not write: the call got as far as its tool, so its code may have run.
func undelivered(tool string, err error) *failure {
	return &failure{Ran: "maybe", Summary: fmt.Sprintf("The code may have run, and its output could not be delivered: this server could not write the %s tool's output as JSON that fits the tool's output schema (%s). It was not retried; running it again could repeat what it did.", tool, clipRunes(err.Error(), 300))}
}

// writeOutput is out as the SDK would have sent it: its JSON with the output schema's
// defaults applied, checked against the schema. An error is an output that cannot be sent
// (a number that is not finite, a value the schema refuses).
func writeOutput(out any, fit *jsonschema.Resolved) ([]byte, error) {
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	if v == nil && fit.Schema().Type == "object" {
		v = map[string]any{}
	}
	_, isObject := v.(map[string]any)
	if isObject {
		if err := fit.ApplyDefaults(&v); err != nil {
			return nil, err
		}
	}
	if err := fit.Validate(&v); err != nil {
		return nil, err
	}
	if !isObject {
		return b, nil
	}
	return json.Marshal(v)
}

// toolError is f as the tool error a model reads.
func toolError(f *failure) *mcp.CallToolResult {
	b, _ := json.Marshal(f)
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}
}

func ptr[T any](v T) *T { return &v }

func timeString(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func joinNames(ls []sandbox.Language) string { return strings.Join(names(ls), " and ") }
