package server

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/plimsollmark/plimsoll/sandbox"
)

type fileInput struct {
	Path    string `json:"path" jsonschema:"A relative path, such as data/orders.csv."`
	Content string `json:"content" jsonschema:"The file's text."`
}

type runInput struct {
	Code     string      `json:"code" jsonschema:"The source code to run. Print what you need, or end with an expression to show its value."`
	Language string      `json:"language,omitempty"`
	Files    []fileInput `json:"files,omitempty" jsonschema:"Text files written into the working directory before the code runs, for data the code should read."`
	Sandbox  string      `json:"sandbox,omitempty" jsonschema:"A handle from open_sandbox, to run where earlier calls ran. Omit to run in a fresh sandbox."`
	Kit      string      `json:"kit,omitempty"`
}

type openInput struct {
	Kit string `json:"kit,omitempty"`
}

type runOutput struct {
	Summary          string   `json:"summary" jsonschema:"The facts of this result in one sentence, for quoting."`
	Language         string   `json:"language"`
	ExitCode         int      `json:"exitCode"`
	TimedOut         bool     `json:"timedOut"`
	Stdout           string   `json:"stdout"`
	Stderr           string   `json:"stderr"`
	Truncated        bool     `json:"truncated" jsonschema:"stdout or stderr was cut, by the daemon's cap or this server's."`
	StateKept        bool     `json:"stateKept" jsonschema:"This call's interpreter and sandbox were still running when it answered, so what it defined can be there for the next call with the same sandbox."`
	FreshInterpreter bool     `json:"freshInterpreter,omitempty" jsonschema:"This call's interpreter had just started: nothing earlier calls defined in this language exists."`
	FilesPersist     bool     `json:"filesPersist" jsonschema:"This call's sandbox was still running when it answered, so its files can be there for the next call."`
	FreshSandbox     bool     `json:"freshSandbox,omitempty" jsonschema:"This call ran in a newly opened sandbox: no file an earlier call wrote is there."`
	SandboxReplaced  string   `json:"sandboxReplaced,omitempty" jsonschema:"What became of this handle's earlier sandbox before this call, which then ran in a new one: ended, and why, or given up with its end unknown. Nothing from the earlier one is there."`
	SandboxEnded     string   `json:"sandboxEnded,omitempty" jsonschema:"Why this call's sandbox ended as it answered: its files and state are gone, and the handle's next call starts a new sandbox."`
	Isolation        string   `json:"isolation"`
	SoftwareIdentity string   `json:"softwareIdentity" jsonschema:"The image the daemon says ran the code, or empty when it states none."`
	RecordSHA256     string   `json:"recordSha256" jsonschema:"SHA-256 of the run record the client checked; get_record returns it."`
	Receipt          *Receipt `json:"receipt,omitempty" jsonschema:"What became of the run's record: absent when no receipts are configured."`
	Pictures         []string `json:"pictures,omitempty" jsonschema:"The titles of the images returned beside this result, in order."`
	PictureNotes     []string `json:"pictureNotes,omitempty" jsonschema:"What became of output lines meant as pictures that gave no image."`
	PictureLinks     []string `json:"pictureLinks,omitempty" jsonschema:"Where the user can open each picture, in the order of pictures."`

	pics []Picture
}

func (o runOutput) attached() []Picture { return o.pics }

type openOutput struct {
	Summary   string   `json:"summary"`
	Sandbox   string   `json:"sandbox"`
	Languages []string `json:"languages"`
	Isolation string   `json:"isolation"`
	ExpiresAt string   `json:"expiresAt" jsonschema:"When the daemon ends the sandbox, RFC 3339 UTC; a call after it runs in a new one, with freshSandbox set."`
	Kit       string   `json:"kit,omitempty" jsonschema:"The kit written into the sandbox with its first run_code call, and again into any sandbox that replaces it."`
}

type handleInput struct {
	Sandbox string `json:"sandbox" jsonschema:"The handle open_sandbox returned."`
}

type closeOutput struct {
	Summary        string `json:"summary"`
	Sandbox        string `json:"sandbox"`
	Deleted        bool   `json:"deleted" jsonschema:"The daemon confirmed the sandbox is gone. The handle stops working either way."`
	Receipts       string `json:"receipts,omitempty" jsonschema:"With receipts on, after a confirmed deletion: closed (every signed close of the handle's sandboxes is stored, so their receipt files are whole), incomplete, or unknown (an earlier sandbox of the handle was still being closed)."`
	ReceiptsReason string `json:"receiptsReason,omitempty"`
}

type recordInput struct {
	RecordSHA256 string `json:"recordSha256" jsonschema:"The recordSha256 a run_code result or failure gave."`
}

type recordJSON struct {
	Version          int    `json:"version"`
	RequestSHA256    string `json:"requestSha256"`
	ResultSHA256     string `json:"resultSha256"`
	Provider         string `json:"provider"`
	Isolation        string `json:"isolation"`
	Environment      string `json:"environment"`
	SoftwareIdentity string `json:"softwareIdentity"`
	SoftwareRuleID   string `json:"softwareRuleId"`
	Policy           string `json:"policy"`
	StartedUnixMs    int64  `json:"startedUnixMs"`
	EndedUnixMs      int64  `json:"endedUnixMs"`
	Session          string `json:"session"`
	Sequence         uint64 `json:"sequence"`
	PreviousSHA256   string `json:"previousSha256"`
	Unanswered       string `json:"unanswered"`
	SHA256           string `json:"sha256"`
}

type recordOutput struct {
	Summary string     `json:"summary"`
	Record  recordJSON `json:"record"`
	Receipt *Receipt   `json:"receipt,omitempty" jsonschema:"Where the signed record is kept, when receipts are configured."`
}

type daemonInfo struct {
	Provider         string   `json:"provider"`
	Isolation        string   `json:"isolation"`
	Protocol         uint32   `json:"protocol"`
	Languages        []string `json:"languages" jsonschema:"What run_code without a sandbox can run."`
	Sessions         bool     `json:"sessions"`
	SandboxLanguages []string `json:"sandboxLanguages,omitempty" jsonschema:"What a sandbox from open_sandbox can run."`
}

type infoOutput struct {
	Summary          string      `json:"summary"`
	Server           string      `json:"server"`
	Version          string      `json:"version"`
	Tools            []string    `json:"tools"`
	SurfaceDigest    string      `json:"surfaceDigest"`
	StaleCheck       string      `json:"staleCheck"`
	MinimumIsolation string      `json:"minimumIsolation"`
	SoftwareRule     string      `json:"softwareRule,omitempty"`
	Daemon           *daemonInfo `json:"daemon,omitempty"`
	DaemonError      string      `json:"daemonError,omitempty"`
}

func (s *Server) register() {
	langs := names(s.cfg.Languages)
	runSchema, err := jsonschema.For[runInput](nil)
	if err != nil {
		panic(err)
	}
	runSchema.Properties["code"].MinLength = ptr(1)
	runSchema.Properties["language"].Enum = anys(langs)
	runSchema.Properties["language"].Description = fmt.Sprintf("The language of code: %s. Default %q; in a sandbox, the first language it runs; on a daemon that runs JavaScript snippets only, JavaScript.", joinNames(s.cfg.Languages), langs[0])
	runSchema.Properties["files"].MaxItems = ptr(MaxFiles)
	runSchema.Properties["sandbox"].Pattern = `^sbx_[A-Za-z0-9_-]{22}$`
	openSchema, err := jsonschema.For[openInput](nil)
	if err != nil {
		panic(err)
	}
	if len(s.cfg.Kits) == 0 {
		// With nothing configured, the surface is exactly what it was before kits.
		delete(runSchema.Properties, "kit")
		if openSchema, err = jsonschema.For[struct{}](nil); err != nil {
			panic(err)
		}
	} else {
		var kits []string
		var lines []string
		for _, k := range s.cfg.Kits {
			kits = append(kits, k.Name)
			lines = append(lines, k.Name+": "+k.Description)
		}
		note := ""
		if s.cfg.KitsNote != "" {
			note = s.cfg.KitsNote + " "
		}
		desc := "A kit whose files are written into the working directory before the code runs. " + note + strings.Join(lines, " ")
		for _, schema := range []*jsonschema.Schema{runSchema, openSchema} {
			schema.Properties["kit"].Enum = anys(kits)
			schema.Properties["kit"].Description = desc
		}
		// Said once, under run_code: the kit list is long, and both tools travel in every list.
		openSchema.Properties["kit"].Description = "A kit written into the sandbox with its first run_code call (and again if the sandbox is replaced); run_code's kit says what each kit holds."
	}
	handleSchema, err := jsonschema.For[handleInput](nil)
	if err != nil {
		panic(err)
	}
	handleSchema.Properties["sandbox"].Pattern = `^sbx_[A-Za-z0-9_-]{22}$`
	recordSchema, err := jsonschema.For[recordInput](nil)
	if err != nil {
		panic(err)
	}
	recordSchema.Properties["recordSha256"].Pattern = `^[0-9a-f]{64}$`

	runOutSchema, err := jsonschema.For[runOutput](nil)
	if err != nil {
		panic(err)
	}
	if s.cfg.Pictures == nil {
		delete(runOutSchema.Properties, "pictures")
		delete(runOutSchema.Properties, "pictureNotes")
	}
	if s.cfg.Pictures == nil || s.cfg.PictureLink == nil {
		delete(runOutSchema.Properties, "pictureLinks")
	}
	openOutSchema, err := jsonschema.For[openOutput](nil)
	if err != nil {
		panic(err)
	}
	if len(s.cfg.Kits) == 0 {
		delete(openOutSchema.Properties, "kit")
	}

	addTool(s, &mcp.Tool{
		Name:  "run_code",
		Title: "Run code in plimsoll",
		Description: fmt.Sprintf("Run %s in an isolated sandbox with no network access and return its exit code, stdout and stderr. ", joinNames(s.cfg.Languages)) +
			"The value of the code's last expression is printed, as in a notebook, so the last line can simply name what you want to see. " +
			"Without sandbox, the call uses a fresh sandbox and interpreter and nothing is kept. With sandbox set to a handle from open_sandbox, the call runs in that sandbox, " +
			"which keeps an interpreter per language and its files between calls: stateKept and filesPersist say what can survive to the next call, freshInterpreter and freshSandbox say what did not survive to this one. " +
			"Calls to one sandbox run one at a time, so send a call that needs an earlier call's effect only after that call has answered. " +
			"To give the code data, such as another tool's output, pass it in files rather than pasting it into the code. " +
			"A program that fails is a result with its exit code. A tool error says in ran whether anything ran: \"no\" is safe to retry after fixing the cause, \"maybe\" is not. " +
			"Every result names the isolation tier the code ran behind and the run record's sha256." + runLimit(s.cfg.RunTimeout),
		InputSchema:  runSchema,
		OutputSchema: runOutSchema,
		Annotations:  &mcp.ToolAnnotations{DestructiveHint: ptr(true), OpenWorldHint: ptr(false)},
	}, s.runCode)

	addTool(s, &mcp.Tool{
		Name:  "open_sandbox",
		Title: "Open a plimsoll sandbox that keeps state",
		Description: "Opens a sandbox whose run_code calls keep files and an interpreter per language between calls, and returns its handle once the daemon has opened it; " +
			"pass the handle as run_code's sandbox, and close it with close_sandbox when done. " +
			fmt.Sprintf("At most %d are open at once: past that the open is refused, nothing is closed for room, and the refusal lists the idle sandboxes in idleSandboxes, which close_sandbox can delete to make room. ", s.cfg.MaxSandboxes) +
			shareSentence(s.cfg) +
			"Fails, saying so, when the daemon keeps no sessions; run_code without sandbox still works then.",
		InputSchema:  openSchema,
		OutputSchema: openOutSchema,
		Annotations:  &mcp.ToolAnnotations{DestructiveHint: ptr(false), OpenWorldHint: ptr(false)},
	}, s.openSandbox)

	addTool(s, &mcp.Tool{
		Name:        "close_sandbox",
		Title:       "Close a plimsoll sandbox",
		Description: "Closes a sandbox from open_sandbox, deleting its files and interpreter state. The handle stops working; deleted says whether the daemon confirmed the deletion.",
		InputSchema: handleSchema,
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(true), IdempotentHint: true, OpenWorldHint: ptr(false)},
	}, s.closeSandbox)

	addTool(s, &mcp.Tool{
		Name:  "get_record",
		Title: "Get a run record",
		Description: "Returns the run record of a run_code call by its sha256: digests of the request as sent and the result as returned, " +
			"the provider, isolation tier, image identity and policy the daemon stated, and the start and end times. " +
			fmt.Sprintf("The client recomputed it before the result was returned. This server keeps the last %d records in memory until it restarts.", KeptRecords),
		InputSchema: recordSchema,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: ptr(false)},
	}, s.getRecord)

	addTool(s, &mcp.Tool{
		Name:  "server_info",
		Title: "Describe this server and its daemon",
		Description: "Returns this server's version and its tools, with a digest of their names, descriptions and schemas, and what the plimsoll daemon states: " +
			"its provider, isolation tier, languages and whether it keeps sessions. If a tool listed here is not one you can call, your host's tool list is out of date.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: ptr(false)},
	}, s.serverInfo)
}

func anys(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// receiptFor says what became of a checked run's record, given the error that came
// with its result (nil, or ErrNotRecorded); nil when nothing records.
func (s *Server) receiptFor(rec *sandbox.RunRecord, err error) *Receipt {
	switch {
	case s.receipts != nil && rec != nil:
		return s.receipts.receiptOf(rec.SHA256, err)
	case s.cfg.Recorder == nil:
		return nil
	case err != nil:
		return &Receipt{Status: "failed", Reason: err.Error()}
	default:
		return &Receipt{Status: "stored"}
	}
}

// admitRun admits one call that runs code (run_code's, or an ExtendRun tool's): refused
// when its receipts could not be kept or the server already holds maxOutstanding such
// calls; release gives the place back.
func (s *Server) admitRun() (release func(), f *failure) {
	if f := s.full(); f != nil {
		return nil, f
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.stopped:
		return nil, shuttingDown
	case s.outstanding >= maxOutstanding:
		return nil, refused(sandbox.RefusalCapacity, "this server already holds %d calls that run code; wait for their answers", maxOutstanding)
	}
	s.outstanding++
	return func() {
		s.mu.Lock()
		s.outstanding--
		s.mu.Unlock()
	}, nil
}

// full refuses, before anything is sent, work whose receipts could not be kept.
func (s *Server) full() *failure {
	if s.receipts == nil {
		return nil
	}
	if err := s.receipts.Full(); err != nil {
		return refused(sandbox.RefusalCapacity, "%v", err)
	}
	return nil
}

// checkInput refuses, before anything is sent, a call this server would not send. An
// omitted language is returned empty: a fresh call takes the server's first, a sandbox
// call its sandbox's first.
func (s *Server) checkInput(in runInput) (sandbox.Language, []sandbox.File, *failure) {
	lang := sandbox.Language(in.Language)
	if lang != "" && !slices.Contains(s.cfg.Languages, lang) {
		return "", nil, refused(sandbox.RefusalRequest, "this server runs %s, not %s", joinNames(s.cfg.Languages), in.Language)
	}
	if len(in.Code) > MaxCodeBytes {
		return "", nil, refused(sandbox.RefusalRequest, "the code is %d bytes; this server takes at most %d", len(in.Code), MaxCodeBytes)
	}
	total := 0
	files := make([]sandbox.File, 0, len(in.Files))
	for _, f := range in.Files {
		if f.Path == ".plimsoll" || strings.HasPrefix(f.Path, ".plimsoll/") {
			return "", nil, refused(sandbox.RefusalRequest, "%q is under .plimsoll/, which the sandbox's runner reserves", f.Path)
		}
		total += len(f.Content)
		files = append(files, sandbox.File{Path: f.Path, Content: f.Content})
	}
	if total > MaxFileBytes {
		return "", nil, refused(sandbox.RefusalRequest, "the files hold %d bytes; this server takes at most %d", total, MaxFileBytes)
	}
	if in.Kit == "" {
		return lang, files, nil
	}
	k := s.kit(in.Kit)
	if k == nil {
		return "", nil, refused(sandbox.RefusalRequest, "this server has no kit %q", in.Kit)
	}
	withKit, f := withKitFiles(k, files, len(in.Code))
	return lang, withKit, f
}

// kit is the configured kit named name, or nil.
func (s *Server) kit(name string) *Kit {
	for i := range s.cfg.Kits {
		if s.cfg.Kits[i].Name == name {
			return &s.cfg.Kits[i]
		}
	}
	return nil
}

// withKitFiles puts k's files before a call's own. A call file at a kit file's path
// is dropped when its content is the same (another kit sharing a library) and refused
// otherwise; so is a call the kit leaves no room for.
func withKitFiles(k *Kit, files []sandbox.File, code int) ([]sandbox.File, *failure) {
	total, mine := code, map[string]string{}
	for _, f := range k.Files {
		mine[f.Path] = f.Content
		total += len(f.Content)
	}
	out := slices.Clone(k.Files)
	for _, f := range files {
		if content, ok := mine[f.Path]; ok {
			if content != f.Content {
				return nil, refused(sandbox.RefusalRequest, "%q is a file of kit %s; give your file another path", f.Path, k.Name)
			}
			continue
		}
		out = append(out, f)
		total += len(f.Content)
	}
	// The runner's own two files need a little room too.
	if limit := sandbox.MaxProjectBytes - (16 << 10); total > limit || len(out) > MaxFiles {
		return nil, refused(sandbox.RefusalRequest, "kit %s and this call's files and code hold %d bytes in %d files; a call takes at most %d bytes in %d files", k.Name, total, len(out), limit, MaxFiles)
	}
	return out, nil
}

func (s *Server) runCode(ctx context.Context, in runInput) (runOutput, *failure) {
	lang, files, f := s.checkInput(in)
	if f != nil {
		return runOutput{}, f
	}
	release, f := s.admitRun()
	if f != nil {
		return runOutput{}, f
	}
	defer release()
	if in.Sandbox == "" {
		return s.runFresh(ctx, lang, in.Code, files)
	}
	return s.runIn(ctx, in.Sandbox, lang, in.Code, files)
}

func (s *Server) output(ctx context.Context, lang sandbox.Language, exit int, timedOut bool, stdout, stderr string, truncated bool, isolation sandbox.IsolationClass, software string, rec *sandbox.RunRecord) runOutput {
	out := runOutput{Language: string(lang), ExitCode: exit, TimedOut: timedOut, Isolation: isolation.String(), SoftwareIdentity: software}
	if s.cfg.Pictures != nil {
		var pics []Picture
		stdout, stderr, pics, out.PictureNotes = s.cfg.Pictures(stdout, stderr)
		out.pics, out.Pictures = keepPictures(pics, &out.PictureNotes)
		out.PictureLinks = s.pictureLinks(out.pics)
	}
	var c1, c2 bool
	out.Stdout, c1 = cut(stdout, s.cfg.MaxOutputBytes)
	out.Stderr, c2 = cut(stderr, s.cfg.MaxOutputBytes)
	out.Truncated = truncated || c1 || c2
	if rec != nil {
		s.keep(ctx, rec)
		out.RecordSHA256 = rec.SHA256
	}
	return out
}

func summarize(out *runOutput, sandboxHandle string) {
	how := fmt.Sprintf("exited %d", out.ExitCode)
	if out.TimedOut {
		how = fmt.Sprintf("timed out (exit %d)", out.ExitCode)
	}
	where := "It ran in a fresh sandbox; nothing is kept."
	if sandboxHandle != "" {
		where = "It ran in sandbox " + sandboxHandle
		if out.FreshSandbox {
			where += ", newly opened (no earlier file is there)"
		}
		if out.SandboxReplaced != "" {
			where += "; the handle's earlier sandbox " + out.SandboxReplaced + ", so this call ran in a new one"
		}
		if out.FreshInterpreter {
			where += ", in a new interpreter (nothing earlier calls defined exists)"
		}
		where += fmt.Sprintf("; state kept for the next call: %t, files kept: %t.", out.StateKept, out.FilesPersist)
		if out.SandboxEnded != "" {
			where += " This call's sandbox ended as it answered (" + out.SandboxEnded + "): its files and state are gone; the handle's next run_code starts a new sandbox."
		}
	}
	cutNote := ""
	if out.Truncated {
		cutNote = " Output was cut; truncated is true."
	}
	if out.Receipt != nil && out.Receipt.Status == "failed" {
		cutNote += " The code ran and this is its checked result, but keeping its record failed: " + out.Receipt.Reason + "."
	}
	switch n := len(out.Pictures); {
	case n == 1:
		cutNote += " One picture is attached as an image."
	case n > 1:
		cutNote += fmt.Sprintf(" %d pictures are attached as images.", n)
	}
	if len(out.PictureLinks) > 0 {
		cutNote += " pictureLinks says where the user can open each."
	}
	if len(out.PictureNotes) > 0 {
		cutNote += " Some picture lines gave no image; pictureNotes says why."
	}
	out.Summary = fmt.Sprintf("The %s code %s behind the %q isolation tier (%s). %s%s Run record sha256 %s; get_record returns the record.",
		out.Language, how, out.Isolation, tierNote, where, cutNote, out.RecordSHA256)
}

// runFresh runs the code once as a project: the files, the code and a runner that
// prints its last expression, as a session cell does. On a daemon that runs only
// snippets (wasm), JavaScript runs as a snippet instead.
func (s *Server) runFresh(ctx context.Context, lang sandbox.Language, code string, files []sandbox.File) (runOutput, *failure) {
	info, err := s.describe(ctx)
	if err != nil {
		return runOutput{}, s.failed(ctx, err)
	}
	if lang == "" {
		lang = s.cfg.Languages[0]
		if !info.SupportsProject && slices.Contains(s.cfg.Languages, sandbox.LanguageJavaScript) {
			lang = sandbox.LanguageJavaScript
		}
	}
	if !info.SupportsProject {
		if lang != sandbox.LanguageJavaScript || len(files) > 0 {
			return runOutput{}, refused(sandbox.RefusalUnsupported, "the daemon (%s) runs JavaScript snippets only, without files", info.Sandbox)
		}
		r, err := s.remote.RunJavaScript(ctx, sandbox.Request{Code: snippetRunner(code), Timeout: s.cfg.RunTimeout, MinimumIsolation: s.cfg.MinimumIsolation, Software: s.cfg.Software})
		if !answered(err, r.Record) {
			s.forgetDescribeOn(err)
			return runOutput{}, s.failed(ctx, err)
		}
		out := s.output(ctx, lang, r.ExitCode, r.TimedOut, r.Stdout, r.Stderr, r.StdoutTruncated || r.StderrTruncated, r.Isolation, r.SoftwareIdentity, r.Record)
		out.Receipt = s.receiptFor(r.Record, err)
		summarize(&out, "")
		return out, nil
	}
	if langs := s.offered(info.Environments.Project); !slices.Contains(langs, lang) {
		return runOutput{}, refused(sandbox.RefusalUnsupported, "the daemon's image has no %s interpreter (it runs %v)", lang, info.Environments.Project.Languages)
	}
	runner := runners[lang]
	req := sandbox.ProjectRequest{
		Files:            append(slices.Clone(files), sandbox.File{Path: runner.file, Content: code}, sandbox.File{Path: runner.path, Content: runner.source}),
		Steps:            []string{runner.step},
		Timeout:          s.cfg.RunTimeout,
		MinimumIsolation: s.cfg.MinimumIsolation,
		Software:         s.cfg.Software,
	}
	r, err := s.remote.RunProject(ctx, req)
	if !answered(err, r.Record) {
		s.forgetDescribeOn(err)
		return runOutput{}, s.failed(ctx, err)
	}
	// From here the result checked; only keeping its record can have failed (err).
	if len(r.Steps) == 0 {
		// No step report: the outcome says what ended the run, not whether the code
		// started, so there is no exit code to give; the checked record is kept.
		f := &failure{Ran: "maybe", Summary: fmt.Sprintf("The run ended %s without a step report (%s); the code may have run. It was not retried.", r.Outcome, r.Detail)}
		if r.Record != nil {
			s.keep(ctx, r.Record)
			f.RecordSHA256 = r.Record.SHA256
		}
		return runOutput{}, f
	}
	st := r.Steps[0]
	out := s.output(ctx, lang, st.ExitCode, st.TimedOut || r.Outcome == sandbox.ProjectOutcomeTimedOut, st.Stdout, st.Stderr, st.StdoutTruncated || st.StderrTruncated, r.Isolation, r.SoftwareIdentity, r.Record)
	out.Receipt = s.receiptFor(r.Record, err)
	summarize(&out, "")
	return out, nil
}

func (s *Server) getRecord(ctx context.Context, in recordInput) (recordOutput, *failure) {
	s.mu.Lock()
	r := s.records[recordKey(ctx, in.RecordSHA256)]
	s.mu.Unlock()
	if r == nil {
		return recordOutput{}, refused(sandbox.RefusalRequest, "this server keeps no record %s: it keeps the last %d records it checked, in memory, until it restarts", in.RecordSHA256, KeptRecords)
	}
	rec := recordJSON{
		Version: r.Version, RequestSHA256: r.RequestSHA256, ResultSHA256: r.ResultSHA256, Provider: r.Provider, Isolation: r.Isolation,
		Environment: r.Environment, SoftwareIdentity: r.SoftwareIdentity, SoftwareRuleID: r.SoftwareRuleID, Policy: r.Policy,
		StartedUnixMs: r.Started.UnixMilli(), EndedUnixMs: r.Ended.UnixMilli(), Session: r.Session, Sequence: r.Sequence,
		PreviousSHA256: r.PreviousSHA256, Unanswered: r.Unanswered, SHA256: r.SHA256,
	}
	software := r.SoftwareIdentity
	if software == "" {
		software = "not stated"
	}
	summary := fmt.Sprintf("Run record %s (version %d): provider %s, isolation tier %q, software identity %s, ran %s to %s",
		r.SHA256, r.Version, r.Provider, r.Isolation, software, r.Started.UTC().Format(time.RFC3339Nano), r.Ended.UTC().Format(time.RFC3339Nano))
	if r.Session != "" {
		summary += fmt.Sprintf(", call %d of a session", r.Sequence)
	}
	summary += "."
	if r.Unanswered != "" {
		summary += fmt.Sprintf(" The call ended without an answer (%s); it may have run.", r.Unanswered)
	}
	out := recordOutput{Summary: summary, Record: rec}
	if s.receipts != nil {
		out.Receipt = s.receipts.receiptOf(r.SHA256, nil)
		if out.Receipt.Status == "stored" {
			out.Summary += fmt.Sprintf(" Its signed line is %s line %d (key %s…; session %s); plimsoll-attest verify-entry checks that line on its own.", out.Receipt.File, out.Receipt.Line, prefix(out.Receipt.KeyID), out.Receipt.Session)
		}
	}
	return out, nil
}

func (s *Server) serverInfo(ctx context.Context, _ struct{}) (infoOutput, *failure) {
	tools := make([]string, len(s.tools))
	for i, t := range s.tools {
		tools[i] = t.Name
	}
	slices.Sort(tools)
	out := infoOutput{
		Server: Name, Version: Version, Tools: tools, SurfaceDigest: SurfaceDigest(s.tools),
		StaleCheck: "Compare tools with the tools you can call from this server. If they differ, or a description differs from what you were given, " +
			"tell the user their MCP host is showing an old tool list and to reconnect or restart the plimsoll server.",
		MinimumIsolation: s.cfg.MinimumIsolation.String(),
		SoftwareRule:     s.cfg.Software.ID(),
	}
	// Read the daemon afresh: this is where a user checks what it states now.
	info, err := s.remote.Describe(ctx)
	line := ""
	if err != nil {
		out.DaemonError = err.Error()
		line = "The daemon did not answer Describe: " + err.Error()
	} else {
		s.mu.Lock()
		s.info = &info
		s.mu.Unlock()
		out.Daemon = &daemonInfo{Provider: info.Sandbox, Isolation: info.Isolation.String(), Protocol: info.Protocol, Languages: names(s.offered(info.Environments.Project)), Sessions: info.SupportsSessions}
		if !info.SupportsProject {
			out.Daemon.Languages = []string{string(sandbox.LanguageJavaScript)}
		}
		keeps := "does not keep"
		if info.SupportsSessions {
			keeps = "keeps"
			out.Daemon.SandboxLanguages = names(s.offered(info.SessionEnvironment))
		}
		line = fmt.Sprintf("The daemon runs %s at the %q tier (%s) and %s sessions.", info.Sandbox, info.Isolation, tierNote, keeps)
	}
	out.Summary = fmt.Sprintf("%s MCP server %s, tools %v, surface digest %s. %s", Name, Version, tools, out.SurfaceDigest, line)
	return out, nil
}

// shareSentence tells a remote connection its app's share of the cap (connectionShare).
func shareSentence(cfg Config) string {
	if !cfg.RequireGrant || cfg.MaxSandboxes < 2 {
		return ""
	}
	return fmt.Sprintf("Connections of the same approved app may hold at most %d of them together, so one app alone never fills the server. ", cfg.MaxSandboxes-1)
}

// runLimit states a call's time limit where a reader of run_code looks for it.
func runLimit(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return fmt.Sprintf(" Each call may run for %d seconds; one that runs longer stops with timedOut set, and in a sandbox its interpreter state is lost while its files stay.", int(d.Round(time.Second).Seconds()))
}
