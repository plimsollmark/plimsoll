package main

// The files a run publishes beside the page, and what the page is drawn from.
//
// Published by the run (the raw evidence):
//
//	bundle.jsonl          every run's request, answer and run record, signed by the harness
//	harness.pub           the harness's public key
//	observations.dsse.json what the harness saw outside the runs (the daemon's Describe, its
//	                      audit lines and /metrics, the image, the keys it gave the daemon,
//	                      the SHA-256 of every other file here), signed by the same key and
//	                      naming the runs' records as its subjects
//	stub.jsonl            every request the stub API received, headers included
//	grants.json           the grants file the daemon read
//	seccomp-default.json  the default seccomp profile, as the daemon pinned it
//	seccomp-sdk.json      the sdk_env variant the daemon derived and pinned
//
// Drawn from them by derive (and rechecked by -verify): evidence.json and index.html.

const (
	observationsType = "https://plimsollmark.github.io/plimsoll/examples/sdk-grants/observations/v1"

	fileBundle   = "bundle.jsonl"
	filePub      = "harness.pub"
	fileObserved = "observations.dsse.json"
	fileStub     = "stub.jsonl"
	fileGrants   = "grants.json"
	fileDefault  = "seccomp-default.json"
	fileVariant  = "seccomp-sdk.json"
	fileEvidence = "evidence.json"
	filePage     = "index.html"
)

// hashedFiles are the published files whose SHA-256 the observations statement names.
var hashedFiles = []string{fileStub, fileGrants, fileDefault, fileVariant}

// observations is the predicate of the harness's signed statement about the run.
type observations struct {
	Date    string            `json:"date"`   // the run's date, UTC
	Commit  string            `json:"commit"` // plimsoll's commit the run was made at
	Daemon  daemonFacts       `json:"daemon"`
	Image   imageFacts        `json:"image"`
	Pins    []pin             `json:"pins"`  // requirements.txt, as the image was built from it
	Keys    map[string]string `json:"keys"`  // profile name -> the key the daemon held for it
	Files   map[string]string `json:"files"` // published file -> SHA-256 of its bytes
	Runs    []runFacts        `json:"runs"`
	Metrics []metricSeries    `json:"metrics"`
}

type daemonFacts struct {
	Provider  string `json:"provider"`
	Isolation string `json:"isolation"`
	Policy    string `json:"policy"` // Describe's policy: the default profile and the sdk_env variant
	Protocol  uint32 `json:"protocol"`
}

type imageFacts struct {
	Tag    string `json:"tag"`
	ID     string `json:"id"`
	Base   string `json:"base"`
	BaseID string `json:"base_id"`
}

// pin is one line of requirements.txt.
type pin struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// runFacts is one run as the harness saw it besides its record: which profile it
// selected, the trace id it sent, and the daemon's audit line for it.
type runFacts struct {
	Name    string    `json:"name"`
	Profile string    `json:"profile,omitempty"`
	TraceID string    `json:"trace_id"`
	Record  string    `json:"record"` // the run record's own SHA-256
	Audit   auditLine `json:"audit"`
}

// auditLine is the fields of the daemon's audit line for a run that the page uses.
type auditLine struct {
	Msg             string `json:"msg"`
	GrantProfile    string `json:"grant_profile"`
	Sandbox         string `json:"sandbox"`
	Isolation       string `json:"isolation"`
	Outcome         string `json:"outcome"`
	HostCalls       int    `json:"host_calls"`
	HostCallsDenied int    `json:"host_calls_denied"`
}

// metricSeries is one host-call series of the daemon's /metrics after every run.
type metricSeries struct {
	Profile string  `json:"profile"`
	Method  string  `json:"method"`
	Route   string  `json:"route"`
	Count   int     `json:"count"`
	SumSec  float64 `json:"sum_seconds"`
}

// evidence is everything the page states, derived from the published files alone.
type evidence struct {
	Date     string        `json:"date"`
	Commit   string        `json:"commit"`
	KeyID    string        `json:"key_id"`
	Daemon   daemonFacts   `json:"daemon"`
	Image    imageFacts    `json:"image"`
	Pins     []pin         `json:"pins"`
	Profiles []profileView `json:"profiles"`
	Seccomp  seccompView   `json:"seccomp"`
	Runs     []runView     `json:"runs"`
	Stub     stubSummary   `json:"stub"`
	Checks   []check       `json:"checks"`
	Files    []fileView    `json:"files"`
}

type fileView struct {
	Name   string `json:"name"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// profileView is one grant profile of grants.json, the fields the page shows.
type profileView struct {
	Name        string              `json:"name"`
	BaseURL     string              `json:"base_url"`
	Allow       []string            `json:"allow"`
	PassHeaders []string            `json:"pass_headers,omitempty"`
	SDKEnv      [][2]string         `json:"sdk_env"`
	RouteBytes  map[string]int64    `json:"route_max_request_bytes,omitempty"`
	RouteTypes  map[string][]string `json:"route_content_types,omitempty"`
	MaxRequest  int64               `json:"max_request_bytes,omitempty"`
	TokenEnv    string              `json:"token_env"`
	Callers     []string            `json:"allowed_callers"`
}

// seccompView is the two profiles by digest and what the variant changes.
type seccompView struct {
	Default      string        `json:"default"` // seccomp:sha256:...
	Variant      string        `json:"variant"`
	DefaultBytes int           `json:"default_bytes"`
	VariantBytes int           `json:"variant_bytes"`
	Added        []seccompRule `json:"added"`
	Removed      []seccompRule `json:"removed"`
	Unchanged    int           `json:"unchanged"` // syscall rules the two share
}

// seccompRule is one allow rule for one syscall, as a profile writes it.
type seccompRule struct {
	Syscall string `json:"syscall"`
	Action  string `json:"action"`
	Args    string `json:"args"`    // the argument conditions, written out; "" is any arguments
	Comment string `json:"comment"` // the rule's own "//" comment, when it has one
}

// runView is one run: its record, what the guest reported, and every call.
type runView struct {
	Name         string            `json:"name"`
	Title        string            `json:"title"`
	Profile      string            `json:"profile,omitempty"`
	TraceID      string            `json:"trace_id"`
	Record       recordView        `json:"record"`
	PolicyIs     string            `json:"policy_is"` // "variant" or "default"
	Outcome      string            `json:"outcome"`
	ExitCode     int               `json:"exit_code"`
	Python       string            `json:"python"`
	SDKs         map[string]string `json:"sdks"`
	Environment  [][2]string       `json:"environment"`  // the guest's own environment, all of it
	SDKEnv       [][2]string       `json:"sdk_env"`      // the variables the profile's sdk_env set, as the guest saw them
	Processes    int               `json:"processes"`    // processes whose environment the guest read
	Unreadable   int               `json:"unreadable"`   // processes whose environment it could not read
	Refused      []string          `json:"refused"`      // those processes: pid, command, the error the guest got
	KeyInGuest   int               `json:"key_in_guest"` // times any key the daemon held appears in the run's stored request and answer
	Sockets      map[string]string `json:"sockets"`
	Calls        []callView        `json:"calls"`
	Audit        auditLine         `json:"audit"`
	Metrics      []metricSeries    `json:"metrics"`
	StubRequests int               `json:"stub_requests"`
}

type recordView struct {
	SHA256      string `json:"sha256"`
	Request     string `json:"request_sha256"`
	Result      string `json:"result_sha256"`
	Provider    string `json:"provider"`
	Isolation   string `json:"isolation"`
	Environment string `json:"environment"`
	Policy      string `json:"policy"`
	StartedMs   int64  `json:"started_unix_ms"`
	EndedMs     int64  `json:"ended_unix_ms"`
}

// callView is one call the guest's library made, beside what the stub received for it.
type callView struct {
	Name    string       `json:"name"`
	Title   string       `json:"title"`
	URL     string       `json:"url"` // as the library sent it, to the local address
	Status  int          `json:"status"`
	Answer  string       `json:"answer,omitempty"`
	Reached bool         `json:"reached"` // the stub received it
	Target  string       `json:"target,omitempty"`
	Headers []headerRow  `json:"headers"`
	Stream  *streamView  `json:"stream,omitempty"`
	Upload  *uploadView  `json:"upload,omitempty"`
	Refusal *refusalView `json:"refusal,omitempty"`
}

// headerRow is one header of a call: what the library sent and what the API received.
// Fate is passed (copied because the profile lists it), replaced (the broker's value in
// place of the library's), same (a header the broker sets itself, to the library's value),
// dropped (sent, never received), added (received, never sent: the broker's own) or
// leaked (sent and received though the profile does not pass it: a finding).
type headerRow struct {
	Name     string `json:"name"`
	Sent     string `json:"sent,omitempty"`
	Received string `json:"received,omitempty"`
	Fate     string `json:"fate"`
}

type streamView struct {
	ContentType string      `json:"content_type"`
	Pieces      []pieceView `json:"pieces"`
	BeforeNext  int         `json:"before_next"` // pieces that reached the guest before the stub wrote the next one
	Compared    int         `json:"compared"`    // pieces that have a next one to compare with
	FirstToLast float64     `json:"first_to_last_ms"`
	WrittenSpan float64     `json:"written_span_ms"`
	MaxDelay    float64     `json:"max_delay_ms"`
	Matched     int         `json:"matched"`  // pieces whose text or event type is the stub's write paired with it
	Unpaired    []pieceView `json:"unpaired"` // the stub's writes the library handed over as no piece (OpenAI's data: [DONE])
}

type pieceView struct {
	N         int     `json:"n"`
	Event     string  `json:"event"`
	WrittenMs float64 `json:"written_ms"` // since the stub wrote the first piece
	ArrivedMs float64 `json:"arrived_ms"` // since the stub wrote the first piece
	NextMs    float64 `json:"next_written_ms,omitempty"`
}

type uploadView struct {
	Bytes       int64      `json:"bytes"`
	GuestSHA256 string     `json:"guest_sha256"`
	StubSHA256  string     `json:"stub_sha256"`
	BodyBytes   int64      `json:"body_bytes"`
	Parts       []stubPart `json:"parts"`
	RouteLimit  int64      `json:"route_limit"`
	FileID      string     `json:"file_id"`
}

type refusalView struct {
	Error       string `json:"error"`
	Status      int    `json:"status"`
	ShouldRetry string `json:"x_should_retry"`
	Body        string `json:"body"`
	RetryCount  string `json:"retry_count"`   // x-stainless-retry-count on the attempt that raised
	StubAtRoute int    `json:"stub_at_route"` // requests the stub received at the refused route
}

// stubSummary counts what the stub received across the whole run.
type stubSummary struct {
	Requests     int `json:"requests"`
	DummyKeyHits int `json:"dummy_key_hits"` // headers or bodies holding a key a profile put in sdk_env
	BrokerKeyOK  int `json:"broker_key_ok"`  // requests whose Authorization is the broker's key for that API
	Undeclared   int `json:"undeclared"`     // requests to a route no profile allows
}

// check is one claim the page makes, with whether the evidence supports it.
type check struct {
	ID     string `json:"id"`
	Says   string `json:"says"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail"`
}
