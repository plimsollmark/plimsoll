// Package grants resolves named host-API capability profiles for the RPC server.
// Profiles are SERVER-side config: an RPC caller selects one by name (the
// grant_profile request field), but BaseURL, the allowed routes, and the token all
// live here — a caller can never define them. This is the safe way to expose the
// per-run sandbox.HostAPIGrant capability over RPC (vs. letting callers ship a raw
// grant, which would make the server a confused deputy and spread tokens through
// request logs).
package grants

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// Registry maps a profile name to a ready, validated host-API grant.
type Registry struct {
	profiles map[string]*Profile
}

// MaxProfileNameBytes is shared with the RPC edge so every configured profile is
// selectable and attacker-controlled names cannot amplify error responses.
const MaxProfileNameBytes = 128

// AdviceMode is a profile's opt-in for Prospector efficiency advice (roadmap
// Phase 2). It routes findings by who can act on them and is OFF by default: a
// profile that never sets `advice` has its traffic left unanalyzed.
type AdviceMode int

const (
	// AdviceOff computes no advice at all — the default.
	AdviceOff AdviceMode = iota
	// AdviceOperator computes findings but keeps them on the operator surface
	// (logs, audit, dashboards); nothing is returned to the caller.
	AdviceOperator
	// AdviceCaller additionally returns agent-fixable findings (a better route the
	// profile already exposes) in the run result, so a product may feed them to the
	// model. API-change findings still go only to the operator surface.
	AdviceCaller
)

// String is the stable config/log name of the mode.
func (m AdviceMode) String() string {
	switch m {
	case AdviceOperator:
		return "operator"
	case AdviceCaller:
		return "caller"
	default:
		return "off"
	}
}

// parseAdvice maps the profile's `advice` config value to an AdviceMode. An empty
// value defaults to off (advice is opt-in); any other unrecognized value is a
// config error, so a typo fails at load rather than silently disabling advice.
func parseAdvice(raw string) (AdviceMode, error) {
	switch strings.TrimSpace(raw) {
	case "", "off":
		return AdviceOff, nil
	case "operator":
		return AdviceOperator, nil
	case "caller":
		return AdviceCaller, nil
	default:
		return AdviceOff, fmt.Errorf("advice %q is not one of off|operator|caller", raw)
	}
}

// AdviceRetention is a profile's opt-in for how much Prospector advisory telemetry
// plimsoll writes to the operator's durable audit log (roadmap Phase 5). plimsoll
// is stateless — it stores no traces or findings itself — so "retention" governs what
// it *emits* to the operator's log sink, which then keeps it for whatever period the
// operator's own logging policy dictates. It is OFF by default and orthogonal to
// AdviceMode: AdviceMode decides *who can act* on a finding (operator vs caller), while
// AdviceRetention decides *what durable record* the operator keeps. With advice on but
// retention unset, findings still drive the live caller wire hint and the bounded
// in-memory /metrics aggregates, but nothing about a run's findings reaches the audit
// log.
type AdviceRetention int

const (
	// RetentionNone writes no advisory records to the audit log — the default. The
	// ephemeral surfaces (caller wire hint, /metrics aggregates) are unaffected.
	RetentionNone AdviceRetention = iota
	// RetentionAggregate writes the per-run aggregate summary only — the finding count
	// and total estimated waste (extra calls, added latency, bytes) — with no
	// per-finding, per-route records.
	RetentionAggregate
	// RetentionDetailed additionally writes one metadata-only record per finding
	// (pattern, severity, remedy, route template, cost): the stream the exported-audit
	// HTML report renders.
	RetentionDetailed
)

// String is the stable config/log name of the retention level.
func (r AdviceRetention) String() string {
	switch r {
	case RetentionAggregate:
		return "aggregate"
	case RetentionDetailed:
		return "detailed"
	default:
		return "none"
	}
}

// parseAdviceRetention maps the profile's `advice_retention` config value to an
// AdviceRetention. Empty defaults to none (retention is opt-in, like the rest of
// plimsoll); any other unrecognized value is a load-time config error.
func parseAdviceRetention(raw string) (AdviceRetention, error) {
	switch strings.TrimSpace(raw) {
	case "", "none":
		return RetentionNone, nil
	case "aggregate":
		return RetentionAggregate, nil
	case "detailed":
		return RetentionDetailed, nil
	default:
		return RetentionNone, fmt.Errorf("advice_retention %q is not one of none|aggregate|detailed", raw)
	}
}

// Profile is one server-held capability plus the authenticated callers allowed to
// select it. Keeping this ACL beside the capability prevents code:run from
// implicitly granting every caller every downstream host-API capability. The
// loaded grant is frozen: it is only reachable through Grant, which deep-copies,
// so per-run consumers can never mutate the registry's configuration.
type Profile struct {
	grant           *sandbox.HostAPIGrant
	allowedCallers  map[string]struct{}
	advice          AdviceMode
	adviceRetention AdviceRetention
	catalog         []sandbox.HostRoute
}

// Advice reports the profile's efficiency-advice opt-in. Nil-safe: an absent
// profile advises nothing.
func (p *Profile) Advice() AdviceMode {
	if p == nil {
		return AdviceOff
	}
	return p.advice
}

// AdviceRetention reports how much advisory telemetry the profile keeps in the audit
// log. Nil-safe: an absent profile retains nothing.
func (p *Profile) AdviceRetention() AdviceRetention {
	if p == nil {
		return RetentionNone
	}
	return p.adviceRetention
}

// Grant returns an independent deep copy of the profile's capability. Handing
// out copies (never the registry-held pointer) keeps the registry effectively
// immutable after Load, no matter what downstream code does with a run's grant.
func (p *Profile) Grant() *sandbox.HostAPIGrant {
	if p == nil {
		return nil
	}
	return p.grant.Clone()
}

// Catalog returns a copy of the profile's known host-API endpoints (a superset of the
// grant's Allow, e.g. the full OpenAPI surface). Prospector uses it to name an ungranted
// route worth adding; it grants nothing. Nil-safe: an absent profile knows no endpoints.
func (p *Profile) Catalog() []sandbox.HostRoute {
	if p == nil || len(p.catalog) == 0 {
		return nil
	}
	return append([]sandbox.HostRoute(nil), p.catalog...)
}

// Allows reports whether caller may select this profile. "*" is an explicit
// operator opt-in for sharing a profile with every authenticated principal.
func (p *Profile) Allows(caller string) bool {
	if p == nil || caller == "" {
		return false
	}
	_, all := p.allowedCallers["*"]
	_, exact := p.allowedCallers[caller]
	return all || exact
}

// Get returns the profile for name. ok is false for an unknown name; a nil or
// empty registry simply knows no profiles.
func (r *Registry) Get(name string) (*Profile, bool) {
	if r == nil || r.profiles == nil {
		return nil, false
	}
	g, ok := r.profiles[name]
	return g, ok
}

// Len reports how many profiles are configured.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.profiles)
}

// fileConfig is the on-disk JSON shape of PLIMSOLL_GRANTS_FILE.
type fileConfig struct {
	Profiles map[string]profileConfig `json:"profiles"`
}

type profileConfig struct {
	BaseURL        string   `json:"base_url"`
	Allow          []string `json:"allow"`           // "METHOD /path" entries, e.g. "PUT /v1/lights/*/on"
	Scopes         []string `json:"scopes"`          // declared token scopes; must exclude code:run / "*"
	AllowedCallers []string `json:"allowed_callers"` // authenticated Principal.UserID values; required
	// Catalog is the full set of "METHOD /path" routes the host API exposes (a superset
	// of Allow, e.g. the whole OpenAPI spec via plimsoll-specgen). It grants nothing —
	// Prospector reads it so a fan-out finding can name the concrete ungranted route the
	// operator should add, instead of a vague "the API needs a change." Optional.
	Catalog []string `json:"catalog"`
	Global  string   `json:"global"` // JS global name; "" = "host"
	Advice  string   `json:"advice"` // "off" (default) | "operator" | "caller"; Prospector opt-in
	// AdviceRetention: "none" (default) | "aggregate" | "detailed". How much advisory
	// telemetry reaches the durable audit log; independent of Advice. No effect when
	// Advice is off (there are no findings to record).
	AdviceRetention string `json:"advice_retention"`

	Token    *tokenConfig `json:"token"`    // how to obtain the per-run credential
	Preamble string       `json:"preamble"` // optional domain-SDK JS layered on the client

	// HealthCheck is an optional concrete "GET /path" the broker probes to detect an
	// overloaded upstream: after an upstream 429/503 trips the per-run circuit breaker,
	// the broker sheds calls and uses this route to detect recovery. Empty = reactive
	// shedding only, no recovery probe.
	HealthCheck string `json:"health_check"`

	// PreambleFile points at a .js file (relative to the grants file) to use as the
	// preamble, for SDKs too large to inline. Mutually exclusive with Preamble.
	PreambleFile string `json:"preamble_file"`
}

// tokenConfig selects how a profile's per-run credential is produced. "static"
// injects the same token every run (env var); "jwt" mints a fresh short-lived
// HS256 JWT per run, scoped to the calling principal (`sub`) — the per-session model.
type tokenConfig struct {
	Type string `json:"type"` // "static" | "jwt" (default "static")

	Env string `json:"env"` // static: env var holding the bearer token

	SecretEnv string `json:"secret_env"` // jwt: env var holding the HS256 signing secret
	TTLSec    int    `json:"ttl_sec"`    // jwt: token lifetime in seconds (default 60)
	Issuer    string `json:"issuer"`     // jwt: iss claim (optional)
	Audience  string `json:"audience"`   // jwt: aud claim (REQUIRED — binds the token to one service)
	KeyID     string `json:"key_id"`     // jwt: kid header for key rotation (optional)
}

// buildMinter turns a profile's token config into a sandbox.TokenMinter. A nil
// config means an unauthenticated host API (no Authorization header).
func buildMinter(profile string, tc *tokenConfig) (sandbox.TokenMinter, error) {
	if tc == nil {
		return nil, nil
	}
	switch tc.Type {
	case "", "static":
		if tc.Env == "" {
			return nil, fmt.Errorf("grants: profile %q: token.env is required for a static token", profile)
		}
		v := os.Getenv(tc.Env)
		if v == "" {
			return nil, fmt.Errorf("grants: profile %q: token env %q is empty or unset", profile, tc.Env)
		}
		return sandbox.StaticToken(v), nil
	case "jwt":
		if tc.SecretEnv == "" {
			return nil, fmt.Errorf("grants: profile %q: token.secret_env is required for a jwt token", profile)
		}
		secret := os.Getenv(tc.SecretEnv)
		if secret == "" {
			return nil, fmt.Errorf("grants: profile %q: jwt secret env %q is empty or unset", profile, tc.SecretEnv)
		}
		if len(secret) < 32 {
			return nil, fmt.Errorf("grants: profile %q: jwt secret env %q must contain at least 32 bytes for HS256", profile, tc.SecretEnv)
		}
		// Audience is mandatory: plimsoll is the issuer, not the verifier, so it
		// cannot enforce that a token is used only against its intended service. A
		// bound `aud` is the only thing that stops a token minted for API X being
		// replayed against API Y when they share the HS256 secret. Fail closed at
		// load rather than mint an audience-less, cross-service-replayable token.
		if strings.TrimSpace(tc.Audience) == "" {
			return nil, fmt.Errorf("grants: profile %q: token.audience is required for a jwt token (binds it to one service; the target MUST reject a mismatched aud)", profile)
		}
		return newJWTMinter([]byte(secret), time.Duration(tc.TTLSec)*time.Second, tc.Issuer, tc.Audience, tc.KeyID), nil
	default:
		return nil, fmt.Errorf("grants: profile %q: unknown token.type %q (want static|jwt)", profile, tc.Type)
	}
}

// LoadFromEnv builds the registry from the file named by PLIMSOLL_GRANTS_FILE. An
// unset var yields an empty registry (no profiles) — grants are off by default.
func LoadFromEnv() (*Registry, error) {
	path := strings.TrimSpace(os.Getenv("PLIMSOLL_GRANTS_FILE"))
	if path == "" {
		return &Registry{}, nil
	}
	return Load(path)
}

// Load reads and validates the profiles file at path. Every profile is checked with
// sandbox.HostAPIGrant.Validate, so a profile that names a forbidden scope
// (code:run / "*") or omits BaseURL fails fast at startup, not at first use.
func Load(path string) (*Registry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("grants: read %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields() // catch config typos rather than silently ignoring them
	var cfg fileConfig
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("grants: parse %s: %w", path, err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return nil, fmt.Errorf("grants: parse %s: %w", path, err)
	}

	r := &Registry{profiles: make(map[string]*Profile, len(cfg.Profiles))}
	for name, pc := range cfg.Profiles {
		if err := validateProfileName(name); err != nil {
			return nil, fmt.Errorf("grants: profile %q: %w", name, err)
		}
		allow, err := parseAllow(pc.Allow)
		if err != nil {
			return nil, fmt.Errorf("grants: profile %q: %w", name, err)
		}
		catalog, err := parseAllow(pc.Catalog)
		if err != nil {
			return nil, fmt.Errorf("grants: profile %q: catalog %w", name, err)
		}
		callers, err := parseAllowedCallers(pc.AllowedCallers)
		if err != nil {
			return nil, fmt.Errorf("grants: profile %q: %w", name, err)
		}
		advice, err := parseAdvice(pc.Advice)
		if err != nil {
			return nil, fmt.Errorf("grants: profile %q: %w", name, err)
		}
		retention, err := parseAdviceRetention(pc.AdviceRetention)
		if err != nil {
			return nil, fmt.Errorf("grants: profile %q: %w", name, err)
		}
		preamble := pc.Preamble
		if pc.PreambleFile != "" {
			if preamble != "" {
				return nil, fmt.Errorf("grants: profile %q: set either preamble or preamble_file, not both", name)
			}
			dir := filepath.Dir(path)
			pf := filepath.Join(dir, pc.PreambleFile)
			// Keep preamble_file within the grants-file directory. The grants file is
			// operator-trusted config, but a stray "../" should not pull an arbitrary
			// host file in as the sandbox preamble (defense in depth).
			if rel, rerr := filepath.Rel(dir, pf); rerr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return nil, fmt.Errorf("grants: profile %q: preamble_file %q escapes the grants directory", name, pc.PreambleFile)
			}
			realDir, err := filepath.EvalSymlinks(dir)
			if err != nil {
				return nil, fmt.Errorf("grants: profile %q: resolve grants directory: %w", name, err)
			}
			realPF, err := filepath.EvalSymlinks(pf)
			if err != nil {
				return nil, fmt.Errorf("grants: profile %q: read preamble_file: %w", name, err)
			}
			if rel, rerr := filepath.Rel(realDir, realPF); rerr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return nil, fmt.Errorf("grants: profile %q: preamble_file %q resolves outside the grants directory", name, pc.PreambleFile)
			}
			b, err := os.ReadFile(realPF)
			if err != nil {
				return nil, fmt.Errorf("grants: profile %q: read preamble_file: %w", name, err)
			}
			preamble = string(b)
		}
		minter, err := buildMinter(name, pc.Token)
		if err != nil {
			return nil, err
		}
		health, err := parseHealthCheck(pc.HealthCheck)
		if err != nil {
			return nil, fmt.Errorf("grants: profile %q: %w", name, err)
		}
		grant := &sandbox.HostAPIGrant{
			BaseURL:     pc.BaseURL,
			Allow:       allow,
			Scopes:      pc.Scopes,
			Global:      pc.Global,
			Preamble:    preamble,
			Minter:      minter,
			HealthCheck: health,
		}
		if err := grant.Validate(); err != nil {
			return nil, fmt.Errorf("grants: profile %q: %w", name, err)
		}
		r.profiles[name] = &Profile{grant: grant, allowedCallers: callers, advice: advice, adviceRetention: retention, catalog: catalog}
	}
	return r, nil
}

func requireJSONEOF(dec *json.Decoder) error {
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return fmt.Errorf("trailing data: %w", err)
	}
	return nil
}

func validateProfileName(name string) error {
	if name == "" {
		return fmt.Errorf("name must be non-empty")
	}
	if name != strings.TrimSpace(name) {
		return fmt.Errorf("name must not have surrounding whitespace")
	}
	if len(name) > MaxProfileNameBytes {
		return fmt.Errorf("name exceeds %d bytes", MaxProfileNameBytes)
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return fmt.Errorf("name may contain only letters, digits, '.', '_' and '-'")
		}
	}
	return nil
}

func parseAllowedCallers(values []string) (map[string]struct{}, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("allowed_callers must name at least one authenticated principal")
	}
	callers := make(map[string]struct{}, len(values))
	for _, raw := range values {
		caller := strings.TrimSpace(raw)
		if caller == "" {
			return nil, fmt.Errorf("allowed_callers contains an empty principal")
		}
		if _, duplicate := callers[caller]; duplicate {
			return nil, fmt.Errorf("allowed_callers contains duplicate principal %q", caller)
		}
		callers[caller] = struct{}{}
	}
	return callers, nil
}

// parseHealthCheck turns an optional "GET /path" line into a *HostRoute for the grant's
// broker-operated backpressure probe. Empty means no probe. Deeper validation (GET-only,
// concrete path) happens in sandbox.HostAPIGrant.Validate, so a malformed one still fails
// at load.
func parseHealthCheck(line string) (*sandbox.HostRoute, error) {
	if strings.TrimSpace(line) == "" {
		return nil, nil
	}
	fields := strings.Fields(line)
	if len(fields) != 2 {
		return nil, fmt.Errorf("health_check %q must be %q", line, "METHOD /path")
	}
	method, path := strings.ToUpper(fields[0]), fields[1]
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("health_check %q: path must be absolute", line)
	}
	return &sandbox.HostRoute{Method: method, Path: path}, nil
}

// parseAllow turns "METHOD /path" lines into HostRoutes.
func parseAllow(lines []string) ([]sandbox.HostRoute, error) {
	routes := make([]sandbox.HostRoute, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("allow entry %q must be %q", line, "METHOD /path")
		}
		method, path := strings.ToUpper(fields[0]), fields[1]
		if !strings.HasPrefix(path, "/") {
			return nil, fmt.Errorf("allow entry %q: path must be absolute", line)
		}
		routes = append(routes, sandbox.HostRoute{Method: method, Path: path})
	}
	return routes, nil
}
