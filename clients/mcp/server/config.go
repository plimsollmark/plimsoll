// Package server is the plimsoll MCP server: five tools over the checked Go client,
// served by any MCP transport. It runs outside plimsolld, as a client of it, with
// its own credential to the daemon.
package server

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// Version is the server's version, stated by initialize and server_info. The npm
// package, the plugin and the bundle state it too; a test keeps them equal.
const Version = "0.1.0"

// Defaults, each chosen against a host's limits rather than for itself.
const (
	// DefaultRunTimeout is each run's budget in the sandbox.
	DefaultRunTimeout = 50 * time.Second
	// DefaultCallTimeout bounds a whole tool call: the Describe, a sandbox's open, the
	// wait for its turn and the run. It sits under the 90 s tool timeout the README's
	// Codex configuration sets, so the server answers before the host gives up.
	DefaultCallTimeout = 80 * time.Second
	// DefaultSessionLifetime is asked of the daemon for each sandbox. A host may kill
	// this process before it closes its sandboxes (Claude Code allows half a second),
	// so the lifetime is what bounds how long an orphaned sandbox holds the daemon.
	DefaultSessionLifetime = 30 * time.Minute
	// DefaultMaxSandboxes is how many sandboxes open_sandbox keeps at once.
	DefaultMaxSandboxes = 3
	// DefaultMaxOutputBytes is how much of stdout and of stderr reaches the model.
	DefaultMaxOutputBytes = 16_000
	// KeptRecords is how many checked records get_record can return.
	KeptRecords = 256
	// MaxCodeBytes and MaxFileBytes bound a call's input before anything is sent.
	MaxCodeBytes = 1 << 20
	MaxFileBytes = 4 << 20
	// MaxFiles leaves the daemon's 200 project files room for a fresh call's runner and code.
	MaxFiles = 198
)

// Config is how the server reaches its daemon and what it allows.
type Config struct {
	// RequireGrant refuses tools without a registered connector grant in their
	// request context. Remote HTTP uses it; stdio retains one local workspace.
	RequireGrant bool
	// URL is plimsolld's absolute http(s) URL.
	URL string
	// Token is a caller token with the code:run scope; empty for an open development daemon.
	Token string
	// InsecureHTTP permits cleartext HTTP to a host other than loopback.
	InsecureHTTP bool
	// MinimumIsolation is the weakest tier a run or sandbox accepts. Default kernel.
	MinimumIsolation sandbox.IsolationClass
	// Software, when set, is the operator's rule for which images may run code.
	Software sandbox.SoftwareRule
	// RunTimeout, CallTimeout and SessionLifetime: see the defaults.
	RunTimeout      time.Duration
	CallTimeout     time.Duration
	SessionLifetime time.Duration
	// Languages are those run_code offers, the first the default.
	Languages []sandbox.Language
	// MaxSandboxes and MaxOutputBytes: see the defaults.
	MaxSandboxes   int
	MaxOutputBytes int
	// Owner is the end user the daemon's per-owner session cap counts. Default "local".
	Owner string

	// For tests and embedders: the HTTP client to the daemon, and a Recorder that
	// receives every checked exchange.
	HTTPClient connect.HTTPClient
	Recorder   client.Recorder
	// RecordObserver receives only a workspace identifier and the digest of a
	// checked record. It must return promptly and must not retain tool content.
	RecordObserver func(grant, digest string)
	// SigningKeyFile and ReceiptsDir, both or neither, turn on signed receipts (see
	// Receipts); ReceiptsMaxBytes bounds the directory (default 1 GiB).
	SigningKeyFile   string
	ReceiptsDir      string
	ReceiptsMaxBytes int64
	// Logger receives what happens outside any tool call (a background close that
	// failed). Default: text to stderr, since stdout is the MCP stream.
	Logger *slog.Logger

	// For embedders, both off by default. Kits are named bundles of files: with any
	// configured, run_code and open_sandbox take kit, and write that kit's files into
	// the sandbox before the code. Pictures, when set, turns lines of a run's output
	// into images returned beside the result (see PicturesFunc).
	Kits     []Kit
	Pictures PicturesFunc
	// PictureLink, when set, is given each picture a result sends (cleaned and re-encoded)
	// and returns where the user can open it, such as a page the embedder serves on this
	// machine; results then list the links in pictureLinks, beside the titles. An empty link
	// is listed as empty. It must return promptly; the PNG is the server's, not the guest's.
	PictureLink func(png []byte, title string) string
	// KitsNote is said once in the kit parameter's description, before the kits: how
	// to use them (where their guide is), when that is the same for every kit.
	KitsNote string
	// Panels are pages a host may show in the chat beside a tool's result (MCP Apps: a
	// ui:// resource of type text/html;profile=mcp-app, the host passing the result to
	// the page). With any, the server declares the io.modelcontextprotocol/ui extension
	// and serves them as resources; a tool names its page with PanelMeta. With none,
	// nothing changes.
	Panels []Panel
}

// Panel is one in-chat page: a self-contained HTML document (scripts and styles inline;
// a host's default policy loads nothing from elsewhere), at a ui:// URI.
type Panel struct {
	URI, Name, Title string
	HTML             string
}

// PanelMIME is the resource type a host renders as a panel.
const PanelMIME = "text/html;profile=mcp-app"

// PanelMeta is a tool's _meta naming its panel: the current key and the older one the
// official helper still sends.
func PanelMeta(uri string) map[string]any {
	return map[string]any{"ui": map[string]any{"resourceUri": uri}, "ui/resourceUri": uri}
}

// Kit is a named bundle of files an embedder offers, such as a library and the data
// it reads. Its files count against the daemon's limits on a call's files.
type Kit struct {
	// Name is what run_code and open_sandbox take: lowercase letters, digits and
	// dashes, at most 40 characters.
	Name string
	// Description is one line for the tool's schema: what the kit is and how to use it.
	Description string
	Files       []sandbox.File
}

// Picture is an image made from a run's output: a PNG, and a short title.
type Picture struct {
	PNG   []byte
	Title string
}

// PicturesFunc is given a run's stdout and stderr before they are cut for the model.
// It returns the two with the lines it used removed, the pictures it made from them,
// and notes for the model (a line it could not use, a picture over its limit). The
// output is the sandbox's, so it must treat every byte as hostile, return promptly,
// and keep each PNG small: every picture goes to the model.
type PicturesFunc func(stdout, stderr string) (outRest, errRest string, pictures []Picture, notes []string)

var kitName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// kitBytes is how much of a call's files the kits may hold, so a call's own files
// and code keep at least a quarter of the daemon's budget.
const kitBytes = sandbox.MaxProjectBytes * 3 / 4

var placeholder = regexp.MustCompile(`^\$\{[^}]*\}$`)

// FromEnv reads the configuration from PLIMSOLL_* variables. An empty value counts
// as unset, and a value still holding a host's placeholder (${user_config.token},
// left in place when a setting was never filled in) is an error, never a value to send.
func FromEnv(getenv func(string) string) (Config, error) {
	var errs []error
	get := func(name string) string {
		v := strings.TrimSpace(getenv(name))
		if placeholder.MatchString(v) {
			errs = append(errs, fmt.Errorf("%s is %s, a placeholder the MCP host did not fill in: set it in the host's configuration", name, v))
			return ""
		}
		return v
	}
	duration := func(name string, min, max time.Duration) time.Duration {
		v := get(name)
		if v == "" {
			return 0
		}
		// Compared as milliseconds before any multiplication, which could overflow.
		ms, err := strconv.ParseInt(v, 10, 64)
		if err != nil || ms < min.Milliseconds() || ms > max.Milliseconds() {
			errs = append(errs, fmt.Errorf("%s must be whole milliseconds from %d to %d, not %q", name, min.Milliseconds(), max.Milliseconds(), v))
			return 0
		}
		return time.Duration(ms) * time.Millisecond
	}
	number := func(name string, min, max int) int {
		v := get(name)
		if v == "" {
			return 0
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < min || n > max {
			errs = append(errs, fmt.Errorf("%s must be a whole number from %d to %d, not %q", name, min, max, v))
			return 0
		}
		return n
	}

	c := Config{URL: get("PLIMSOLL_URL"), Token: get("PLIMSOLL_TOKEN")}
	if c.URL == "" && len(errs) == 0 {
		errs = append(errs, errors.New("PLIMSOLL_URL is not set: give the plimsolld URL, such as http://127.0.0.1:8080"))
	}
	switch v := get("PLIMSOLL_INSECURE_HTTP"); v {
	case "":
	case "1":
		c.InsecureHTTP = true
	default:
		errs = append(errs, fmt.Errorf("PLIMSOLL_INSECURE_HTTP must be 1 or unset, not %q", v))
	}
	if v := get("PLIMSOLL_MIN_ISOLATION"); v != "" {
		switch tier := sandbox.ParseIsolationClass(v); tier {
		case sandbox.IsolationVM, sandbox.IsolationKernel, sandbox.IsolationContainer, sandbox.IsolationProcess:
			c.MinimumIsolation = tier
		default:
			errs = append(errs, fmt.Errorf("PLIMSOLL_MIN_ISOLATION must be vm, kernel, container or process, not %q", v))
		}
	}
	if v := get("PLIMSOLL_SOFTWARE_IDENTITY"); v != "" {
		ids := strings.Split(v, ",")
		for i := range ids {
			ids[i] = strings.TrimSpace(ids[i])
		}
		c.Software = sandbox.SoftwareRule{Mode: sandbox.SoftwareApproved, Identities: ids}
		if len(ids) == 1 {
			c.Software.Mode = sandbox.SoftwareExact
		}
		if err := c.Software.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("PLIMSOLL_SOFTWARE_IDENTITY: %w", err))
		}
	}
	if v := get("PLIMSOLL_LANGUAGES"); v != "" {
		seen := map[string]bool{}
		for _, l := range strings.Split(v, ",") {
			l = strings.TrimSpace(l)
			if (l != string(sandbox.LanguagePython) && l != string(sandbox.LanguageJavaScript)) || seen[l] {
				errs = append(errs, fmt.Errorf("PLIMSOLL_LANGUAGES must list python and/or javascript once each, not %q", v))
				break
			}
			seen[l] = true
			c.Languages = append(c.Languages, sandbox.Language(l))
		}
	}
	c.SigningKeyFile, c.ReceiptsDir = get("PLIMSOLL_SIGNING_KEY_FILE"), get("PLIMSOLL_RECEIPTS_DIR")
	if (c.SigningKeyFile == "") != (c.ReceiptsDir == "") {
		errs = append(errs, errors.New("PLIMSOLL_SIGNING_KEY_FILE and PLIMSOLL_RECEIPTS_DIR turn receipts on together: set both, or neither"))
	}
	c.ReceiptsMaxBytes = int64(number("PLIMSOLL_RECEIPTS_MAX_MB", 1, 1_000_000)) << 20
	c.RunTimeout = duration("PLIMSOLL_TIMEOUT_MS", time.Second, time.Hour)
	c.CallTimeout = duration("PLIMSOLL_CALL_TIMEOUT_MS", time.Second, 2*time.Hour)
	c.SessionLifetime = duration("PLIMSOLL_SANDBOX_LIFETIME_MS", time.Minute, 12*time.Hour)
	c.MaxSandboxes = number("PLIMSOLL_MAX_SANDBOXES", 1, 16)
	c.MaxOutputBytes = number("PLIMSOLL_MAX_OUTPUT_BYTES", 1_000, 1_000_000)
	if err := errors.Join(errs...); err != nil {
		return Config{}, err
	}
	return c, nil
}

// withDefaults fills what was left zero, and checks what only makes sense together.
func (c Config) withDefaults() (Config, error) {
	if c.MinimumIsolation == sandbox.IsolationUnknown {
		c.MinimumIsolation = sandbox.IsolationKernel
	}
	if c.RunTimeout == 0 {
		c.RunTimeout = DefaultRunTimeout
	}
	if c.CallTimeout == 0 {
		c.CallTimeout = DefaultCallTimeout
	}
	if c.SessionLifetime == 0 {
		c.SessionLifetime = DefaultSessionLifetime
	}
	if len(c.Languages) == 0 {
		c.Languages = []sandbox.Language{sandbox.LanguagePython, sandbox.LanguageJavaScript}
	}
	if c.MaxSandboxes == 0 {
		c.MaxSandboxes = DefaultMaxSandboxes
	}
	if c.MaxOutputBytes == 0 {
		c.MaxOutputBytes = DefaultMaxOutputBytes
	}
	if c.Owner == "" {
		c.Owner = "local"
	}
	if c.ReceiptsMaxBytes == 0 {
		c.ReceiptsMaxBytes = 1 << 30
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if c.MaxSandboxes < 1 || c.MaxSandboxes > 16 || c.MaxOutputBytes < 1_000 || c.RunTimeout < time.Second || c.SessionLifetime < time.Minute {
		return c, fmt.Errorf("configuration out of range: MaxSandboxes %d (1 to 16), MaxOutputBytes %d (at least 1000), RunTimeout %s (at least 1s), SessionLifetime %s (at least 1m)",
			c.MaxSandboxes, c.MaxOutputBytes, c.RunTimeout, c.SessionLifetime)
	}
	seen := map[string]bool{}
	for _, k := range c.Kits {
		if !kitName.MatchString(k.Name) || seen[k.Name] {
			return c, fmt.Errorf("kit %q: a name is lowercase letters, digits and dashes, at most 40 characters, and names differ", k.Name)
		}
		seen[k.Name] = true
		total, paths := 0, map[string]bool{}
		for _, f := range k.Files {
			if f.Path == "" || f.Path == ".plimsoll" || strings.HasPrefix(f.Path, ".plimsoll/") || strings.HasPrefix(f.Path, "/") || paths[f.Path] {
				return c, fmt.Errorf("kit %q: file %q is empty, absolute, repeated or under .plimsoll/", k.Name, f.Path)
			}
			paths[f.Path] = true
			total += len(f.Content)
		}
		if total > kitBytes || len(k.Files) == 0 || len(k.Files) > MaxFiles/2 {
			return c, fmt.Errorf("kit %q holds %d files and %d bytes; a kit holds 1 to %d files and at most %d bytes", k.Name, len(k.Files), total, MaxFiles/2, kitBytes)
		}
	}
	uris := map[string]bool{}
	for _, p := range c.Panels {
		if !strings.HasPrefix(p.URI, "ui://") || len(p.URI) > 200 || uris[p.URI] || p.Name == "" || p.HTML == "" || len(p.HTML) > 2<<20 {
			return c, fmt.Errorf("panel %q: a panel has a ui:// URI of its own, a name, and an HTML page of at most 2 MiB", p.URI)
		}
		uris[p.URI] = true
	}
	// A run that cannot finish inside the call would be cut off by the server's own
	// deadline, which the model would read as a run that may have happened.
	if c.RunTimeout+10*time.Second > c.CallTimeout {
		return c, fmt.Errorf("the run timeout (%s) must be at least 10 s under the call timeout (%s), which also covers opening a sandbox; a call that waited for its sandbox's turn is refused, not cut off, when less than the run timeout plus 5 s remains", c.RunTimeout, c.CallTimeout)
	}
	return c, nil
}
