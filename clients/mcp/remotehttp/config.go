package remotehttp

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/plimsollmark/plimsoll/clients/mcp/server"
	"github.com/plimsollmark/plimsoll/sandbox"
)

const mcpBodyLimit int64 = 32 << 20 // 5 MiB decoded tool input, worst-case JSON escaping plus framing.

// Config keeps the public HTTP origin separate from the private daemon endpoint.
type Config struct {
	Listen    string
	PublicURL string
	StateDir  string
	Daemon    server.Config
	// ExecutionEnabled is an explicit startup opt-in. Authorization can be checked
	// through a real public proxy while every MCP operation remains unavailable.
	ExecutionEnabled bool
	// Enrollment serves only locally authorized passkey registration, no OAuth or tools.
	Enrollment bool
	// VisitorHeader names the header the local reverse proxy sets to the address it
	// received a request from, overwriting or appending to any the visitor sent;
	// per-visitor limits key on its last entry. Empty: no per-visitor limit.
	VisitorHeader string
}

// FromEnv reads only HTTP settings. The caller supplies the existing daemon config
// for normal serving; enrollment does not need a daemon or its credential.
func FromEnv(get func(string) string, daemon server.Config, enrollment bool) (Config, error) {
	c := Config{Listen: strings.TrimSpace(get("PLIMSOLL_MCP_LISTEN")), PublicURL: strings.TrimSpace(get("PLIMSOLL_MCP_PUBLIC_URL")), StateDir: strings.TrimSpace(get("PLIMSOLL_MCP_STATE_DIR")), Daemon: daemon, Enrollment: enrollment}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8750"
	}
	if h := strings.TrimSpace(get("PLIMSOLL_MCP_VISITOR_HEADER")); h != "" {
		c.VisitorHeader = http.CanonicalHeaderKey(h)
	}
	switch strings.TrimSpace(get("PLIMSOLL_MCP_EXECUTION")) {
	case "", "disabled":
	case "enabled":
		c.ExecutionEnabled = true
	default:
		return c, errors.New("PLIMSOLL_MCP_EXECUTION must be disabled or enabled")
	}
	return c, c.validate()
}

func (c *Config) validate() error {
	if c.VisitorHeader != "" && (len(c.VisitorHeader) > 64 || strings.IndexFunc(c.VisitorHeader, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-')
	}) >= 0 || c.VisitorHeader == "Authorization" || c.VisitorHeader == "Cookie" || c.VisitorHeader == "Host" || c.VisitorHeader == "Origin") {
		return errors.New("PLIMSOLL_MCP_VISITOR_HEADER must name the header the reverse proxy sets to the visitor's address, such as X-Forwarded-For")
	}
	host, port, err := net.SplitHostPort(c.Listen)
	p, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || p < 1 || p > 65535 || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("PLIMSOLL_MCP_LISTEN must be a literal loopback address and port")
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Path != "" && u.Path != "/" || strings.ToLower(u.Host) != u.Host || strings.HasSuffix(u.Hostname(), ".") || strings.ContainsAny(u.Host, "\\\r\n\t ") {
		return errors.New("PLIMSOLL_MCP_PUBLIC_URL must be one fixed HTTPS origin, without path, user info, query or fragment")
	}
	if net.ParseIP(u.Hostname()) != nil || !strings.Contains(u.Hostname(), ".") {
		return errors.New("public passkey origin must have a DNS hostname")
	}
	if u.Port() != "" {
		// A browser omits the default port from Origin and Host, so an explicit
		// :443 could never match either; the origin is written without it.
		if n, err := strconv.Atoi(u.Port()); err != nil || n < 1 || n > 65535 || n == 443 || strconv.Itoa(n) != u.Port() {
			return errors.New("invalid public HTTPS port: give a port from 1 to 65535 in canonical form, and omit 443")
		}
	}
	c.PublicURL = strings.TrimSuffix(c.PublicURL, "/")
	if !filepath.IsAbs(c.StateDir) {
		return errors.New("PLIMSOLL_MCP_STATE_DIR must be an absolute owner-only directory")
	}
	if c.Daemon.MinimumIsolation == sandbox.IsolationUnknown {
		c.Daemon.MinimumIsolation = sandbox.IsolationKernel
	}
	if c.Daemon.CallTimeout == 0 {
		c.Daemon.CallTimeout = server.DefaultCallTimeout
	}
	if !c.Enrollment {
		if c.Daemon.Token == "" {
			return errors.New("remote HTTP requires a dedicated authenticated daemon caller")
		}
		if !c.Daemon.MinimumIsolation.Meets(sandbox.IsolationKernel) {
			return errors.New("remote HTTP requires a kernel or VM isolation floor")
		}
		if c.Daemon.InsecureHTTP {
			return errors.New("remote HTTP refuses an insecure daemon transport override")
		}
		if c.Daemon.ReceiptsDir == "" || c.Daemon.SigningKeyFile == "" {
			return errors.New("remote HTTP requires signed receipts")
		}
		// One app holds at most one fewer than the cap, so a cap of one would hold
		// nothing back for another app (0 means the default of 3).
		if c.Daemon.MaxSandboxes == 1 {
			return errors.New("remote HTTP requires PLIMSOLL_MAX_SANDBOXES of at least 2, so one approved app never fills the server")
		}
	}
	return nil
}
