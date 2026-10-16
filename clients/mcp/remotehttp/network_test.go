package remotehttp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMetadataTransportRejectsRedirectsOversizeSlowAndRebinding(t *testing.T) {
	for _, kind := range []string{"success", "redirect", "oversize", "slow", "internal"} {
		t.Run(kind, func(t *testing.T) {
			var hits, dials, lookups atomic.Int32
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				switch kind {
				case "redirect":
					http.Redirect(w, r, "https://127.0.0.1/never-follow", 302)
				case "oversize":
					_, _ = io.WriteString(w, strings.Repeat("x", 32769))
				case "slow":
					<-r.Context().Done()
				default:
					_, _ = io.WriteString(w, `{"checked":true}`)
				}
			}))
			defer ts.Close()
			u, _ := url.Parse(chatgptMetadata)
			backend, _ := url.Parse(ts.URL)
			lookup := func(context.Context, string) ([]net.IPAddr, error) {
				lookups.Add(1)
				ip := "1.1.1.1"
				if kind == "internal" || lookups.Load() > 1 {
					ip = "127.0.0.1"
				}
				return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
			}
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				dials.Add(1)
				if address != "1.1.1.1:443" {
					t.Error("metadata dial did not use the previously verified IP")
				}
				var d net.Dialer
				return d.DialContext(ctx, network, backend.Host)
			}
			c := metadataHTTPClient(u, lookup, dial)
			defer c.CloseIdleConnections()
			// This trust override belongs solely to the local TLS fixture. The real
			// constructor always verifies the original vendor hostname and certificate.
			c.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if kind == "slow" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 30*time.Millisecond)
				defer cancel()
			}
			body, err := readMetadata(ctx, chatgptMetadata, c)
			if kind == "success" {
				if err != nil || !json.Valid(body) || lookups.Load() != 1 || dials.Load() != 1 {
					t.Fatal("validated metadata transport failed")
				}
			} else if err == nil {
				t.Fatal("unsafe metadata transport succeeded")
			}
			if hits.Load() > 1 || lookups.Load() > 1 {
				t.Fatal("redirect was followed or DNS looked up again")
			}
			if kind == "internal" && dials.Load() != 0 {
				t.Fatal("internal DNS answer reached dial")
			}
		})
	}
}

func TestHTTPProxyAndSupportedProtocolRevisions(t *testing.T) {
	f := newFixture(t)
	id := clientID(t, f.e)
	verifier := strings.Repeat("p", 43)
	b := authorizeBrowser(t, f.e, id, verifier)
	login(t, f, b)
	pair := exchangeCode(t, f.e, id, approveCode(t, f.e, b), verifier)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.e.cfg.Listen = listener.Addr().String()
	_ = listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- f.e.Run(ctx) }()
	backend, _ := url.Parse("http://" + f.e.cfg.Listen)
	proxy := httputil.NewSingleHostReverseProxy(backend)
	ts := httptest.NewTLSServer(proxy)
	defer ts.Close()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(6 * time.Second):
			t.Error("proxy backend did not stop")
		}
	}()
	// Wait for the actual bounded listener, rather than assuming Run has started.
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", backend.Host, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("backend did not listen")
		}
		time.Sleep(5 * time.Millisecond)
	}
	for _, revision := range []string{"2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"} {
		for _, origin := range []string{"", "https://claude.ai"} {
			method := "initialize"
			params := map[string]any{"protocolVersion": revision, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "local-proxy-check", "version": "0"}}
			if revision == "2026-07-28" {
				method = "server/discover"
				params = map[string]any{"_meta": map[string]any{mcp.MetaKeyProtocolVersion: revision, mcp.MetaKeyClientInfo: map[string]any{"name": "local-proxy-check", "version": "0"}, mcp.MetaKeyClientCapabilities: map[string]any{}}}
			}
			body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
			r, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(string(body)))
			r.Host = "mcp.example.test"
			r.Header.Set("Authorization", "Bearer "+pair.AccessToken)
			r.Header.Set("Accept", "application/json, text/event-stream")
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("MCP-Protocol-Version", revision)
			r.Header.Set("Mcp-Method", method)
			if origin != "" {
				r.Header.Set("Origin", origin)
			}
			response, err := ts.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			var result struct {
				Result struct {
					Protocol  string   `json:"protocolVersion"`
					Supported []string `json:"supportedVersions"`
				} `json:"result"`
			}
			err = json.NewDecoder(response.Body).Decode(&result)
			_ = response.Body.Close()
			if err != nil || response.StatusCode != 200 || result.Result.Protocol != revision && !slices.Contains(result.Result.Supported, revision) {
				t.Fatalf("protocol %s over real proxy failed: status %d protocol %s: %v", revision, response.StatusCode, result.Result.Protocol, err)
			}
		}
	}
}
