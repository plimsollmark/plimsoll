package remotehttp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"
)

const chatgptMetadata = "https://chatgpt.com/oauth/client.json"
const claudeRedirect = "https://claude.ai/api/mcp/auth_callback"
const chatgptRedirect = "https://chatgpt.com/connector_platform_oauth_redirect"

func approvedRedirect(s string) bool { return s == claudeRedirect || s == chatgptRedirect }
func approvedMetadata(s string) bool { return s == chatgptMetadata }

type cachedClient struct {
	record  clientRecord
	expires time.Time
}
type clientResolver struct {
	mu    sync.Mutex
	cache map[string]cachedClient
	busy  chan struct{}
	fetch func(context.Context, string) ([]byte, error)
}

func newResolver() *clientResolver {
	return &clientResolver{cache: map[string]cachedClient{}, busy: make(chan struct{}, 2), fetch: fetchMetadata}
}

func publicIP(ip net.IP) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return false
	}
	// IsPrivate does not include shared carrier space or all special-purpose
	// destinations. These cannot be vendor metadata endpoints.
	for _, block := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
		_, n, _ := net.ParseCIDR(block)
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

func fetchMetadata(ctx context.Context, id string) ([]byte, error) {
	if !approvedMetadata(id) {
		return nil, errors.New("client metadata location is not approved")
	}
	u, _ := url.Parse(id)
	var dial net.Dialer
	c := metadataHTTPClient(u, net.DefaultResolver.LookupIPAddr, dial.DialContext)
	defer c.CloseIdleConnections()
	return readMetadata(ctx, id, c)
}

// Dependencies are private function arguments so the network policy itself can
// be exercised against a local TLS fixture, without a production bypass.
func metadataHTTPClient(u *url.URL, lookup func(context.Context, string) ([]net.IPAddr, error), dial func(context.Context, string, string) (net.Conn, error)) *http.Client {
	tr := &http.Transport{Proxy: nil, DisableCompression: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, MaxConnsPerHost: 2, ResponseHeaderTimeout: 3 * time.Second}
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || host != u.Hostname() || port != "443" {
			return nil, errors.New("unapproved metadata destination")
		}
		ips, err := lookup(ctx, host)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("client metadata DNS unavailable")
		}
		for _, a := range ips {
			if !publicIP(a.IP) {
				return nil, errors.New("client metadata resolves to a non-public address")
			}
		}
		return dial(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func readMetadata(ctx context.Context, id string, c *http.Client) ([]byte, error) {
	if !approvedMetadata(id) {
		return nil, errors.New("client metadata location is not approved")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, id, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, errors.New("client metadata unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("client metadata did not return 200")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32769))
	if err != nil || len(b) > 32768 {
		return nil, errors.New("client metadata unreadable or oversized")
	}
	return b, nil
}

func (c *clientResolver) resolve(ctx context.Context, id string) (clientRecord, error) {
	if !approvedMetadata(id) {
		return clientRecord{}, errors.New("client is not approved")
	}
	c.mu.Lock()
	cached, ok := c.cache[id]
	c.mu.Unlock()
	if ok && time.Now().Before(cached.expires) {
		return cached.record, nil
	}
	select {
	case c.busy <- struct{}{}:
		defer func() { <-c.busy }()
	default:
		return clientRecord{}, errors.New("client metadata fetch limit reached")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	b, err := c.fetch(ctx, id)
	if err != nil {
		return clientRecord{}, err
	}
	var d struct {
		ID        string   `json:"client_id"`
		Name      string   `json:"client_name"`
		Redirects []string `json:"redirect_uris"`
		Method    string   `json:"token_endpoint_auth_method"`
		Methods   []string `json:"token_endpoint_auth_methods_supported"`
	}
	if err = json.Unmarshal(b, &d); err != nil || d.ID != id || len(d.Name) > 80 || len(d.Redirects) == 0 || len(d.Redirects) > 8 {
		return clientRecord{}, errors.New("invalid client metadata")
	}
	if len(d.Methods) > 0 && !slices.Contains(d.Methods, "none") || len(d.Methods) == 0 && d.Method != "none" {
		return clientRecord{}, errors.New("client does not support public-client authentication")
	}
	want := chatgptRedirect
	if !slices.Contains(d.Redirects, want) {
		return clientRecord{}, errors.New("client metadata has no approved hosted callback")
	}
	r := clientRecord{ID: id, Name: d.Name, Redirects: []string{want}}
	c.mu.Lock()
	c.cache[id] = cachedClient{r, time.Now().Add(time.Hour)}
	c.mu.Unlock()
	return r, nil
}
