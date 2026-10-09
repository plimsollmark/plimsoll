package sandbox

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// RouteBudget counts the calls charged to each capped route of a grant
// (HostAPIGrant.RouteMaxCalls). A run's broker gets a fresh one. A session keeps one
// for its whole life and hands it to the broker of every granted call, so a cap spans
// the session: code a session keeps can run between its calls, so a cap that started
// over with each call would bound nothing (a cap of two jobs gave six over three
// calls). Counts are keyed by the API's origin and the capped route, so two grants that
// cap the same route of the same API draw on one count. MaxCalls stays per call: it
// bounds one call's loop, not what a session may spend.
type RouteBudget struct {
	mu    sync.Mutex
	calls map[routeKey]int
}

type routeKey struct{ origin, method, path string }

// NewRouteBudget returns an empty budget.
func NewRouteBudget() *RouteBudget { return &RouteBudget{calls: map[routeKey]int{}} }

// charge admits one call against every cap in capped, all or nothing under one lock:
// a call one cap refuses spends none of another's, and calls arriving together
// cannot share a cap's last call. A route is keyed as calls are matched to it
// (cappedRoutesMatching folds case), so "/v2/ep1/run" and "/v2/EP1/run", in one grant
// or two, are one count: charged once per call, against the tighter of their caps. The
// origin is keyed the same way (canonicalOrigin), so two profiles that reach one API
// through "https://api.example" and "https://api.example:443" share its counts.
func (b *RouteBudget) charge(origin string, capped []HostRoute, limits map[HostRoute]int) bool {
	if len(capped) == 0 {
		return true
	}
	limit := make(map[routeKey]int, len(capped))
	for _, r := range capped {
		k := routeKey{origin: canonicalOrigin(origin), method: strings.ToUpper(r.Method), path: strings.ToLower(r.Path)}
		if l, seen := limit[k]; !seen || limits[r] < l {
			limit[k] = limits[r]
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, l := range limit {
		if b.calls[k] >= l {
			return false
		}
	}
	for k := range limit {
		b.calls[k]++
	}
	return true
}

// canonicalOrigin is how an origin is keyed, so that two grants reaching one API
// through different spellings of its origin share its counts: the scheme and host
// lowercased, a trailing dot on a host name dropped, an IP literal in its one
// canonical form, the port as a number, and the port the scheme implies dropped
// (round-4, round-5 and round-6 reviews, 2026-10-08: ":443", IPv6 brackets, ":0443"
// and an expanded IPv6 address each split a count). It is only a key, so an origin it
// cannot parse is used as it stands.
func canonicalOrigin(origin string) string {
	lower := strings.ToLower(origin)
	u, err := url.Parse(lower)
	if err != nil || u.Host == "" {
		return lower
	}
	host := strings.TrimSuffix(u.Hostname(), ".")
	if addr, err := netip.ParseAddr(host); err == nil {
		host = addr.Unmap().String()
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return lower
		}
		port = strconv.FormatUint(n, 10)
		if (u.Scheme == "https" && n == 443) || (u.Scheme == "http" && n == 80) {
			port = ""
		}
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return u.Scheme + "://" + host
}
