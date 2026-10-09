package main

import (
	"math"
	"net"

	"golang.org/x/net/netutil"
)

// metricsMaxConnections bounds the metrics listener. A scraper holds one or two
// connections; 64 leaves room for several scrapers and an operator's curl, and keeps
// a metrics port that was exposed by mistake from spending the descriptors runs need.
const metricsMaxConnections = 64

// rpcConnectionCap is how many connections the RPC listener holds open at once: half
// the process's descriptor limit, which Go raises to the hard limit at startup. Each
// open connection holds a descriptor, an idle keep-alive one for IdleTimeout, so
// without a cap anyone who can reach the port could open enough of them to leave none
// for the runs already in flight (docker CLI pipes, broker sockets, session relays).
// At the cap a new connection waits in the kernel's accept queue instead. The other
// half stays for runs. A per-client connection limit belongs in front of the daemon,
// at a proxy or firewall, which can see client addresses the way plimsolld cannot
// behind one. 0 means the limit is unknown and nothing is capped.
func rpcConnectionCap() int {
	n := descriptorLimit() / 2
	if n > math.MaxInt32 {
		n = math.MaxInt32
	}
	return int(n)
}

// connectionCaps splits rpcConnectionCap between the RPC listener and, when the
// daemon serves one, the egress guard's, so the two together never hold more than
// half the descriptor limit. Guests reach the guard and callers the RPC listener, so
// neither can take the other's half.
func connectionCaps(guard bool) (rpcConns, guardConns int) {
	return splitConnections(rpcConnectionCap(), guard)
}

// splitConnections divides a connection budget of n between the RPC listener and,
// with guard, the guard's. A budget of 0 is unknown, and stays uncapped on both:
// splitting it into ones would let a single client hold each listener's only
// connection. Each share of a known budget is at least one.
func splitConnections(n int, guard bool) (rpcConns, guardConns int) {
	switch {
	case n <= 0:
		return 0, 0
	case !guard:
		return n, 0
	}
	return max(1, n-n/2), max(1, n/2)
}

// limitConnections caps ln at n open connections; n <= 0 leaves it uncapped.
func limitConnections(ln net.Listener, n int) net.Listener {
	if n <= 0 {
		return ln
	}
	return netutil.LimitListener(ln, n)
}
