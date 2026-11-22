package main

import (
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// Open developer mode (a real provider, no token, no callers file, PLIMSOLL_INSECURE=1)
// authenticates no one, so its one boundary is the loopback bind. Until 2026-11-20 nothing
// enforced it: the default PLIMSOLL_ADDR (":8746", every interface) served open mode to
// every network the machine was on, and the Host check let any caller through who wrote
// "Host: localhost" (finding hunt-security-1). These tests hold the rule: open mode starts
// only when the RPC listener bound a loopback address, judged from the bound address.

// listenOrSkip binds addr, or skips when this machine cannot (no IPv6 loopback, say).
func listenOrSkip(t *testing.T, addr string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot listen on %s here: %v", addr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// nonLoopbackIP is an IPv4 address of an interface of this machine that is up and not
// the loopback interface (an address other hosts could reach), or "" when it has none
// (a test environment with loopback only).
func nonLoopbackIP(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLoopback() || ipn.IP.To4() == nil || ipn.IP.IsLinkLocalUnicast() {
				continue
			}
			return ipn.IP.String()
		}
	}
	return ""
}

// TestOpenModeBindErrorJudgesTheBoundAddress judges real listeners' addresses: loopback
// ones pass, every-interface and machine addresses are refused, and a kind of address
// plimsolld does not listen on is refused rather than taken for loopback.
func TestOpenModeBindErrorJudgesTheBoundAddress(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:0", "[::1]:0", "localhost:0"} {
		t.Run("serves "+addr, func(t *testing.T) {
			ln := listenOrSkip(t, addr)
			if err := openModeBindError(ln.Addr()); err != nil {
				t.Fatalf("bound %s: %v, want served", ln.Addr(), err)
			}
		})
	}
	refused := []string{"0.0.0.0:0", ":0"}
	if ip := nonLoopbackIP(t); ip != "" {
		refused = append(refused, net.JoinHostPort(ip, "0"))
	}
	for _, addr := range refused {
		t.Run("refuses "+addr, func(t *testing.T) {
			ln := listenOrSkip(t, addr)
			err := openModeBindError(ln.Addr())
			if err == nil {
				t.Fatalf("bound %s: served, want refused", ln.Addr())
			}
			for _, want := range []string{ln.Addr().String(), "PLIMSOLL_ADDR=127.0.0.1:8746", "PLIMSOLL_TOKEN", "PLIMSOLL_CLIENTS_FILE", "loopback only"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q does not name %q", err, want)
				}
			}
		})
	}
	for name, a := range map[string]net.Addr{
		"a machine address": &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 8746},
		"an unspecified v6": &net.TCPAddr{IP: net.IPv6unspecified, Port: 8746},
		"a unix socket":     &net.UnixAddr{Name: "/run/plimsolld.sock", Net: "unix"},
	} {
		if err := openModeBindError(a); err == nil {
			t.Errorf("%s (%s): served, want refused", name, a)
		}
	}
}

// TestOpenModeRefusesANonLoopbackBind runs the real main(): open mode with the wasm
// provider refuses to start on an address other hosts reach, naming the address and the
// way out, before the provider's readiness check; on loopback it starts, a token on a
// non-loopback address starts, and the disabled provider, which runs no code, keeps any
// address.
func TestOpenModeRefusesANonLoopbackBind(t *testing.T) {
	base := []string{"PATH=" + os.Getenv("PATH"), "SANDBOX_PROVIDER=wasm", "PLIMSOLL_METRICS_ADDR=off"}
	open := append(slices.Clone(base), "PLIMSOLL_INSECURE=1")
	refused := []string{"0.0.0.0:0", ":0"}
	machine := nonLoopbackIP(t)
	if machine != "" {
		refused = append(refused, net.JoinHostPort(machine, "0"))
	}
	for _, addr := range refused {
		t.Run("refuses "+addr, func(t *testing.T) {
			code, log := exitDaemon(t, append(slices.Clone(open), "PLIMSOLL_ADDR="+addr), 30*time.Second)
			if code == 0 || !strings.Contains(log, "open mode is not bound to loopback") || !strings.Contains(log, "PLIMSOLL_ADDR=127.0.0.1:8746") {
				t.Fatalf("exit %d, want a refusal naming the loopback rule; log:\n%s", code, log)
			}
			if strings.Contains(log, "sandbox provider ready") || strings.Contains(log, "plimsolld listening") {
				t.Fatalf("the daemon got past the bind check; log:\n%s", log)
			}
		})
	}
	for _, addr := range []string{"127.0.0.1:0", "[::1]:0", "localhost:0"} {
		t.Run("serves "+addr, func(t *testing.T) {
			_ = listenOrSkip(t, addr) // skips where this machine cannot bind it
			d := startDaemon(t, append(slices.Clone(open), "PLIMSOLL_ADDR="+addr), 30*time.Second)
			host, _, err := net.SplitHostPort(d.addr)
			if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
				t.Fatalf("open mode reported listening on %q, not a loopback address", d.addr)
			}
			d.stop(t, 30*time.Second)
		})
	}
	every := "0.0.0.0:0"
	if machine != "" {
		every = net.JoinHostPort(machine, "0")
	}
	t.Run("a token on "+every, func(t *testing.T) {
		d := startDaemon(t, append(slices.Clone(base), "PLIMSOLL_ADDR="+every, "PLIMSOLL_TOKEN="+strings.Repeat("t", 32)), 30*time.Second)
		d.stop(t, 30*time.Second)
	})
	t.Run("the disabled provider on "+every, func(t *testing.T) {
		d := startDaemon(t, []string{"PATH=" + os.Getenv("PATH"), "PLIMSOLL_METRICS_ADDR=off", "PLIMSOLL_ADDR=" + every}, 30*time.Second)
		d.stop(t, 30*time.Second)
	})
}
