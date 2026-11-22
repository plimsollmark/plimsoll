// Package refusedport gives tests a loopback port that refuses connections and that no
// other process can take while the test runs. Only tests import it.
//
// A port a test merely found free (a listener opened and closed, or a closed test server's
// URL) can be taken by any process on the machine before the test connects to it, and
// go test runs other packages' servers on loopback ports at the same time. Three gate runs
// in a row on 2026-11-15 failed that way: another server answered where a test expected a
// refusal. Hold binds a socket to the address without listening on it: a connection there
// is refused, and since the socket does not set SO_REUSEADDR, no other bind succeeds until
// the test ends.
package refusedport

import (
	"errors"
	"net"
	"syscall"
	"testing"
)

// Hold binds a TCP socket to ip:port without listening on it and keeps it until t ends. It
// returns syscall.EADDRINUSE when another socket has the address, and another error when
// the machine has no such address (no IPv6 loopback, say).
func Hold(t testing.TB, ip net.IP, port int) error {
	t.Helper()
	family := syscall.AF_INET6
	if ip.To4() != nil {
		family = syscall.AF_INET
	}
	fd, err := syscall.Socket(family, syscall.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	syscall.CloseOnExec(fd)
	if family == syscall.AF_INET {
		sa := &syscall.SockaddrInet4{Port: port}
		copy(sa.Addr[:], ip.To4())
		err = syscall.Bind(fd, sa)
	} else if err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1); err == nil {
		sa := &syscall.SockaddrInet6{Port: port}
		copy(sa.Addr[:], ip.To16())
		err = syscall.Bind(fd, sa)
	}
	if err != nil {
		_ = syscall.Close(fd)
		return err
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	return nil
}

// HoldV6 holds [::1]:port as Hold does and reports false only when another socket has it;
// a machine with no IPv6 loopback has nothing there to take.
func HoldV6(t testing.TB, port int) bool {
	t.Helper()
	return !errors.Is(Hold(t, net.IPv6loopback, port), syscall.EADDRINUSE)
}

// Port returns a loopback port that nothing listens on, held on 127.0.0.1 and on [::1]
// until t ends, so a connection to it is refused on either address.
func Port(t testing.TB) int {
	t.Helper()
	for range 20 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		if Hold(t, net.IPv4(127, 0, 0, 1), port) == nil && HoldV6(t, port) {
			return port
		}
	}
	t.Fatal("refusedport: no port free on both loopback addresses after 20 tries")
	return 0
}
