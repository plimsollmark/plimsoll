package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const testName = "sandboxd.plimsoll.invalid"

// testCA makes a CA and a serving certificate for testName, both in memory.
func testCA(t *testing.T, serial int64) (caPEM, certPEM, keyPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ = x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{testName}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// testKeys writes a pair into a 0700 directory under the test's own, both files mode
// 0440, as the driver writes them.
func testKeys(t *testing.T, certPEM, keyPEM []byte) keyFiles {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "guard")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	k := keyFiles{guard: dir, cert: filepath.Join(dir, "tls.crt"), key: filepath.Join(dir, "tls.key"), owner: uint32(os.Getuid()), group: uint32(os.Getgid())}
	writePair(t, k, certPEM, keyPEM)
	return k
}

func writePair(t *testing.T, k keyFiles, certPEM, keyPEM []byte) {
	t.Helper()
	_ = os.Remove(k.cert)
	_ = os.Remove(k.key)
	for f, b := range map[string][]byte{k.cert: certPEM, k.key: keyPEM} {
		if err := os.WriteFile(f, b, pairMode); err != nil {
			t.Fatal(err)
		}
		// WriteFile's mode passes through the umask.
		if err := os.Chmod(f, pairMode); err != nil {
			t.Fatal(err)
		}
	}
}

// echoBackend stands in for sandboxd: it echoes every byte and counts its connections.
func echoBackend(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var n atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String(), &n
}

// front serves k in front of backend on a loopback port.
func front(t *testing.T, k keyFiles, backend string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Closing the listener stops serve, not a handle already running, and a handle that
	// logs after its test has ended races with the testing package (seen under -race, about
	// one run in 60). The cleanup marks the test done under the same lock every log line
	// takes, so a line either lands before the cleanup returns or is dropped.
	var mu sync.Mutex
	done := false
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		done = true
		mu.Unlock()
	})
	logf := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if !done {
			t.Logf(format, args...)
		}
	}
	go serve(ln, k.config(), backend, logf)
	return ln.Addr().String()
}

func clientConfig(t *testing.T, caPEM []byte, protos ...string) *tls.Config {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("no CA")
	}
	return &tls.Config{RootCAs: pool, ServerName: testName, NextProtos: protos, MinVersion: tls.VersionTLS13}
}

func TestCheckArgs(t *testing.T) {
	tok := "--auth-token-sha256=" + strings.Repeat("ab", 32)
	good := []string{"--root-dir=/work", "--listen-host=127.0.0.1", "--grpc-port=9091", tok}
	if err := checkArgs(good); err != nil {
		t.Fatalf("good arguments refused: %v", err)
	}
	if err := checkArgs([]string{"-listen-host=127.0.0.1", "-grpc-port=9091", "-" + tok[1:]}); err != nil {
		t.Fatalf("single-dash flags refused: %v", err)
	}
	// Every flag the pinned sandboxd takes passes, so the list refuses only what it lacks.
	for name := range sandboxdFlags {
		if name == "auth-token-sha256" || name == "auth-token-file" || name == "listen-host" || name == "grpc-port" {
			continue
		}
		if err := checkArgs(append(slices.Clone(good), "--"+name+"=x")); err != nil {
			t.Errorf("the pinned sandboxd's flag --%s refused: %v", name, err)
		}
	}
	for name, args := range map[string][]string{
		"no listen host":       {"--grpc-port=9091"},
		"no gRPC port":         {"--listen-host=127.0.0.1"},
		"every address":        {"--listen-host=0.0.0.0", "--grpc-port=9091"},
		"the TLS port":         {"--listen-host=127.0.0.1", "--grpc-port=9090"},
		"listen host twice":    {"--listen-host=127.0.0.1", "--grpc-port=9091", "-listen-host=127.0.0.1"},
		"a value without =":    {"--listen-host", "127.0.0.1", "--grpc-port=9091"},
		"a bare word":          {"--listen-host=127.0.0.1", "--grpc-port=9091", "serve"},
		"the end of flags":     {"--listen-host=127.0.0.1", "--grpc-port=9091", "--", "--listen-host=0.0.0.0"},
		"an empty listen host": {"--listen-host=", "--grpc-port=9091"},
		"IPv6 loopback":        {"--listen-host=::1", "--grpc-port=9091", tok},
		"no token":             {"--listen-host=127.0.0.1", "--grpc-port=9091"},
		"a token twice":        {"--listen-host=127.0.0.1", "--grpc-port=9091", tok, tok},
		"a token not hex":      {"--listen-host=127.0.0.1", "--grpc-port=9091", "--auth-token-sha256=ab"},
		"a token file":         {"--listen-host=127.0.0.1", "--grpc-port=9091", tok, "--auth-token-file=/t"},
		// finding release-58: a flag the pinned sandboxd does not take, as a later one might
		// (one that loosens its token check, say), in both dash forms and in another case
		"an unknown flag":              {"--listen-host=127.0.0.1", "--grpc-port=9091", "--allow-unauthenticated=true"},
		"an unknown single-dash flag":  {"--listen-host=127.0.0.1", "--grpc-port=9091", "-allow-unauthenticated=true"},
		"a known flag in another case": {"--listen-host=127.0.0.1", "--grpc-port=9091", "--Root-Dir=/work"},
	} {
		// every case but the token's own carries a good token, so it is refused for its own fault
		if !strings.Contains(name, "token") && name != "IPv6 loopback" {
			args = append(args, tok)
		}
		if err := checkArgs(args); err == nil {
			t.Errorf("%s: %q accepted", name, args)
		}
	}
}

// A client that completes TLS 1.3 and negotiates h2 reaches the backend and hears it.
func TestFrontForwardsAfterAnH2Handshake(t *testing.T) {
	caPEM, certPEM, keyPEM := testCA(t, 2)
	backend, n := echoBackend(t)
	addr := front(t, testKeys(t, certPEM, keyPEM), backend)
	c, err := tls.Dial("tcp", addr, clientConfig(t, caPEM, "h2"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.ConnectionState().NegotiatedProtocol != "h2" || c.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatalf("negotiated %q at %x", c.ConnectionState().NegotiatedProtocol, c.ConnectionState().Version)
	}
	msg := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("read %q, %v", got, err)
	}
	if n.Load() != 1 {
		t.Fatalf("%d backend connections", n.Load())
	}
}

// Nothing that has not negotiated h2 over TLS reaches sandboxd: a client offering only
// HTTP/1.1, a client offering no protocol, a cleartext HTTP/2 client and a TLS 1.2 one.
func TestFrontRefusesAllButTLSWithH2(t *testing.T) {
	caPEM, certPEM, keyPEM := testCA(t, 2)
	backend, n := echoBackend(t)
	addr := front(t, testKeys(t, certPEM, keyPEM), backend)

	// Go's server completes a handshake whose client offers only http/1.1 with no
	// protocol (a fallback for such clients), and the front then closes it.
	refused := func(name string, cfg *tls.Config) {
		c, err := tls.Dial("tcp", addr, cfg)
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Write([]byte("hello"))
		if b, err := io.ReadAll(c); err == nil && len(b) > 0 {
			t.Errorf("%s: read %q", name, b)
		}
	}
	refused("only http/1.1", clientConfig(t, caPEM, "http/1.1"))
	refused("no ALPN", clientConfig(t, caPEM))
	tls12 := clientConfig(t, caPEM, "h2")
	tls12.MinVersion, tls12.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	if c, err := tls.Dial("tcp", addr, tls12); err == nil {
		c.Close()
		t.Error("a TLS 1.2 client completed the handshake")
	}
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = raw.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00"))
	b, _ := io.ReadAll(raw)
	raw.Close()
	if bytes.Contains(b, []byte("PRI")) {
		t.Errorf("cleartext HTTP/2 was echoed: %q", b)
	}
	// fixed-wait: 100 ms for a connection that must never reach the backend; nothing can signal that a thing did not happen, so this is a bounded look: a late one would be missed, and a slow machine cannot fail it
	time.Sleep(100 * time.Millisecond)
	if n.Load() != 0 {
		t.Fatalf("%d connections reached the backend", n.Load())
	}
}

// The key and the certificate must have exactly mode 0440 for their owner and group, as
// the driver writes them, and the directory guarding them must be closed to everyone but
// its owner; anything else refuses to load, at startup and at every handshake. Deleting
// the mode comparison in pairFile passes the loose modes (the build's note, 2026-11-24).
func TestKeyFilesAcceptOnlyTheDriversModes(t *testing.T) {
	_, certPEM, keyPEM := testCA(t, 2)
	k := testKeys(t, certPEM, keyPEM)
	if _, err := k.load(); err != nil {
		t.Fatalf("the driver's 0440 files refused: %v", err)
	}
	for _, f := range []string{k.key, k.cert} {
		for _, mode := range []os.FileMode{0o400, 0o444, 0o640, 0o460, 0o441, 0o550, 0o600, 0o040} {
			if err := os.Chmod(f, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := k.load(); err == nil || !strings.Contains(err.Error(), "mode 0440 exactly") {
				t.Errorf("%s at %#o: %v", filepath.Base(f), mode, err)
			}
		}
		_ = os.Chmod(f, pairMode)
	}
	if err := os.Chmod(k.guard, 0o711); err != nil {
		t.Fatal(err)
	}
	if _, err := k.load(); err == nil {
		t.Error("a guard directory others may traverse was accepted")
	}
	if err := os.Chmod(k.guard, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := k.load(); err == nil {
		t.Error("a guard directory its group may enter was accepted")
	}
	_ = os.Chmod(k.guard, 0o700)
	other := k
	other.owner++
	if _, err := other.load(); err == nil {
		t.Error("files owned by another uid were accepted")
	}
	other = k
	other.group++
	if _, err := other.load(); err == nil || !strings.Contains(err.Error(), "gid") {
		t.Errorf("files of another group: %v", err)
	}
	if _, err := k.load(); err != nil {
		t.Fatalf("restored files refused: %v", err)
	}
}

// A pair renewed under a running pod is served at the next handshake.
func TestRotatedPairIsServedAtTheNextHandshake(t *testing.T) {
	caPEM, certPEM, keyPEM := testCA(t, 2)
	k := testKeys(t, certPEM, keyPEM)
	backend, _ := echoBackend(t)
	addr := front(t, k, backend)
	serial := func(ca []byte) int64 {
		c, err := tls.Dial("tcp", addr, clientConfig(t, ca, "h2"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
	}
	if s := serial(caPEM); s != 2 {
		t.Fatalf("serial %d", s)
	}
	ca2, cert2, key2 := testCA(t, 3)
	writePair(t, k, cert2, key2)
	if s := serial(ca2); s != 3 {
		t.Fatalf("after rotation, serial %d", s)
	}
}

// Failed handshakes write a bounded number of lines to the container log.
func TestFailuresLogABoundedNumberOfLines(t *testing.T) {
	var lines int
	clock := time.Unix(1000, 0)
	logf := limitedLog(func(string, ...any) { lines++ }, func() time.Time { return clock })
	for range 1000 {
		logf("x")
	}
	if lines != maxLogged+1 {
		t.Fatalf("%d lines", lines)
	}
	// a burst does not silence the pod for good: the next window logs again
	clock = clock.Add(logWindow)
	logf("a real failure")
	if lines != maxLogged+2 {
		t.Fatalf("after the window, %d lines", lines)
	}
}

// The front's own log line for a real failed handshake carries none of the client's bytes:
// a guest that offers an ALPN protocol of its choosing (escape sequences and all) gets a
// line naming the failure, not echoing the offer.
func TestTheFrontLogsAFailedHandshakeWithoutTheClientsBytes(t *testing.T) {
	caPEM, certPEM, keyPEM := testCA(t, 2)
	backend, _ := echoBackend(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var lines []string
	go serve(ln, testKeys(t, certPEM, keyPEM).config(), backend, func(f string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(f, a...))
	})
	if c, err := tls.Dial("tcp", ln.Addr().String(), clientConfig(t, caPEM, "planted\x1b[2Jowned")); err == nil {
		c.Close()
		t.Fatal("a client offering only an unknown protocol completed the handshake")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		got := append([]string(nil), lines...)
		mu.Unlock()
		if len(got) > 0 {
			for _, l := range got {
				if strings.Contains(l, "planted") || strings.Contains(l, "\x1b") {
					t.Fatalf("the log quotes the client: %q", l)
				}
			}
			// The failure is named from crypto/tls's own words for it ("application
			// protocol", handshakeFailure): this real handshake is what holds that reading to
			// the Go release in use. With other words the line would say "refused by TLS".
			if !strings.Contains(strings.Join(got, "\n"), "no protocol in common") {
				t.Fatalf("a real handshake with no protocol in common was logged as %q: crypto/tls words this failure another way now, and handshakeFailure no longer reads it", got)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the failed handshake was not logged at all")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The terminator reaps every child: an orphan reparented to it while sandboxd runs is waited for
// (no zombie holding a pid), and sandboxd's own exit status comes back as run's. The test process
// makes itself a child subreaper, as process 1 is in a pod, so the orphan comes to it.
func TestReapCollectsOrphansAndReturnsTheChildsStatus(t *testing.T) {
	if err := setChildSubreaper(); err != nil {
		t.Skipf("prctl(PR_SET_CHILD_SUBREAPER): %v", err)
	}
	// the subshell forks a short sleep and exits at once, so the sleep is orphaned and exits while the child runs on
	cmd := exec.Command("/bin/sh", "-c", "(sleep 0.1 &) ; sleep 0.6; exit 3")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var orphans []int
	ws := reap(cmd.Process.Pid, func(pid int) { orphans = append(orphans, pid) })
	if !ws.Exited() || ws.ExitStatus() != 3 {
		t.Fatalf("the child's status: %#x", uint32(ws))
	}
	// the orphaned sleep (its subshell is sh's child, which sh reaps) is reaped by the loop, not
	// left as a zombie: the only process this test leaves to reparent
	if len(orphans) != 1 || orphans[0] == cmd.Process.Pid {
		t.Fatalf("reaped %v besides the child %d, want its one orphan", orphans, cmd.Process.Pid)
	}
	if err := statusErr(ws); exitCode(err) != 3 {
		t.Fatalf("exit code %d from %v", exitCode(err), err)
	}
	if statusErr(syscall.WaitStatus(0)) != nil {
		t.Fatal("exit 0 is an error")
	}
}

// A client that refuses the pod's certificate is named by its alert, the operator's clue to a
// wrong CA or name; the alert text comes from crypto/tls's own table, and anything outside that
// shape is not logged.
func TestAClientsAlertIsNamedAndNothingElse(t *testing.T) {
	if got := handshakeFailure(errors.New("remote error: tls: bad certificate")); got != "the client refused this pod's certificate (bad certificate)" {
		t.Fatalf("%q", got)
	}
	if got := handshakeFailure(errors.New("remote error: tls: alert(200)")); !strings.Contains(got, "alert(200)") {
		t.Fatalf("%q", got)
	}
	if got := handshakeFailure(errors.New("remote error: tls: bad certificate planted\x1b[2J")); got != "refused by TLS" {
		t.Fatalf("%q", got)
	}
}

// What a failed handshake logs never quotes the client: an ALPN offer of the guest's
// choosing stays out of the container log.
func TestAFailedHandshakeLogsNoClientBytes(t *testing.T) {
	for _, err := range []error{
		errors.New(`tls: client requested unsupported application protocols (["\x1b[2Jowned"])`),
		tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"},
		errors.New("remote error: tls: bad certificate \x1b[31m"),
	} {
		if got := handshakeFailure(err); strings.Contains(got, "owned") || strings.Contains(got, "\x1b") || strings.Contains(got, "first record") {
			t.Errorf("%v logged as %q", err, got)
		}
	}
}

// lastAnswerBackend stands in for sandboxd ending a connection after its last answer: it
// reads what the client sends (as sandboxd's HTTP/2 server does) while it writes n bytes,
// then ends its side and reads on until the front closes. It does not close with bytes
// unread, which would make its own kernel reset the connection and drop its answer's end
// before the front saw it: what is measured here is the front's loop alone.
func lastAnswerBackend(t *testing.T, n int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		drained := make(chan struct{})
		go func() { _, _ = io.Copy(io.Discard, c); close(drained) }()
		_, _ = c.Write(bytes.Repeat([]byte{'x'}, n))
		_ = c.(*net.TCPConn).CloseWrite()
		<-drained
	}()
	return ln.Addr().String()
}

// Finding release-59: when sandboxd writes its last bytes and closes, the client reads
// every one of them, also when it reads slowly (so they still wait in the front's buffers
// when sandboxd's side ends) and is still sending (as an HTTP/2 client's acknowledgements
// and pings are).
func TestTheLastAnswerReachesTheClientWhole(t *testing.T) {
	const n = 8 << 20
	for _, sending := range []bool{false, true} {
		t.Run(fmt.Sprintf("client still sending %v", sending), func(t *testing.T) {
			caPEM, certPEM, keyPEM := testCA(t, 2)
			addr := front(t, testKeys(t, certPEM, keyPEM), lastAnswerBackend(t, n))
			c, err := tls.Dial("tcp", addr, clientConfig(t, caPEM, "h2"))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(30 * time.Second))
			if _, err := c.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
				t.Fatal(err)
			}
			stop := make(chan struct{})
			defer close(stop)
			if sending {
				go func() {
					tick := time.NewTicker(time.Millisecond)
					defer tick.Stop()
					for {
						select {
						case <-stop:
							return
						case <-tick.C:
							if _, err := c.Write([]byte("ping-ping")); err != nil {
								return
							}
						}
					}
				}()
			}
			got, buf := 0, make([]byte, 16<<10)
			var rerr error
			for i := 0; rerr == nil; i++ {
				var k int
				k, rerr = c.Read(buf)
				got += k
				if i%8 == 0 {
					// fixed-wait: a slow reader on purpose, so the answer's end still waits in the front's buffers when sandboxd has closed; nothing is waited for
					time.Sleep(time.Millisecond)
				}
			}
			if got != n || !errors.Is(rerr, io.EOF) {
				t.Fatalf("read %d of %d bytes, then %v; want every byte, then the end", got, n, rerr)
			}
		})
	}
}
