// Command dependency-receipt signs, and checks, what the programs in one gVisor sandbox did
// while a package was installed and imported there, read from runsc's syscall log outside
// the sandbox (package receipt beside this file says how).
//
//	go run ./examples/dependency-receipt -log LOG -key harness.key -out receipt.intoto.json \
//	    [-bundle BUNDLE -line N -record-pub harness.pub]
//	go run ./examples/dependency-receipt -check receipt.intoto.json -pub harness.pub -log LOG \
//	    [-bundle BUNDLE -line N -record-pub harness.pub]
//
// LOG is runsc's boot log, as runsc wrote it or gzip-compressed; the receipt names the
// uncompressed bytes. -bundle and -line name the signed run record of the run the sandbox
// served, which is verified under -record-pub (the receipt signer's key when not given) and
// must name the pod the log names.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/examples/dependency-receipt/receipt"
	"github.com/plimsollmark/plimsoll/examples/dependency-receipt/runsclog"
	"github.com/plimsollmark/plimsoll/sandbox"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "dependency-receipt:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("dependency-receipt", flag.ContinueOnError)
	logPath := fs.String("log", "", "runsc's boot log (JSON form), as written or gzip-compressed")
	keyPath := fs.String("key", "", "the signing key (PEM PKCS #8 Ed25519)")
	out := fs.String("out", "", "where to write the signed receipt (never over an existing file)")
	checkPath := fs.String("check", "", "a signed receipt to check against -log")
	pubPath := fs.String("pub", "", "the receipt signer's public key (PEM PKIX Ed25519), for -check")
	bundle := fs.String("bundle", "", "a plimsoll bundle holding the run record of the run the sandbox served")
	line := fs.Int("line", 0, "the run's line in -bundle, from 1")
	recordPub := fs.String("record-pub", "", "the key that signed -bundle (default: -pub, or the signing key's public half)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *logPath == "" {
		return errors.New("needs -log, and either -key and -out, or -check and -pub")
	}
	if (*bundle == "") != (*line == 0) {
		return errors.New("-bundle and -line go together")
	}
	switch {
	case *checkPath == "" && *keyPath != "" && *out != "":
		priv, err := readKey(*keyPath)
		if err != nil {
			return err
		}
		rec, err := runRecord(*bundle, *line, *recordPub, priv.Public().(ed25519.PublicKey))
		if err != nil {
			return err
		}
		return sign(priv, *logPath, rec, *out, stdout)
	case *checkPath != "" && *pubPath != "" && *keyPath == "" && *out == "":
		pub, err := readPub(*pubPath)
		if err != nil {
			return err
		}
		rec, err := runRecord(*bundle, *line, *recordPub, pub)
		if err != nil {
			return err
		}
		return check(pub, *checkPath, *logPath, rec, stdout)
	}
	return errors.New("needs -log, and either -key and -out, or -check and -pub")
}

func sign(priv ed25519.PrivateKey, logPath string, rec *sandbox.RunRecord, out string, stdout io.Writer) error {
	log, closeLog, err := openLog(logPath)
	if err != nil {
		return err
	}
	defer closeLog()
	p, subjects, err := receipt.Build(log, rec)
	if err != nil {
		return err
	}
	signer := attest.NewSigner(priv)
	env, err := receipt.Sign(signer, p, subjects)
	if err != nil {
		return err
	}
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "signed a dependency behavior receipt with key %s: %s\n", signer.KeyID(), summary(p))
	return nil
}

func check(pub ed25519.PublicKey, envPath, logPath string, rec *sandbox.RunRecord, stdout io.Writer) error {
	raw, err := os.ReadFile(envPath)
	if err != nil {
		return err
	}
	if len(raw) > attest.MaxLineBytes {
		return fmt.Errorf("%s is larger than %d bytes, the most an envelope may be", envPath, attest.MaxLineBytes)
	}
	var env attest.Envelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return fmt.Errorf("%s: %w", envPath, err)
	}
	log, closeLog, err := openLog(logPath)
	if err != nil {
		return err
	}
	defer closeLog()
	p, err := receipt.Check(env, pub, log, rec)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "receipt checked: signed by key %s, and exactly what the log shows: %s. "+
		"Not established by this check: that the log is the one runsc wrote for that pod (that is the signer's word), "+
		"and anything the receipt lists as not observed\n", attest.KeyID(pub), summary(p))
	return nil
}

// summaryDests is how many network destinations the one-line summary names; the receipt
// itself lists every one.
const summaryDests = 20

// summary says in one line what a receipt states.
func summary(p receipt.Predicate) string {
	programs := 0
	for _, pr := range p.Processes {
		programs += len(pr.Programs)
	}
	// Every destination a connection or a send named, whatever the call's outcome. The guest
	// chooses how many there are, so they are counted through a set and only the first
	// summaryDests are named.
	seen := map[string]bool{}
	var dests []string
	for _, side := range [][]runsclog.Net{p.Effected.Network, p.Attempted.Network, p.Undetermined.Network} {
		for _, x := range side {
			if (x.Kind == "connect" || x.Kind == "send") && x.Addr != "" {
				if d := fmt.Sprintf("%s %s:%d", x.Kind, x.Addr, x.Port); !seen[d] {
					seen[d] = true
					dests = append(dests, d)
				}
			}
		}
	}
	slices.Sort(dests)
	tried := "none"
	if len(dests) > summaryDests {
		tried = fmt.Sprintf("%d distinct, the first %d in order: %s", len(dests), summaryDests, strings.Join(dests[:summaryDests], ", "))
	} else if len(dests) > 0 {
		tried = strings.Join(dests, ", ")
	}
	count := func(c receipt.Calls) int { return len(c.Opened) + len(c.Changes) + len(c.Network) }
	var b strings.Builder
	fmt.Fprintf(&b, "sandbox %s, %d programs started in %d processes, %d files written, network destinations tried: %s; "+
		"calls that returned an error: %d; calls whose outcome is not in the log: %d; unclear entries: %d; log sha256 %s",
		p.Instance, programs, len(p.Processes), len(p.Effected.Written), tried,
		count(p.Attempted), count(p.Undetermined), len(p.Unclear), p.Log.SHA256)
	if p.Run != nil {
		fmt.Fprintf(&b, "; joined to run record %s (%s, isolation %s)", p.Run.Record, p.Run.Provider, p.Run.Isolation)
	}
	return b.String()
}

// openLog opens a log as written or gzip-compressed, telling them apart by gzip's magic
// bytes, not the file name.
func openLog(path string) (io.Reader, func(), error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	br := bufio.NewReader(f)
	magic, err := br.Peek(2)
	if err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		z, err := gzip.NewReader(br)
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		return z, func() { z.Close(); f.Close() }, nil
	}
	return br, func() { f.Close() }, nil
}

// runRecord reads and verifies the run record on line n of bundle under the key at pubPath,
// or under fallback when pubPath is "". It returns nil when bundle is "".
func runRecord(bundle string, n int, pubPath string, fallback ed25519.PublicKey) (*sandbox.RunRecord, error) {
	if bundle == "" {
		return nil, nil
	}
	if n < 1 {
		return nil, errors.New("-line counts from 1")
	}
	pub := fallback
	if pubPath != "" {
		var err error
		if pub, err = readPub(pubPath); err != nil {
			return nil, err
		}
	}
	f, err := os.Open(bundle)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := attest.ReadBundle(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", bundle, err)
	}
	if n > len(entries) {
		return nil, fmt.Errorf("%s has %d lines, not %d", bundle, len(entries), n)
	}
	e := entries[n-1]
	if len(e.Request) == 0 && len(e.Response) == 0 {
		return nil, fmt.Errorf("line %d of %s holds no call: it is a checkpoint or a session's close statement", n, bundle)
	}
	rec, err := attest.VerifyCall(attest.NewVerifier(pub), e)
	if err != nil {
		return nil, fmt.Errorf("line %d of %s: %w", n, bundle, err)
	}
	return &rec, nil
}

func readKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return attest.ParsePrivateKey(b)
}

func readPub(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return attest.ParsePublicKey(b)
}
