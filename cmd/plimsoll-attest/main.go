// Command plimsoll-attest is a harness for plimsoll's run records, run outside
// the daemon: it makes a signing key, runs a request and signs its checked
// record into a bundle, verifies a bundle (signatures, digests, session
// chains), and replays a bundle's single runs to compare results.
//
//	plimsoll-attest keygen -out harness
//	plimsoll-attest run -daemon http://127.0.0.1:8080 -key harness.key -bundle runs.jsonl request.json
//	plimsoll-attest verify -pub harness.pub runs.jsonl
//	plimsoll-attest replay -daemon http://127.0.0.1:8080 runs.jsonl
//
// replay sends each single run again, and each recorded session's calls, in
// order, into a fresh session.
//
// The request file is a plimsoll.v1.RunRequest in protobuf JSON, for example
// {"protocol": 1, "javascript": {"code": "console.log(1)"}}. The daemon's
// bearer token is read from PLIMSOLL_CALLER_TOKEN, and the signing key from
// -key or, when that is absent, from PLIMSOLL_ATTEST_KEY (the PEM itself), so
// neither appears in a process listing. The key never goes to the daemon.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/client"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
)

const usage = `usage:
  plimsoll-attest keygen -out PREFIX            write PREFIX.key (mode 0600) and PREFIX.pub
  plimsoll-attest run -daemon URL -key FILE -bundle FILE REQUEST.json
                                                run one request, append its signed record
  plimsoll-attest verify -pub FILE BUNDLE       check signatures, digests and session chains
  plimsoll-attest replay -daemon URL BUNDLE     run each single run again and each session in a
                                                fresh session, compare results

environment:
  PLIMSOLL_CALLER_TOKEN   bearer token for the daemon (omit for an open dev daemon)
  PLIMSOLL_ATTEST_KEY     the signing key's PEM, when -key is not given
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "run":
		err = run(os.Args[2:], os.Stdout)
	case "verify":
		err = verify(os.Args[2:], os.Stdout)
	case "replay":
		err = replay(os.Args[2:], os.Stdout)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "plimsoll-attest:", err)
		os.Exit(1)
	}
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "path prefix for PREFIX.key and PREFIX.pub")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || fs.NArg() != 0 {
		return errors.New("keygen needs -out PREFIX and nothing else")
	}
	priv, pub, err := attest.GenerateKey()
	if err != nil {
		return err
	}
	// O_EXCL: an existing key is never overwritten.
	f, err := os.OpenFile(*out+".key", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(priv); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.WriteFile(*out+".pub", pub, 0o644)
}

func loadSigner(path string) (*attest.Signer, error) {
	var pemBytes []byte
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		pemBytes = b
	} else if v := os.Getenv("PLIMSOLL_ATTEST_KEY"); v != "" {
		pemBytes = []byte(v)
	} else {
		return nil, errors.New("no signing key: give -key FILE or set PLIMSOLL_ATTEST_KEY")
	}
	key, err := attest.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}
	return attest.NewSigner(key), nil
}

func remote(daemon string, opts ...client.Option) (*client.Remote, error) {
	if tok := os.Getenv("PLIMSOLL_CALLER_TOKEN"); tok != "" {
		opts = append(opts, client.WithToken(tok))
	}
	return client.New(daemon, opts...)
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	daemon := fs.String("daemon", "", "the daemon's base URL")
	keyPath := fs.String("key", "", "the signing key (PEM PKCS #8 Ed25519)")
	bundlePath := fs.String("bundle", "", "the bundle to append to (created if absent)")
	timeout := fs.Duration("timeout", 6*time.Minute, "how long to wait for the run")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *daemon == "" || *bundlePath == "" || fs.NArg() != 1 {
		return errors.New("run needs -daemon URL, -bundle FILE and one REQUEST.json")
	}
	signer, err := loadSigner(*keyPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	req := &plimsollv1.RunRequest{}
	if err := protojson.Unmarshal(raw, req); err != nil {
		return fmt.Errorf("%s: %w", fs.Arg(0), err)
	}
	bundle, err := os.OpenFile(*bundlePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer bundle.Close()
	r, err := remote(*daemon, client.WithRecorder(attest.NewHarness(signer, bundle)))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	resp, rec, err := r.Exchange(ctx, req)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "ran on %s (%s): %s\nrecord %s signed into %s\n",
		resp.GetSandbox(), resp.GetIsolation(), summary(resp), rec.SHA256, *bundlePath)
	return nil
}

func summary(resp *plimsollv1.RunResponse) string {
	switch r := resp.GetResult().(type) {
	case *plimsollv1.RunResponse_Javascript:
		return fmt.Sprintf("exit %d", r.Javascript.GetExitCode())
	case *plimsollv1.RunResponse_Project:
		return fmt.Sprintf("%s, %d steps", r.Project.GetOutcome(), len(r.Project.GetSteps()))
	case *plimsollv1.RunResponse_Module:
		return fmt.Sprintf("%s, %d rows", r.Module.GetOutcome(), len(r.Module.GetRuns()))
	}
	return "no result"
}

func readBundle(path string) ([]attest.Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return attest.ReadBundle(f)
}

func verify(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pubPath := fs.String("pub", "", "the harness's public key (PEM PKIX Ed25519)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pubPath == "" || fs.NArg() != 1 {
		return errors.New("verify needs -pub FILE and one BUNDLE")
	}
	pemBytes, err := os.ReadFile(*pubPath)
	if err != nil {
		return err
	}
	pub, err := attest.ParsePublicKey(pemBytes)
	if err != nil {
		return err
	}
	entries, err := readBundle(fs.Arg(0))
	if err != nil {
		return err
	}
	rep, err := attest.VerifyBundle(entries, attest.NewVerifier(pub))
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "verified %d entries signed by key %s: %d single runs", len(entries), attest.KeyID(pub), rep.Runs)
	for _, s := range rep.Sessions {
		fmt.Fprintf(stdout, "; session %s…, %d calls, chain closed", s.Session[:12], s.Calls)
	}
	fmt.Fprintln(stdout)
	return nil
}

func replay(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	daemon := fs.String("daemon", "", "the daemon's base URL")
	timeout := fs.Duration("timeout", 6*time.Minute, "how long to wait for each run")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *daemon == "" || fs.NArg() != 1 {
		return errors.New("replay needs -daemon URL and one BUNDLE")
	}
	entries, err := readBundle(fs.Arg(0))
	if err != nil {
		return err
	}
	r, err := remote(*daemon)
	if err != nil {
		return err
	}
	send := func(ctx context.Context, req *plimsollv1.RunRequest) (*plimsollv1.RunResponse, error) {
		ctx, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()
		resp, _, err := r.Exchange(ctx, req)
		return resp, err
	}
	results, err := attest.Replay(context.Background(), entries, send)
	if err != nil {
		return err
	}
	sessions, err := attest.ReplaySessions(context.Background(), entries, func(ctx context.Context) (attest.SessionSender, error) {
		s, err := r.OpenSession(ctx, client.SessionOptions{})
		if err != nil {
			return nil, err
		}
		return sessionSender{s: s, timeout: *timeout}, nil
	})
	if err != nil {
		return err
	}
	results = append(results, sessions...)
	differ := 0
	for _, res := range results {
		switch {
		case res.Err != nil:
			differ++
			fmt.Fprintf(stdout, "entry %d: the replay failed: %v\n", res.Entry, res.Err)
		case res.Match() && res.Session != "":
			fmt.Fprintf(stdout, "entry %d (session %s…): same result (%s)\n", res.Entry, res.Session[:12], res.Recorded[:16])
		case res.Match():
			fmt.Fprintf(stdout, "entry %d: same result (%s)\n", res.Entry, res.Recorded[:16])
		default:
			differ++
			fmt.Fprintf(stdout, "entry %d: different result: recorded %s, replayed %s\n", res.Entry, res.Recorded[:16], res.Replayed[:16])
		}
	}
	if differ > 0 {
		return fmt.Errorf("%d of %d replays did not reproduce the recorded result", differ, len(results))
	}
	return nil
}

// sessionSender replays a recorded session's calls into a fresh client session.
type sessionSender struct {
	s       *client.Session
	timeout time.Duration
}

func (ss sessionSender) Send(ctx context.Context, req *plimsollv1.RunRequest) (*plimsollv1.RunResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, ss.timeout)
	defer cancel()
	resp, _, err := ss.s.Exchange(ctx, req)
	return resp, err
}

func (ss sessionSender) Close(ctx context.Context) error {
	_, err := ss.s.Close(ctx)
	return err
}
