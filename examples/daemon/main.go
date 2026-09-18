// Command daemon runs the whole service path end to end: it starts plimsolld with a
// real multi-client auth file, calls it with the official Go client, and shows what
// the server refuses. Each refusal is checked for the specific error the protection
// produces, because a request that merely failed (connection refused, a timeout, a
// rate limit) proves nothing about the check it was meant to exercise.
//
// Run it from the repository root, because it builds the daemon from source:
//
//	go run ./examples/daemon
//
// It needs no docker and no credentials. The daemon is started with
// SANDBOX_PROVIDER=wasm so the example works anywhere; every other part of the path
// (auth, the Connect wire protocol, Describe, the per-dispatch isolation floor) is
// exactly what a production deployment uses. Swap the provider environment for
// docker plus runsc and nothing in this file changes except the tier it reports.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// callerID is this client's principal. With a clients file, each caller is its own
// principal rather than sharing one bearer: that is what makes per-caller rate
// limits, per-profile ACLs and audit lines that name the actual caller possible.
const callerID = "example-client"

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "example failed:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	workDir, err := os.MkdirTemp("", "plimsoll-example-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)

	token, clientsPath, err := writeClientsFile(workDir)
	if err != nil {
		return err
	}
	fmt.Printf("auth      | clients file at %s\n", clientsPath)
	fmt.Printf("auth      | the file stores sha256(token), so it holds no live secret\n")

	binary, err := buildDaemon(ctx, workDir)
	if err != nil {
		return err
	}

	addr, err := freeAddr()
	if err != nil {
		return err
	}

	daemon, err := startDaemon(ctx, binary, addr, clientsPath)
	if err != nil {
		return err
	}
	defer stop(daemon)

	baseURL := "http://" + addr
	if err := waitForReady(ctx, baseURL); err != nil {
		return err
	}
	fmt.Printf("daemon    | ready at %s\n\n", baseURL)

	if err := describe(ctx, baseURL, token); err != nil {
		return err
	}
	if err := runCode(ctx, baseURL, token); err != nil {
		return err
	}
	if err := refuseBelowFloor(ctx, baseURL, token); err != nil {
		return err
	}
	return refuseBadToken(ctx, baseURL)
}

// describe asks the server what it actually is. A gateway should route on this rather
// than hard-coding a tier: the answer is measured from the running provider, so it
// changes when the deployment changes.
func describe(ctx context.Context, baseURL, token string) error {
	remote, err := dial(baseURL, token)
	if err != nil {
		return err
	}
	info, err := remote.Describe(ctx)
	if err != nil {
		return fmt.Errorf("describe: %w", err)
	}
	fmt.Printf("describe  | provider=%s isolation=%s projects=%t js-grants=%t protocol=%d (client speaks %d)\n\n",
		info.Sandbox, info.Isolation, info.SupportsProject,
		info.SupportsJavaScriptGrants, info.Protocol, client.Protocol)
	return nil
}

// runCode dispatches a snippet over the wire and prints the run's own evidence.
func runCode(ctx context.Context, baseURL, token string) error {
	remote, err := dial(baseURL, token)
	if err != nil {
		return err
	}
	result, err := remote.RunJavaScript(ctx, sandbox.Request{
		Code:    `console.log(JSON.stringify({sum: [1,2,3,4].reduce((a,b) => a+b, 0)}));`,
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	fmt.Printf("run       | exit=%d isolation=%s duration=%s\n",
		result.ExitCode, result.Isolation, result.Duration.Round(time.Millisecond))
	fmt.Printf("run       | stdout=%s\n", result.Stdout)
	return nil
}

// refuseBelowFloor asks for a boundary this deployment does not have. The handler
// compares the floor against current provider evidence before admission, so the
// refusal means no code ran at all: it is safe to retry elsewhere, which is the whole
// reason the check happens before dispatch rather than after.
//
// "It returned an error" is not the evidence. The client restores the Sandbox
// sentinels across RPC so that errors.Is works the same against a Remote as against
// a local provider, and that is what lets this function tell the isolation refusal
// apart from every other way a request can fail. Anything else is reported as a
// failure of the example, not as a protection that worked.
func refuseBelowFloor(ctx context.Context, baseURL, token string) error {
	remote, err := dial(baseURL, token)
	if err != nil {
		return err
	}
	_, err = remote.RunJavaScript(ctx, sandbox.Request{
		Code:             `console.log("this must never run");`,
		Timeout:          10 * time.Second,
		MinimumIsolation: sandbox.IsolationKernel,
	})
	if err == nil {
		return errors.New("a kernel floor was satisfied by a process-tier provider, which is a bug")
	}
	if !errors.Is(err, sandbox.ErrInsufficientIsolation) {
		return fmt.Errorf("floor: the request failed, but not with the isolation refusal: %w", err)
	}
	fmt.Printf("\nfloor     | asked for kernel isolation from a process-tier provider\n")
	fmt.Printf("floor     | refused: %s\n", oneLine(err))
	fmt.Printf("floor     | checked: errors.Is(err, sandbox.ErrInsufficientIsolation), not merely err != nil\n")
	fmt.Printf("floor     | the refusal is pre-dispatch, so the snippet never executed\n")
	return nil
}

// refuseBadToken proves auth is fail-closed once configured. The same discipline
// applies: only a Connect Unauthenticated code counts. A daemon that had crashed, or
// a port nothing listens on, would also make this call fail, and neither is auth.
func refuseBadToken(ctx context.Context, baseURL string) error {
	remote, err := dial(baseURL, "not-the-token")
	if err != nil {
		return err
	}
	_, err = remote.Describe(ctx)
	if err == nil {
		return errors.New("the server answered an unauthenticated caller, which is a bug")
	}
	if code := connect.CodeOf(err); code != connect.CodeUnauthenticated {
		return fmt.Errorf("auth: the request failed with %s, not unauthenticated: %w", code, err)
	}
	fmt.Printf("\nauth      | a wrong bearer is refused: %s\n", oneLine(err))
	fmt.Printf("auth      | checked: connect code unauthenticated, not merely err != nil\n")
	return nil
}

// dial builds a client. New is checked: it rejects non-absolute URLs, and refuses
// cleartext off loopback unless the caller opts in explicitly, which is why the
// development-only option below is named the way it is.
func dial(baseURL, token string) (*client.Remote, error) {
	remote, err := client.New(baseURL,
		client.WithToken(token),
		client.WithInsecureHTTP(), // loopback only; a real deployment serves TLS
	)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	return remote, nil
}

// writeClientsFile creates the multi-client auth file. Tokens are stored as SHA-256
// hex, never in the clear, so possessing the file does not give you a way in.
// Outside an example, `plimsoll-clients create` writes the same file (see
// docs/callers.md); this one is inlined so the program stays self-contained.
func writeClientsFile(dir string) (token, path string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))

	path = filepath.Join(dir, "clients.json")
	body := fmt.Sprintf(`{"clients":[{"id":%q,"token_sha256":%q,"scopes":["code:run"]}]}`,
		callerID, hex.EncodeToString(sum[:]))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return "", "", err
	}
	return token, path, nil
}

// buildDaemon compiles plimsolld from the checkout so the example runs the code in
// this tree rather than whatever happens to be installed.
func buildDaemon(ctx context.Context, dir string) (string, error) {
	binary := filepath.Join(dir, "plimsolld")
	cmd := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/plimsolld")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("build plimsolld (run this from the repository root): %w", err)
	}
	return binary, nil
}

func startDaemon(ctx context.Context, binary, addr, clientsPath string) (*exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, binary)
	cmd.Env = append(os.Environ(),
		"SANDBOX_PROVIDER=wasm",
		"PLIMSOLL_ADDR="+addr,
		"PLIMSOLL_CLIENTS_FILE="+clientsPath,
	)
	// The daemon's structured audit line goes to stderr: one record per run, naming
	// the calling principal and never the code or the token. Watch for it below.
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start plimsolld: %w", err)
	}
	return cmd, nil
}

func stop(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
}

// waitForReady polls /readyz, which the daemon serves outside auth alongside
// /healthz and /metrics.
func waitForReady(ctx context.Context, baseURL string) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/readyz", nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("plimsolld did not become ready within 30s")
}

// oneLine flattens a server error for display. Connect errors carry the server's
// message plus its code, separated by a newline.
func oneLine(err error) string {
	return strings.ReplaceAll(strings.TrimSpace(err.Error()), "\n", " | ")
}

// freeAddr reserves a loopback port by binding it and handing back the address.
func freeAddr() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := listener.Addr().String()
	return addr, listener.Close()
}
