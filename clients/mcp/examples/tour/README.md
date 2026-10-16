# The MCP tour: recorded examples for the trainer page

This program records the examples the MCP trainer page shows. It starts the plimsoll MCP
server binary over stdio, the way an MCP host such as Claude Code or Codex starts it, and plays
the model's part with scripted calls, made the way a model makes them: no model chooses the
calls, but each one goes over the same connection and reaches the same server, which runs the
code on a real plimsolld. Everything sent and returned is written to
[docs/trainers/mcp-tour.js](../../../../docs/trainers/mcp-tour.js), which sets one global,
`window.MCP_TOUR`, for the page to read. The file is generated: do not edit it by hand.

The scenarios, in order:

1. **Check, don't guess**: a primality test of 2**61 - 1 in a fresh sandbox.
2. **Your file, analyzed**: a made-up CSV passed in `files`, summarized with Python's standard library.
3. **A notebook that remembers**: data loaded once in a sandbox, two follow-up calls that use it.
4. **The debug loop**: a check that fails with a traceback, the fix, the pass.
5. **Untrusted code, no network**: a request to an https URL fails inside the sandbox.
6. **Two languages, one sandbox**: Python writes a file, JavaScript reads it.
7. **A runaway loop**: an endless loop is stopped at the run's time budget, and the sandbox answers the next call.
8. **Prove it later**: example 1's run record, its signed receipt line, and `plimsoll-attest verify-entry` on that line.
9. **A fourth sandbox, refused**: with three open, a fourth `open_sandbox` is refused and names the idle ones.

Each scenario records every tool call (its arguments, the full result or the tool error, and the
wall time), a sentence built from the real results, and the plan's claims for it, each marked
held or not. When a real result differs from what the scenario expects, the file keeps the real
result and marks the claim as not held; the program then exits 3.

## What it needs

- `-server`: the `plimsoll-mcp` binary. `-attest`: the `plimsoll-attest` binary. The program
  builds neither, so what it records is exactly the binary it was given.
- `-daemon`: a plimsolld that keeps sessions (`SANDBOX_MAX_SESSIONS` of 3 or more, none of them
  held by anything else), whose project image runs Python and Node (`plimsoll/sandbox-python`,
  from `make docker-images`), at the `kernel` tier or above, which the server requires by
  default. The committed recording was made with `SANDBOX_PROVIDER=docker`,
  `SANDBOX_DOCKER_RUNTIME=runsc` (gVisor), `SANDBOX_DOCKER_PROJECT_IMAGE=plimsoll/sandbox-python:latest`
  and `SANDBOX_MAX_SESSIONS=4`.
- `-token-file`: a file holding the caller token, unless the daemon is open. The token goes into
  the server's environment only; the program never prints it, and refuses to write an output
  that contains it.
- `-out`: where to write the JavaScript file.

The server runs with three settings, recorded in the file: `PLIMSOLL_MAX_SANDBOXES=3`, the
server's default, so scene 9 shows the cap a user gets without configuring one;
`PLIMSOLL_TIMEOUT_MS=3000`, because scene 7 waits out the run's budget and three seconds keeps
the recording short while every other run here finishes in about one; and
`PLIMSOLL_CALL_TIMEOUT_MS=15000`, since the server requires a call's budget to be at least 10
seconds above the run's (it also covers opening a sandbox and waiting for a turn).

The program makes an Ed25519 demo signing key and a receipts directory in a new temporary
directory, turns receipts on with them, and deletes the directory when it ends. Only the public
half of the key reaches the output, beside the receipt line, so the page can check the signature
in the browser.

## Rerun it

From the repository root, with the daemon running:

```sh
(cd clients/mcp && go build -o ../../tmp/plimsoll-mcp ./cmd/plimsoll-mcp)
go build -o tmp/plimsoll-attest ./cmd/plimsoll-attest
(cd clients/mcp && go run ./examples/tour \
  -server ../../tmp/plimsoll-mcp -attest ../../tmp/plimsoll-attest \
  -daemon http://127.0.0.1:8746 -token-file ../../tmp/token \
  -out ../../docs/trainers/mcp-tour.js)
```

It takes about 15 seconds and starts no paid service. Exit 0 means every claim held; 3, that the
file was written but some claims did not hold (they are listed on stderr); 1, that it stopped on
an error and wrote nothing.

## The test

`go test ./examples/tour/` (in `clients/mcp`, and in `make mcp-suite`) needs no daemon. It
reads the committed file and checks that it parses, holds all nine scenarios, and names only
tools the current server registers; that its surface digest is the current server's (a server
built from the same settings), so any change to a tool's name, description or schema marks the
recording stale until it is rerun; that the receipt line's signature verifies with the embedded
public key over the bytes the file says are signed, and passes `attest.VerifyEntry`; and that the
file holds no private key and nothing that looks like a token.
