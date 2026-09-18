# Getting started

By the end of this page you will have a `plimsolld` that authenticates you, a Go
program of your own that runs a snippet through it and states the isolation floor
it requires, and you will have watched that program be refused before anything ran
when the daemon could not meet the floor, then satisfied when you switched to a
stronger tier. Everything up to the last step runs on one machine with no docker,
no account and no network. Nothing here spends money; the E2B provider is not part
of this page.

You need Go 1.26.6 or newer and git. The last step needs Linux, docker, and root
for the gVisor installer.

## 1. Clone and build

```sh
git clone https://github.com/plimsollmark/plimsoll && cd plimsoll
go build ./...
```

## 2. Create a caller

A caller is a program the daemon will accept requests from. Give it an id and let
the command mint its token:

```sh
TOKEN="$(go run ./cmd/plimsoll-clients create \
  -file clients.json -id tutorial -token-stdout)"
```

The token is printed once, to stdout, and nowhere else; `clients.json` holds only
its SHA-256 fingerprint. The command's other output goes to stderr and ends with a
reminder that a running daemon does not notice file edits. There is no daemon yet,
so move on. [docs/callers.md](callers.md) covers rotation, revocation and import.

## 3. Start the daemon

```sh
SANDBOX_PROVIDER=wasm \
PLIMSOLL_ADDR=127.0.0.1:8746 \
PLIMSOLL_CLIENTS_FILE=clients.json \
PLIMSOLL_LOG_FORMAT=text \
go run ./cmd/plimsolld
```

Three choices are made on that line. `wasm` is the in-process provider: JavaScript
runs on an embedded QuickJS engine inside the daemon, with no docker daemon and no
per-run cost, at process-tier isolation, which is not a boundary for hostile code.
`127.0.0.1:8746` binds loopback only; the default `:8746` listens on every
interface. The clients file turns authentication on, and it fails closed: a request
without a valid token is refused before its body is read. Leave this terminal
running. You should see:

```
level=INFO msg="sandbox provider ready" provider=wasm
level=INFO msg="multi-client auth enabled" clients=1
level=INFO msg="plimsolld listening" addr=127.0.0.1:8746 provider=wasm isolation=process auth=true ...
```

`plimsolld -h` lists every variable the daemon reads.

## 4. Write the client

Save this as `hello/main.go` inside the clone. It makes the same request twice, once
with a floor the daemon can meet and once with a floor it cannot:

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/sandbox"
)

func main() {
	remote, err := client.New("http://127.0.0.1:8746", client.WithToken(os.Getenv("PLIMSOLL_CALLER_TOKEN")))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, floor := range []sandbox.IsolationClass{sandbox.IsolationProcess, sandbox.IsolationKernel} {
		res, err := remote.RunJavaScript(ctx, sandbox.Request{
			Code:             "console.log(6 * 7)",
			Timeout:          5 * time.Second,
			MinimumIsolation: floor,
		})
		switch {
		case errors.Is(err, sandbox.ErrInsufficientIsolation):
			fmt.Printf("floor %-8v refused before dispatch; nothing ran\n", floor)
		case err != nil:
			fmt.Printf("floor %-8v error: %v\n", floor, err)
		default:
			fmt.Printf("floor %-8v ran behind %v, exit %d, stdout %q\n", floor, res.Isolation, res.ExitCode, res.Stdout)
		}
	}
}
```

Run it in a second terminal, in the same shell that holds `TOKEN`:

```sh
PLIMSOLL_CALLER_TOKEN="$TOKEN" go run ./hello
```

```
floor process  ran behind process, exit 0, stdout "42\n"
floor kernel   refused before dispatch; nothing ran
```

Read the two lines as the whole design. The first request said "process or
stronger", the daemon's evidence said `process`, so it ran, and the result reports
the tier it actually ran behind. The second said "kernel or stronger". The handler
compared that floor with the provider's evidence immediately before admission and
refused, so **no code ran**; the client sees it as `ErrInsufficientIsolation`
through `errors.Is`, the same sentinel an in-process provider would return. That
refusal is the case the project exists for: a deployment still pointing at the
development tier while the caller demands a production one.

Three things worth noticing in the client. `client.New` accepts loopback cleartext
as is and refuses any other cleartext address unless you opt into the
development-only `client.WithInsecureHTTP()`. The token rides on every request; in a
real caller it comes from that caller's secret store, not an environment variable
in a tutorial. And a snippet that fails is not an error: `exit` would be non-zero
and `err` nil, because the user's code failing is a normal result and only a run
that could not happen is an error.

In the daemon's terminal, one audit line per run names the caller and never the
code or the token:

```
level=INFO msg="code run" rpc=RunJavaScriptV2 caller=tutorial code_bytes=18 grant_profile="" sandbox=wasm isolation=process exit_code=0 timed_out=false duration_ms=294
```

## 5. Change the tier, not the program

Stop the daemon (Ctrl-C). The program and the caller stay as they are; only the
daemon's configuration changes.

**Container tier.** With docker installed, pull and build the two images the
provider verifies at startup, then restart under the docker provider:

```sh
make docker-images

SANDBOX_PROVIDER=docker \
PLIMSOLL_ADDR=127.0.0.1:8746 \
PLIMSOLL_CLIENTS_FILE=clients.json \
PLIMSOLL_LOG_FORMAT=text \
go run ./cmd/plimsolld
```

Startup takes a few seconds longer: the provider launches a throwaway container and
proves from its own mount table that the root is read-only and every writable
mount is a sized `noexec` tmpfs. It also warns, correctly, that `runc` shares the
host kernel. Run the client again:

```
floor process  ran behind container, exit 0, stdout "42\n"
floor kernel   refused before dispatch; nothing ran
```

The first line moved up a tier without the program changing. The second is still
refused, because a container under `runc` is not a kernel boundary and the daemon
will not say it is.

**Kernel tier.** Install the pinned gVisor release and register the `runsc` runtime
(the installer sets the `--host-uds=open` flag the broker socket needs), then add
one variable:

```sh
sudo ./docker/install-gvisor.sh

SANDBOX_PROVIDER=docker \
SANDBOX_DOCKER_RUNTIME=runsc \
PLIMSOLL_ADDR=127.0.0.1:8746 \
PLIMSOLL_CLIENTS_FILE=clients.json \
PLIMSOLL_LOG_FORMAT=text \
go run ./cmd/plimsolld
```

The outputs quoted above are from real runs on the wasm and `runc` paths. With
`runsc` registered, the second line of the client's output reads `ran behind
kernel`, because the floor is now met; the daemon's startup log carries
`isolation=kernel` after it has verified the runtime registration and run the same
mount checks under it. That tier is provider and configuration evidence plus the
behavioral smoke test, not an attestation, and the README says exactly what it
rests on under [Isolation tiers](../README.md#isolation-tiers).

## Where next

- The README's [what comes back](../README.md#what-comes-back-and-what-it-means)
  explains every outcome the client can see and which ones are safe to retry.
- [docs/callers.md](callers.md) for a second caller, rotation, revocation, and what
  a running daemon does with a changed file.
- Grants, for letting the snippet call your own API without ever holding the
  credential: README [capability grants](../README.md#capability-grants), then
  `go run ./examples/grant`.
- Production posture: `PLIMSOLL_HARDENED=1` refuses to serve unless every advertised
  property is verifiably in force (README [hardened mode](../README.md#hardened-mode)).
- The [interactive lessons](https://plimsollmark.github.io/plimsoll/trainers/) cover
  the same ground with pictures and no clone.
