# Getting started

By the end of this page you will have:

- `plimsolld`, the plimsoll server, running on your machine and accepting only callers
  it knows;
- a Go program of your own that sends it JavaScript and states the weakest sandbox it
  will accept;
- seen the daemon refuse that program before running anything, and then run it once you
  switch the daemon to a stronger sandbox.

The strength of a run's sandbox is its <dfn>*isolation tier*</dfn>, one of four levels
(weakest first: `process`, `container`, `kernel`, `vm`). The weakest tier a request will
accept is its <dfn>*floor*</dfn>.

Steps 2 to 4 need only your machine: no docker, no cloud account, and no network beyond
`127.0.0.1`. Cloning and building may download code. Step 5 needs docker, and its last
part needs root. Nothing on this page costs money, because it uses no cloud service.

You need git and Go 1.26.9 or newer. On 1.26.9, Go's vulnerability scanner
(`govulncheck`) reports no known vulnerabilities in the standard library code the daemon
calls; earlier 1.26 releases had published vulnerabilities in its HTTP/2 server, its
HTTP/1 connection handling and its reverse proxy. Step 5 needs Linux.

## 1. Clone and build

```sh
git clone https://github.com/plimsollmark/plimsoll && cd plimsoll
go build ./...
```

## 2. Create a caller

A caller is a program the daemon will accept requests from. Give it an id, and the
command creates its token:

```sh
TOKEN="$(go run ./cmd/plimsoll-clients create \
  -file clients.json -id tutorial -token-stdout)"
```

The token is printed once, to stdout, and nowhere else; `clients.json` keeps only a
SHA-256 hash of it. The command's other messages go to stderr and end with a reminder
that a running daemon does not notice changes to the file. There is no daemon yet, so
move on. [docs/callers.md](callers.md) covers rotation, revocation and import.

## 3. Start the daemon

Open a second terminal in the clone directory. Keep the first terminal open so it
still holds `TOKEN` from step 2.

```sh
SANDBOX_PROVIDER=wasm \
PLIMSOLL_ADDR=127.0.0.1:8746 \
PLIMSOLL_CLIENTS_FILE=clients.json \
PLIMSOLL_LOG_FORMAT=text \
go run ./cmd/plimsolld
```

That command makes three choices:

- `SANDBOX_PROVIDER=wasm` picks the <dfn>*provider*</dfn>, the backend that runs the
  code. `wasm` runs JavaScript on <dfn>*QuickJS*</dfn>, a small JavaScript engine compiled
  to <dfn>*WebAssembly*</dfn> (a portable bytecode that runs inside a host program), inside
  the daemon itself. It needs no docker and costs nothing per run, and its tier is
  `process`: no wall at all against hostile code.
- `PLIMSOLL_ADDR=127.0.0.1:8746` makes the daemon listen on your machine only. The
  default, `:8746`, listens on every network interface.
- `PLIMSOLL_CLIENTS_FILE` turns authentication on, and it <dfn>*fails closed*</dfn>:
  anything it cannot verify is refused, so a request without a valid token is turned
  away before its body is read.

Leave this terminal running. You should see:

```
level=INFO msg="multi-client auth enabled" clients=1
level=INFO msg="sandbox provider ready" provider=wasm
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

Run it in the first terminal, which still holds `TOKEN`:

```sh
PLIMSOLL_CALLER_TOKEN="$TOKEN" go run ./hello
```

```
floor process  ran behind process, exit 0, stdout "42\n"
floor kernel   refused before dispatch; nothing ran
```

These two lines are the whole design. The first request asked for `process` or
stronger. The daemon's provider reports `process`, so the code ran, and the result names
the tier it ran behind. The second request asked for `kernel` or stronger. Just before
starting the run, the daemon compared that floor with what its provider reports, and
refused, so **no code ran**. Your program sees the refusal as `ErrInsufficientIsolation`
through `errors.Is`, the same error value an in-process provider returns. This refusal
is the case plimsoll exists for: a deployment still set up for development while the
caller demands production-grade isolation.

Three more things about the client:

- `client.New` accepts unencrypted HTTP to a loopback address such as `127.0.0.1`. It
  refuses unencrypted HTTP to any other address unless you opt into the
  development-only `client.WithInsecureHTTP()`.
- The token goes with every request. A real caller would read it from its secret store,
  not from an environment variable.
- A snippet that fails is not an error. Its exit code is non-zero and `err` is nil,
  because code that ran and failed is a normal result; `err` means the run could not
  happen.

In the daemon's terminal, each run writes one log line that names the caller, and never
the code or the token:

```
level=INFO msg="code run" op=javascript caller=tutorial code_bytes=18 grant_profile="" sandbox=wasm isolation=process exit_code=0 timed_out=false duration_ms=292
```

## 5. Change the tier, not the program

Stop the daemon (Ctrl-C). The program and the caller stay as they are; only the
daemon's configuration changes.

**Container tier.** With docker installed, build the sandbox images with `make
docker-images`, then restart the daemon with the docker provider. At startup the
provider checks that both of its images, one for snippets and one for projects, are
present:

```sh
make docker-images

SANDBOX_PROVIDER=docker \
PLIMSOLL_ADDR=127.0.0.1:8746 \
PLIMSOLL_CLIENTS_FILE=clients.json \
PLIMSOLL_LOG_FORMAT=text \
go run ./cmd/plimsolld
```

Startup takes a few seconds longer. The provider starts a throwaway container and
checks, from inside it, that the root filesystem is read-only and that the only
writable places are fixed-size <dfn>*tmpfs*</dfn> mounts (filesystems held in memory),
from which no program can be run. It also warns, correctly, that
<dfn>*runc*</dfn>, docker's default runtime, lets the container share your machine's
kernel. Run the client again:

```
floor process  ran behind container, exit 0, stdout "42\n"
floor kernel   refused before dispatch; nothing ran
```

The first line moved up a tier without the program changing. The second is still
refused, because a container under `runc` is not a kernel-level wall, and the daemon
will not say it is.

**Kernel tier.** Install <dfn>*gVisor*</dfn>, a layer that handles the container's
requests to the operating system itself, so the code never talks to your kernel
directly. The installer fetches a <dfn>*pinned*</dfn> gVisor release (one exact version,
which changes only when this repository changes it) and registers gVisor's runtime,
<dfn>*runsc*</dfn>, with docker. It also sets the `--host-uds=open` flag, which lets a
sandbox connect to a socket on your machine; plimsoll passes a run's API calls through
one. Then add one variable:

```sh
sudo ./docker/install-gvisor.sh

SANDBOX_PROVIDER=docker \
SANDBOX_DOCKER_RUNTIME=runsc \
PLIMSOLL_ADDR=127.0.0.1:8746 \
PLIMSOLL_CLIENTS_FILE=clients.json \
PLIMSOLL_LOG_FORMAT=text \
go run ./cmd/plimsolld
```

The outputs above are from real runs of the `wasm` and `runc` setups. With `runsc`
registered, the second line of the client's output reads `ran behind kernel`, because
the floor is now met. The daemon's startup log shows `isolation=kernel` once it has
confirmed that docker has `runsc` registered and has rerun the same filesystem checks
under it. That tier rests on configuration and those checks. It is not
<dfn>*attestation*</dfn>, cryptographic proof from the hardware of what software is
running. [docs/isolation-tiers.md](isolation-tiers.md) says exactly what each tier rests
on.

## Embedding it instead of running the daemon

If your own program should run the code, skip the daemon and import the package.
`sandbox.Build` reads its settings from the environment, returns an error instead of
guessing at a bad setting, and picks the Disabled provider when `SANDBOX_PROVIDER` is
unset, so nothing runs unless you opt in.

```sh
go get github.com/plimsollmark/plimsoll
```

```go
provider, err := sandbox.Build(os.Getenv)   // errors rather than guessing
if err != nil { return err }
if err := provider.EnsureReady(ctx); err != nil { return err } // preflight + smoke test

result, err := provider.Sandbox.RunJavaScript(ctx, sandbox.Request{
    Code:    userCode,
    Timeout: 10 * time.Second,
})
// err means the run never happened. Code that merely failed returns
// result.ExitCode != 0, which is a normal result, not an error.
```

Output limits apply either way. Each output stream is cut at the provider's limit, 64
KiB by default, and the result's truncation flags are the only sign that it was cut:
plimsoll never writes a marker into the output itself. See
[what comes back](run-results.md).

## Installing without a clone

```sh
go install github.com/plimsollmark/plimsoll/cmd/plimsolld@latest
go install github.com/plimsollmark/plimsoll/cmd/plimsoll-clients@latest
```

There are no prebuilt binaries and no daemon container image yet. `go install` builds
from the tagged module source, checked against Go's checksum database
(`sum.golang.org`) like any other module.

## Where next

- [What comes back, and what it means](run-results.md)
  explains every outcome the client can see and which ones are safe to retry.
- [docs/callers.md](callers.md) for a second caller, rotation, revocation, and what
  a running daemon does with a changed file.
- A <dfn>*grant*</dfn> lets a run's code call your own API without ever holding the
  credential: read [capability grants](capability-grants.md), then run
  `go run ./examples/grant`.
- For production, <dfn>*hardened mode*</dfn> (`PLIMSOLL_HARDENED=1`) makes the daemon
  refuse to start unless every production safeguard is configured
  ([hardened mode](hardened-mode.md)).
- The [interactive lessons](https://plimsollmark.github.io/plimsoll/trainers/) cover
  the same ground with pictures and no clone, and the
  [glossary](https://plimsollmark.github.io/plimsoll/trainers/glossary.html) defines
  every term in one plain sentence.
