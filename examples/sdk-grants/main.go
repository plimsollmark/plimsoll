// Command sdk-grants shows an agent's code using the OpenAI and Anthropic Python
// libraries, unmodified, inside a plimsoll docker sandbox that never holds the API key,
// and writes the page that shows what happened.
//
// A grant profile that sets sdk_env gives the run a local address inside the sandbox
// (127.0.0.1:8471) and puts the library's base URL and a dummy key in the guest's
// environment. The broker outside the sandbox checks each request against the profile's
// allow list, copies only the headers pass_headers names, sets the real key itself,
// passes a streamed answer through piece by piece and an upload of up to the route's
// limit. Such a run gets a seccomp profile of its own, derived from the default, which
// adds IPv4 TCP sockets.
//
// No model API is called and nothing is spent: a stub API on loopback stands in for a
// small part of the two APIs (a chat or messages call, the same streamed, a multipart
// file upload, and a route the profile does not allow) and writes down every request it
// receives, headers included. It needs docker and the images make docker-images builds;
// it builds plimsolld and the example's image (sdk.Dockerfile, which installs the two
// libraries from wheels pinned by version and hash; the build uses the network, a run
// never does). Run it from the repository root:
//
//	go run ./examples/sdk-grants           # build the image, run everything, write docs/examples/sdk-grants/
//	go run ./examples/sdk-grants -verify   # recheck the published files; starts nothing
//	go run ./examples/sdk-grants -render   # rewrite the page from evidence.json
//	go run ./examples/sdk-grants -derive   # rebuild evidence.json and the page from the published raw files
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

func main() {
	out := flag.String("out", filepath.Join("docs", "examples", "sdk-grants"), "the page's directory")
	work := flag.String("work", filepath.Join("tmp", "sdk-grants-example"), "scratch for plimsolld, its log and the grants file; emptied first, never published")
	build := flag.Bool("build", true, "build the example's image first (docker build of sdk.Dockerfile)")
	verify := flag.Bool("verify", false, "recheck the published files and write nothing")
	render := flag.Bool("render", false, "rewrite index.html from the published evidence.json; start nothing")
	rederive := flag.Bool("derive", false, "rebuild evidence.json and index.html from the published raw files (the bundle, the statement, the stub's log, the profiles); start nothing")
	flag.Parse()

	var err error
	switch {
	case *rederive:
		var c config
		if c, err = newConfig(*out, *work, false); err == nil {
			var ev *evidence
			if ev, err = derive(c.out); err == nil {
				err = publish(c.out, ev, c.repo)
			}
		}
	case *verify:
		if err = verifyPublished(*out); err == nil {
			fmt.Println("sdk-grants: the bundle and the statement verify, the evidence is what the published files give, and the page is what the evidence renders")
		}
	case *render:
		err = renderPublished(*out)
	default:
		var c config
		if c, err = newConfig(*out, *work, *build); err == nil {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			err = runAll(ctx, c)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sdk-grants:", err)
		os.Exit(1)
	}
}

func newConfig(out, work string, build bool) (config, error) {
	repo, err := os.Getwd()
	if err != nil {
		return config{}, err
	}
	if _, err := os.Stat(filepath.Join(repo, "cmd", "plimsolld")); err != nil {
		return config{}, fmt.Errorf("run this from the repository root (no cmd/plimsolld in %s)", repo)
	}
	abs := func(p string) string {
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(repo, p)
	}
	return config{repo: repo, out: abs(out), work: abs(work), build: build}, nil
}
