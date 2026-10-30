// Command ship-scan shows the ship scan end to end: a daemon with a withheld set, five
// calls that ship what a harness or an agent might, and what the caller and the operator
// each see. docs/ship-scan.md is the reference; this is the walk-through.
//
// Run it from the repository root, because it builds plimsolld and plimsoll-withheld
// from source:
//
//	go run ./examples/ship-scan            # run the calls, write the page and its evidence
//	go run ./examples/ship-scan -verify    # check the published files offline; starts nothing
//	go run ./examples/ship-scan -render    # rewrite the page from the published evidence
//
// It needs no docker, no network, no credentials and no model: the daemon runs with
// SANDBOX_PROVIDER=wasm. The set is the one docs/ship-scan.md recommends: the harness's
// files refused (shipping them is the harness developer's mistake), its hidden seeds
// audited (a refusal would tell an agent that guessed one that the guess was right).
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
	out := flag.String("out", filepath.Join("docs", "examples", "ship-scan"), "where the page and its evidence go")
	verify := flag.Bool("verify", false, "check the published files offline; start nothing")
	render := flag.Bool("render", false, "rewrite the page from the published evidence; start nothing")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch {
	case *verify:
		err = verifyPublished(*out)
		if err == nil {
			fmt.Println("verified  |", *out)
		}
	case *render:
		err = renderPublished(*out)
	default:
		err = runAndPublish(ctx, *out)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ship-scan:", err)
		os.Exit(1)
	}
}
