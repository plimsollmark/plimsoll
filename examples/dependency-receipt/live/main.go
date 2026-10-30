// Command live runs the dependency behavior receipt end to end through plimsoll and writes
// the page that shows it, docs/examples/dependency-receipt/: three npm packages, each
// installed and imported in its own run that plimsolld dispatched to a Kubernetes
// agent-sandbox pod under gVisor, every run's record signed into one bundle, and for each
// run a receipt of what the programs in that pod did, read from runsc's syscall log on the
// node and joined to the run's record by the pod's UID. Two tampered copies (a connection
// deleted from a receipt, one byte of a log changed) are checked too, and must fail.
//
// The live run needs a kind cluster with agent-sandbox v1.0.7 and the gvisor-receipt
// runtime class (examples/dependency-receipt/fixtures/capture.sh -install puts its runsc
// handler in the node), docker, kind and kubectl, and the agent-sandbox image built from
// docker/agentsandbox.Dockerfile. It makes a namespace of its own and deletes it after.
// Nothing is paid for: the cluster is local. From the repository root:
//
//	go run ./examples/dependency-receipt/live            # run everything, write the page
//	go run ./examples/dependency-receipt/live -verify    # recheck the published files offline
//	go run ./examples/dependency-receipt/live -render    # rewrite index.html from evidence.json
//	go run ./examples/dependency-receipt/live -assemble  # rebuild the page from the last run's scratch
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

func main() {
	out := flag.String("out", filepath.Join("docs", "examples", "dependency-receipt"), "the page's directory")
	work := flag.String("work", filepath.Join("tmp", "dependency-receipt-live"), "scratch: binaries, secrets, raw output; emptied first, never published; its secrets are deleted when the run ends unless -keep")
	cluster := flag.String("cluster", "plimsoll-as", "the kind cluster's name (kubectl's context must be kind-NAME)")
	image := flag.String("image", "plimsoll/sandbox-agentsandbox:dev", "the agent-sandbox image (docker/agentsandbox.Dockerfile)")
	class := flag.String("runtime-class", "gvisor-receipt", "the RuntimeClass whose runsc logs every call the receipt reads")
	handler := flag.String("handler", "runsc-receipt", "that class's handler, declared to plimsolld as gVisor")
	keep := flag.Bool("keep", false, "leave the namespace, the daemon and the secrets it reads (the signing key among them) in place afterwards")
	verify := flag.Bool("verify", false, "recheck the published files and write nothing; starts nothing")
	render := flag.Bool("render", false, "rewrite index.html from the published evidence.json; starts nothing")
	assembleOnly := flag.Bool("assemble", false, "rebuild the published files from the last run's scratch in -work; starts nothing")
	flag.Parse()

	var err error
	switch {
	case *verify:
		err = verifyPublished(*out)
		if err == nil {
			fmt.Println("dependency-receipt live: the bundle verifies, every receipt checks against its log and record, the three changed or mismatched inputs are refused, and the page is what evidence.json renders")
		}
	case *render:
		err = renderPublished(*out)
	default:
		var c config
		c, err = newConfig(*out, *work, *cluster, *image, *class, *handler, *keep)
		if err != nil {
			break
		}
		if *assembleOnly {
			err = assembleAndPublish(c)
			break
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		err = runLive(ctx, c)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "dependency-receipt live:", err)
		os.Exit(1)
	}
}

func newConfig(out, work, cluster, image, class, handler string, keep bool) (config, error) {
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
	c := config{repo: repo, out: abs(out), work: abs(work), cluster: cluster, image: image, runtimeClass: class, handler: handler, keep: keep}
	// The live run empties -work first: never a directory the repository is in.
	if rel, err := filepath.Rel(c.work, repo); err == nil && !strings.HasPrefix(rel, "..") {
		return config{}, fmt.Errorf("-work %s holds the repository; name a scratch directory", c.work)
	}
	return c, os.MkdirAll(c.out, 0o755)
}
