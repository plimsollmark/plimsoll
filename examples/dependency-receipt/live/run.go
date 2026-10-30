package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/examples/dependency-receipt/runsclog"
	"github.com/plimsollmark/plimsoll/examples/internal/daemonproc"
	"github.com/plimsollmark/plimsoll/sandbox"
)

//go:embed cluster.yaml
var clusterYAML string

// The names the run makes on the cluster, all inside one namespace of its own but the
// cluster role that lets the service account read runtime classes.
const (
	namespace = "plimsoll-dependency-receipt"
	pool      = "receipt"
	daemonCtr = "plimsoll-dependency-receipt-plimsolld"
	memoryMB  = 512
	logRoot   = "/var/log/runsc-observe"
)

// fixtures are the packages installed, one run each, in the order the page shows them: the
// quiet one is the baseline (no install script), the network one starts a connection, and
// the canary one writes outside its own directory, which this sandbox refuses.
var fixtures = []string{"quiet", "network", "canary"}

// config is where the run reads and writes, and the cluster it uses.
type config struct {
	repo         string // the repository root (absolute)
	out          string // the page's directory
	work         string // scratch, never published
	cluster      string // the kind cluster's name
	image        string // the agent-sandbox image, as docker and the template name it
	runtimeClass string // the RuntimeClass of the template's pods
	handler      string // its handler, which the daemon is told is gVisor
	keep         bool   // leave the namespace and the daemon for a look afterwards
}

func (c config) node() string { return c.cluster + "-control-plane" }

// rawRun is what one run left in the work directory before the page's evidence is drawn
// from it: the fixture, the line its record took in the bundle, and the node's log path.
type rawRun struct {
	Fixture  string `json:"fixture"`
	Line     int    `json:"line"`
	Instance string `json:"instance"`
	NodeLog  string `json:"node_log"`
}

// rawSetup is what the run read about the cluster and the daemon, for the evidence.
type rawSetup struct {
	Kubernetes   string            `json:"kubernetes"`
	Runtime      string            `json:"container_runtime"`
	AgentSandbox string            `json:"agent_sandbox"`
	RuntimeClass string            `json:"runtime_class"`
	Handler      string            `json:"handler"`
	Image        string            `json:"image"`
	Daemon       map[string]string `json:"daemon"` // every setting plimsolld ran with but its secrets' paths
	Build        build             `json:"build"`
	Runs         []rawRun          `json:"runs"`
}

// build is what plimsolld and the receipt command were built from: the Go release, the
// checkout's commit, and the paths that differed from it.
type build struct {
	Go       string `json:"go"`
	Revision string `json:"revision"`
	// Base is where the checkout meets main, and Ahead the subjects of its commits past it:
	// a commit landed by rebase gets a new hash, and these still say what was built.
	Base        string   `json:"main_base"`
	Ahead       []string `json:"ahead_of_main"`
	Uncommitted []string `json:"uncommitted"`
}

// buildFacts reads the commit from git itself. The binaries are built with -buildvcs=false:
// in a git worktree that sits inside its main checkout's directory, Go's own stamp names
// the main checkout's commit, not the worktree's (seen on 2026-10-29).
func buildFacts(ctx context.Context, c config) (build, error) {
	var b build
	var err error
	if b.Go, err = run(ctx, c.repo, nil, "go", "env", "GOVERSION"); err != nil {
		return b, err
	}
	if b.Revision, err = run(ctx, c.repo, nil, "git", "rev-parse", "HEAD"); err != nil {
		return b, err
	}
	b.Ahead = []string{}
	if base, err := run(ctx, c.repo, nil, "git", "merge-base", "HEAD", "main"); err == nil {
		b.Base = base
		if log, err := run(ctx, c.repo, nil, "git", "log", "--reverse", "--format=%s", base+"..HEAD"); err == nil && log != "" {
			b.Ahead = strings.Split(log, "\n")
		}
	}
	// Not through run, which trims: a porcelain line starts with its two status columns, the
	// first of them often a space.
	cmd := exec.CommandContext(ctx, "git", "status", "--porcelain=v1", "--untracked-files=all")
	cmd.Dir = c.repo
	status, err := cmd.Output()
	if err != nil {
		return b, fmt.Errorf("git status: %w", err)
	}
	// The page's own directory is output, emptied before the build: not an input.
	out, err := filepath.Rel(c.repo, c.out)
	if err != nil {
		return b, err
	}
	out = filepath.ToSlash(out) + "/"
	b.Uncommitted = []string{}
	for _, l := range strings.Split(strings.TrimRight(string(status), "\n"), "\n") {
		if len(l) > 3 && l[2] == ' ' && !strings.HasPrefix(l[3:], out) {
			b.Uncommitted = append(b.Uncommitted, l[3:])
		}
	}
	return b, nil
}

// runLive does the whole thing on the cluster, then assembles and publishes the page.
func runLive(ctx context.Context, c config) (err error) {
	if err := preflight(ctx, c); err != nil {
		return err
	}
	if err := os.RemoveAll(c.work); err != nil {
		return err
	}
	// An earlier run's published files go now, so the build's list of uncommitted paths
	// names inputs only.
	if err := clearPublished(c.out); err != nil {
		return err
	}
	for _, d := range []string{"bin", "secrets", "logs", "receipts", "tampered"} {
		if err := os.MkdirAll(filepath.Join(c.work, d), 0o700); err != nil {
			return err
		}
	}
	setup := rawSetup{RuntimeClass: c.runtimeClass, Handler: c.handler, Image: c.image}
	if setup.Kubernetes, err = kubectl(ctx, "get", "nodes", "-o", "jsonpath={.items[0].status.nodeInfo.kubeletVersion}"); err != nil {
		return err
	}
	if setup.Runtime, err = kubectl(ctx, "get", "nodes", "-o", "jsonpath={.items[0].status.nodeInfo.containerRuntimeVersion}"); err != nil {
		return err
	}
	if setup.AgentSandbox, err = kubectl(ctx, "get", "deploy", "-n", "agent-sandbox-system", "-o", "jsonpath={.items[0].spec.template.spec.containers[0].image}"); err != nil {
		return err
	}

	step("building plimsolld and the receipt command")
	bin := filepath.Join(c.work, "bin")
	if err := goBuild(ctx, c, filepath.Join(bin, "plimsolld"), "./cmd/plimsolld"); err != nil {
		return err
	}
	if err := goBuild(ctx, c, filepath.Join(bin, "dependency-receipt"), "./examples/dependency-receipt"); err != nil {
		return err
	}
	if setup.Build, err = buildFacts(ctx, c); err != nil {
		return err
	}

	step("loading " + c.image + " into the kind node")
	if _, err := run(ctx, "", nil, "kind", "load", "docker-image", c.image, "--name", c.cluster); err != nil {
		return err
	}

	step("making the secrets: the sandboxd token, the caller's token, the signing key")
	secrets := filepath.Join(c.work, "secrets")
	// The signing key, the tokens and the cluster's credentials go when the run ends
	// (this defer runs after the daemon is stopped and the namespace deleted): kept, the
	// key that harness.pub vouches for would let anyone on this machine sign receipts the
	// published key verifies. -assemble needs harness.pub only; -keep keeps them for the
	// daemon it leaves running (release review, 2026-10-29).
	defer func() {
		if c.keep {
			return
		}
		if rerr := os.RemoveAll(secrets); err == nil {
			err = rerr
		}
	}()
	sandboxdToken := randomHex(32)
	if err := os.WriteFile(filepath.Join(secrets, "sandboxd.token"), []byte(sandboxdToken), 0o600); err != nil {
		return err
	}
	callerToken, _, err := daemonproc.ClientsFile(secrets, "receipt-page")
	if err != nil {
		return err
	}
	privPEM, pubPEM, err := attest.GenerateKey()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(secrets, "harness.key"), privPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(c.work, "harness.pub"), pubPEM, 0o644); err != nil {
		return err
	}

	nodeIP, err := run(ctx, "", nil, "docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", c.node())
	if err != nil {
		return err
	}
	kindNet, err := run(ctx, "", nil, "docker", "network", "inspect", "kind", "-f", "{{range .IPAM.Config}}{{if .Subnet}}{{.Subnet}} {{end}}{{end}}")
	if err != nil {
		return err
	}
	ingress := ""
	for _, s := range strings.Fields(kindNet) {
		if _, n, err := net.ParseCIDR(s); err == nil && n.IP.To4() != nil {
			ingress = n.String()
			break
		}
	}
	podCIDR, err := kubectl(ctx, "get", "nodes", "-o", "jsonpath={.items[0].spec.podCIDR}")
	if err != nil {
		return err
	}
	if net.ParseIP(nodeIP) == nil || ingress == "" || podCIDR == "" {
		return fmt.Errorf("the node's address %q, kind's network %q, the pod range %q", nodeIP, kindNet, podCIDR)
	}
	_, pods, err := net.ParseCIDR(podCIDR)
	if err != nil {
		return err
	}
	// The whole /16 the node's /24 sits in, as kind's default pod subnet is.
	podRoute := (&net.IPNet{IP: pods.IP.Mask(net.CIDRMask(16, 32)), Mask: net.CIDRMask(16, 32)}).String()

	before, err := nodeLogDirs(ctx, c)
	if err != nil {
		return err
	}

	step("making the namespace " + namespace + ": service account, template under " + c.runtimeClass + ", warm pool")
	var manifest bytes.Buffer
	sum := sha256.Sum256([]byte(sandboxdToken))
	if err := template.Must(template.New("cluster").Parse(clusterYAML)).Execute(&manifest, map[string]any{
		"Namespace": namespace, "Pool": pool, "Ingress": ingress, "RuntimeClass": c.runtimeClass,
		"Image": c.image, "TokenSHA256": hex.EncodeToString(sum[:]), "MemoryMB": memoryMB,
	}); err != nil {
		return err
	}
	if _, err := run(ctx, "", manifest.Bytes(), "kubectl", "apply", "-f", "-"); err != nil {
		return err
	}
	defer func() {
		if c.keep {
			step("leaving the namespace and the daemon in place (-keep)")
			return
		}
		cerr := cleanup(context.WithoutCancel(ctx), c, before)
		if err == nil {
			err = cerr
		}
	}()
	if _, err := kubectl(ctx, "wait", "-n", namespace, "sandboxwarmpool/"+pool, "--for=jsonpath={.status.readyReplicas}=2", "--timeout=240s"); err != nil {
		return err
	}
	apiToken, err := kubectl(ctx, "create", "token", "plimsoll", "-n", namespace, "--duration=2h")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(secrets, "api.token"), []byte(apiToken), 0o600); err != nil {
		return err
	}
	ca, err := kubectl(ctx, "config", "view", "--raw", "--minify", "-o", "jsonpath={.clusters[0].cluster.certificate-authority-data}")
	if err != nil {
		return err
	}
	caPEM, err := base64.StdEncoding.DecodeString(ca)
	if err != nil {
		return fmt.Errorf("the cluster's CA in the kubeconfig: %w", err)
	}
	if err := os.WriteFile(filepath.Join(secrets, "ca.crt"), caPEM, 0o600); err != nil {
		return err
	}

	// The daemon runs in a container on kind's docker network, with a route to the pod
	// range through the node: plimsolld reaches each pod's sandboxd at the pod's address,
	// which only the cluster network routes (docs/agentsandbox.md).
	setup.Daemon = map[string]string{
		"SANDBOX_PROVIDER":                    "agentsandbox",
		"SANDBOX_MIN_ISOLATION":               "kernel",
		"SANDBOX_AGENTSANDBOX_API_SERVER":     "https://" + nodeIP + ":6443",
		"SANDBOX_AGENTSANDBOX_NAMESPACE":      namespace,
		"SANDBOX_AGENTSANDBOX_WARM_POOL":      pool,
		"SANDBOX_AGENTSANDBOX_RUNTIME_CLASS":  c.runtimeClass,
		"SANDBOX_AGENTSANDBOX_RUNSC_HANDLERS": c.handler,
		"SANDBOX_AGENTSANDBOX_IMAGE":          c.image,
		"SANDBOX_MEMORY_MB":                   fmt.Sprint(memoryMB),
		"SANDBOX_CPUS":                        "1",
	}
	files := map[string]string{
		"SANDBOX_AGENTSANDBOX_CA_FILE":             "/cfg/ca.crt",
		"SANDBOX_AGENTSANDBOX_TOKEN_FILE":          "/cfg/api.token",
		"SANDBOX_AGENTSANDBOX_SANDBOXD_TOKEN_FILE": "/cfg/sandboxd.token",
		"PLIMSOLL_CLIENTS_FILE":                    "/cfg/clients.json",
		"PLIMSOLL_ADDR":                            "0.0.0.0:8080",
		"PLIMSOLL_METRICS_ADDR":                    "off",
	}
	step("starting plimsolld on kind's network (its startup smoke test claims two pods)")
	args := []string{"run", "-d", "--name", daemonCtr, "--network", "kind", "--cap-add", "NET_ADMIN",
		"-p", "127.0.0.1::8080", "-v", bin + ":/plimsoll:ro", "-v", secrets + ":/cfg:ro"}
	for _, m := range []map[string]string{setup.Daemon, files} {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			args = append(args, "-e", k+"="+m[k])
		}
	}
	args = append(args, "alpine:3", "/bin/sh", "-c", "ip route add "+podRoute+" via "+nodeIP+" && exec /plimsoll/plimsolld")
	_, _ = run(ctx, "", nil, "docker", "rm", "-f", daemonCtr)
	if _, err := run(ctx, "", nil, "docker", args...); err != nil {
		return err
	}
	defer func() {
		if c.keep {
			return
		}
		stopDaemon(context.WithoutCancel(ctx), c)
	}()
	port, err := run(ctx, "", nil, "docker", "port", daemonCtr, "8080/tcp")
	if err != nil {
		return err
	}
	base := "http://" + strings.TrimSpace(strings.Split(port, "\n")[0])
	if err := waitReady(ctx, base, 3*time.Minute); err != nil {
		logs, _ := daemonLog(context.WithoutCancel(ctx))
		return fmt.Errorf("%w; its log:\n%s", err, tail(string(logs), 40))
	}

	priv, err := attest.ParsePrivateKey(privPEM)
	if err != nil {
		return err
	}
	bundlePath := filepath.Join(c.work, "bundle.jsonl")
	bundle, err := os.OpenFile(bundlePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer bundle.Close()
	harness := attest.NewHarness(attest.NewSigner(priv), bundle)
	remote, err := client.New(base, client.WithToken(callerToken), client.WithRecorder(harness))
	if err != nil {
		return err
	}
	for i, name := range fixtures {
		step("run " + fmt.Sprint(i+1) + ": install and import the " + name + " package through plimsoll")
		req, err := installRequest(c, name)
		if err != nil {
			return err
		}
		res, err := remote.RunProject(ctx, req)
		if err != nil {
			return fmt.Errorf("the %s run: %w", name, err)
		}
		if res.Record == nil || res.Instance == "" || res.Record.Instance != res.Instance {
			return fmt.Errorf("the %s run came back with no record or no instance (%+v)", name, res.Record)
		}
		fmt.Printf("    %s, %s, outcome %s, %d steps, record %.12s\n", res.Instance, res.Isolation, res.Outcome, len(res.Steps), res.Record.SHA256)
		setup.Runs = append(setup.Runs, rawRun{Fixture: name, Line: i + 1, Instance: res.Instance})
	}
	// The checkpoint closes the bundle: a bundle cut short of it fails verification.
	if err := harness.Checkpoint(); err != nil {
		return err
	}
	if err := bundle.Close(); err != nil {
		return err
	}

	step("stopping plimsolld; then reading each run's runsc log from the node")
	stopDaemon(ctx, c)
	for i := range setup.Runs {
		r := &setup.Runs[i]
		uid := strings.TrimPrefix(r.Instance, "k8s-pod-uid:")
		path, raw, err := fetchLog(ctx, c, uid, before)
		if err != nil {
			return fmt.Errorf("the %s run's log: %w", r.Fixture, err)
		}
		r.NodeLog = path
		if err := writeGzip(filepath.Join(c.work, "logs", r.Fixture+".boot.json.gz"), raw); err != nil {
			return err
		}
		fmt.Printf("    %s: %d bytes from %s\n", r.Fixture, len(raw), path)
	}
	if err := writeJSON(filepath.Join(c.work, "setup.json"), setup); err != nil {
		return err
	}
	if err := signAndCheck(ctx, c); err != nil {
		return err
	}
	return assembleAndPublish(c)
}

// installRequest is one run: the fixture package's files sent as a project, installed
// offline by npm from its directory (--install-links copies it into node_modules as a
// tarball install would, and runs its install script), then imported.
func installRequest(c config, name string) (sandbox.ProjectRequest, error) {
	req := sandbox.ProjectRequest{
		Files: []sandbox.File{{Path: "package.json", Content: `{"name":"receipt-run","version":"1.0.0","private":true}` + "\n"}},
		Steps: []string{
			"npm install --offline --no-audit --no-fund --foreground-scripts --install-links ./packages/" + name,
			`node -e 'require("plimsoll-fixture-` + name + `")'`,
		},
		Timeout:          2 * time.Minute,
		MinimumIsolation: sandbox.IsolationKernel,
	}
	dir := filepath.Join(c.repo, "examples", "dependency-receipt", "fixtures", "packages", name)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return req, err
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return req, err
		}
		req.Files = append(req.Files, sandbox.File{Path: "packages/" + name + "/" + e.Name(), Content: string(b)})
	}
	return req, nil
}

// signAndCheck signs each run's receipt with the receipt command, joined to the run's line
// in the bundle, checks it, and makes the two tampered cases and checks those.
func signAndCheck(ctx context.Context, c config) error {
	var setup rawSetup
	if err := readJSON(filepath.Join(c.work, "setup.json"), &setup); err != nil {
		return err
	}
	cmd := filepath.Join(c.work, "bin", "dependency-receipt")
	key := filepath.Join(c.work, "secrets", "harness.key")
	pub := filepath.Join(c.work, "harness.pub")
	bundle := filepath.Join(c.work, "bundle.jsonl")
	var transcripts []transcript
	say := func(name string, args ...string) (transcript, error) {
		t := transcript{Name: name, Args: args}
		x := exec.CommandContext(ctx, cmd, args...)
		var stdout, stderr bytes.Buffer
		x.Stdout, x.Stderr = &stdout, &stderr
		err := x.Run()
		var exit *exec.ExitError
		switch {
		case err == nil:
		case errors.As(err, &exit):
			t.Exit = exit.ExitCode()
		default:
			return t, err
		}
		t.Stdout, t.Stderr = stdout.String(), stderr.String()
		transcripts = append(transcripts, t)
		return t, nil
	}
	rel := func(p string) string { r, _ := filepath.Rel(c.work, p); return filepath.ToSlash(r) }
	for _, r := range setup.Runs {
		log := filepath.Join(c.work, "logs", r.Fixture+".boot.json.gz")
		out := filepath.Join(c.work, "receipts", r.Fixture+".intoto.json")
		line := fmt.Sprint(r.Line)
		if t, err := say("sign "+r.Fixture, "-log", log, "-key", key, "-out", out, "-bundle", bundle, "-line", line); err != nil || t.Exit != 0 {
			return fmt.Errorf("signing the %s receipt: %v %s", r.Fixture, err, t.Stderr)
		}
		if t, err := say("check "+r.Fixture, "-check", out, "-pub", pub, "-log", log, "-bundle", bundle, "-line", line); err != nil || t.Exit != 0 {
			return fmt.Errorf("checking the %s receipt: %v %s", r.Fixture, err, t.Stderr)
		}
	}

	// The two tampered cases, on the network run.
	var net rawRun
	for _, r := range setup.Runs {
		if r.Fixture == "network" {
			net = r
		}
	}
	envPath := filepath.Join(c.work, "receipts", "network.intoto.json")
	logPath := filepath.Join(c.work, "logs", "network.boot.json.gz")
	priv, err := readPrivateKey(key)
	if err != nil {
		return err
	}
	tampered, gone, err := dropConnection(envPath, attest.NewSigner(priv), priv.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	droppedPath := filepath.Join(c.work, "tampered", "network-connection-deleted.intoto.json")
	if err := os.WriteFile(droppedPath, tampered, 0o644); err != nil {
		return err
	}
	t, err := say("check a receipt with a connection deleted", "-check", droppedPath, "-pub", pub, "-log", logPath, "-bundle", bundle, "-line", fmt.Sprint(net.Line))
	if err != nil || t.Exit == 0 {
		return fmt.Errorf("the receipt with a connection deleted checked (%v)", err)
	}
	raw, err := readLog(logPath)
	if err != nil {
		return err
	}
	edit, err := oneByteEdit(raw)
	if err != nil {
		return err
	}
	changed, err := applyEdit(raw, edit)
	if err != nil {
		return err
	}
	changedPath := filepath.Join(c.work, "tampered", "network-one-byte.boot.json")
	if err := os.WriteFile(changedPath, changed, 0o644); err != nil {
		return err
	}
	t, err = say("check the receipt against the log with one byte changed", "-check", envPath, "-pub", pub, "-log", changedPath, "-bundle", bundle, "-line", fmt.Sprint(net.Line))
	if err != nil || t.Exit == 0 {
		return fmt.Errorf("the receipt checked against a changed log (%v)", err)
	}
	// The join: the network run's log, signed as if it were the quiet run's.
	quiet := setup.Runs[0]
	t, err = say("sign the network log joined to the quiet run's record", "-log", logPath, "-key", key,
		"-out", filepath.Join(c.work, "tampered", "never-written.intoto.json"), "-bundle", bundle, "-line", fmt.Sprint(quiet.Line))
	if err != nil || t.Exit == 0 || quiet.Fixture != "quiet" {
		return fmt.Errorf("the network log was signed joined to the %s run's record (%v)", quiet.Fixture, err)
	}
	if err := writeJSON(filepath.Join(c.work, "tampered", "dropped.json"), gone); err != nil {
		return err
	}
	for i := range transcripts {
		for j, a := range transcripts[i].Args {
			if filepath.IsAbs(a) {
				transcripts[i].Args[j] = rel(a)
			}
		}
	}
	if err := writeJSON(filepath.Join(c.work, "tampered", "edit.json"), edit); err != nil {
		return err
	}
	return writeJSON(filepath.Join(c.work, "transcripts.json"), transcripts)
}

// transcript is one run of the receipt command: its arguments (paths relative to the
// work directory), what it printed and how it exited.
type transcript struct {
	Name   string   `json:"name"`
	Args   []string `json:"args"`
	Exit   int      `json:"exit"`
	Stdout string   `json:"stdout"`
	Stderr string   `json:"stderr"`
}

// preflight refuses to start without the cluster, its gVisor runtime class for the receipt
// and the tools the run calls.
func preflight(ctx context.Context, c config) error {
	for _, tool := range []string{"kubectl", "kind", "docker", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("the run needs %s on PATH", tool)
		}
	}
	cur, err := kubectl(ctx, "config", "current-context")
	if err != nil {
		return err
	}
	if cur != "kind-"+c.cluster {
		return fmt.Errorf("kubectl's context is %q, not kind-%s", cur, c.cluster)
	}
	h, err := kubectl(ctx, "get", "runtimeclass", c.runtimeClass, "-o", "jsonpath={.handler}")
	if err != nil {
		return err
	}
	if h != c.handler {
		return fmt.Errorf("runtime class %s has handler %q, not %s (examples/dependency-receipt/fixtures/capture.sh -install makes it)", c.runtimeClass, h, c.handler)
	}
	if out, err := kubectl(ctx, "get", "namespace", namespace, "--ignore-not-found", "-o", "name"); err != nil || out != "" {
		return fmt.Errorf("namespace %s already exists (a run that was kept, or is still going): delete it first (%v)", namespace, err)
	}
	runner, err := os.ReadFile(filepath.Join(c.repo, "docker", "runner.mjs"))
	if err != nil {
		return err
	}
	inImage, err := run(ctx, "", nil, "docker", "run", "--rm", "--network", "none", "--entrypoint", "sha256sum", c.image, "/runner.mjs")
	if err != nil {
		return err
	}
	if sum := sha256.Sum256(runner); !strings.HasPrefix(inImage, hex.EncodeToString(sum[:])+" ") {
		return fmt.Errorf("%s's /runner.mjs is not this tree's docker/runner.mjs: rebuild it from docker/agentsandbox.Dockerfile", c.image)
	}
	return nil
}

// cleanup deletes what the run made on the cluster: the namespace (and with it the pool,
// its pods, the template and the network policy), the cluster role and its binding, then
// the runsc log directories the namespace's pods left on the node.
func cleanup(ctx context.Context, c config, before map[string]bool) error {
	step("deleting the namespace, the cluster role, and the node's logs of its pods")
	var errs []error
	if _, err := kubectl(ctx, "delete", "namespace", namespace, "--ignore-not-found", "--wait=true", "--timeout=300s"); err != nil {
		errs = append(errs, err)
	}
	for _, kind := range []string{"clusterrolebinding", "clusterrole"} {
		if _, err := kubectl(ctx, "delete", kind, namespace+"-runtimeclasses", "--ignore-not-found"); err != nil {
			errs = append(errs, err)
		}
	}
	after, err := nodeLogDirs(ctx, c)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	var mine []string
	for d := range after {
		if !before[d] {
			mine = append(mine, logRoot+"/"+d)
		}
	}
	slices.Sort(mine)
	if len(mine) > 0 {
		// Only directories made during the run whose logs name this run's namespace: other
		// pods on the node keep theirs.
		script := `for d in "$@"; do if grep -rqF "$NS" "$d"; then rm -r "$d" && echo "$d"; fi; done`
		out, err := run(ctx, "", nil, "docker", append([]string{"exec", "-e", "NS=" + namespace, c.node(), "sh", "-c", script, "sh"}, mine...)...)
		if err != nil {
			errs = append(errs, err)
		}
		fmt.Printf("    removed %d of the node's %d new log directories\n", len(strings.Fields(out)), len(mine))
	}
	return errors.Join(errs...)
}

// stopDaemon sends plimsolld SIGTERM (it drains, deleting its claims), keeps its log in the
// work directory and removes its container.
func stopDaemon(ctx context.Context, c config) {
	if out, _ := run(ctx, "", nil, "docker", "ps", "-a", "-q", "-f", "name=^"+daemonCtr+"$"); out == "" {
		return
	}
	_, _ = run(ctx, "", nil, "docker", "stop", "-t", "60", daemonCtr)
	if logs, err := daemonLog(ctx); err == nil {
		_ = os.WriteFile(filepath.Join(c.work, "plimsolld.log"), logs, 0o600)
	}
	_, _ = run(ctx, "", nil, "docker", "rm", daemonCtr)
}

// daemonLog is plimsolld's log so far: it writes to stderr, which docker logs replays on
// its own stderr.
func daemonLog(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, "docker", "logs", daemonCtr).CombinedOutput()
}

// nodeLogDirs lists the runsc log directories on the node.
func nodeLogDirs(ctx context.Context, c config) (map[string]bool, error) {
	out, err := run(ctx, "", nil, "docker", "exec", c.node(), "ls", "-1", logRoot)
	if err != nil {
		return nil, err
	}
	dirs := map[string]bool{}
	for _, d := range strings.Fields(out) {
		dirs[d] = true
	}
	return dirs, nil
}

// fetchLog finds, among the log directories made during the run, the one boot log that
// names the pod uid, and reads it once runsc has written its closing line (the sandbox
// stops when the pod is deleted, which the run's claim deletion starts).
func fetchLog(ctx context.Context, c config, uid string, before map[string]bool) (string, []byte, error) {
	deadline := time.Now().Add(2 * time.Minute)
	var last error
	for time.Now().Before(deadline) {
		path, raw, err := readPodLog(ctx, c, uid, before)
		if err == nil {
			if _, err = runsclog.Read(bytes.NewReader(raw)); err == nil {
				return path, raw, nil
			}
		}
		last = err
		time.Sleep(2 * time.Second)
	}
	return "", nil, fmt.Errorf("no complete log names pod %s within two minutes: %w", uid, last)
}

func readPodLog(ctx context.Context, c config, uid string, before map[string]bool) (string, []byte, error) {
	now, err := nodeLogDirs(ctx, c)
	if err != nil {
		return "", nil, err
	}
	var candidates []string
	for d := range now {
		if !before[d] {
			candidates = append(candidates, logRoot+"/"+d)
		}
	}
	slices.Sort(candidates)
	if len(candidates) == 0 {
		return "", nil, errors.New("no log directory made during the run")
	}
	script := `for d in "$@"; do for f in "$d"/*.boot.txt; do [ -f "$f" ] && grep -lF "$UID_" "$f"; done; done; true`
	out, err := run(ctx, "", nil, "docker", append([]string{"exec", "-e", "UID_=" + uid, c.node(), "sh", "-c", script, "sh"}, candidates...)...)
	if err != nil {
		return "", nil, err
	}
	found := strings.Fields(out)
	if len(found) != 1 {
		return "", nil, fmt.Errorf("%d boot logs name pod %s: %v", len(found), uid, found)
	}
	// At most one byte over the reader's cap leaves the node: the log's size is the pod's
	// programs' to choose (every call is logged), and a whole read of a huge one would
	// land in this process's memory before the reader's cap applied (release
	// release review, 2026-10-29).
	raw, err := runBytes(ctx, "docker", "exec", c.node(), "head", "-c", fmt.Sprint(runsclog.MaxLogBytes+1), found[0])
	if err == nil && len(raw) > runsclog.MaxLogBytes {
		err = fmt.Errorf("the boot log %s is larger than the reader takes (%d bytes)", found[0], runsclog.MaxLogBytes)
	}
	return found[0], raw, err
}

func waitReady(ctx context.Context, base string, within time.Duration) error {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/readyz", nil)
		if err != nil {
			return err
		}
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if out, _ := run(ctx, "", nil, "docker", "inspect", "-f", "{{.State.Running}}", daemonCtr); out != "true" {
			return errors.New("plimsolld exited before it was ready")
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("plimsolld was not ready within %v", within)
}

func goBuild(ctx context.Context, c config, out, pkg string) error {
	_, err := run(ctx, c.repo, nil, "env", "CGO_ENABLED=0", "GOOS=linux", "go", "build", "-trimpath", "-buildvcs=false", "-o", out, pkg)
	return err
}

func kubectl(ctx context.Context, args ...string) (string, error) {
	return run(ctx, "", nil, "kubectl", args...)
}

// run runs a command and returns its stdout, trimmed; an error carries its stderr.
func run(ctx context.Context, dir string, stdin []byte, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, tail(stderr.String(), 20))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func runBytes(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, tail(stderr.String(), 20))
	}
	return out, nil
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// writeGzip writes b gzip-compressed at the best level with no name or time in the header,
// so the same log gives the same file.
func writeGzip(path string, b []byte) error {
	var out bytes.Buffer
	z, err := gzip.NewWriterLevel(&out, gzip.BestCompression)
	if err != nil {
		return err
	}
	if _, err := z.Write(b); err != nil {
		return err
	}
	if err := z.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, out.Bytes(), 0o644)
}

// readLog reads a log as written or gzip-compressed.
func readLog(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b {
		z, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		defer z.Close()
		return io.ReadAll(io.LimitReader(z, runsclog.MaxLogBytes+1))
	}
	return b, nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return attest.ParsePrivateKey(b)
}

func step(s string) { fmt.Println("==", s) }
