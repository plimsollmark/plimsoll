package wslc

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/runnerwire"
)

// gVisor inside each run's session VM (SANDBOX_WSLC_GVISOR=1, per-run mode only). The
// trial that showed it works ran runsc as the default runtime of a real WSLC session. The
// rules it is built to (the tier stays vm, each run's evidence states gVisor was proven on,
// a run is refused and never falls back to runc, hardened mode keeps refusing the provider
// until an independent audit has looked at it).
//
// How it works, and what it rests on. WSLC starts a session's dockerd with no flags and
// rewrites /etc/docker/daemon.json at every VM boot, so a registration made in one VM is
// gone in the next. The template disk therefore carries runsc and the helpers it needs
// (installGVisor, streamed through `wslc system session run` with the archive on stdin,
// then read back and checked by SHA-512 inside the VM), and every run's VM gets the
// settings written, dockerd reloaded (SIGHUP) and the default runtime read back before
// `container run` (registerGVisor). A read-back that is not runsc refuses the run, marked
// not dispatched, and no code anywhere starts a container under runc in this mode. It
// rests on three behaviors Microsoft does not document and can change in any WSL release:
// `session enter`, `system session run` as root in the VM, and dockerd reading
// /etc/docker/daemon.json with a SIGHUP reload. A change in any of them fails closed here.
// Every argument is a fixed word or a checked path (exec.go); the settings and the proof
// scripts travel on stdin.

const (
	// vmGVisorDir is where the template carries gVisor: on the session's storage disk
	// (/var/lib/docker is that disk), so a copy of the template has it at every boot.
	vmGVisorDir = "/var/lib/docker/gvisor"
	vmRunsc     = vmGVisorDir + "/runsc"
	// helperDir is the directory beside runsc that holds the helpers, in the operator's
	// files and in the VM alike (runsc finds them relative to itself).
	helperDir = "gvisor-bin"
	// msDaemonJSON is what WSL 3.0.5 writes at boot (read 2026-11-13, 25 bytes). The
	// provider rewrites only a file it has seen: anything else refuses the run.
	msDaemonJSON = `{"features":{"cdi":true}}`
	// gvisorDaemonJSON keeps Microsoft's own entry, registers runsc and makes it the
	// default runtime.
	gvisorDaemonJSON = `{"features":{"cdi":true},"runtimes":{"runsc":{"path":"` + vmRunsc + `"}},"default-runtime":"runsc"}`
	// gvisorPlatform is the only platform the provider states: the session VM has no
	// /dev/kvm, and systrap works anywhere.
	gvisorPlatform = "systrap"
	// PolicyGVisor is the Policy of every result of a run that started after gVisor was
	// proven to be the default runtime of its own VM; the run's record names it. A run
	// without it never started under gVisor, and in this mode no run starts under runc.
	PolicyGVisor = "gvisor:proven"
	// GVisorQualification is added to PerRunQualification wherever the tier is stated when
	// gVisor is on.
	GVisorQualification = "gVisor, a user-space kernel on its systrap platform, also runs inside that VM as an added wall: the VM's default container runtime is read back as gVisor's before each run, a run is refused when it is not, and the VM wall's qualification above is unchanged."
)

var (
	// helperNameRE is a file name inside gvisor-bin: no path separator, no leading dot.
	helperNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	sha512RE     = regexp.MustCompile(`^[0-9a-f]{128}$`)
	// containerNameRE is a run container's name (containerName), the only thing besides
	// fixed text that a script built here holds.
	containerNameRE = regexp.MustCompile(`^plimsoll-wslc-[0-9a-f]{24}$`)
	runscVersionRE  = regexp.MustCompile(`^runsc version [A-Za-z0-9._+-]+$`)
)

// Qualification is the sentence that goes with this provider's tier wherever it is stated
// (the startup log): the per-run mode's, with gVisor's own position added when it is on.
// The shared mode has its own: the tier there is a plain word that the docker provider
// also states, so the sentence says what the word does not.
func (p *Provider) Qualification() string {
	switch {
	case p.cfg.Mode != ModePerRun:
		return SharedQualification
	case p.cfg.GVisor:
		return PerRunQualification + " " + GVisorQualification
	}
	return PerRunQualification
}

// GVisor is whether gVisor is the runtime of every run (SANDBOX_WSLC_GVISOR=1).
func (p *Provider) GVisor() bool { return p.cfg.GVisor }

// gvFile is one file of gVisor's set: where it is for the operator, where it is in the
// VM's gvisor directory, and the digest it must have.
type gvFile struct {
	rel    string // "runsc" or "gvisor-bin/NAME"
	local  string
	sha512 string
}

// gvisorFiles is the set the template carries: runsc, then the named helpers in name order.
func (c Config) gvisorFiles() []gvFile {
	files := []gvFile{{rel: "runsc", local: c.RunscPath, sha512: c.RunscSHA512}}
	names := make([]string, 0, len(c.RunscHelpers))
	for n := range c.RunscHelpers {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		files = append(files, gvFile{rel: helperDir + "/" + n, local: path.Join(path.Dir(c.RunscPath), helperDir, n), sha512: c.RunscHelpers[n]})
	}
	return files
}

// validateGVisor is the per-run mode's check of the gVisor settings: off means none may be
// set; on means the binary's path and digest, and each helper's name and digest.
func (c Config) validateGVisor(add func(string, ...any)) {
	if !c.GVisor {
		if c.RunscPath != "" || c.RunscSHA512 != "" || len(c.RunscHelpers) > 0 {
			add("SANDBOX_WSLC_RUNSC_PATH, SANDBOX_WSLC_RUNSC_SHA512 and SANDBOX_WSLC_RUNSC_HELPERS need SANDBOX_WSLC_GVISOR=1")
		}
		return
	}
	switch {
	case c.RunscPath == "":
		add("SANDBOX_WSLC_GVISOR=1 needs SANDBOX_WSLC_RUNSC_PATH: the runsc binary, which this provider never downloads")
	case !strings.HasPrefix(c.RunscPath, "/") || path.Clean(c.RunscPath) != c.RunscPath:
		add("SANDBOX_WSLC_RUNSC_PATH must be a clean absolute path (got %q)", c.RunscPath)
	}
	switch {
	case c.RunscSHA512 == "":
		add("SANDBOX_WSLC_RUNSC_PATH needs SANDBOX_WSLC_RUNSC_SHA512: a path without its digest pins nothing (docs/gvisor.md)")
	case !sha512RE.MatchString(c.RunscSHA512):
		add("SANDBOX_WSLC_RUNSC_SHA512 must be 128 lowercase hex digits (got %d characters)", len(c.RunscSHA512))
	}
	for name, sum := range c.RunscHelpers {
		if !helperNameRE.MatchString(name) {
			add("SANDBOX_WSLC_RUNSC_HELPERS: %q is not a plain file name in gvisor-bin", name)
		}
		if !sha512RE.MatchString(sum) {
			add("SANDBOX_WSLC_RUNSC_HELPERS: the digest of %q must be 128 lowercase hex digits", name)
		}
	}
}

// checkGVisorPresent is Preflight's cheap half: every file of the set exists and is a
// regular file. The digests are checked when the template is built (openGVisorFiles), not
// on every /readyz.
func (p *Provider) checkGVisorPresent() error {
	for _, f := range p.cfg.gvisorFiles() {
		st, err := os.Stat(f.local)
		if err != nil || !st.Mode().IsRegular() {
			return fmt.Errorf("wslc: gVisor needs %s (a regular file): %v", f.local, err)
		}
	}
	return nil
}

// gvOpen is one file of the set, opened and its digest checked.
type gvOpen struct {
	gvFile
	f    *os.File
	size int64
}

// openGVisorFiles opens every file of the set and refuses one whose SHA-512 is not the
// configured one, before anything is sent. The same open handle is what installGVisor
// streams; the digest read back inside the VM is what is finally trusted.
func (p *Provider) openGVisorFiles() ([]gvOpen, error) {
	var opened []gvOpen
	closeAll := func() {
		for _, o := range opened {
			o.f.Close()
		}
	}
	for _, g := range p.cfg.gvisorFiles() {
		f, err := os.Open(g.local)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("wslc: gVisor: %w", err)
		}
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() {
			f.Close()
			closeAll()
			return nil, fmt.Errorf("wslc: gVisor: %s is not a regular file (%v)", g.local, err)
		}
		h := sha512.New()
		if _, err := io.Copy(h, f); err != nil {
			f.Close()
			closeAll()
			return nil, fmt.Errorf("wslc: gVisor: reading %s: %w", g.local, err)
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != g.sha512 {
			f.Close()
			closeAll()
			return nil, fmt.Errorf("wslc: gVisor: %s has SHA-512 %s, not the configured %s: refusing to put it on the template", g.local, got, g.sha512)
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			f.Close()
			closeAll()
			return nil, err
		}
		opened = append(opened, gvOpen{gvFile: g, f: f, size: st.Size()})
	}
	return opened, nil
}

// writeGVisorArchive writes the set as a gzipped tar under fixed names, owned by root.
func writeGVisorArchive(w io.Writer, files []gvOpen) error {
	gz, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(gz)
	epoch := time.Unix(0, 0)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: helperDir + "/", Mode: 0o755, ModTime: epoch}); err != nil {
		return err
	}
	for _, o := range files {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: o.rel, Mode: 0o755, Size: o.size, ModTime: epoch}); err != nil {
			return err
		}
		if _, err := io.Copy(tw, o.f); err != nil {
			return fmt.Errorf("streaming %s: %w", o.local, err)
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// installGVisor puts the set into the template's session: the archive travels on the
// standard input of `wslc system session run tar` (never as an argument, never through a
// Windows folder), then a sync, then the digests are read back inside the VM
// (verifyGVisorStore). Called after the image is loaded, before the session ends.
func (p *Provider) installGVisor(ctx context.Context, session string) error {
	files, err := p.openGVisorFiles()
	if err != nil {
		return err
	}
	defer func() {
		for _, o := range files {
			o.f.Close()
		}
	}()
	run := func(stdin io.Reader, argv ...string) error {
		_, err := p.outputWithStdin(ctx, stdin, append([]string{"--session", session, "system", "session", "run"}, argv...)...)
		return err
	}
	if err := run(nil, "mkdir", "-p", vmGVisorDir+"/"+helperDir); err != nil {
		return err
	}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(writeGVisorArchive(pw, files)) }()
	err = run(pr, "tar", "-xzf", "-", "-C", vmGVisorDir)
	pr.CloseWithError(errors.New("the extraction ended"))
	if err != nil {
		return fmt.Errorf("sending gVisor into the template: %w", err)
	}
	if err := run(nil, "sync"); err != nil {
		return err
	}
	return nil
}

// A script is fixed text (plus names that passed a regular expression) sent on the
// standard input of `wslc system session run sh`, which runs as root in the session VM.
// Its first line names it, for the stand-in and for a reader of the logs.
func scriptKind(kind string) string { return "# plimsoll-script: " + kind + "\n" }

// sessionScript runs script in the session VM and returns its whole output.
func (p *Provider) sessionScript(ctx context.Context, session, script string) (string, error) {
	out, err := p.outputWithStdin(ctx, strings.NewReader(script), "--session", session, "system", "session", "run", "sh")
	return string(out), err
}

// kvLines reads `key=value` lines into a map from key to values in order.
func kvLines(out string) map[string][]string {
	m := map[string][]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && k != "" {
			m[k] = append(m[k], v)
		}
	}
	return m
}

// one is the single value of a key, or "" when it is absent or repeated.
func one(m map[string][]string, key string) string {
	if v := m[key]; len(v) == 1 {
		return v[0]
	}
	return ""
}

// registerScript writes the docker service's settings, reloads it and reads the default
// runtime back. write false is the live test's: the same checks and read-back with no
// write and no reload, which is a session whose settings were never rewritten.
func registerScript(write bool) string {
	var b strings.Builder
	b.WriteString(scriptKind("register-runsc"))
	b.WriteString("want='" + msDaemonJSON + "'\n")
	b.WriteString("ours='" + gvisorDaemonJSON + "'\n")
	b.WriteString(`cur=$(cat /etc/docker/daemon.json </dev/null) || exit 41
if [ "$cur" != "$want" ] && [ "$cur" != "$ours" ]; then echo "daemon.json holds settings this provider has not seen" >&2; exit 42; fi
pid=$(pidof dockerd </dev/null) || exit 43
case "$pid" in *" "*) echo "more than one dockerd" >&2; exit 44;; esac
`)
	if write {
		b.WriteString("cat > /etc/docker/daemon.json <<'PLIMSOLL_DAEMON_JSON'\n" + gvisorDaemonJSON + "\nPLIMSOLL_DAEMON_JSON\n")
		b.WriteString("kill -HUP \"$pid\" || exit 45\n")
	}
	b.WriteString(`i=0
rt=
while [ "$i" -lt 50 ]; do
  rt=$(docker info --format '{{.DefaultRuntime}}' </dev/null 2>/dev/null)
  [ "$rt" = runsc ] && break
  i=$((i+1))
  sleep 0.1
done
echo "default-runtime=$rt"
echo "runtimes=$(docker info --format '{{range $k, $v := .Runtimes}}{{$k}}:{{$v.Path}} {{end}}' </dev/null 2>&1)"
echo "dockerd-pid=$pid"
`)
	return b.String()
}

// registerGVisor is the per-run check, between the boot ID read and `container run`: write
// the settings, reload dockerd, read the default runtime back, and refuse unless it is
// runsc. There is no other branch: a registration that did not take is an error, and the
// caller refuses the run (not dispatched, environment). It is not retried and never
// followed by a run under any other runtime.
func (p *Provider) registerGVisor(ctx context.Context, session string) error {
	p.pr.mu.Lock()
	write := !p.pr.skipGVisorWrite
	p.pr.mu.Unlock()
	out, err := p.sessionScript(ctx, session, registerScript(write))
	if err != nil {
		return fmt.Errorf("wslc: gVisor: writing the docker settings in the run's VM and reloading it: %w (the script had printed %q)", err, out)
	}
	m := kvLines(out)
	if got := one(m, "default-runtime"); got != "runsc" {
		return fmt.Errorf("wslc: gVisor: the run's VM reads default runtime %q after the settings were written and dockerd reloaded, not runsc; the run is refused and is never started under runc", got)
	}
	if !slices.Contains(strings.Fields(one(m, "runtimes")), "runsc:"+vmRunsc) {
		return fmt.Errorf("wslc: gVisor: the run's VM does not list runsc at %s (%q); the run is refused", vmRunsc, one(m, "runtimes"))
	}
	return nil
}

// verifyScript lists what the VM's gvisor directory holds with each file's SHA-512, and
// runsc's own version.
func verifyScript(files []gvFile) string {
	var b strings.Builder
	b.WriteString(scriptKind("verify-runsc"))
	b.WriteString("cd " + vmGVisorDir + " || exit 61\n")
	b.WriteString("sha512sum --")
	for _, f := range files {
		b.WriteString(" " + f.rel)
	}
	b.WriteString(" </dev/null | sed 's/^\\([0-9a-f]*\\)  \\(.*\\)$/sha512=\\2 \\1/'\n")
	b.WriteString("find . -mindepth 1 ! -type d </dev/null | sed 's/^/file=/'\n")
	b.WriteString("find . -mindepth 1 -type d </dev/null | sed 's/^/dir=/'\n")
	b.WriteString("echo \"version=$(./runsc --version </dev/null 2>&1 | head -n 1)\"\n")
	return b.String()
}

// gvisorStore is what verifyGVisorStore read in the VM.
type gvisorStore struct {
	Version string
}

// verifyGVisorStore reads the VM's gvisor directory and refuses unless it holds exactly the
// configured set, each file with the configured SHA-512, and runsc reports a version. It
// is the check that makes the template's gVisor the pinned one: the digest is read from
// the bytes in the store, not from the file that was sent.
func (p *Provider) verifyGVisorStore(ctx context.Context, session string) (gvisorStore, error) {
	files := p.cfg.gvisorFiles()
	out, err := p.sessionScript(ctx, session, verifyScript(files))
	if err != nil {
		return gvisorStore{}, fmt.Errorf("wslc: gVisor: reading the template's gvisor directory: %w", err)
	}
	m := kvLines(out)
	got := map[string]string{}
	for _, v := range m["sha512"] {
		if name, sum, ok := strings.Cut(v, " "); ok {
			got[name] = sum
		}
	}
	for _, f := range files {
		if got[f.rel] != f.sha512 {
			return gvisorStore{}, fmt.Errorf("wslc: gVisor: %s in the store has SHA-512 %q, want the configured %s", f.rel, got[f.rel], f.sha512)
		}
	}
	want := make([]string, 0, len(files))
	for _, f := range files {
		want = append(want, "./"+f.rel)
	}
	have := slices.Clone(m["file"])
	slices.Sort(have)
	slices.Sort(want)
	if !slices.Equal(have, want) {
		return gvisorStore{}, fmt.Errorf("wslc: gVisor: the store's gvisor directory holds files %q, want exactly %q", have, want)
	}
	for _, d := range m["dir"] {
		if d != "./"+helperDir {
			return gvisorStore{}, fmt.Errorf("wslc: gVisor: the store's gvisor directory holds an unexpected directory %q", d)
		}
	}
	v := one(m, "version")
	if !runscVersionRE.MatchString(v) {
		return gvisorStore{}, fmt.Errorf("wslc: gVisor: the stored runsc answered %q to --version", v)
	}
	return gvisorStore{Version: v}, nil
}

// proveScript reads, from the session VM while name's container exists, what the smoke test
// proves from the VM's side: the container's runtime, that no bind or volume was handed to
// it, its memory limit from its own cgroup (the container cannot see it under gVisor), and
// each Sentry process's own system-call filter and platform.
func proveScript(name string) (string, error) {
	if !containerNameRE.MatchString(name) {
		return "", fmt.Errorf("wslc: %q is not a run container's name", name)
	}
	return scriptKind("prove-container") + "NAME=" + name + `
i=0
run=
while [ "$i" -lt 100 ]; do
  run=$(docker inspect --format '{{.State.Running}}' "$NAME" </dev/null 2>/dev/null)
  [ "$run" = true ] && break
  i=$((i+1))
  sleep 0.2
done
echo "running=$run"
[ "$run" = true ] || exit 51
id=$(docker inspect --format '{{.Id}}' "$NAME" </dev/null) || exit 52
echo "runtime=$(docker inspect --format '{{.HostConfig.Runtime}}' "$NAME" </dev/null)"
echo "mounts=$(docker inspect --format '{{len .Mounts}}' "$NAME" </dev/null)"
echo "binds=$(docker inspect --format '{{len .HostConfig.Binds}}' "$NAME" </dev/null)"
echo "memory-max=$(cat /sys/fs/cgroup/docker/$id/memory.max </dev/null 2>/dev/null)"
for pid in $(ps -eo pid,args </dev/null | sed -n 's/^ *\([0-9][0-9]*\) runsc-sandbox .*/\1/p'); do
  sec=$(sed -n 's/^Seccomp:[[:space:]]*//p' /proc/$pid/status </dev/null 2>/dev/null)
  plat=$(tr '\000' ' ' </proc/$pid/cmdline 2>/dev/null | sed -n 's/.*--platform[= ]\([a-z0-9]*\).*/\1/p')
  [ -n "$plat" ] || plat=$(` + vmRunsc + ` flags </dev/null 2>&1 | sed -n 's/.*specifies which platform to use.*(default "\([a-z0-9]*\)").*/\1/p' | head -n 1)
  echo "sentry=$pid seccomp=$sec platform=$plat"
done
`, nil
}

// gvisorProof is what the session VM said about the boundary test's container while it existed.
type gvisorProof struct {
	Running   bool
	Runtime   string
	Mounts    string
	Binds     string
	MemoryMax string
	Sentries  []sentryRead
}

// sentryRead is one runsc-sandbox process (gVisor's Sentry): its own seccomp filter line
// and its platform, as read in the VM.
type sentryRead struct{ PID, Seccomp, Platform string }

// readGVisorProof polls the VM until name's container is running, then reads the proof.
func (p *Provider) readGVisorProof(ctx context.Context, session, name string) (gvisorProof, error) {
	script, err := proveScript(name)
	if err != nil {
		return gvisorProof{}, err
	}
	out, err := p.sessionScript(ctx, session, script)
	if err != nil {
		return gvisorProof{}, fmt.Errorf("wslc: gVisor: reading the container from the VM's side: %w", err)
	}
	m := kvLines(out)
	pr := gvisorProof{Running: one(m, "running") == "true", Runtime: one(m, "runtime"), Mounts: one(m, "mounts"),
		Binds: one(m, "binds"), MemoryMax: one(m, "memory-max")}
	for _, line := range m["sentry"] {
		f := strings.Fields("pid=" + line)
		s := sentryRead{}
		for _, kv := range f {
			k, v, _ := strings.Cut(kv, "=")
			switch k {
			case "pid":
				s.PID = v
			case "seccomp":
				s.Seccomp = v
			case "platform":
				s.Platform = v
			}
		}
		pr.Sentries = append(pr.Sentries, s)
	}
	return pr, nil
}

// GVisorEvidence is what the startup smoke test read about gVisor in the per-run VMs: the
// runtime, the pinned files and what was read from the VM's side. Like every other
// evidence it is configuration and provider evidence plus the smoke test, never runtime
// attestation.
type GVisorEvidence struct {
	Runtime       string            // the default runtime read back in each smoke VM: runsc
	RunscVersion  string            // runsc --version, run from the stored binary in the VM
	RunscSHA512   string            // the binary's digest, read from the store in the VM
	Helpers       map[string]string // each helper's name and digest, read the same way
	Platform      string            // the Sentry's platform, read from the VM: systrap
	SentrySeccomp string            // the Sentry's own system-call filter line, read from the VM
	SentryCount   int
}

// gvisorHold is how long the gVisor smoke test's boundary test keeps its container alive after its
// work, so the session VM can be read while the container exists (--rm removes it the moment
// the runner exits). Startup only.
const gvisorHold = 10 * time.Second

// boundaryScriptHolding is the boundary test's script, which does not exit before gvisorHold
// has passed.
var boundaryScriptHolding = probeScript + fmt.Sprintf("setTimeout(() => {}, %d);\n", gvisorHold.Milliseconds())

// runBoundaryTestUnderGVisor runs the boundary test in session with a name chosen here, and meanwhile
// reads the container from the session VM's side (readGVisorProof). It returns the proof
// and the test's run; the run's context ends when either side fails, and the caller's
// give-up path terminates the session.
func (p *Provider) runBoundaryTestUnderGVisor(ctx, vmctx context.Context, cand *verified, session string) (gvisorProof, planRun, error) {
	name := containerName()
	type result struct {
		out planRun
		err error
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan result, 1)
	go func() {
		out, err := p.runInNamed(runCtx, cand, session, name, []runnerwire.File{{Path: probeFile, Content: boundaryScriptHolding}}, []string{probeStep}, nil, 60*time.Second)
		done <- result{out, err}
	}()
	proof, perr := p.readGVisorProof(vmctx, session, name)
	if perr != nil {
		cancel()
	}
	r := <-done
	if perr != nil {
		return gvisorProof{}, planRun{}, errors.Join(perr, r.err)
	}
	if r.err != nil {
		return gvisorProof{}, planRun{}, r.err
	}
	return proof, r.out, nil
}

// checkGVisorReadings is what replaces, under gVisor, the three smoke test readings gVisor
// answers differently (found different in a trial of gVisor in a WSLC session). Each still proves the property it
// proved before, and none is accepted without the proof of gVisor itself, from inside (its
// kernel string, its own boot ID) and from the session VM's side (the runtime of the
// container, read by name while it existed, and a running runsc-sandbox process).
//
//   - The filter line (Seccomp: 2 inside the container) becomes: the line inside reads 0 or 2,
//     and every Sentry process, read in the VM, runs under a filter of its own (Seccomp: 2).
//     The guest's system calls go to the Sentry, not to the VM's kernel.
//   - memory.max inside the container becomes the limit read from the container's cgroup in
//     the VM (checkBoundary).
//   - The kernel and boot ID equal to the session VM's become: the kernel string is gVisor's
//     and differs from the VM's, the boot ID is its own (not the VM's), and the container was
//     found by name in this session's own dockerd.
func checkGVisorReadings(r boundaryReport, kernel, bootID string, gv *gvisorProof) error {
	if !strings.Contains(strings.ToLower(r.Kernel), "gvisor") || r.Kernel == kernel {
		return fmt.Errorf("the container's kernel release %q is not gVisor's (the session VM's is %q): the run is not under gVisor", r.Kernel, kernel)
	}
	if !strings.Contains(strings.ToLower(r.ProcVersion), "gvisor") {
		return fmt.Errorf("the container's /proc/version %q does not name gVisor", r.ProcVersion)
	}
	if !bootIDRE.MatchString(r.BootID) || r.BootID == bootID {
		return fmt.Errorf("the container's boot ID %q is not a boot ID of its own: under gVisor it is the Sentry's and must differ from the session VM's %q", r.BootID, bootID)
	}
	if !gv.Running || gv.Runtime != "runsc" {
		return fmt.Errorf("the session VM reads the boundary test's container as running=%v with runtime %q, not runsc", gv.Running, gv.Runtime)
	}
	if len(gv.Sentries) == 0 {
		return errors.New("the session VM has no runsc-sandbox process while the boundary test's container runs")
	}
	for _, s := range gv.Sentries {
		if s.Platform != gvisorPlatform {
			return fmt.Errorf("gVisor's Sentry %s runs on platform %q, not %s", s.PID, s.Platform, gvisorPlatform)
		}
		if s.Seccomp != "2" {
			return fmt.Errorf("gVisor's Sentry %s has Seccomp %q, not a filter (2): the Sentry is not under its own system-call filter", s.PID, s.Seccomp)
		}
	}
	if gv.Mounts != "0" || gv.Binds != "0" {
		return fmt.Errorf("the session VM reads %s mounts and %s binds on the boundary test's container, want none: no Windows folder may be handed to it", gv.Mounts, gv.Binds)
	}
	if s := r.Status["Seccomp"]; s != "0" && s != "2" {
		return fmt.Errorf("the guest's Seccomp line reads %q inside gVisor, want 0 (gVisor's) or 2", s)
	}
	return nil
}

// gvisorEvidence is what the gVisor smoke session read, for the provider's evidence.
func (p *Provider) gvisorEvidence(store gvisorStore, gv gvisorProof) *GVisorEvidence {
	e := &GVisorEvidence{Runtime: gv.Runtime, RunscVersion: store.Version, RunscSHA512: p.cfg.RunscSHA512,
		Helpers: map[string]string{}, SentryCount: len(gv.Sentries)}
	for n, sum := range p.cfg.RunscHelpers {
		e.Helpers[n] = sum
	}
	if len(gv.Sentries) > 0 {
		e.Platform, e.SentrySeccomp = gv.Sentries[0].Platform, gv.Sentries[0].Seccomp
	}
	return e
}

// sameGVisor is whether two smoke sessions read the same gVisor.
func sameGVisor(a, b *GVisorEvidence) bool {
	return a != nil && b != nil && a.Runtime == b.Runtime && a.RunscVersion == b.RunscVersion && a.RunscSHA512 == b.RunscSHA512 && a.Platform == b.Platform
}
