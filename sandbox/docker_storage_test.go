package sandbox

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestDockerWritableBudgetValidation covers the aggregate writable-storage
// budget: the sum of /tmp + /dev/shm + /work must fit SANDBOX_DISK_MB, an unset
// /work takes the remainder, and impossible envelopes fail closed. No daemon.
func TestDockerWritableBudgetValidation(t *testing.T) {
	d := DefaultDocker("")
	if err := d.validateWritableBudget(); err != nil {
		t.Fatalf("no budget configured must validate: %v", err)
	}

	d.DiskBudgetMB = 256
	if err := d.validateWritableBudget(); err != nil {
		t.Fatalf("256 MiB budget with defaults must validate: %v", err)
	}
	if got := d.workDiskMB(); got != 256-16-16 {
		t.Fatalf("derived /work = %d MiB, want the budget remainder %d", got, 256-16-16)
	}

	// A budget the fixed mounts already exhaust leaves no room for /work.
	d.DiskBudgetMB = 32
	if err := d.validateWritableBudget(); err == nil {
		t.Fatal("budget equal to /tmp + /dev/shm must fail: /work has no room")
	}

	// An explicit /work that overflows the budget must fail, not silently shrink.
	d.DiskBudgetMB = 128
	d.WorkDiskMB = 128
	if err := d.validateWritableBudget(); err == nil {
		t.Fatal("explicit mounts summing over the budget must fail closed")
	}

	d.WorkDiskMB = 0
	d.TmpDiskMB = -1
	if err := d.validateWritableBudget(); err == nil {
		t.Fatal("negative mount sizes must fail closed")
	}
}

// TestDockerLockdownBoundsWritableMounts verifies every writable surface in the
// generated flags is a sized, noexec tmpfs — in particular /dev/shm, which the
// daemon would otherwise provide as an unaccounted writable 64 MiB default.
func TestDockerLockdownBoundsWritableMounts(t *testing.T) {
	d := DefaultDocker("")
	args := strings.Join(d.lockdownArgs("c", true, d.Runtime), " ")
	for _, want := range []string{
		"--read-only",
		"--tmpfs /tmp:rw,noexec,nosuid,size=16m",
		"--tmpfs /dev/shm:rw,noexec,nosuid,size=16m",
		"--tmpfs /work:rw,noexec,nosuid,size=128m,mode=1777",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("lockdown args lack %q: %s", want, args)
		}
	}

	d.DiskBudgetMB = 512
	d.TmpDiskMB = 32
	args = strings.Join(d.lockdownArgs("c", true, d.Runtime), " ")
	for _, want := range []string{
		"--tmpfs /tmp:rw,noexec,nosuid,size=32m",
		"--tmpfs /work:rw,noexec,nosuid,size=464m,mode=1777", // 512 - 32 - 16
	} {
		if !strings.Contains(args, want) {
			t.Errorf("budget-derived lockdown args lack %q: %s", want, args)
		}
	}
}

func TestCheckTmpfsMount(t *testing.T) {
	mounts := "overlay / overlay ro,relatime 0 0\n" +
		"tmpfs /tmp tmpfs rw,nosuid,noexec,relatime,size=16384k 0 0\n" +
		"shm /dev/shm tmpfs rw,nosuid,nodev,relatime,size=65536k 0 0\n" +
		"devpts /dev/pts devpts rw 0 0\n"
	if err := checkTmpfsMount(mounts, "/tmp", 16); err != nil {
		t.Fatalf("conforming /tmp mount rejected: %v", err)
	}
	// /dev/shm above lacks noexec and has the wrong size — both must fail.
	if err := checkTmpfsMount(mounts, "/dev/shm", 16); err == nil {
		t.Fatal("wrong-size /dev/shm mount accepted")
	}
	if err := checkTmpfsMount(mounts, "/work", 128); err == nil {
		t.Fatal("absent /work mount accepted")
	}
	if err := checkTmpfsMount("tmpfs /tmp tmpfs rw,nosuid,noexec 0 0\n", "/tmp", 16); err == nil {
		t.Fatal("mount without a size option accepted — an unreported bound is an unproven bound")
	}
	if err := checkTmpfsMount("none /tmp ramfs rw,nosuid,noexec,size=16384k 0 0\n", "/tmp", 16); err == nil {
		t.Fatal("non-tmpfs filesystem accepted")
	}
}

// TestParseImageIDAndVolumes covers the combined identity+volume inspect parse:
// the ID binds the volume verdict to exact image content, so malformed output
// must fail closed rather than degrade to an unverified tag run.
func TestParseImageIDAndVolumes(t *testing.T) {
	id, vols, err := parseImageIDAndVolumes([]byte(`{"Id":"sha256:abc","Config":{}}` + "\n"))
	if err != nil || id != "sha256:abc" || len(vols) != 0 {
		t.Fatalf("volume-free image: id=%q vols=%v err=%v", id, vols, err)
	}
	id, vols, err = parseImageIDAndVolumes([]byte(`{"Id":"sha256:abc","Config":{"Volumes":{"/data":{},"/cache":{}}}}`))
	if err != nil || id != "sha256:abc" {
		t.Fatalf("volume image: id=%q err=%v", id, err)
	}
	if len(vols) != 2 || vols[0] != "/cache" || vols[1] != "/data" {
		t.Fatalf("volumes = %v, want sorted [/cache /data]", vols)
	}
	for _, bad := range []string{"null", "", "{broken", `{"Config":{}}`, `{"Id":"abc","Config":{}}`} {
		if _, _, err := parseImageIDAndVolumes([]byte(bad)); err == nil {
			t.Errorf("parseImageIDAndVolumes(%q) accepted malformed inspect output", bad)
		}
	}
}

// TestCheckWritableSet: the smoke's exhaustive verdict — the actually-writable
// mounts must be exactly the promised ones, in either direction.
func TestCheckWritableSet(t *testing.T) {
	if err := checkWritableSet([]string{"/dev/shm", "/tmp"}, []string{"/tmp", "/dev/shm"}); err != nil {
		t.Fatalf("matching set rejected: %v", err)
	}
	if err := checkWritableSet([]string{"/tmp", "/dev/shm", "/var/cache"}, []string{"/tmp", "/dev/shm"}); err == nil {
		t.Fatal("unaccounted writable mount accepted")
	}
	if err := checkWritableSet([]string{"/tmp"}, []string{"/tmp", "/dev/shm"}); err == nil {
		t.Fatal("promised-but-unwritable mount accepted")
	}
}

// TestCheckPidsLimit: the process limit counts as proven only when the guest's own
// cgroup states exactly the configured value. "max" is what Kata's Docker runtime
// reported for --pids-limit 64 while 204 processes started.
func TestCheckPidsLimit(t *testing.T) {
	if err := checkPidsLimit("256", "256", "inside the container"); err != nil {
		t.Fatalf("matching limit rejected: %v", err)
	}
	for _, c := range []struct{ got, want string }{
		{"max", "64"},   // accepted by the runtime, not applied
		{"128", "256"},  // a different bound
		{"", "256"},     // no cgroup file readable in the guest
		{"256", ""},     // nothing configured: no bound to prove
		{"max", "-1"},   // docker's "unlimited" is not a bound either
		{"256", "25x6"}, // not a number
	} {
		if err := checkPidsLimit(c.got, c.want, "inside the container"); err == nil {
			t.Errorf("checkPidsLimit(%q, %q) accepted", c.got, c.want)
		}
	}
	if !strings.Contains(smokeProbeScript(false, false), `"/sys/fs/cgroup/pids.max"`) {
		t.Fatal("the smoke probe does not read the process limit")
	}
}

// TestHostPidsMaxPath: under runsc the process limit is read from the sandbox's
// host cgroup, located through /proc/<pid>/cgroup of the PID docker reports. The
// path must name the container, or the PID belonged to some other process.
func TestHostPidsMaxPath(t *testing.T) {
	id := strings.Repeat("ab12", 16)
	for _, c := range []struct{ name, listing, want string }{
		{"v2 systemd driver", "0::/system.slice/docker-" + id + ".scope\n", "/sys/fs/cgroup/system.slice/docker-" + id + ".scope/pids.max"},
		{"v2 cgroupfs driver", "0::/docker/" + id, "/sys/fs/cgroup/docker/" + id + "/pids.max"},
		{"hybrid prefers the v1 pids line", "12:pids:/docker/" + id + "\n5:cpu,cpuacct:/docker/" + id + "\n0::/", "/sys/fs/cgroup/pids/docker/" + id + "/pids.max"},
		{"v1 pids shares a line", "3:pids,devices:/docker/" + id, "/sys/fs/cgroup/pids/docker/" + id + "/pids.max"},
	} {
		got, err := hostPidsMaxPath(c.listing, id)
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.name, got, err, c.want)
		}
	}
	for _, c := range []struct{ name, listing, id string }{
		{"another process's cgroup", "0::/user.slice/user-1000.slice/session-1.scope", id},
		{"a different container", "0::/system.slice/docker-" + strings.Repeat("cd34", 16) + ".scope", id},
		{"no usable line", "garbage\n", id},
		{"empty listing", "", id},
		{"short ID", "0::/docker/ab12", "ab12"},
	} {
		if got, err := hostPidsMaxPath(c.listing, c.id); err == nil {
			t.Errorf("%s: accepted %q", c.name, got)
		}
	}
}

// TestDockerExecutionStateRequiresVerifiedImages: changing a configured image
// reference after Preflight must fail closed instead of running a tag whose
// volume config was never inspected.
func TestDockerExecutionStateRequiresVerifiedImages(t *testing.T) {
	d := DefaultDocker("")
	d.stateMu.Lock()
	d.ready = true
	d.daemonHost = "unix:///run/docker.sock"
	d.verifiedRuntime = d.Runtime
	d.verifiedImageIDs = map[string]string{
		d.Image:        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		d.ProjectImage: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
	}
	d.stateMu.Unlock()
	if _, err := d.executionState(); err != nil {
		t.Fatalf("verified state rejected: %v", err)
	}
	d.Image = "some-other-image:latest"
	if _, err := d.executionState(); err == nil {
		t.Fatal("unverified image reference was admissible")
	}
}

// TestDockerPreflightRejectsImageWithVolumes proves an image-declared VOLUME —
// which docker run would turn into an unbounded anonymous writable host volume —
// fails readiness before any run can use it.
func TestDockerPreflightRejectsImageWithVolumes(t *testing.T) {
	requireDocker(t)
	// Tag the throwaway image: under BuildKit with attestations the -q digest is
	// a manifest-list ID the daemon cannot always inspect directly.
	const img = "crsbx-test-volume-image:local"
	build := exec.Command("docker", "build", "-q", "-t", img, "-")
	build.Stdin = strings.NewReader("FROM scratch\nVOLUME /data\n")
	if out, err := build.CombinedOutput(); err != nil {
		infraSkip(t, "cannot build throwaway VOLUME image: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", img).Run() })

	d := testDocker()
	d.Image = img
	d.ProjectImage = img
	err := d.Preflight(context.Background())
	if err == nil || !strings.Contains(err.Error(), "declares VOLUME") {
		t.Fatalf("Preflight = %v, want a declares-VOLUME rejection", err)
	}
}

// TestDockerPreflightRequiresLocalImages: readiness must reflect the exact
// artifacts runs will use — an absent image is not ready, not lazily pulled.
func TestDockerPreflightRequiresLocalImages(t *testing.T) {
	requireDocker(t)
	d := testDocker()
	d.Image = "plimsoll/definitely-absent:never-pulled"
	d.ProjectImage = d.Image
	err := d.Preflight(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not inspectable") {
		t.Fatalf("Preflight = %v, want a not-inspectable-image error", err)
	}
}

// TestDockerSmokeTestVerifiesStorageBounds runs the real probe containers for
// both configured images under the configured runtime/profile and requires the
// in-container evidence to prove every writable bound — including that the
// promised tmpfs mounts are the ONLY mounts accepting writes at all.
func TestDockerSmokeTestVerifiesStorageBounds(t *testing.T) {

	d := testDocker()
	requireSnippetImage(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := d.SmokeTest(ctx); err != nil {
		t.Fatalf("SmokeTest: %v", err)
	}
}

// TestDockerRunUsesPreflightVerifiedImageID proves runs launch the content ID
// Preflight inspected, not the mutable tag: after Preflight, the tag is
// re-pointed at a VOLUME-declaring scratch image (which cannot run node and
// would auto-create an anonymous writable volume). The run must still execute
// the verified content and succeed.
func TestDockerRunUsesPreflightVerifiedImageID(t *testing.T) {

	const tag = "crsbx-test-tag-swap:local"
	if out, err := exec.Command("docker", "tag", "node:22-alpine", tag).CombinedOutput(); err != nil {
		infraSkip(t, "cannot tag throwaway image: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", tag).Run() })

	d := testDocker()
	requireSnippetImage(t, d)
	d.Image = tag
	// Freeze the readiness clock so the run below is served from the verified
	// state instead of racing the cache TTL into a re-Preflight.
	now := time.Now()
	d.preflightNow = func() time.Time { return now }
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := d.Preflight(ctx); err != nil {
		t.Fatalf("Preflight: %v", err)
	}

	swap := exec.Command("docker", "build", "-q", "-t", tag, "-")
	swap.Stdin = strings.NewReader("FROM scratch\nVOLUME /data\n")
	if out, err := swap.CombinedOutput(); err != nil {
		infraSkip(t, "cannot re-point tag at a VOLUME image: %v: %s", err, out)
	}

	res, err := d.RunJavaScript(ctx, Request{Code: "console.log(6*7)"})
	if err != nil {
		t.Fatalf("run after tag swap failed — the mutable tag, not the verified ID, was launched: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "42") {
		t.Fatalf("run after tag swap = %+v, want the verified image's output", res)
	}
}

// TestCheckMemoryIsolation: only a clear refusal proves the runner's memory, and so
// its report key, is out of a step's reach; an open, a missing result or anything
// unexpected fails closed.
func TestCheckMemoryIsolation(t *testing.T) {
	for _, ok := range []string{"EACCES", "EPERM"} {
		if err := checkMemoryIsolation(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"open", "", "ENOENT", "spawn EAGAIN"} {
		if err := checkMemoryIsolation(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if !strings.Contains(smokeProbeScript(false, false), `"/proc/" + process.ppid + "/mem"`) {
		t.Fatal("the smoke probe does not check memory isolation")
	}
}
