package wslc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/nativehelper"
)

// The fake wslc is internal/fakewslc, built once by TestMain and started through a link
// named wslc.exe in each test's own directory: it answers from fake.json there and
// records each call in calls.jsonl.
var fakeBinary string

func TestMain(m *testing.M) {
	// The live kill test starts this binary again as the process it kills.
	if os.Getenv(killHelperEnv) == "1" {
		os.Exit(killHelperMain())
	}
	dir, err := os.MkdirTemp("", "plimsoll-fakewslc-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fakeBinary = filepath.Join(dir, "fakewslc")
	build := exec.Command("go", "build", "-o", fakeBinary, "./internal/fakewslc")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building the fake wslc: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// fakeSetup is the fake's fake.json (internal/fakewslc.Setup).
type fakeSetup struct {
	Version          string            `json:"version"`
	Images           json.RawMessage   `json:"images"`
	Kernel           string            `json:"kernel"`
	BootID           string            `json:"bootID"`
	Moby             string            `json:"moby"`
	ProbeStep        string            `json:"probeStep"`
	ProbeStdout      string            `json:"probeStdout"`
	Mode             string            `json:"mode"`
	StepExit         int               `json:"stepExit"`
	RemoveFails      bool              `json:"removeFails"`
	ContainerSleepMs int               `json:"containerSleepMs"`
	DefaultSession   string            `json:"defaultSession"`
	GPU              string            `json:"gpu"`
	VMMounts         string            `json:"vmMounts"`
	DriveC           string            `json:"driveC"`
	LAD              string            `json:"lad"`
	EnterMode        string            `json:"enterMode"`
	SameBootID       bool              `json:"sameBootID"`
	StoreExtra       string            `json:"storeExtra"`
	CopyFails        bool              `json:"copyFails"`
	ACL              string            `json:"acl"`
	ACLFails         bool              `json:"aclFails"`
	ACLs             map[string]string `json:"acls"`
	SaveFails        bool              `json:"saveFails"`

	DaemonJSON       string `json:"daemonJSON"`
	ReloadRuntime    string `json:"reloadRuntime"`
	ContainerRuntime string `json:"containerRuntime"`
	VMMemoryMax      string `json:"vmMemoryMax"`
	SentrySeccomp    string `json:"sentrySeccomp"`
	Platform         string `json:"platform"`
	NoSentry         bool   `json:"noSentry"`
	ContainerMounts  string `json:"containerMounts"`
	StoreCorrupt     string `json:"storeCorrupt"`
	ExtraStoreFile   bool   `json:"extraStoreFile"`
	ExtractFails     bool   `json:"extractFails"`
	RunscVersion     string `json:"runscVersion"`
	KeepReportBootID bool   `json:"keepReportBootID"`
	ProveFails       bool   `json:"proveFails"`
}

// fakeCall is one recorded call.
type fakeCall struct {
	Prog    string   `json:"prog"`
	Argv    []string `json:"argv"`
	Env     []string `json:"env"`
	Stdin   string   `json:"stdin"`
	Session string   `json:"session"`
	Script  string   `json:"script"`
}

// fakeState is the fake's state.json (internal/fakewslc.State).
type fakeState struct {
	Sessions map[string]struct {
		Dir    string   `json:"dir"`
		BootID string   `json:"bootID"`
		Runs   int      `json:"runs"`
		Images []string `json:"images"`
	} `json:"sessions"`
	Terminated  []string            `json:"terminated"`
	Active      int                 `json:"active"`
	MaxActive   int                 `json:"maxActive"`
	RunRuntimes map[string][]string `json:"runRuntimes"`
}

// fakeGPU is the GPU device line a session VM answers, as read on a real WSLC session.
const fakeGPU = "crw-rw-rw- 1 root root 10, 258 Nov 12 02:47 /dev/dxg"

// fakeVMMounts is a session VM's mount table, abridged from one read on 2026-11-11.
const fakeVMMounts = `none / overlay rw,relatime 0 0
drvfs /run/wsl/virtiofs-mounts/drvfs virtiofs rw,relatime 0 0
drvfs /usr/lib/wsl/drivers virtiofs ro,relatime 0 0
/dev/sdc /var/lib/docker ext4 rw,relatime,discard 0 0
`

// aclEntry is one rule of an access list answer.
func aclEntry(sid, typ string, rights int64, inherited bool) string {
	return fmt.Sprintf(`{"sid":%q,"type":%q,"rights":%d,"inherited":%t,"inheritOnly":false}`, sid, typ, rights, inherited)
}

// aclChildrenOnly is a rule that applies to what is in a folder, not to the folder itself.
func aclChildrenOnly(sid string, rights int64) string {
	return fmt.Sprintf(`{"sid":%q,"type":"Allow","rights":%d,"inherited":false,"inheritOnly":true}`, sid, rights)
}

const (
	fakeUserSID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
	fullControl = 2032127 // FileSystemRights.FullControl
	modifyRight = 1245631 // FileSystemRights.Modify
	readExecute = 1179817 // FileSystemRights.ReadAndExecute
)

// aclAnswerOf is the run root's access list as the script prints it, for an owner and rules.
func aclAnswerOf(owner string, entries ...string) string {
	return fmt.Sprintf(`{"user":%q,"owner":%q,"entries":[%s]}`, fakeUserSID, owner, strings.Join(entries, ","))
}

// ownerOnlyACL is what a folder under the user's local application data gives: the user,
// SYSTEM and Administrators, all inherited.
var ownerOnlyACL = aclAnswerOf(fakeUserSID,
	aclEntry(fakeUserSID, "Allow", fullControl, true),
	aclEntry("S-1-5-18", "Allow", fullControl, true),
	aclEntry("S-1-5-32-544", "Allow", fullControl, true))

// fakeImageID is the image ID the fake's inspect answers.
var fakeImageID = "sha256:" + strings.Repeat("ab", 32)

const fakeKernel = "6.18.58.1-microsoft-standard-WSL2"
const fakeBootID = "0f0e0d0c-0b0a-4908-8706-050403020100"

// goodProbe is the report a container built by runArgv with the default configuration
// gives.
func goodProbe() map[string]any { return goodProbeFor(Config{}) }

// goodProbeFor is the report a container built by runArgv with cfg gives.
// goodHelper is the probe's reading of an image's project runner that passes: the native
// helper this test binary carries, root's, mode 0755.
func goodHelper() map[string]any {
	sum, err := nativehelper.SHA256(runtime.GOARCH)
	if err != nil {
		panic(err)
	}
	return map[string]any{"type": "file", "uid": 0, "mode": 0o755, "size": 516768, "sha256": sum}
}

func goodProbeFor(cfg Config) map[string]any {
	cfg.withDefaults()
	uid := "61000\t61000\t61000\t61000"
	nproc := fmt.Sprint(cfg.Nproc)
	return map[string]any{
		"status": map[string]string{"Uid": uid, "Gid": uid, "Groups": "", "CapInh": "0000000000000000", "CapPrm": "0000000000000000",
			"CapEff": "0000000000000000", "CapBnd": "0000000000000000", "CapAmb": "0000000000000000",
			"Seccomp": "2", "Seccomp_filters": "1", "NoNewPrivs": "0"},
		"kernel": fakeKernel, "bootID": fakeBootID, "interfaces": []string{"lo"},
		"connect": map[string]string{"1.1.1.1:443": "ENETUNREACH", "8.8.8.8:53": "ENETUNREACH", "169.254.169.254:80": "ENETUNREACH"},
		"mountinfo": []string{
			"600 500 0:60 / / rw,relatime - overlay overlay rw,lowerdir=/l,upperdir=/u,workdir=/w",
			"601 600 0:61 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw",
			"602 600 0:62 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755",
			"603 602 0:63 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=16384k",
			"604 600 0:64 / /tmp rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=16384k",
			"605 600 0:65 / /var/tmp rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=16384k",
			fmt.Sprintf("606 600 0:66 / /work rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=%dk,mode=1777", cfg.workMB()*1024),
			"607 600 8:1 /etc/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/sdb rw",
		},
		"writable":  []string{"/dev/shm", "/tmp", "/var/tmp", "/work"},
		"walk":      map[string]any{"entries": 31000, "unlistable": 4, "truncated": false},
		"memoryMax": fmt.Sprint(cfg.MemoryMB * 1024 * 1024), "pidsMax": "max",
		"limits":    map[string]string{"Max processes": nproc + " " + nproc, "Max open files": "4096 4096", "Max core file size": "0 0"},
		"resolv":    "nameserver 127.0.0.1\noptions ndots:0\n",
		"envNames":  []string{"HOME", "NODE_VERSION", "PATH", "PLIMSOLL_RUNNER_PID", "PWD", "SHLVL", "YARN_VERSION"},
		"runnerMem": "EACCES",
		"helper":    goodHelper(),
		"gpu":       "absent",
	}
}

// goodSetup is a fake that passes every check of a provider with the default
// configuration.
func goodSetup(t *testing.T) fakeSetup { return goodSetupFor(t, Config{}) }

// goodSetupFor is a fake that passes every check of a provider configured as cfg.
func goodSetupFor(t *testing.T, cfg Config) fakeSetup {
	t.Helper()
	probe, err := json.Marshal(goodProbeFor(cfg))
	if err != nil {
		t.Fatal(err)
	}
	images, _ := json.Marshal([]map[string]any{{
		"Id": fakeImageID, "RepoDigests": []string{"docker.io/plimsoll/sandbox@sha256:" + strings.Repeat("cd", 32)},
		"Architecture": "amd64", "Os": "linux",
		"Config": map[string]any{"Env": []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "NODE_VERSION=22.11.0", "YARN_VERSION=1.22.22"}},
	}})
	return fakeSetup{Version: "3.0.5.0", Images: images, Kernel: fakeKernel, BootID: fakeBootID, Moby: "Docker version 28.5.1, build e180ab8",
		ProbeStep: probeStep, ProbeStdout: string(probe), DefaultSession: "wslc-cli-test", GPU: fakeGPU, VMMounts: fakeVMMounts,
		LAD: `C:\Users\fake\AppData\Local`, ACL: ownerOnlyACL}
}

// fake is one fake wslc in its own directory, with a directory standing for C:\.
type fake struct {
	t      *testing.T
	dir    string
	driveC string
}

func newFake(t *testing.T, setup fakeSetup) *fake {
	t.Helper()
	f := &fake{t: t, dir: t.TempDir(), driveC: t.TempDir()}
	for _, name := range []string{"wslc.exe", "powershell.exe", "mkfs.ext4"} {
		if err := os.Symlink(fakeBinary, filepath.Join(f.dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	f.set(setup)
	return f
}

func (f *fake) path() string { return filepath.Join(f.dir, "wslc.exe") }

func (f *fake) set(setup fakeSetup) {
	f.t.Helper()
	setup.DriveC = f.driveC
	b, _ := json.Marshal(setup)
	if err := os.WriteFile(filepath.Join(f.dir, "fake.json"), b, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fake) calls() []fakeCall {
	f.t.Helper()
	file, err := os.Open(filepath.Join(f.dir, "calls.jsonl"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		f.t.Fatal(err)
	}
	defer file.Close()
	var out []fakeCall
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 1<<20), 32<<20)
	for sc.Scan() {
		var c fakeCall
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func (f *fake) clearCalls() { _ = os.Remove(filepath.Join(f.dir, "calls.jsonl")) }

// runs are the recorded `container run` calls.
func (f *fake) runs() []fakeCall {
	var out []fakeCall
	for _, c := range f.calls() {
		a := c.Argv
		if len(a) >= 2 && a[0] == "--session" {
			a = a[2:]
		}
		if c.Prog == "wslc.exe" && len(a) >= 2 && a[0] == "container" && a[1] == "run" {
			out = append(out, c)
		}
	}
	return out
}

// removes are the names of the containers `container remove --force` was called for.
func (f *fake) removes() []string {
	var out []string
	for _, c := range f.calls() {
		if len(c.Argv) == 4 && slices.Equal(c.Argv[:3], []string{"container", "remove", "--force"}) {
			out = append(out, c.Argv[3])
		}
	}
	return out
}

// provider builds a shared-mode provider on the fake (the default mode is per-run, so the
// shared mode is named here) with the default configuration otherwise.
func (f *fake) provider(mut ...func(*Config)) *Provider {
	f.t.Helper()
	cfg := Config{Path: f.path(), Image: "plimsoll/sandbox:latest", Mode: ModeShared}
	for _, m := range mut {
		m(&cfg)
	}
	if cfg.Mode == ModePerRun {
		cfg.PowerShell, cfg.Mkfs = filepath.Join(f.dir, "powershell.exe"), filepath.Join(f.dir, "mkfs.ext4")
	}
	p, err := New(cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	p.removePause, p.listPoll, p.teardownTimeout = time.Millisecond, 5*time.Millisecond, time.Second
	p.drives = map[string]string{"C": f.driveC}
	f.t.Cleanup(p.drain)
	return p
}

// perRun is the per-run mode.
func perRun(c *Config) { c.Mode = ModePerRun }

// state is the fake's sessions and terminations.
func (f *fake) state() fakeState {
	f.t.Helper()
	var st fakeState
	b, err := os.ReadFile(filepath.Join(f.dir, "state.json"))
	if os.IsNotExist(err) {
		return st
	}
	if err != nil {
		f.t.Fatal(err)
	}
	if err := json.Unmarshal(b, &st); err != nil {
		f.t.Fatal(err)
	}
	return st
}

// enters are the recorded `system session enter` calls, each with the input its holder got.
func (f *fake) enters() []fakeCall {
	var out []fakeCall
	for _, c := range f.calls() {
		if len(c.Argv) >= 3 && strings.Join(c.Argv[:3], " ") == "system session enter" {
			out = append(out, c)
		}
	}
	return out
}

// runRoot is the per-run root the fake's LAD gives, as the provider sees it.
func (f *fake) runRoot() string {
	return filepath.Join(f.driveC, "Users/fake/AppData/Local/plimsoll-wslc")
}
