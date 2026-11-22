// Command fakewslc stands in for wslc.exe in package wslc's tests, and for the two other
// programs the per-run mode starts, powershell.exe and mkfs.ext4: the tests build it once
// and start it through links named after each, and it acts by the name it was started
// under. It answers as those programs would, from fake.json beside itself, keeps the
// sessions it has created in state.json there (under a file lock, since a run's holder and
// its commands are separate processes), and records each call's argv, environment and
// stdin in calls.jsonl. It reads its setup from a file because hostCommand gives it PATH
// alone, which is one of the things the tests check. It answers as Microsoft's source at
// WSL tag 3.0.5 says wslc does, so it shares any misreading of that source.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"github.com/plimsollmark/plimsoll/internal/outsidefacts"

	"github.com/plimsollmark/plimsoll/sandbox/internal/runnerwire"
)

// Setup is fake.json.
type Setup struct {
	Version     string          `json:"version"`
	Images      json.RawMessage `json:"images"`
	Kernel      string          `json:"kernel"`
	BootID      string          `json:"bootID"` // the default session's
	Moby        string          `json:"moby"`
	ProbeStep   string          `json:"probeStep"`   // the smoke test's step
	ProbeStdout string          `json:"probeStdout"` // that step's stdout
	// Mode is how `container run` behaves: "" runs the plan and reports, "silent" exits 0
	// with no report, "fail" exits 3 with no report, "hang" never exits.
	Mode        string `json:"mode"`
	StepExit    int    `json:"stepExit"`
	RemoveFails bool   `json:"removeFails"`
	// ContainerSleepMs delays every container run's report.
	ContainerSleepMs int `json:"containerSleepMs"`

	// The default session's name, and what a session VM answers.
	DefaultSession string `json:"defaultSession"`
	GPU            string `json:"gpu"`      // `ls -l /dev/dxg` in a session VM; "" is absent
	VMMounts       string `json:"vmMounts"` // a session VM's /proc/self/mounts

	// The per-run mode. DriveC is the directory that stands for C:\; LAD is the local
	// application data folder powershell.exe answers, in Windows form.
	DriveC string `json:"driveC"`
	LAD    string `json:"lad"`
	// EnterMode is how `system session enter` behaves: "" holds the session until its
	// input ends, "fail" exits 1 at once, "unlisted" holds it without listing it, "die"
	// lists it and exits at once leaving it listed (a killed holder), "stay" ends at its
	// input's end but leaves the session listed.
	EnterMode string `json:"enterMode"`
	// SameBootID gives every named session the default session's boot ID.
	SameBootID bool `json:"sameBootID"`
	// StoreExtra puts a container ("container") in every named session's store.
	StoreExtra string `json:"storeExtra"`
	CopyFails  bool   `json:"copyFails"`
	// ACL is what powershell.exe prints for the run root's access list script ("" prints
	// nothing, an unreadable answer); ACLFails makes that script exit 1.
	ACL      string `json:"acl"`
	ACLFails bool   `json:"aclFails"`
	// ACLs answers the script for one path (a Windows path, as the script quotes it) with
	// its own list in place of ACL: a folder above the run root, the template's folder or
	// its disk file.
	ACLs map[string]string `json:"acls"`
	// SaveFails makes `save` write part of its archive and exit 1.
	SaveFails bool `json:"saveFails"`

	// gVisor (SANDBOX_WSLC_GVISOR=1). DaemonJSON is what a booted session's
	// /etc/docker/daemon.json holds ("" is Microsoft's). ReloadRuntime "runc" makes the
	// reload leave the default runtime runc, as a daemon that ignores the file would.
	// ContainerRuntime is the runtime the VM reports for the boundary test's container ("" is the
	// session's default at the time it ran). VMMemoryMax, SentrySeccomp and Platform are
	// what the VM reads ("" is the good value); NoSentry has no runsc-sandbox process;
	// ContainerMounts is the container's mount count (default 0).
	DaemonJSON       string `json:"daemonJSON"`
	ReloadRuntime    string `json:"reloadRuntime"`
	ContainerRuntime string `json:"containerRuntime"`
	VMMemoryMax      string `json:"vmMemoryMax"`
	SentrySeccomp    string `json:"sentrySeccomp"`
	Platform         string `json:"platform"`
	NoSentry         bool   `json:"noSentry"`
	ContainerMounts  string `json:"containerMounts"`
	// StoreCorrupt names a file whose stored bytes read back with another digest;
	// ExtraStoreFile adds a file nobody sent; ExtractFails makes the tar extraction fail;
	// RunscVersion is what the stored runsc prints ("" is a release name).
	StoreCorrupt   string `json:"storeCorrupt"`
	ExtraStoreFile bool   `json:"extraStoreFile"`
	ExtractFails   bool   `json:"extractFails"`
	RunscVersion   string `json:"runscVersion"`
	// KeepReportBootID leaves the boundary test's boot ID as the setup wrote it (gVisor's own)
	// instead of the session VM's; ProveFails makes the VM-side read of the container fail,
	// as for a container that is not in this session.
	KeepReportBootID bool `json:"keepReportBootID"`
	ProveFails       bool `json:"proveFails"`
}

// Call is one recorded call.
type Call struct {
	Prog    string   `json:"prog"`
	Argv    []string `json:"argv"`
	Env     []string `json:"env"`
	Stdin   string   `json:"stdin"`
	Session string   `json:"session"`
	Script  string   `json:"script"` // powershell.exe's decoded -EncodedCommand
}

// Session is one named session in state.json.
type Session struct {
	Dir    string   `json:"dir"`
	BootID string   `json:"bootID"`
	Runs   int      `json:"runs"`
	Images []string `json:"images"`
	// GVisor is the files of the session's gvisor directory (name to SHA-512), kept beside
	// the disk like Images; DaemonJSON and Runtime are this boot's docker settings.
	GVisor     map[string]string `json:"gvisor"`
	DaemonJSON string            `json:"daemonJSON"`
	Runtime    string            `json:"runtime"`
	// Listed is set once a `system info` answer has named the session: a "die" holder
	// waits for it, so it dies under its run, after the provider saw the session listed.
	Listed bool `json:"listed"`
}

// State is state.json.
type State struct {
	Sessions   map[string]*Session `json:"sessions"`
	Terminated []string            `json:"terminated"`
	// Active is the container runs in progress now, and MaxActive the most there were at
	// once (a run counts from its start to the end of its ContainerSleepMs).
	Active    int `json:"active"`
	MaxActive int `json:"maxActive"`
	// RunRuntimes is, per session, the default runtime at the time of each `container run`.
	RunRuntimes map[string][]string `json:"runRuntimes"`
}

// What this stand-in models of the real programs comes from the table of outside facts
// (internal/outsidefacts), not from copies here: the file WSL writes at boot and ls's words for
// a missing file. A fact that changes there changes this stand-in, and the provider's test
// (TestTheProviderAgreesWithTheFactsItsStandInIsBuiltFrom) then fails until the provider is
// read against it again.
var (
	msDaemonJSON  = outsidefacts.Value("wslc-daemon-json-exact")
	lsAbsentWords = outsidefacts.Value("wslc-ls-no-such-file-words")
)

var dir string

func main() { os.Exit(run()) }

func run() int {
	// The tests start it through links in the fake's own directory.
	dir = filepath.Dir(os.Args[0])
	raw, err := os.ReadFile(filepath.Join(dir, "fake.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake wslc: no fake.json:", err)
		return 2
	}
	var setup Setup
	if err := json.Unmarshal(raw, &setup); err != nil {
		fmt.Fprintln(os.Stderr, "fake wslc:", err)
		return 2
	}
	call := Call{Prog: filepath.Base(os.Args[0]), Argv: os.Args[1:], Env: os.Environ()}
	switch call.Prog {
	case "powershell.exe":
		return powershell(setup, call)
	case "mkfs.ext4":
		record(call)
		return mkfs(call.Argv)
	}
	args := call.Argv
	if len(args) >= 2 && args[0] == "--session" {
		call.Session, args = args[1], args[2:]
	}
	isRun := len(args) >= 2 && args[0] == "container" && args[1] == "run"
	isEnter := len(args) >= 3 && strings.Join(args[:3], " ") == "system session enter"
	isSh := len(args) == 4 && strings.Join(args[:3], " ") == "system session run" && args[3] == "sh"
	isTar := len(args) >= 4 && strings.Join(args[:3], " ") == "system session run" && args[3] == "tar"
	var tarred map[string]string
	var tarErr error
	switch {
	case isRun || isSh:
		in, _ := io.ReadAll(os.Stdin)
		call.Stdin = string(in)
	case isTar:
		in, _ := io.ReadAll(os.Stdin)
		tarred, tarErr = readTar(in)
		names := make([]string, 0, len(tarred))
		for n := range tarred {
			names = append(names, n)
		}
		slices.Sort(names)
		call.Stdin = "tar: " + strings.Join(names, ",")
	}
	if !isEnter {
		record(call)
	}
	if call.Session != "" && call.Session != setup.DefaultSession && !isEnter {
		var known bool
		withState(func(st *State) {
			s, ok := st.Sessions[call.Session]
			known = ok
			if ok && isRun {
				s.Runs++
				if st.RunRuntimes == nil {
					st.RunRuntimes = map[string][]string{}
				}
				st.RunRuntimes[call.Session] = append(st.RunRuntimes[call.Session], s.Runtime)
			}
		})
		if !known {
			fmt.Fprintf(os.Stderr, "Session '%s' not found\n", call.Session)
			return 1
		}
	}
	joined := strings.Join(args, " ")
	switch {
	case joined == "version --format json":
		fmt.Printf(`{"Client":{"Version":%q}}`+"\n", setup.Version)
	case joined == "system info --format json":
		var names []string
		if setup.DefaultSession != "" {
			names = append(names, setup.DefaultSession)
		}
		withState(func(st *State) {
			for n, sess := range st.Sessions {
				names = append(names, n)
				sess.Listed = true
			}
		})
		slices.Sort(names)
		type entry struct{ Name string }
		var list []entry
		for _, n := range names {
			list = append(list, entry{n})
		}
		b, _ := json.Marshal(map[string]any{"Server": map[string]any{"Sessions": list}})
		fmt.Println(string(b))
	case len(args) == 3 && args[0] == "image" && args[1] == "inspect":
		os.Stdout.Write(setup.Images)
	case len(args) >= 4 && strings.Join(args[:3], " ") == "system session run":
		return sessionRun(setup, call.Session, args[3:], call.Stdin, tarred, tarErr)
	case joined == "system session terminate":
		var ok bool
		withState(func(st *State) {
			if _, ok = st.Sessions[call.Session]; ok {
				delete(st.Sessions, call.Session)
				st.Terminated = append(st.Terminated, call.Session)
			}
		})
		if !ok {
			fmt.Fprintln(os.Stderr, "no such session")
			return 1
		}
	case isEnter:
		return enter(setup, call, args[3:])
	case len(args) == 4 && args[0] == "save" && args[1] == "-o":
		content := "image archive of " + args[3]
		if setup.SaveFails {
			content = content[:8]
		}
		if err := os.WriteFile(toLinux(setup, args[2]), []byte(content), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if setup.SaveFails {
			fmt.Fprintln(os.Stderr, "the archive could not be written in full")
			return 1
		}
	case len(args) == 4 && strings.Join(args[:3], " ") == "load -q -i" && call.Session != "":
		b, err := os.ReadFile(toLinux(setup, args[3]))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		id := strings.TrimPrefix(string(b), "image archive of ")
		withState(func(st *State) { st.Sessions[call.Session].Images = append(st.Sessions[call.Session].Images, id) })
	case joined == "image list --all --quiet --no-trunc":
		if call.Session == "" || call.Session == setup.DefaultSession {
			var imgs []struct{ Id string }
			_ = json.Unmarshal(setup.Images, &imgs)
			for _, i := range imgs {
				fmt.Println(i.Id)
			}
			break
		}
		withState(func(st *State) {
			for _, i := range st.Sessions[call.Session].Images {
				fmt.Println(i)
			}
		})
	case joined == "container list --all --quiet":
		if call.Session != "" && setup.StoreExtra == "container" {
			fmt.Println("0123456789ab")
		}
	case joined == "volume list --quiet":
	case len(args) == 4 && args[0] == "container" && args[1] == "remove" && args[2] == "--force":
		if setup.RemoveFails {
			fmt.Fprintln(os.Stderr, "no such container")
			return 1
		}
	case isRun:
		boot := "" // the default session: the probe reports what the setup says
		if call.Session != "" && call.Session != setup.DefaultSession {
			withState(func(st *State) { boot = st.Sessions[call.Session].BootID })
		}
		return container(setup, call.Stdin, boot)
	default:
		fmt.Fprintln(os.Stderr, "fake wslc: unknown command:", joined)
		return 2
	}
	return 0
}

// sessionRun answers `system session run` in a session VM.
func sessionRun(setup Setup, session string, argv []string, stdin string, tarred map[string]string, tarErr error) int {
	boot := setup.BootID
	if session != "" && session != setup.DefaultSession {
		withState(func(st *State) { boot = st.Sessions[session].BootID })
	}
	switch strings.Join(argv, " ") {
	case "uname -r":
		fmt.Println(setup.Kernel)
	case "cat /proc/sys/kernel/random/boot_id":
		fmt.Println(boot)
	case "dockerd --version":
		fmt.Println(setup.Moby)
	case "cat /proc/uptime":
		fmt.Println("1.42 20.10")
	case "ls -l /dev/dxg":
		if setup.GPU == "" {
			fmt.Fprintln(os.Stderr, "ls: /dev/dxg: "+lsAbsentWords+" or directory")
			return 1
		}
		fmt.Println(setup.GPU)
	case "cat /proc/self/mounts":
		fmt.Print(setup.VMMounts)
	case "mkdir -p /var/lib/docker/gvisor/gvisor-bin", "sync":
	case "tar -xzf - -C /var/lib/docker/gvisor":
		if setup.ExtractFails || tarErr != nil {
			fmt.Fprintln(os.Stderr, "tar: short read", tarErr)
			return 2
		}
		withState(func(st *State) {
			s := st.Sessions[session]
			if s.GVisor == nil {
				s.GVisor = map[string]string{}
			}
			for n, sum := range tarred {
				s.GVisor[n] = sum
			}
		})
	case "sh":
		return script(setup, session, stdin)
	default:
		fmt.Fprintln(os.Stderr, "fake wslc: unknown session command:", argv)
		return 2
	}
	return 0
}

var (
	oursRE = regexp.MustCompile(`(?m)^ours='(.*)'$`)
	nameRE = regexp.MustCompile(`(?m)^NAME=(plimsoll-wslc-[0-9a-f]{24})$`)
)

// readTar reads a gzipped tar and returns each regular file's SHA-512.
func readTar(b []byte) (map[string]string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	out := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		hash := sha512.New()
		if _, err := io.Copy(hash, tr); err != nil {
			return nil, err
		}
		out[strings.TrimPrefix(h.Name, "./")] = hex.EncodeToString(hash.Sum(nil))
	}
}

// script plays the scripts the provider sends to `sh` in a session VM, by the kind named on
// the script's first line.
func script(setup Setup, session, text string) int {
	first, _, _ := strings.Cut(text, "\n")
	kind := strings.TrimPrefix(first, "# plimsoll-script: ")
	var out strings.Builder
	code := 0
	withState(func(st *State) {
		s := st.Sessions[session]
		switch kind {
		case "register-runsc":
			ours := ""
			if m := oursRE.FindStringSubmatch(text); m != nil {
				ours = m[1]
			}
			if s.DaemonJSON != msDaemonJSON && s.DaemonJSON != ours {
				fmt.Fprintln(os.Stderr, "daemon.json holds settings this provider has not seen")
				code = 42
				return
			}
			if strings.Contains(text, "cat > /etc/docker/daemon.json") {
				s.DaemonJSON = ours
				// dockerd takes the new default only if the runtime's binary is there.
				if _, ok := s.GVisor["runsc"]; ok && setup.ReloadRuntime != "runc" {
					s.Runtime = "runsc"
				}
			}
			fmt.Fprintf(&out, "default-runtime=%s\nruntimes=io.containerd.runc.v2:runc runc:runc runsc:/var/lib/docker/gvisor/runsc \ndockerd-pid=238\n", s.Runtime)
		case "verify-runsc":
			names := make([]string, 0, len(s.GVisor))
			for n := range s.GVisor {
				names = append(names, n)
			}
			slices.Sort(names)
			for _, n := range names {
				sum := s.GVisor[n]
				if n == setup.StoreCorrupt {
					sum = strings.Repeat("0", 128)
				}
				fmt.Fprintf(&out, "sha512=%s %s\nfile=./%s\n", n, sum, n)
			}
			if setup.ExtraStoreFile {
				fmt.Fprintln(&out, "file=./extra")
			}
			if len(names) > 1 {
				fmt.Fprintln(&out, "dir=./gvisor-bin")
			}
			v := setup.RunscVersion
			if v == "" {
				v = "runsc version release-20260907.0"
			}
			fmt.Fprintf(&out, "version=%s\n", v)
		case "prove-container":
			if nameRE.FindStringSubmatch(text) == nil {
				fmt.Fprintln(os.Stderr, "no container name")
				code = 2
				return
			}
			if setup.ProveFails {
				fmt.Fprintln(os.Stderr, "Error: No such object")
				code = 51
				return
			}
			runtime := s.Runtime
			if setup.ContainerRuntime != "" {
				runtime = setup.ContainerRuntime
			}
			mem := setup.VMMemoryMax
			if mem == "" {
				mem = "536870912"
			}
			mounts := setup.ContainerMounts
			if mounts == "" {
				mounts = "0"
			}
			fmt.Fprintf(&out, "running=true\nruntime=%s\nmounts=%s\nbinds=0\nmemory-max=%s\n", runtime, mounts, mem)
			if !setup.NoSentry {
				sec, plat := setup.SentrySeccomp, setup.Platform
				if sec == "" {
					sec = "2"
				}
				if plat == "" {
					plat = "systrap"
				}
				fmt.Fprintf(&out, "sentry=1171 seccomp=%s platform=%s\n", sec, plat)
			}
		default:
			fmt.Fprintln(os.Stderr, "fake wslc: unknown script kind:", kind)
			code = 2
		}
	})
	fmt.Print(out.String())
	return code
}

// enter plays `system session enter DIR --name NAME`: the session is listed while its
// input is open, and its store's images are kept beside the disk when it ends.
func enter(setup Setup, call Call, args []string) int {
	if len(args) != 3 || args[1] != "--name" {
		fmt.Fprintln(os.Stderr, "fake wslc: bad enter:", args)
		return 2
	}
	storage, name := toLinux(setup, args[0]), args[2]
	if setup.EnterMode == "fail" {
		record(call)
		fmt.Fprintln(os.Stderr, "the session could not be created")
		return 1
	}
	disk := filepath.Join(storage, "storage.vhdx")
	if _, err := os.Stat(disk); err != nil {
		record(call)
		fmt.Fprintf(os.Stderr, "No WSLC session found at %s\n", args[0])
		return 1
	}
	if setup.EnterMode != "unlisted" {
		var images []string
		if b, err := os.ReadFile(disk + ".images"); err == nil {
			images = strings.Fields(string(b))
		}
		boot := setup.BootID
		if !setup.SameBootID {
			sum := sha256.Sum256([]byte(name))
			h := hex.EncodeToString(sum[:16])
			boot = h[0:8] + "-" + h[8:12] + "-4" + h[13:16] + "-8" + h[17:20] + "-" + h[20:32]
		}
		var gv map[string]string
		if b, err := os.ReadFile(disk + ".gvisor"); err == nil {
			_ = json.Unmarshal(b, &gv)
		}
		daemon := setup.DaemonJSON
		if daemon == "" {
			daemon = msDaemonJSON
		}
		withState(func(st *State) {
			st.Sessions[name] = &Session{Dir: storage, BootID: boot, Images: images, GVisor: gv, DaemonJSON: daemon, Runtime: "runc"}
		})
	}
	fmt.Fprintf(os.Stderr, "Created session: '%s'\n", name)
	if setup.EnterMode == "die" {
		// A killed holder: it dies once the provider has seen its session listed, as a
		// holder the OOM killer takes under its run does, and leaves the session listed.
		// Dying before that, a race the test cannot steer, would test the refusal of a
		// holder that never got going instead.
		for wait := time.Now().Add(10 * time.Second); time.Now().Before(wait); time.Sleep(10 * time.Millisecond) {
			listed := false
			withState(func(st *State) {
				if sess, ok := st.Sessions[name]; ok {
					listed = sess.Listed
				}
			})
			if listed {
				break
			}
		}
		record(call)
		return 137
	}
	in, _ := io.ReadAll(os.Stdin)
	call.Stdin = string(in)
	record(call)
	if setup.EnterMode == "stay" {
		return 0
	}
	withState(func(st *State) {
		if s, ok := st.Sessions[name]; ok {
			_ = os.WriteFile(disk+".images", []byte(strings.Join(s.Images, "\n")), 0o644)
			if len(s.GVisor) > 0 {
				b, _ := json.Marshal(s.GVisor)
				_ = os.WriteFile(disk+".gvisor", b, 0o644)
			}
			delete(st.Sessions, name)
		}
	})
	fmt.Println("logout")
	return 0
}

var (
	copyRE = regexp.MustCompile(`New-Item -ItemType Directory -Path '([^']+)' \| Out-Null; Copy-Item -LiteralPath '([^']+)' -Destination '([^']+)'`)
)

// powershell plays the two scripts the provider sends.
func powershell(setup Setup, call Call) int {
	if len(call.Argv) != 4 || call.Argv[2] != "-EncodedCommand" {
		record(call)
		fmt.Fprintln(os.Stderr, "fake powershell: bad arguments")
		return 2
	}
	raw, err := base64.StdEncoding.DecodeString(call.Argv[3])
	if err != nil || len(raw)%2 != 0 {
		record(call)
		return 2
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	call.Script = string(utf16.Decode(u))
	record(call)
	switch {
	case strings.Contains(call.Script, "[Environment]::GetFolderPath('LocalApplicationData')"):
		fmt.Println(setup.LAD)
	case strings.Contains(call.Script, "Get-Acl -LiteralPath"):
		if setup.ACLFails {
			fmt.Fprintln(os.Stderr, "Get-Acl: access denied")
			return 1
		}
		for win, acl := range setup.ACLs {
			if strings.Contains(call.Script, "Get-Acl -LiteralPath '"+win+"';") {
				fmt.Println(acl)
				return 0
			}
		}
		fmt.Println(setup.ACL)
	case copyRE.MatchString(call.Script):
		m := copyRE.FindStringSubmatch(call.Script)
		if setup.CopyFails {
			fmt.Fprintln(os.Stderr, "Copy-Item: the disk is full")
			return 1
		}
		d := toLinux(setup, m[1])
		if err := os.Mkdir(d, 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "New-Item:", err)
			return 1
		}
		for _, suffix := range []string{"", ".images", ".gvisor"} {
			b, err := os.ReadFile(toLinux(setup, m[2]) + suffix)
			if err != nil && suffix == "" {
				fmt.Fprintln(os.Stderr, "Copy-Item:", err)
				return 1
			}
			if err == nil {
				_ = os.WriteFile(toLinux(setup, m[3])+suffix, b, 0o644)
			}
		}
	default:
		fmt.Fprintln(os.Stderr, "fake powershell: unknown script")
		return 2
	}
	return 0
}

// mkfs plays mkfs.ext4 on a file: it writes a little data in two places, so the VHDX
// writer has blocks to store and holes to skip.
func mkfs(argv []string) int {
	f, err := os.OpenFile(argv[len(argv)-1], os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer f.Close()
	for _, off := range []int64{1024, 64<<20 + 512} {
		if _, err := f.WriteAt([]byte(strings.Repeat("ext4", 1024)), off); err != nil {
			return 1
		}
	}
	return 0
}

// toLinux maps a Windows path of the form C:/... to the directory that stands for C:.
func toLinux(setup Setup, win string) string {
	rest, ok := strings.CutPrefix(strings.ReplaceAll(win, `\`, "/"), "C:/")
	if !ok {
		return "/nonexistent/" + win
	}
	return filepath.Join(setup.DriveC, rest)
}

// withState runs f on state.json under an exclusive lock, and saves it.
func withState(f func(*State)) {
	lock, err := os.OpenFile(filepath.Join(dir, "state.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		panic(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		panic(err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	st := State{Sessions: map[string]*Session{}}
	if b, err := os.ReadFile(filepath.Join(dir, "state.json")); err == nil {
		_ = json.Unmarshal(b, &st)
		if st.Sessions == nil {
			st.Sessions = map[string]*Session{}
		}
	}
	f(&st)
	b, _ := json.Marshal(st)
	_ = os.WriteFile(filepath.Join(dir, "state.json"), b, 0o600)
}

// record appends one call to calls.jsonl.
func record(call Call) {
	line, _ := json.Marshal(call)
	f, err := os.OpenFile(filepath.Join(dir, "calls.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		_, _ = f.Write(append(line, '\n'))
		_ = f.Close()
	}
}

// container plays the runner for one plan: each step's result is canned (the probe step
// gets ProbeStdout), and the report is framed and signed as the project runner frames it.
func container(setup Setup, stdin, boot string) int {
	switch setup.Mode {
	case "silent":
		fmt.Println("some output, no report")
		return 0
	case "fail":
		fmt.Fprintln(os.Stderr, "guest-controlled text that must not reach an error")
		return 3
	case "hang":
		time.Sleep(time.Hour)
		return 0
	}
	withState(func(st *State) { st.Active++; st.MaxActive = max(st.MaxActive, st.Active) })
	time.Sleep(time.Duration(setup.ContainerSleepMs) * time.Millisecond)
	withState(func(st *State) { st.Active-- })
	var plan struct {
		Steps     []string `json:"steps"`
		ReportKey string   `json:"reportKey"`
	}
	if err := json.Unmarshal([]byte(stdin), &plan); err != nil {
		fmt.Fprintln(os.Stderr, "fake runner: bad plan:", err)
		return 1
	}
	key, err := hex.DecodeString(plan.ReportKey)
	if err != nil {
		return 1
	}
	type step struct {
		Command         string `json:"command"`
		Stdout          []byte `json:"stdoutBase64"`
		Stderr          []byte `json:"stderrBase64"`
		StdoutTruncated bool   `json:"stdoutTruncated"`
		StderrTruncated bool   `json:"stderrTruncated"`
		ExitCode        int    `json:"exitCode"`
		TimedOut        bool   `json:"timedOut"`
		DurationMs      int64  `json:"durationMs"`
	}
	body := struct {
		Steps              []step `json:"steps"`
		Artifacts          []any  `json:"artifacts"`
		ArtifactsTruncated bool   `json:"artifactsTruncated"`
	}{Artifacts: []any{}}
	for _, s := range plan.Steps {
		st := step{Command: s, DurationMs: 3}
		if s == setup.ProbeStep {
			// The probe reads the boot ID of the VM it runs in: a named session's own.
			var probe map[string]any
			if err := json.Unmarshal([]byte(setup.ProbeStdout), &probe); err == nil && boot != "" && !setup.KeepReportBootID {
				probe["bootID"] = boot
				st.Stdout, _ = json.Marshal(probe)
			} else {
				st.Stdout = []byte(setup.ProbeStdout)
			}
		} else {
			st.Stdout, st.Stderr, st.ExitCode = []byte("ran: "+s+"\n"), []byte("err\n"), setup.StepExit
		}
		body.Steps = append(body.Steps, st)
		if st.ExitCode != 0 {
			break
		}
	}
	b, _ := json.Marshal(body)
	h := hmac.New(sha256.New, key)
	h.Write(b)
	fmt.Printf("\n%s %d %s\n%s", runnerwire.Marker, len(b), hex.EncodeToString(h.Sum(nil)), b)
	return 0
}
