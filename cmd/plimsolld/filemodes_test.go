package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/internal/settings"
	"github.com/plimsollmark/plimsoll/internal/withheld"
)

// The callers file, the grants file and the withheld set decide who may run code and what
// a run may reach, so a file another user of the machine could change hands that user a
// caller of their own at the next restart (finding hunt-security-4). The decision of
// 2026-11-20: hardened mode refuses to start on one, any other mode logs one warning line
// naming the setting and the mode bits. The rule itself is internal/settings/configfile's.

const (
	modesToken = "modes-0123456789abcdef0123456789abcdef"
	modesLabel = "harness/secret-label.js" // in the withheld set; must never reach the log
)

// modeFiles writes the three files, each alone in a directory of its own, and returns
// each setting's file path.
func modeFiles(t *testing.T) map[string]string {
	t.Helper()
	sum := sha256.Sum256([]byte(modesToken))
	clients, err := json.Marshal(map[string]any{"clients": []map[string]any{
		{"id": "caller", "token_sha256": hex.EncodeToString(sum[:]), "scopes": []string{"code:run"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	digest := withheld.FileDigest([]byte("console.log(1)\n"))
	set, err := json.Marshal(map[string]any{"version": withheld.Version, "mode": "refuse", "entries": []map[string]any{
		{"kind": "file", "sha256": hex.EncodeToString(digest[:]), "label": modesLabel},
	}})
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	out := map[string]string{}
	for setting, raw := range map[string][]byte{
		settings.NameOf(settings.ClientsFile):  clients,
		settings.NameOf(settings.GrantsFile):   []byte(`{"profiles":{}}`),
		settings.NameOf(settings.WithheldFile): set,
	} {
		dir := filepath.Join(base, strings.ToLower(setting))
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "file.json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		out[setting] = path
	}
	return out
}

// setMode chmods path (after creation, so the umask does not decide) and restores what
// the temporary directory's cleanup needs.
func setMode(t *testing.T, path string, m os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, m); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o700) })
}

func modesEnv(files map[string]string, hardened bool) []string {
	env := []string{"PATH=" + os.Getenv("PATH"), "SANDBOX_PROVIDER=wasm", "PLIMSOLL_ADDR=127.0.0.1:0", "PLIMSOLL_METRICS_ADDR=off"}
	for setting, path := range files {
		env = append(env, setting+"="+path)
	}
	if hardened {
		env = append(env, "PLIMSOLL_HARDENED=1")
	}
	return env
}

// looseWarnings is, per setting, the warning lines of a daemon's log about its file.
func looseWarnings(t *testing.T, log string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, line := range strings.Split(log, "\n") {
		var rec struct {
			Level, Msg, Setting, Problems string
		}
		if json.Unmarshal([]byte(line), &rec) != nil || !strings.Contains(rec.Msg, "a file a setting names can be changed") {
			continue
		}
		if rec.Level != "WARN" {
			t.Fatalf("the file warning is logged at %s: %s", rec.Level, line)
		}
		out[rec.Setting] = append(out[rec.Setting], rec.Problems)
	}
	return out
}

// looseCases are the three ways a file can be changed by another user that each test
// applies to each file in turn.
var looseCases = []struct {
	name    string
	dir     bool // chmod the file's directory, not the file
	mode    os.FileMode
	problem string
}{
	{"group-writable file", false, 0o620, "has mode 0620, which its group can write"},
	{"others-writable file", false, 0o602, "has mode 0602, which every other user can write"},
	{"group-writable directory", true, 0o770, "has mode 0770, which lets its group replace what it holds"},
	{"others-writable directory", true, 0o707, "has mode 0707, which lets every other user replace what it holds"},
}

// TestHardenedRefusesAFileAnotherUserCanChange runs the real main() in hardened mode
// with each of the three files, in turn, group-writable, others-writable and in a
// directory its group or others can write: startup refuses, naming the setting and the
// mode, before the provider's readiness check and without quoting the file. With every
// file 0600 or group-readable (0640 in a 0750 directory), the rule says nothing (hardened
// mode still refuses the wasm provider for its own reasons, which this test ignores).
func TestHardenedRefusesAFileAnotherUserCanChange(t *testing.T) {
	for _, setting := range []string{settings.NameOf(settings.ClientsFile), settings.NameOf(settings.GrantsFile), settings.NameOf(settings.WithheldFile)} {
		for _, c := range looseCases {
			t.Run(setting+" "+c.name, func(t *testing.T) {
				files := modeFiles(t)
				target := files[setting]
				if c.dir {
					target = filepath.Dir(target)
				}
				setMode(t, target, c.mode)
				code, log := exitDaemon(t, modesEnv(files, true), 30*time.Second)
				want := "hardened mode refuses a file another user of this machine could change (" + setting + ": "
				if code == 0 || !strings.Contains(log, want) || !strings.Contains(log, c.problem) {
					t.Fatalf("exit %d, want a refusal naming %s and %q; log:\n%s", code, setting, c.problem, log)
				}
				if strings.Contains(log, "sandbox provider ready") || strings.Contains(log, "plimsolld listening") {
					t.Fatalf("the daemon got past the early hardened pass; log:\n%s", log)
				}
				if strings.Contains(log, modesLabel) || strings.Contains(log, `"token_sha256"`) {
					t.Fatalf("the refusal quotes a file's content; log:\n%s", log)
				}
				for other := range files {
					if other != setting && strings.Contains(log, "could change ("+other+": ") {
						t.Fatalf("%s refused although only %s is loose; log:\n%s", other, setting, log)
					}
				}
			})
		}
	}
	for name, m := range map[string][2]os.FileMode{"0600 files": {0o700, 0o600}, "group-readable files": {0o750, 0o640}} {
		t.Run("accepts "+name, func(t *testing.T) {
			files := modeFiles(t)
			for _, path := range files {
				setMode(t, path, m[1])
				setMode(t, filepath.Dir(path), m[0])
			}
			_, log := exitDaemon(t, modesEnv(files, true), 30*time.Second)
			if strings.Contains(log, "another user of this machine could change") {
				t.Fatalf("hardened mode refused a file nobody else can change; log:\n%s", log)
			}
		})
	}
}

// TestLooseFileWarnsOutsideHardenedMode runs the real main() outside hardened mode with
// each file loose in turn: the daemon starts and logs exactly one warning line for that
// file, naming the setting and the mode bits, never the file's content; group-readable
// files draw none.
func TestLooseFileWarnsOutsideHardenedMode(t *testing.T) {
	for _, setting := range []string{settings.NameOf(settings.ClientsFile), settings.NameOf(settings.GrantsFile), settings.NameOf(settings.WithheldFile)} {
		for _, c := range []int{0, 2} { // a file, and a directory
			c := looseCases[c]
			t.Run(setting+" "+c.name, func(t *testing.T) {
				files := modeFiles(t)
				target := files[setting]
				if c.dir {
					target = filepath.Dir(target)
				}
				setMode(t, target, c.mode)
				d := startDaemon(t, modesEnv(files, false), 60*time.Second)
				log := d.logText()
				d.stop(t, 30*time.Second)
				warned := looseWarnings(t, log)
				if len(warned[setting]) != 1 || !strings.Contains(warned[setting][0], c.problem) {
					t.Fatalf("want one warning for %s saying %q, got %q; log:\n%s", setting, c.problem, warned, log)
				}
				if len(warned) != 1 {
					t.Fatalf("warnings for files that are not loose: %q", warned)
				}
				if strings.Contains(log, modesLabel) || strings.Contains(log, `"token_sha256"`) {
					t.Fatalf("the warning quotes a file's content; log:\n%s", log)
				}
			})
		}
	}
	t.Run("group-readable files draw none", func(t *testing.T) {
		files := modeFiles(t)
		for _, path := range files {
			setMode(t, path, 0o640)
			setMode(t, filepath.Dir(path), 0o750)
		}
		d := startDaemon(t, modesEnv(files, false), 60*time.Second)
		log := d.logText()
		d.stop(t, 30*time.Second)
		if w := looseWarnings(t, log); len(w) != 0 {
			t.Fatalf("warnings for group-readable files: %q", w)
		}
	})
}

// TestUnsetAddressIsThisMachineOnly, by the decision of 2026-11-20: an unset
// PLIMSOLL_ADDR reads as 127.0.0.1:8746, and plimsolld -h says so.
func TestUnsetAddressIsThisMachineOnly(t *testing.T) {
	if got := settings.Addr.Get(func(string) string { return "" }); got != "127.0.0.1:8746" {
		t.Fatalf("unset PLIMSOLL_ADDR reads as %q, want 127.0.0.1:8746", got)
	}
	if h := helpText(); !strings.Contains(h, "(default 127.0.0.1:8746, this machine only)") {
		t.Fatalf("plimsolld -h does not state the unset address:\n%s", h)
	}
}

// TestOpenModeWithNoAddressServesLoopbackOnly runs the real main() in open mode (the wasm
// provider, PLIMSOLL_INSECURE=1, no token) with PLIMSOLL_ADDR unset: it starts, listens on
// 127.0.0.1:8746, answers there, and nothing answers on the machine's own address. It
// needs port 8746 free on this machine and skips otherwise.
func TestOpenModeWithNoAddressServesLoopbackOnly(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8746", "0.0.0.0:8746"} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Skipf("port 8746 is in use on this machine (%s): %v", addr, err)
		}
		_ = ln.Close()
	}
	d := startDaemon(t, []string{"PATH=" + os.Getenv("PATH"), "SANDBOX_PROVIDER=wasm", "PLIMSOLL_INSECURE=1", "PLIMSOLL_METRICS_ADDR=off"}, 30*time.Second)
	defer d.stop(t, 30*time.Second)
	if d.addr != "127.0.0.1:8746" {
		t.Fatalf("open mode with no address listened on %q, want 127.0.0.1:8746", d.addr)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://127.0.0.1:8746/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz on loopback answered %d", resp.StatusCode)
	}
	if machine := nonLoopbackIP(t); machine != "" {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(machine, "8746"), 2*time.Second)
		if err == nil {
			_ = c.Close()
			t.Fatalf("the daemon answered on the machine's own address %s:8746", machine)
		}
	} else {
		t.Log("this machine has no non-loopback address; only the loopback half was shown")
	}
}
