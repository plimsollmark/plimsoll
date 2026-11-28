package sandbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox/internal/nativehelper"
)

// Other builds of the native helper, for the startup checks' refusals. The build pinned
// 1b403142 (file contract 5) is the one before the identity command, and it is the same size as
// the build after it, so a check that can only see the size could not tell them apart.

// earlierHelperBlob and earlierHelperSHA256 name that build: its git object (committed as
// sandbox/internal/nativehelper/program/plimsoll-helper_amd64 in b170f37ee) and its SHA-256.
const (
	earlierHelperBlob   = "89931b53a654b2dd19accd30ea94f9d08af4472f"
	earlierHelperSHA256 = "1b403142dc274dd62c6c6eeba429e26833bb7c792ccf79687fb469b48e2d137a"
)

// EarlierHelperBuild is the build pinned 1b403142, read from this checkout's git history; false
// when the history does not hold it (a copy made without that commit).
func EarlierHelperBuild(t *testing.T) ([]byte, bool) {
	t.Helper()
	b, err := exec.Command("git", "cat-file", "blob", earlierHelperBlob).Output()
	if err != nil {
		t.Logf("the earlier helper build is not in this checkout's history (%v)", err)
		return nil, false
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != earlierHelperSHA256 {
		t.Fatalf("git object %s has sha256 %x, not the build pinned %s", earlierHelperBlob, sum, earlierHelperSHA256)
	}
	return b, true
}

// SameSizeOtherHelperBuild is this build with one byte of the identity it carries changed: the
// same size, a working program, that reports another build.
func SameSizeOtherHelperBuild(t *testing.T) []byte {
	t.Helper()
	prog, err := nativehelper.Program("amd64")
	if err != nil {
		t.Fatal(err)
	}
	id, err := nativehelper.Identity()
	if err != nil {
		t.Fatal(err)
	}
	hexID := []byte(strings.TrimPrefix(id, "inputs "))
	if bytes.Count(prog, hexID) != 1 {
		t.Fatalf("the committed helper carries its identity %d times; want once", bytes.Count(prog, hexID))
	}
	other := bytes.Clone(hexID)
	if other[0] == '0' {
		other[0] = '1'
	} else {
		other[0] = '0'
	}
	return bytes.Replace(prog, hexID, other, 1)
}

// ImageWithFile builds a throwaway image FROM base holding content at /plimsoll-test-file
// (root's), then steps (Dockerfile lines, run as root), and removes it after the test.
func ImageWithFile(t *testing.T, base string, content []byte, steps string) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("builds a docker image")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	tag := throwawayTag("helper-build")
	build := exec.Command("docker", "build", "-q", "-t", tag, "-f", "-", dir)
	build.Stdin = strings.NewReader("FROM " + base + "\nUSER root\nCOPY f /plimsoll-test-file\n" + steps)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build an image holding another helper build: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", tag).Run() })
	return tag
}
