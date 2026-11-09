package main

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/internal/withheld"
)

// The fake docker accepts only save by the inspected ID. No test starts Docker.
func knownCLI(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	setPath := filepath.Join(dir, "set.json")
	knownPath := filepath.Join(dir, "known.json")
	write(t, filepath.Join(dir, "seeds"), "731904\n")
	var set bytes.Buffer
	if _, err := run([]string{"build", "-mode", "audit", "-values", filepath.Join(dir, "seeds")}, &set, io.Discard); err != nil {
		t.Fatal(err)
	}
	write(t, setPath, set.String())
	flags := []byte{0, 4}
	xz := append([]byte("\xfd7zXZ\x00"), flags...)
	xz = binary.LittleEndian.AppendUint32(xz, crc32.ChecksumIEEE(flags))
	archive := filepath.Join(dir, "image.tar")
	imageArchive(t, archive, map[string]string{"opt/data.xz": string(xz) + "the rest of the stream"}, `{}`)
	script := `#!/bin/sh
if [ "$1" = image ]; then
 printf '%s\n' "$KNOWN_TEST_ID"
elif [ "$1" = save ] && [ "$2" = "$KNOWN_TEST_ID" ]; then
 cat "$KNOWN_TEST_ARCHIVE"
 exit "${KNOWN_TEST_SAVE_EXIT:-0}"
else
 exit 99
fi
`
	docker := filepath.Join(dir, "docker")
	write(t, docker, script)
	if err := os.Chmod(docker, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("KNOWN_TEST_ID", "sha256:"+strings.Repeat("a", 64))
	t.Setenv("KNOWN_TEST_ARCHIVE", archive)
	t.Setenv("KNOWN_TEST_SAVE_EXIT", "0")
	return setPath, knownPath, archive
}

func TestKnownUnreadableCommandRoundTrip(t *testing.T) {
	set, path, archive := knownCLI(t)
	args := []string{"known-unreadable", "-set", set, "-known", path, "image:latest"}
	call := func() {
		t.Helper()
		var out bytes.Buffer
		if code, err := run(args, &out, io.Discard); code != 0 || err != nil {
			t.Fatalf("known-unreadable: exit %d: %v", code, err)
		}
		if !strings.Contains(out.String(), "opt/data.xz") {
			t.Fatalf("missing file: %s", out.String())
		}
	}
	call()
	k, err := withheld.LoadKnown(path)
	if err != nil {
		t.Fatal(err)
	}
	if k.Images() != 1 {
		t.Fatalf("images: %d", k.Images())
	}
	s, err := withheld.Load(set)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res, err := s.ScanImage(t.Context(), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Unreadable) != 1 || len(k.Unknown(os.Getenv("KNOWN_TEST_ID"), res.Unreadable)) != 0 {
		t.Fatalf("not round-tripped: %+v", res.Unreadable)
	}
	t.Setenv("KNOWN_TEST_ID", "sha256:"+strings.Repeat("b", 64))
	call()
	k, err = withheld.LoadKnown(path)
	if err != nil || k.Images() != 2 {
		t.Fatalf("lost another image: %v", err)
	}
	// Regenerating one image replaces its list and retains the other image.
	imageArchive(t, archive, map[string]string{}, `{}`)
	if code, err := run(args, io.Discard, io.Discard); code != 0 || err != nil {
		t.Fatal(code, err)
	}
	k, err = withheld.LoadKnown(path)
	if err != nil || k.Images() != 2 {
		t.Fatal("lost images", err)
	}
	if len(k.Unknown("sha256:"+strings.Repeat("b", 64), res.Unreadable)) != 1 || len(k.Unknown("sha256:"+strings.Repeat("a", 64), res.Unreadable)) != 0 {
		t.Fatal("wrong image replaced")
	}
}

func TestKnownUnreadableCommandFailurePreservesList(t *testing.T) {
	set, path, archive := knownCLI(t)
	args := []string{"known-unreadable", "-set", set, "-known", path, "image"}
	if _, err := run(args, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"lock", "save failure", "bad archive", "bad id", "bad list"} {
		t.Run(mode, func(t *testing.T) {
			switch mode {
			case "lock":
				if err := os.Mkdir(path+".lock", 0700); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(path + ".lock")
			case "save failure":
				t.Setenv("KNOWN_TEST_SAVE_EXIT", "1")
			case "bad archive":
				write(t, archive, "broken archive enough bytes to reject")
				defer imageArchive(t, archive, map[string]string{}, `{}`)
			case "bad id":
				t.Setenv("KNOWN_TEST_ID", "--output=elsewhere")
			case "bad list":
				write(t, path, `{"version":1,"images":null}`)
				defer write(t, path, string(before))
			}
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := run(args, io.Discard, io.Discard); err == nil {
				t.Fatal("failed writer succeeded")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(original, after) {
				t.Fatal("failed writer changed list", err)
			}
		})
	}
}

func TestKnownUnreadableConcurrentWriterRefuses(t *testing.T) {
	set, path, _ := knownCLI(t)
	ready := filepath.Join(t.TempDir(), "ready")
	release := ready + ".release"
	t.Setenv("KNOWN_TEST_READY", ready)
	t.Setenv("KNOWN_TEST_RELEASE", release)
	// Hold a real writer inside docker save, after it acquired the list lock.
	docker := filepath.Join(strings.Split(os.Getenv("PATH"), string(os.PathListSeparator))[0], "docker")
	body, err := os.ReadFile(docker)
	if err != nil {
		t.Fatal(err)
	}
	script := strings.Replace(string(body), ` cat "$KNOWN_TEST_ARCHIVE"`, ` touch "$KNOWN_TEST_READY"
 while [ ! -e "$KNOWN_TEST_RELEASE" ]; do sleep 0.01; done
 cat "$KNOWN_TEST_ARCHIVE"`, 1)
	write(t, docker, script)
	args := []string{"known-unreadable", "-set", set, "-known", path, "image"}
	done := make(chan error, 1)
	go func() { _, err := run(args, io.Discard, io.Discard); done <- err }()
	defer func() {
		write(t, release, "")
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first writer did not reach save")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if code, err := run(args, io.Discard, io.Discard); code != 2 || err == nil || !strings.Contains(err.Error(), "cannot lock") {
		t.Fatalf("concurrent writer: %d %v", code, err)
	}
}
