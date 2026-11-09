package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/internal/withheld"
)

const harness = "import random\n\ndef hidden_case(seed):\n    random.seed(seed)\n    return [random.random() for _ in range(8)]\n"

// fakeImages hands scanImages saved images built in memory, as the docker provider
// hands it docker save's output.
type fakeImages struct {
	images [][]byte
	err    error
}

func (f fakeImages) ImageArchives(_ context.Context, fn func(ref, id string, archive io.Reader) error) error {
	if f.err != nil {
		return f.err
	}
	for i, img := range f.images {
		if err := fn("img", "sha256:"+strings.Repeat(string(rune('a'+i)), 64), bytes.NewReader(img)); err != nil {
			return err
		}
	}
	return nil
}

// savedImage is an image archive with one layer holding the given files.
func savedImage(t *testing.T, files map[string]string) []byte {
	t.Helper()
	tarOf := func(members [][2]string) []byte {
		var b bytes.Buffer
		w := tar.NewWriter(&b)
		for _, m := range members {
			if err := w.WriteHeader(&tar.Header{Name: m[0], Mode: 0o644, Size: int64(len(m[1])), Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte(m[1])); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	var layer [][2]string
	for name, content := range files {
		layer = append(layer, [2]string{name, content})
	}
	return tarOf([][2]string{{"blobs/sha256/layer", string(tarOf(layer))}, {"blobs/sha256/config", `{"config":{}}`}})
}

// testSet withholds the harness file (refuse) and a seed (audit).
func testSet(t *testing.T) *withheld.Set {
	t.Helper()
	file := withheld.FileDigest([]byte(harness))
	seed := withheld.ValueDigest([]byte("q7Zk2mV9"))
	raw, err := json.Marshal(map[string]any{"version": withheld.Version, "mode": "refuse", "entries": []map[string]any{
		{"kind": "file", "sha256": hex.EncodeToString(file[:]), "label": "harness/sim.py"},
		{"kind": "value", "sha256": hex.EncodeToString(seed[:]), "length": 8, "label": "seeds.txt:1", "mode": "audit"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	set, err := withheld.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestScanImagesRefusesAnImageHoldingARefuseEntry(t *testing.T) {
	set := testSet(t)
	clean := savedImage(t, map[string]string{"app/main.py": "print(1)\n"})
	baked := savedImage(t, map[string]string{"usr/src/harness/sim.py": harness})
	err := scanImages(context.Background(), fakeImages{images: [][]byte{clean, baked}}, set)
	if err == nil || !strings.Contains(err.Error(), "harness/sim.py") {
		t.Fatalf("an image holding the harness: %v; want a refusal naming it", err)
	}
}

func TestScanImagesServesBesideAnAuditFindOrAClean(t *testing.T) {
	set := testSet(t)
	audit := savedImage(t, map[string]string{"app/config.py": "SEED = 'q7Zk2mV9'\n"})
	clean := savedImage(t, map[string]string{"app/main.py": "print(1)\n"})
	if err := scanImages(context.Background(), fakeImages{images: [][]byte{audit, clean}}, set); err != nil {
		t.Fatalf("an audit-mode find and a clean image: %v; want the daemon to serve", err)
	}
}

func TestScanImagesFailsWhenTheImagesCannotBeRead(t *testing.T) {
	set := testSet(t)
	if err := scanImages(context.Background(), fakeImages{err: errors.New("docker save failed")}, set); err == nil {
		t.Fatal("a failed docker save let the daemon serve")
	}
	if err := scanImages(context.Background(), fakeImages{images: [][]byte{[]byte("not a tar archive at all, but long enough to read")}}, set); err == nil {
		t.Fatal("an unreadable archive let the daemon serve")
	}
}

// zstd bytes are the same unreadable-layer fixture used in withheld/image_test.go.
func TestScanImagesKnownUnreadable(t *testing.T) {
	const id = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	zstd := string([]byte{0x28, 0xb5, 0x2f, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	img := savedImage(t, map[string]string{"lib/opaque.bin": zstd})
	for _, tc := range []struct {
		name, listID, reason     string
		size                     int
		configured, allow, audit bool
	}{
		{name: "unconfigured"},
		{name: "unlisted", configured: true},
		{name: "listed", configured: true, listID: id, reason: "archive_zstd", size: 18, allow: true},
		{name: "changed size", configured: true, listID: id, reason: "archive_zstd", size: 19},
		{name: "changed reason", configured: true, listID: id, reason: "archive_xz", size: 18},
		{name: "another image", configured: true, listID: "sha256:" + strings.Repeat("b", 64), reason: "archive_zstd", size: 18},
		{name: "audit only unlisted", configured: true, audit: true},
		{name: "audit only listed", configured: true, listID: id, reason: "archive_zstd", size: 18, allow: true, audit: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PLIMSOLL_WITHHELD_KNOWN_FILE", "")
			if tc.configured {
				images := []any{}
				if tc.listID != "" {
					images = append(images, map[string]any{"image_id": tc.listID, "files": []any{map[string]any{"path": "blobs/sha256/layer:lib/opaque.bin", "reason": tc.reason, "size": tc.size}}})
				}
				raw, err := json.Marshal(map[string]any{"version": 1, "images": images})
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "known.json")
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("PLIMSOLL_WITHHELD_KNOWN_FILE", path)
			}
			set := testSet(t)
			if tc.audit {
				sum := withheld.ValueDigest([]byte("q7Zk2mV9"))
				raw := fmt.Sprintf(`{"version":2,"mode":"audit","entries":[{"kind":"value","sha256":"%x","length":8,"label":"seed"}]}`, sum)
				var err error
				set, err = withheld.Parse([]byte(raw))
				if err != nil {
					t.Fatal(err)
				}
			}
			err := scanImages(context.Background(), fakeImages{images: [][]byte{img}}, set)
			if tc.allow {
				if err != nil {
					t.Fatalf("listed unreadable refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("unlisted unreadable file let the daemon serve")
			}
			for _, want := range []string{"img", id, "lib/opaque.bin", "plimsoll-withheld known-unreadable"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("refusal %q does not name %q", err, want)
				}
			}
		})
	}
}

func TestScanImagesUnknownNameIsEscaped(t *testing.T) {
	t.Setenv("PLIMSOLL_WITHHELD_KNOWN_FILE", "")
	img := savedImage(t, map[string]string{"bad\n\x1b.bin": string([]byte{0x28, 0xb5, 0x2f, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})})
	err := scanImages(context.Background(), fakeImages{images: [][]byte{img}}, testSet(t))
	if err == nil {
		t.Fatal("unlisted control-character name let the daemon serve")
	}
	if strings.ContainsAny(err.Error(), "\n\x1b") || !strings.Contains(err.Error(), `bad\x0a\x1b.bin`) {
		t.Fatalf("unsafe or missing file name: %q", err)
	}
}

func TestScanImagesBadKnownListRefusesStartup(t *testing.T) {
	for _, bad := range []string{"missing", `{"version":1,"images":null}`} {
		path := filepath.Join(t.TempDir(), "known.json")
		if bad != "missing" {
			if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
				t.Fatal(err)
			}
		}
		t.Setenv("PLIMSOLL_WITHHELD_KNOWN_FILE", path)
		err := scanImages(context.Background(), fakeImages{images: [][]byte{savedImage(t, map[string]string{"main.py": "print(1)"})}}, testSet(t))
		if err == nil {
			t.Fatal("bad configured list let startup serve")
		}
	}
}

func TestScanShellQuote(t *testing.T) {
	for _, value := range []string{"normal.json", "a 'quote'.json", `$(printf injected); file`, "bad\n\x1b"} {
		out, err := exec.Command("sh", "-c", "printf '%s' "+scanShellQuote(value)).Output()
		if err != nil || string(out) != withheld.CleanWhere(value) {
			t.Fatalf("quote %q: %q %v", value, out, err)
		}
	}
}
