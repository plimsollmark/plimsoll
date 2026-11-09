package withheld

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const knownTestID = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestKnownParserAndMatching(t *testing.T) {
	good := fmt.Sprintf(`{"version":1,"images":[{"image_id":%q,"files":[{"path":"layer:file","reason":"archive_zstd","size":8}]}]}`, knownTestID)
	k, err := ParseKnown([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	u := Unreadable{Key: "layer:file", Where: "layer:file", Reason: BoundZstd, Size: 8}
	if got := k.Unknown(knownTestID, []Unreadable{u}); len(got) != 0 {
		t.Fatalf("known file unknown: %v", got)
	}
	for _, change := range []string{"id", "path", "reason", "size"} {
		id, v := knownTestID, u
		switch change {
		case "id":
			id = "sha256:" + strings.Repeat("b", 64)
		case "path":
			v.Key = "other"
		case "reason":
			v.Reason = BoundXZ
		case "size":
			v.Size++
		}
		if len(k.Unknown(id, []Unreadable{v})) != 1 {
			t.Errorf("changed %s was accepted", change)
		}
	}
	round, err := k.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := ParseKnown(round)
	if err != nil {
		t.Fatal(err)
	}
	again, err := loaded.Marshal()
	if err != nil || !bytes.Equal(round, again) {
		t.Fatalf("unstable round trip: %v", err)
	}
	for name, raw := range map[string]string{
		"unknown field":   strings.Replace(good, `"size":8`, `"size":8,"typo":1`, 1),
		"wrong case":      strings.Replace(good, `"size":8`, `"Size":8`, 1),
		"duplicate field": strings.Replace(good, `"size":8`, `"size":8,"size":9`, 1),
		"missing size":    strings.Replace(good, `,"size":8`, "", 1),
		"null size":       strings.Replace(good, `"size":8`, `"size":null`, 1),
		"negative size":   strings.Replace(good, `"size":8`, `"size":-1`, 1),
		"fraction":        strings.Replace(good, `"size":8`, `"size":8.5`, 1),
		"overflow":        strings.Replace(good, `"size":8`, `"size":9223372036854775808`, 1),
		"unknown reason":  strings.Replace(good, "archive_zstd", "nonsense", 1),
		"invalid id":      strings.Replace(good, knownTestID, "tag:latest", 1),
		"null images":     `{"version":1,"images":null}`,
		"null files":      fmt.Sprintf(`{"version":1,"images":[{"image_id":%q,"files":null}]}`, knownTestID),
		"trailing data":   good + " {}",
		"duplicate file":  strings.Replace(good, `"size":8}`, `"size":8},{"path":"layer:file","reason":"archive_zstd","size":8}`, 1),
		"duplicate image": fmt.Sprintf(`{"version":1,"images":[{"image_id":%q,"files":[]},{"image_id":%q,"files":[]}]}`, knownTestID, knownTestID),
		"control path":    strings.Replace(good, "layer:file", `layer:bad\nfile`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseKnown([]byte(raw)); err == nil {
				t.Fatalf("accepted %s", raw)
			}
		})
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "known.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte(" "), MaxKnownFileBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKnown(path); err == nil {
		t.Fatal("accepted oversized list")
	}
}

func TestImageUnreadableEvidence(t *testing.T) {
	s := setOf(t, ModeRefuse, nil, value(harnessSeed, "seed", ""))
	zstd := string(unb64(simPyZst))
	archive := layerTarOf(t, [2]string{"blobs/z", zstd}, [2]string{"blobs/l", string(layerTarOf(t, [2]string{"lib/opaque", zstd}, [2]string{"lib/big", strings.Repeat("\x00", MaxImageFileBytes+1)}))})
	res := scanImage(t, s, archive)
	if len(res.Unreadable) != 3 {
		t.Fatalf("unreadable %+v", res.Unreadable)
	}
	for i, want := range []Unreadable{
		{Key: "blobs/z", Where: "blobs/z", Reason: BoundZstd, Size: int64(len(zstd))},
		{Key: "blobs/l:lib/opaque", Where: "blobs/l:lib/opaque", Reason: BoundZstd, Size: int64(len(zstd))},
		{Key: "blobs/l:lib/big", Where: "blobs/l:lib/big", Reason: BoundImageFileBytes, Size: MaxImageFileBytes + 1},
	} {
		if res.Unreadable[i] != want {
			t.Errorf("got %+v, want %+v", res.Unreadable[i], want)
		}
	}
	// The same display text must never acknowledge two different raw file names.
	a, b := "bad\n\x1b", `bad\x0a\x1b`
	if CleanWhere(a) != CleanWhere(b) || KnownPath(a) == KnownPath(b) {
		t.Fatal("unsafe name key collision")
	}
	res = scanImage(t, s, layerTarOf(t, [2]string{a, zstd}, [2]string{b, zstd}))
	k := NewKnown()
	if err := k.Set(knownTestID, res.Unreadable[:1]); err != nil {
		t.Fatal(err)
	}
	if len(k.Unknown(knownTestID, res.Unreadable)) != 1 {
		t.Fatal("escaped name acknowledged another file")
	}
	if _, err := s.ScanImage(context.Background(), bytes.NewReader(layerTarOf(t, [2]string{"same", zstd}, [2]string{"same", zstd}))); err == nil {
		t.Fatal("duplicate unreadable archive path accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ScanImage(ctx, bytes.NewReader(layerTarOf(t, [2]string{"z", zstd}))); err == nil {
		t.Fatal("canceled zstd scan accepted")
	}
}
