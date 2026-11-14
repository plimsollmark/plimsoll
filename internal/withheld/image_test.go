package withheld

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"slices"
	"strings"
	"testing"
)

const (
	harnessSource = "import random\n\ndef hidden_case(seed):\n    random.seed(seed)\n    return [random.random() for _ in range(8)]\n"
	harnessSeed   = "q7Zk2mV9"
)

// tarOf is a tar holding files in order; a name ending in / is a directory.
func layerTarOf(t *testing.T, files ...[2]string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, f := range files {
		h := &tar.Header{Name: f[0], Mode: 0o644, Size: int64(len(f[1])), Typeflag: tar.TypeReg}
		if strings.HasSuffix(f[0], "/") {
			h = &tar.Header{Name: f[0], Mode: 0o755, Typeflag: tar.TypeDir}
		}
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := w.Write([]byte(f[1])); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func layerGzipOf(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// savedImage is an image archive as docker save writes an OCI layout: a first layer with
// the harness, a second (gzip) layer that deletes it and adds the app, the configuration
// with the seed in its environment, and the index.
func savedImage(t *testing.T) []byte {
	l1 := layerTarOf(t, [2]string{"usr/src/harness/", ""}, [2]string{"usr/src/harness/sim.py", harnessSource}, [2]string{"etc/hostname", "box\n"})
	l2 := layerGzipOf(t, layerTarOf(t, [2]string{"usr/src/harness/.wh.sim.py", ""}, [2]string{"app/main.py", "print('hello')\n"}))
	cfg := `{"architecture":"amd64","config":{"Env":["PATH=/usr/bin","TASK_SEED=` + harnessSeed + `"]},"history":[{"created_by":"COPY harness /usr/src/harness"}]}`
	return layerTarOf(t,
		[2]string{"blobs/sha256/l1", string(l1)},
		[2]string{"blobs/sha256/l2", string(l2)},
		[2]string{"blobs/sha256/cfg", cfg},
		[2]string{"index.json", `{"schemaVersion":2,"manifests":[]}`},
		[2]string{"oci-layout", `{"imageLayoutVersion":"1.0.0"}`})
}

func scanImage(t *testing.T, s *Set, archive []byte) ImageResult {
	t.Helper()
	res, err := s.ScanImage(context.Background(), bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestScanImageFindsAFileALaterLayerDeletes(t *testing.T) {
	s := setOf(t, ModeRefuse, nil, file(harnessSource, "harness/sim.py", ""))
	res := scanImage(t, s, savedImage(t))
	if got := labels(res.Found); !slices.Equal(got, []string{"harness/sim.py"}) {
		t.Fatalf("found %v, want the harness file (it is in the first layer's bytes though the second deletes it)", got)
	}
	if want := "blobs/sha256/l1:usr/src/harness/sim.py"; !slices.Contains(res.Found[0].Where, want) {
		t.Fatalf("found at %v, want %s", res.Found[0].Where, want)
	}
	if res.Layers != 2 || len(res.Incomplete) != 0 {
		t.Fatalf("layers %d, incomplete %v; want 2 layers read whole", res.Layers, res.Incomplete)
	}
}

func TestScanImageFindsAValueInTheConfigurationAndInAGzipLayer(t *testing.T) {
	s := setOf(t, ModeAudit, nil, value(harnessSeed, "seeds.txt:1", ""))
	archive := savedImage(t)
	res := scanImage(t, s, archive)
	if len(res.Found) != 1 || !slices.Contains(res.Found[0].Where, "blobs/sha256/cfg") {
		t.Fatalf("found %+v, want the seed in the image configuration's environment", res.Found)
	}
	// The same seed in a file of a gzip layer.
	l := layerGzipOf(t, layerTarOf(t, [2]string{"app/config.py", "SEED = '" + harnessSeed + "'\n"}))
	res = scanImage(t, s, layerTarOf(t, [2]string{"blobs/sha256/l3", string(l)}))
	if len(res.Found) != 1 || !slices.Contains(res.Found[0].Where, "blobs/sha256/l3:app/config.py") {
		t.Fatalf("found %+v, want the seed in the gzip layer's app/config.py", res.Found)
	}
}

func TestScanImageOfACleanImage(t *testing.T) {
	s := setOf(t, ModeRefuse, nil, file("something else entirely, long enough to be a file\n", "other.py", ""), value("Zx81mQ4w", "seeds.txt:1", ""))
	res := scanImage(t, s, savedImage(t))
	if len(res.Found) != 0 || len(res.Incomplete) != 0 {
		t.Fatalf("found %+v, incomplete %v in a clean image", res.Found, res.Incomplete)
	}
	// Files: three of the first layer's... two regular files, two of the second, the
	// configuration, the index and oci-layout.
	if res.Layers != 2 || res.Files != 7 {
		t.Fatalf("read %d layers and %d files, want 2 and 7", res.Layers, res.Files)
	}
}

func TestScanImageReportsWhatItCannotRead(t *testing.T) {
	s := setOf(t, ModeRefuse, nil, value(harnessSeed, "seeds.txt:1", ""))
	zstd := string([]byte{0x28, 0xb5, 0x2f, 0xfd, 0, 0, 0, 0})
	big := strings.Repeat("\x00", MaxImageFileBytes) + harnessSeed // the seed past the bound is not read
	res := scanImage(t, s, layerTarOf(t, [2]string{"blobs/sha256/z", zstd}, [2]string{"blobs/sha256/l", string(layerTarOf(t, [2]string{"data/big.bin", big}))}))
	want := []Incomplete{{Where: "blobs/sha256/z", Bound: BoundZstd}, {Where: "blobs/sha256/l:data/big.bin", Bound: BoundImageFileBytes}}
	if !slices.Equal(res.Incomplete, want) {
		t.Fatalf("incomplete %v, want %v", res.Incomplete, want)
	}
	if len(res.Found) != 0 {
		t.Fatalf("found %+v past the bound", res.Found)
	}
	if !strings.Contains(BoundImageFileBytes.Text(), "64 MiB") {
		t.Fatalf("the bound's text %q does not state its size", BoundImageFileBytes.Text())
	}
}

func TestScanImageRefusesAnArchiveThatIsNotOne(t *testing.T) {
	s := setOf(t, ModeRefuse, nil, value(harnessSeed, "seeds.txt:1", ""))
	if _, err := s.ScanImage(context.Background(), strings.NewReader("not a tar at all, just text that is long enough")); err == nil {
		t.Fatal("a non-tar archive scanned without an error")
	}
}

// Places states each Where of a find or an incomplete part apart, the layer, the path and
// the part, as written, so a report need not split the Where string (a layer named
// "a:b" and one named "a" holding "b:..." would read alike).
func TestScanImagePlacesEachWhere(t *testing.T) {
	s := setOf(t, ModeAudit, nil, value(harnessSeed, "seeds.txt:1", ""), file(harnessSource, "harness/sim.py", ""))
	res := scanImage(t, s, savedImage(t))
	for where, want := range map[string]Place{
		"blobs/sha256/l1:usr/src/harness/sim.py": {Layer: "blobs/sha256/l1", Path: "usr/src/harness/sim.py", Part: PartContent},
		"blobs/sha256/cfg":                       {Path: "blobs/sha256/cfg", Part: PartContent},
	} {
		if got, ok := res.Places[where]; !ok || got != want {
			t.Errorf("Places[%q] = %+v (%v), want %+v", where, got, ok, want)
		}
	}
	zstd := string([]byte{0x28, 0xb5, 0x2f, 0xfd, 0, 0, 0, 0})
	var lb bytes.Buffer
	w := tar.NewWriter(&lb)
	for _, h := range []*tar.Header{
		{Name: "opt/" + harnessSeed + "/x", Mode: 0o644, Typeflag: tar.TypeReg},
		{Name: "opt/link", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "/srv/" + harnessSeed},
	} {
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	res = scanImage(t, s, layerTarOf(t, [2]string{"blobs/sha256/z", zstd}, [2]string{"blobs/sha256/a:b", lb.String()}))
	for where, want := range map[string]Place{
		"blobs/sha256/z": {Layer: "blobs/sha256/z", Part: PartContent},
		"blobs/sha256/a:b:opt/" + harnessSeed + "/x (path)": {Layer: "blobs/sha256/a:b", Path: "opt/" + harnessSeed + "/x", Part: PartPath},
		"blobs/sha256/a:b:opt/link (link target)":           {Layer: "blobs/sha256/a:b", Path: "opt/link", Part: PartLinkTarget},
	} {
		if got, ok := res.Places[where]; !ok || got != want {
			t.Errorf("Places[%q] = %+v (%v), want %+v", where, got, ok, want)
		}
	}
}
