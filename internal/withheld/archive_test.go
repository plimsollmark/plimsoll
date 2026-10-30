package withheld

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// The hackathon's simulator, the harness file the archive tests withhold.
const simPy = "import numpy as np\n\ndef step(state, u, dt):\n    return state + dt * (u - 0.3 * state)\n"

// Archives made by Python 3's bz2, tarfile, zipfile and lzma modules (Go has no
// writer for them): simPy compressed by bz2; harness/sim.py in a .tar.bz2 and in a zip
// whose member is bzip2-compressed; simPy compressed by xz.
const (
	simPyBz2    = "QlpoOTFBWSZTWXsEZpYAABpZgEAQQH9IECcj3iAgAEECmNJhpNDJmoU0aANAAB4q6DhNNLfastmjqWX9LRDGnB+l7c4DcwMck0X6k5AnZNh8jNEGJZlgXiUoQnav4u5IpwoSD2CM0sA="
	simPyTarBz2 = "QlpoOTFBWSZTWTEVbccAAIfbhMyQQH//EBAAZ2PeIAAICAggAJSGhKbU2p6aE09RtJ6mR6hk/UgklRmSNqZNMTEMjRpgzn2ZgQPiECKMq5CyXk8gySDgE2V0HJqM7vej5Rxl+ds/5VfdDihQYmGz2MBHcgIUQh3pwzZ58Ta2lczF+sEKaBC1OXqKx3USaOQyc7Lsa83JucFrqeFPC03hIme53Ttt1JkkG4u5IpwoSBiKtuOA"
	simPyZipBz2 = "UEsDBC4AAAAMAAAAXF30klEZaAAAAFYAAAAOAAAAaGFybmVzcy9zaW0ucHlCWmg5MUFZJlNZewRmlgAAGlmAQBBAf0gQJyPeICAAQQKY0mGk0MmahTRoA0AAHiroOE00t9qy2aOpZf0tEMacH6XtzgNzAxyTRfqTkCdk2HyM0QYlmWBeJShCdq/i7kinChIPYIzSwFBLAQIuAy4AAAAMAAAAXF30klEZaAAAAFYAAAAOAAAAAAAAAAAAAACAAQAAAABoYXJuZXNzL3NpbS5weVBLBQYAAAAAAQABADwAAACUAAAAAAA="
	simPyXz     = "/Td6WFoAAATm1rRGAgAhARYAAAB0L+Wj4ABVAE5dADSbSme4Ujxz6pqAyg1MRxIGFIfi/bwHoBmk5G+eM/QiywWfCgZjUkBtPD82y8+pQpjYUHliVkOk1RDExfSpTde2WKsXqq2wvBW3SDYyoAAAAIeD9QDJx+BNAAFqVsfCnD0ftvN9AQAAAAAEWVo="
	// one bzip2 stream of the byte "a"; concatenated, the shortest blocks a stream holds
	tinyBz2 = "QlpoOTFBWSZTWRmTm2sAAAABACAAIAAhGEaC7kinChIDMnNtYA=="
	// Archives the scan recognizes and cannot read: a zip of harness/sim.py (simPy) and
	// seeds.txt ("seeds\n100001\n731904\n") deflated and encrypted with the traditional
	// PKWARE cipher under the password "pw" (written by a script, since neither Go nor
	// Python writes one; `unzip -P pw` and Python's zipfile both decrypt it); the same two
	// files in a zip of LZMA members (method 14), by Python's zipfile; simPy compressed by
	// the zstd command.
	encryptedZip = "UEsDBBQAAQAIAAAAAAD0klEZVwAAAFYAAAAOAAAAaGFybmVzcy9zaW0ucHnj3qUVUttClf71HaLLfmgwFfMjrYlYQKn/T5Ie9c7pUgczxjepqoyqnCXsyvro2NBInH6lgU9BV/XjM+i7DBIFrreqD9MWkrJbdxaLs/vsThmq8mCAn91QSwMEFAABAAgAAAAAAF1xg+QgAAAAFAAAAAkAAABzZWVkcy50eHTy7tQQqmElhcItSuhK2x321W06TsPw6MY2xiZvd1+7CFBLAQIUABQAAQAIAAAAAAD0klEZVwAAAFYAAAAOAAAAAAAAAAAAAAAAAAAAAABoYXJuZXNzL3NpbS5weVBLAQIUABQAAQAIAAAAAABdcYPkIAAAABQAAAAJAAAAAAAAAAAAAAAAAIMAAABzZWVkcy50eHRQSwUGAAAAAAIAAgBzAAAAygAAAAAA"
	lzmaZip      = "UEsDBD8AAgAOACKKXF30klEZXgAAAFYAAAAOAAAAaGFybmVzcy9zaW0ucHkJBAUAXQAAgAAANJtKZ7hSPHPqmoDKDUxHEgYUh+L9vAegGaTkb54z9CLLBZ8KBmNSQG08PzbLz6lCmNhQeWJWQ6TVEMTF9KlN17ZYqxeqrbC8FbdI6cvwH/+jGYAAUEsDBD8AAgAOACKKXF1dcYPkJgAAABQAAAAJAAAAc2VlZHMudHh0CQQFAF0AAIAAADmZbMh2NYhCW/fC4XE2y9+Fp2d6yXwb/8qIAABQSwECPwM/AAIADgAiilxd9JJRGV4AAABWAAAADgAAAAAAAAAAAAAAgAEAAAAAaGFybmVzcy9zaW0ucHlQSwECPwM/AAIADgAiilxdXXGD5CYAAAAUAAAACQAAAAAAAAAAAAAAgAGKAAAAc2VlZHMudHh0UEsFBgAAAAACAAIAcwAAANcAAAAAAA=="
	simPyZst     = "KLUv/SRWNQIAssQOEaDtoEll2cUYVV993MI8VTGiG8SROS+n4OK9Pv4nabP8/02h1wk94VY9QeSeZ7x24/tUr9HR95YwuhYCAHZOuL7mHr3wtQI="
	// Python 3's zlib.compress(b"731904"): 14 bytes, shorter than the 18 of any other
	// archive (Go's writer adds an empty block and writes 18).
	seedZlib = "eJwzNza0NDABAARSATk="
)

// beforeDirectory is a zip cut short where its central directory starts (the offset
// its end record states), as a download or a copy cut off at the end leaves it.
func beforeDirectory(z []byte) []byte {
	return z[:binary.LittleEndian.Uint32(z[len(z)-6:])]
}

// sevenZip is a 7z signature header (no 7z writer here): the signature, version 0.4, and
// the start header's CRC-32 over a next header's offset, size and CRC.
func sevenZip() []byte {
	h := append([]byte("7z\xbc\xaf\x27\x1c"), 0, 4, 0, 0, 0, 0)
	h = binary.LittleEndian.AppendUint64(h, 128)
	h = binary.LittleEndian.AppendUint64(h, 40)
	h = binary.LittleEndian.AppendUint32(h, 0x1234)
	binary.LittleEndian.PutUint32(h[8:], crc32.ChecksumIEEE(h[12:32]))
	return append(h, make([]byte, 168)...)
}

// rar5 and rar4 are each format's signature and main archive header (no rar writer
// here): RAR 5's CRC-32, header size 3, type 1, flags 0, archive flags 0; RAR 4's
// header CRC, type 0x73, flags 0, size 13 and its reserved fields.
func rar5() []byte {
	h := append([]byte("Rar!\x1a\x07\x01\x00"), 0, 0, 0, 0, 3, 1, 0, 0)
	binary.LittleEndian.PutUint32(h[8:], crc32.ChecksumIEEE(h[12:]))
	return append(h, make([]byte, 64)...)
}

func rar4() []byte { return rar4Sized(13) }

// rar4Sized is rar4 with a main header of size bytes (a long one holds a comment).
func rar4Sized(size int) []byte {
	h := append([]byte("Rar!\x1a\x07\x00"), 0, 0, 0x73, 0, 0)
	h = binary.LittleEndian.AppendUint16(h, uint16(size))
	h = append(h, make([]byte, size-7)...)
	binary.LittleEndian.PutUint16(h[7:], uint16(crc32.ChecksumIEEE(h[9:])))
	return append(h, make([]byte, 64)...)
}

// tarTyped is a tar header for a member of typ holding content, its checksum valid,
// with content and the padding after it.
func tarTyped(typ byte, name, content string) []byte {
	h := tarHeader(name, len(content))
	h[156] = typ
	resum(h)
	return append(append(h, content...), make([]byte, (512-len(content)%512)%512)...)
}

func unb64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// base64Lines is data as the base64 command writes it: wrapped at 76 columns.
func base64Lines(data []byte) string {
	return wrap(base64.StdEncoding.EncodeToString(data), 76, "\n") + "\n"
}

type member struct{ name, content string }

func tarOf(ms ...member) []byte {
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, m := range ms {
		if err := w.WriteHeader(&tar.Header{Name: m.name, Mode: 0o644, Size: int64(len(m.content)), Typeflag: tar.TypeReg}); err != nil {
			panic(err)
		}
		if _, err := io.WriteString(w, m.content); err != nil {
			panic(err)
		}
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return b.Bytes()
}

func gzipOf(data []byte) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write(data)
	w.Close()
	return b.Bytes()
}

func deflateOf(data []byte) []byte {
	var b bytes.Buffer
	w, _ := flate.NewWriter(&b, flate.BestCompression)
	w.Write(data)
	w.Close()
	return b.Bytes()
}

// zlibOf is data as Python's zlib.compress writes it at level (-1, its default, is 6):
// the header 78 9c at the default, 78 01 at 1, 78 da at 9.
func zlibOf(data []byte, level int) []byte {
	var b bytes.Buffer
	w, err := zlib.NewWriterLevel(&b, level)
	if err != nil {
		panic(err)
	}
	w.Write(data)
	w.Close()
	return b.Bytes()
}

// zipOf is a zip from Go's writer, which puts each member's sizes in a data
// descriptor after it, as streaming writers do.
func zipOf(method uint16, ms ...member) []byte {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, m := range ms {
		f, err := w.CreateHeader(&zip.FileHeader{Name: m.name, Method: method})
		if err != nil {
			panic(err)
		}
		io.WriteString(f, m.content)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return b.Bytes()
}

// rawZip is a zip written byte by byte, as zip and Python write one to a file: sizes in
// each local header, offsets from the archive's start (so a prefix shifts them all, as
// cat stub archive.zip does), and in zip64 form the 32-bit sizes, offsets and counts
// replaced by a zip64 extra field and end record.
func rawZip(prefix []byte, zip64 bool, ms ...member) []byte {
	le := binary.LittleEndian
	var b, cd bytes.Buffer
	for _, m := range ms {
		method, body := uint16(0), []byte(m.content)
		if strings.HasSuffix(m.name, ".z") {
			method, body = 8, deflateOf(body)
		}
		crc := crc32.ChecksumIEEE([]byte(m.content))
		off := b.Len()
		h := make([]byte, 30)
		copy(h, "PK\x03\x04")
		le.PutUint16(h[4:], 20)
		le.PutUint16(h[8:], method)
		le.PutUint32(h[14:], crc)
		le.PutUint32(h[18:], uint32(len(body)))
		le.PutUint32(h[22:], uint32(len(m.content)))
		le.PutUint16(h[26:], uint16(len(m.name)))
		b.Write(h)
		b.WriteString(m.name)
		b.Write(body)
		c := make([]byte, 46)
		copy(c, "PK\x01\x02")
		le.PutUint16(c[4:], 20)
		le.PutUint16(c[6:], 20)
		le.PutUint16(c[10:], method)
		le.PutUint32(c[16:], crc)
		le.PutUint32(c[20:], uint32(len(body)))
		le.PutUint32(c[24:], uint32(len(m.content)))
		le.PutUint16(c[28:], uint16(len(m.name)))
		le.PutUint32(c[42:], uint32(off))
		var extra []byte
		if zip64 {
			le.PutUint32(c[20:], 0xffffffff)
			le.PutUint32(c[24:], 0xffffffff)
			le.PutUint32(c[42:], 0xffffffff)
			extra = le.AppendUint16(extra, 1)
			extra = le.AppendUint16(extra, 24)
			extra = le.AppendUint64(extra, uint64(len(m.content)))
			extra = le.AppendUint64(extra, uint64(len(body)))
			extra = le.AppendUint64(extra, uint64(off))
		}
		le.PutUint16(c[30:], uint16(len(extra)))
		cd.Write(c)
		cd.WriteString(m.name)
		cd.Write(extra)
	}
	cdOff, cdSize := b.Len(), cd.Len()
	b.Write(cd.Bytes())
	e := make([]byte, 22)
	copy(e, "PK\x05\x06")
	le.PutUint16(e[8:], uint16(len(ms)))
	le.PutUint16(e[10:], uint16(len(ms)))
	le.PutUint32(e[12:], uint32(cdSize))
	le.PutUint32(e[16:], uint32(cdOff))
	if zip64 {
		at := b.Len()
		r := make([]byte, 56)
		copy(r, "PK\x06\x06")
		le.PutUint64(r[4:], 44)
		le.PutUint16(r[12:], 45)
		le.PutUint16(r[14:], 45)
		le.PutUint64(r[24:], uint64(len(ms)))
		le.PutUint64(r[32:], uint64(len(ms)))
		le.PutUint64(r[40:], uint64(cdSize))
		le.PutUint64(r[48:], uint64(cdOff))
		b.Write(r)
		l := make([]byte, 20)
		copy(l, "PK\x06\x07")
		le.PutUint64(l[8:], uint64(at))
		le.PutUint32(l[16:], 1)
		b.Write(l)
		le.PutUint16(e[8:], 0xffff)
		le.PutUint16(e[10:], 0xffff)
		le.PutUint32(e[12:], 0xffffffff)
		le.PutUint32(e[16:], 0xffffffff)
	}
	b.Write(e)
	return append(slices.Clone(prefix), b.Bytes()...)
}

// pyBytes is data as a Python bytes literal writes it: printable ASCII as itself, the
// rest as \xHH.
func pyBytes(data []byte) string {
	var b strings.Builder
	b.WriteString(`b"`)
	for _, c := range data {
		if c >= ' ' && c < 0x7f && c != '"' && c != '\\' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	b.WriteString(`"`)
	return b.String()
}

// tarHeader is one ustar header for a regular file of size bytes, its checksum valid.
func tarHeader(name string, size int) []byte {
	h := make([]byte, 512)
	copy(h, name)
	copy(h[100:], "0000644\x00")
	copy(h[108:], "0000000\x00")
	copy(h[116:], "0000000\x00")
	copy(h[124:], fmt.Sprintf("%011o\x00", size))
	copy(h[136:], "00000000000\x00")
	h[156] = '0'
	copy(h[257:], "ustar\x0000")
	copy(h[148:], "        ")
	sum := 0
	for _, c := range h {
		sum += int(c)
	}
	copy(h[148:], fmt.Sprintf("%06o\x00 ", sum))
	return h
}

func archiveSet(t testing.TB) *Set {
	return setOf(t, ModeRefuse, nil, file(simPy, "harness/sim.py", ""), value("731904", "practice-seeds.txt:3", ModeAudit))
}

// scanText scans text as one file's content and returns the labels found; any
// incomplete part fails the test.
func scanText(t *testing.T, s *Set, text string) []string {
	t.Helper()
	res, err := s.Scan(context.Background(), []Part{{Where: "files[0].content", Data: []byte(text), Whole: true}})
	if err != nil || len(res.Incomplete) > 0 {
		t.Fatalf("scan: %v, incomplete %v", err, res.Incomplete)
	}
	return labels(res.Found)
}

// A withheld file or value is found inside each archive a harness might ship, in each
// way it can ship: a tar of text as it is (valid UTF-8, so a call may carry it), and
// anything else as base64 (a step runs base64 -d) or as a byte string's escapes.
func TestArchiveMembersAreFound(t *testing.T) {
	set := archiveSet(t)
	both := []string{"harness/sim.py", "practice-seeds.txt:3"}
	harness := []string{"harness/sim.py"}
	seed := []string{"practice-seeds.txt:3"}
	sim := member{"helpers/model.py", simPy}
	viewer := member{"viewer.html", `<a href="viewer.html?seed=731904">`}
	for _, tc := range []struct {
		name, text string
		want       []string
	}{
		{"tar as it is", string(tarOf(sim, viewer)), both},
		{"tar.gz in base64", base64Lines(gzipOf(tarOf(sim, viewer))), both},
		{"tar.gz in a data: URI", "data:application/gzip;base64," + base64.StdEncoding.EncodeToString(gzipOf(tarOf(sim))), harness},
		{"gz in base64", base64Lines(gzipOf([]byte(simPy))), harness},
		{"gz members one after another", base64Lines(append(gzipOf([]byte(simPy[:30])), gzipOf([]byte(simPy[30:]))...)), harness},
		{"zip stored, data descriptors", base64Lines(zipOf(zip.Store, sim, viewer)), both},
		{"zip deflated, data descriptors", base64Lines(zipOf(zip.Deflate, sim, viewer)), both},
		{"zip stored, sizes in the headers", base64Lines(rawZip(nil, false, sim, viewer)), both},
		{"zip deflated, sizes in the headers", base64Lines(rawZip(nil, false, member{"sim.z", simPy})), harness},
		{"zip after a stub", base64Lines(rawZip([]byte("#!/bin/sh\nexec unzip \"$0\"\n"), false, sim, member{"v.z", viewer.content})), both},
		{"zip64", base64Lines(rawZip(nil, true, sim, member{"v.z", viewer.content})), both},
		{"bz2 in base64", simPyBz2, harness},
		{"tar.bz2 in base64", simPyTarBz2, harness},
		{"zip with a bzip2 member", simPyZipBz2, harness},
		{"tar.gz in a deflated zip member", base64Lines(zipOf(zip.Deflate, member{"deps.tgz", string(gzipOf(tarOf(sim)))})), harness},
		{"zip in a tar", base64Lines(tarOf(member{"bundle.zip", string(zipOf(zip.Store, sim))})), harness},
		{"gz in a tar", base64Lines(tarOf(member{"README", "notes\n"}, member{"sim.py.gz", string(gzipOf([]byte(simPy)))})), harness},
		{"tar in a tar", string(tarOf(member{"inner.tar", string(tarOf(sim))})), harness},
		{"gz as a byte string's escapes", "FIXTURE = " + pyBytes(gzipOf([]byte(simPy))) + "\n", harness},
		{"zip as a byte string's escapes", "FIXTURE = " + pyBytes(rawZip(nil, false, sim)) + "\n", harness},
		{"tar as a byte string's escapes", "T = " + pyBytes(tarOf(sim, viewer)) + "\n", both},
		// A zip with no central directory, or members its directory leaves out, read from
		// the local headers as bsdtar and Java's ZipInputStream read it.
		{"zip cut short before its directory", base64Lines(beforeDirectory(rawZip(nil, false, sim, viewer))), both},
		{"zip cut short, deflated", base64Lines(beforeDirectory(rawZip(nil, false, member{"sim.z", simPy}, member{"v.z", viewer.content}))), both},
		{"zip cut short, stored, data descriptors", base64Lines(beforeDirectory(zipOf(zip.Store, sim, viewer))), both},
		{"zip cut short, deflated, data descriptors", base64Lines(beforeDirectory(zipOf(zip.Deflate, sim, viewer))), both},
		{"zip cut short, as a byte string's escapes", "Z = " + pyBytes(beforeDirectory(zipOf(zip.Deflate, sim))) + "\n", harness},
		{"a member the directory leaves out", base64Lines(append(beforeDirectory(rawZip(nil, false, member{"sim.z", simPy})),
			rawZip(nil, false, member{"v.z", viewer.content})...)), both},
		{"tar member with a base-256 size", string(tarBase256(sim)), harness},
		// A stored member whose sizes follow it ends where libarchive ends it: at the first
		// descriptor signature (CRCs ignored), here inside its bytes, or at the first one
		// whose CRC-32 holds.
		{"stored member cut at a signature inside it", base64Lines(storedLater(simPy + "PK\x07\x08 and more")), harness},
		{"a seed compressed", base64Lines(gzipOf([]byte("seeds\n100001\n731904\n"))), seed},
		{"a seed in a member's name", base64Lines(gzipOf(tarOf(member{"cases/seed_731904.json", "{}"}))), seed},
		{"base64 after a joined line", "DATA\n" + base64Lines(gzipOf([]byte(simPy))), harness},
		{"gz four deep", base64Lines(gzipOf(gzipOf(gzipOf(gzipOf([]byte(simPy)))))), harness},
		// zlib, as Python's zlib.compress writes it, at each level's header.
		{"zlib in base64", base64Lines(zlibOf([]byte(simPy), zlib.DefaultCompression)), harness},
		{"zlib at level 1", base64Lines(zlibOf([]byte(simPy), zlib.BestSpeed)), harness},
		{"zlib at level 9", base64Lines(zlibOf([]byte(simPy), zlib.BestCompression)), harness},
		{"zlib as a byte string's escapes", "Z = " + pyBytes(zlibOf([]byte(simPy), zlib.DefaultCompression)) + "\n", harness},
		{"zlib after ordinary text", "# (See the README.) x^2\n" + base64Lines(zlibOf([]byte(simPy), zlib.DefaultCompression)), harness},
		{"a seed in a step, zlib in base64, shorter than any other archive",
			"python3 -c \"import base64, zlib; print(zlib.decompress(base64.b64decode('" + seedZlib + "')))\"", seed},
		{"a seed zlib-compressed, the base64 alone", seedZlib, seed},
		{"zlib in a tar", base64Lines(tarOf(member{"sim.py.z", string(zlibOf([]byte(simPy), zlib.DefaultCompression))})), harness},
		{"a tar.gz in zlib", base64Lines(zlibOf(gzipOf(tarOf(sim, viewer)), zlib.DefaultCompression)), both},
		{"zlib streams one after another", base64Lines(append(zlibOf([]byte("seeds\n100001\n"), 6), zlibOf([]byte(simPy), 6)...)), harness},
	} {
		if got := scanText(t, set, tc.text); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: found %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The zips written byte by byte here are ones archive/zip reads too: the walker reads
// what unzip, Python and Go read, not a format of its own.
func TestRawZipsAreZips(t *testing.T) {
	for _, z := range [][]byte{
		rawZip(nil, false, member{"a", "x"}, member{"b.z", simPy}),
		rawZip([]byte("stub"), false, member{"a", "x"}),
		rawZip(nil, true, member{"a", "x"}, member{"b.z", simPy}),
	} {
		r, err := zip.NewReader(bytes.NewReader(z), int64(len(z)))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range r.File {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadAll(rc); err != nil {
				t.Fatalf("%s: %v", f.Name, err)
			}
		}
	}
}

// What the scan does not recognize, each a documented limit: an archive encoded twice,
// hex, raw deflate (no signature at all), a zlib stream whose Adler-32 does not hold (cut
// short, or altered: a two-byte header alone is not believed), and a gz whose base64 a
// letter misaligns. Not found, and not incomplete either.
func TestArchivesTheScanDoesNotRead(t *testing.T) {
	set := archiveSet(t)
	z := zlibOf([]byte(simPy), zlib.DefaultCompression)
	altered := slices.Clone(z)
	altered[len(altered)-1] ^= 1
	for _, tc := range []struct{ name, text string }{
		{"base64 of base64 of a gz", base64Lines([]byte(base64Lines(gzipOf([]byte(simPy)))))},
		{"hex of a gz", hex.EncodeToString(gzipOf([]byte(simPy)))},
		{"a zlib stream without its Adler-32", base64Lines(z[:len(z)-4])},
		{"a zlib stream whose Adler-32 is altered", base64Lines(altered)},
		{"raw deflate", base64Lines(deflateOf([]byte(simPy)))},
		{"a gz glued to a letter before it", "x" + base64.StdEncoding.EncodeToString(gzipOf([]byte(simPy)))},
	} {
		if got := scanText(t, set, tc.text); len(got) != 0 {
			t.Errorf("%s: found %v; the docs say it is not read", tc.name, got)
		}
	}
}

// What the scan recognizes and cannot read makes the part incomplete, with the reason:
// a set with a refuse entry refuses the call (internal/rpc), since the unread bytes could
// carry one. Each holds the withheld file and seed where the scan cannot see them.
func TestArchivesTheScanCannotRead(t *testing.T) {
	set := archiveSet(t)
	in := func(b Bound) []Incomplete { return []Incomplete{{"files[0].content", b}} }
	sparse := slices.Concat(tarTyped('S', "sim.py", simPy), make([]byte, 1024))
	pax := slices.Concat(tarTyped('x', "PaxHeaders/sim.py", "30 size=86\n"), tarTyped('0', "sim.py", ""), []byte(simPy))
	for _, tc := range []struct {
		name, text string
		want       []Incomplete
	}{
		{"an encrypted zip", base64Lines(unb64(encryptedZip)), in(BoundZipEncrypted)},
		{"an encrypted zip as a byte string's escapes", "Z = " + pyBytes(unb64(encryptedZip)) + "\n", in(BoundZipEncrypted)},
		{"an encrypted zip cut short before its directory", base64Lines(beforeDirectory(unb64(encryptedZip))), in(BoundZipEncrypted)},
		{"an encrypted zip in a gz", base64Lines(gzipOf(unb64(encryptedZip))), in(BoundZipEncrypted)},
		{"a zip of LZMA members", base64Lines(unb64(lzmaZip)), in(BoundZipMethod)},
		{"a zip of LZMA members cut short", base64Lines(beforeDirectory(unb64(lzmaZip))), in(BoundZipMethod)},
		{"xz", base64Lines(unb64(simPyXz)), in(BoundXZ)},
		{"xz in a tar", base64Lines(tarOf(member{"sim.py.xz", string(unb64(simPyXz))})), in(BoundXZ)},
		{"zstd", base64Lines(unb64(simPyZst)), in(BoundZstd)},
		{"zstd as a byte string's escapes", "Z = " + pyBytes(unb64(simPyZst)) + "\n", in(BoundZstd)},
		{"zstd in a deflated zip member", base64Lines(zipOf(zip.Deflate, member{"sim.py.zst", string(unb64(simPyZst))})), in(BoundZstd)},
		{"7z", base64Lines(sevenZip()), in(Bound7z)},
		{"rar 5", base64Lines(rar5()), in(BoundRar)},
		{"rar 4", base64Lines(rar4()), in(BoundRar)},
		{"rar 4 with a main header of 9,000 bytes", base64Lines(rar4Sized(9000)), in(BoundRar)},
		{"a GNU sparse tar member", string(sparse), in(BoundTarSparse)},
		{"a PAX header setting a member's size", string(pax), in(BoundTarPax)},
	} {
		res, err := set.Scan(context.Background(), []Part{{Where: "files[0].content", Data: []byte(tc.text), Whole: true}})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Found) > 0 || !reflect.DeepEqual(res.Incomplete, tc.want) {
			t.Errorf("%s: found %v, incomplete %v; want nothing found, incomplete %v", tc.name, labels(res.Found), res.Incomplete, tc.want)
		}
	}
}

// A withheld file that itself holds a descriptor signature is found in a stored member
// whose sizes follow it: libarchive reads on past a signature whose CRC-32 does not hold.
func TestStoredMemberEndsWhereItsCRCHolds(t *testing.T) {
	odd := "PK\x07\x08 is not where this file ends\n" + simPy
	set := setOf(t, ModeRefuse, nil, file(odd, "harness/odd.py", ""))
	if got := scanText(t, set, base64Lines(storedLater(odd))); !reflect.DeepEqual(got, []string{"harness/odd.py"}) {
		t.Fatalf("found %v", got)
	}
}

// A signature spelled in code (a format sniffer's table) is not taken for an archive,
// with its escapes decoded or as written: each check past the signature asks for bytes
// text does not hold.
func TestSignaturesInCodeAreNotArchives(t *testing.T) {
	sniffer := `KINDS = {
    b"\xfd7zXZ\x00": "xz", b"\xfd7zXZ\x00\x00\x01": "xz",
    b"\x28\xb5\x2f\xfd": "zstd", b"(\xb5/\xfd": "zstd",
    b"7z\xbc\xaf\x27\x1c": "7z", b"7z\xbc\xaf\x27\x1c\x00\x04": "7z",
    b"Rar!\x1a\x07\x00": "rar", b"Rar!\x1a\x07\x01\x00": "rar5",
    b"PK\x03\x04": "zip", b"PK\x03\x04\x14\x00": "zip", b"PK\x05\x06": "zip", b"PK\x07\x08": "zip",
}
def kind(data):
    return next((k for m, k in KINDS.items() if data.startswith(m)), None)
`
	// Text after it, so that a length read from the text still fits inside the part.
	sniffer += string(ordinaryText(1 << 17))
	if got := scanText(t, archiveSet(t), sniffer); len(got) != 0 {
		t.Fatalf("found %v in a sniffer", got)
	}
}

// A bound reached makes the part incomplete, named by its place and the bound, once;
// what was read before it is still scanned, and a part reached after it is named too.
func TestArchiveBounds(t *testing.T) {
	set := archiveSet(t)
	if !set.Refuses() {
		t.Fatal("a set with a refuse-mode entry must say so")
	}
	if setOf(t, ModeAudit, nil, value("731904", "s", "")).Refuses() {
		t.Fatal("an audit-only set refuses nothing")
	}
	bomb := base64Lines(gzipOf(make([]byte, MaxArchiveBytes+1)))
	var fakes []byte // gzip headers over nothing: every one is an archive the scan reads
	for range MaxArchiveEntries + 10 {
		fakes = append(fakes, 0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	}
	var overlap []byte // headers each claiming every byte after it
	const n = 1200
	for k := range n {
		overlap = append(overlap, tarHeader("f", (n-k-1)*512)...)
	}
	deep := []byte(simPy)
	for range MaxArchiveDepth + 1 {
		deep = gzipOf(deep)
	}
	// Zeros after the zlib stream, so the gzip around it codes it rather than storing it,
	// where it would be read as written at every depth.
	deepZlib := append(zlibOf([]byte(simPy), zlib.DefaultCompression), make([]byte, 4096)...)
	for range MaxArchiveDepth {
		deepZlib = gzipOf(deepZlib)
	}
	// False starts: zlib streams of 4 MiB each whose Adler-32 does not hold, so each is
	// inflated whole and not believed; what they write counts against the member bound,
	// which the seventeenth passes.
	fake := zlibOf(make([]byte, 4<<20), zlib.BestCompression)
	fake[len(fake)-1] ^= 1
	var fakeZlibs []byte
	for range MaxArchiveMemberBytes/(4<<20) + 1 {
		fakeZlibs = append(fakeZlibs, fake...)
	}
	longFake := zlibOf(make([]byte, MaxArchiveBytes+1<<20), zlib.BestCompression)
	longFake[len(longFake)-1] ^= 1
	// The most members one zip may hold within the entry bound (its end record is one
	// entry), the withheld file last; 65,535 is also the count a zip states as 0xffff
	// without being zip64.
	ms := make([]member, MaxArchiveEntries-2, MaxArchiveEntries)
	for i := range ms {
		ms[i] = member{fmt.Sprintf("%x", i), ""}
	}
	// As written, not in base64: base64's URL-safe pass decodes the pieces of a standard
	// run between its + and / again, and a piece that holds a whole local header is one
	// more member read.
	most := string(rawZip(nil, false, append(ms, member{"sim.py", simPy})...))
	over := string(rawZip(nil, false, append(ms, member{"x", ""}, member{"sim.py", simPy})...))
	for _, tc := range []struct {
		name  string
		parts []string
		found []string
		want  []Incomplete
	}{
		{"a gzip bomb", []string{base64Lines(gzipOf([]byte(simPy))), bomb}, []string{"harness/sim.py"},
			[]Incomplete{{"files[1].content", BoundArchiveBytes}}},
		{"after the bytes are spent", []string{bomb, base64Lines(gzipOf([]byte("x")))}, nil,
			[]Incomplete{{"files[0].content", BoundArchiveBytes}, {"files[1].content", BoundArchiveBytes}}},
		{"too many archives", []string{base64Lines(fakes)}, nil, []Incomplete{{"files[0].content", BoundEntries}}},
		{"overlapping tar members", []string{string(overlap)}, nil, []Incomplete{{"files[0].content", BoundMemberBytes}}},
		{"five deep", []string{base64Lines(deep)}, nil, []Incomplete{{"files[0].content", BoundDepth}}},
		{"zlib five deep", []string{base64Lines(deepZlib)}, nil, []Incomplete{{"files[0].content", BoundDepth}}},
		{"a zlib bomb", []string{base64Lines(zlibOf([]byte(simPy), 6)), base64Lines(zlibOf(make([]byte, MaxArchiveBytes+1), 9))},
			[]string{"harness/sim.py"}, []Incomplete{{"files[1].content", BoundArchiveBytes}}},
		{"zlib false starts past the member bound", []string{base64Lines(fakeZlibs)}, nil, []Incomplete{{"files[0].content", BoundMemberBytes}}},
		// Longer than the 8 MiB, so read on and dropped until its Adler-32 fails: a false
		// start, charged to the member bound, and no bound reached.
		{"a zlib false start longer than the bound", []string{base64Lines(longFake)}, nil, nil},
		{"a chain of empty gzip members", []string{base64Lines(bytes.Repeat(gzipOf(nil), MaxArchiveEntries+1))}, nil,
			[]Incomplete{{"files[0].content", BoundEntries}}},
		// The zip is read whole, its 65,535 members and end record taking every entry; the
		// zlib headers its offsets happen to hold are tries too, and past the bound.
		{"the most zip members", []string{most}, []string{"harness/sim.py"}, []Incomplete{{"files[0].content", BoundEntries}}},
		{"one zip member more", []string{over}, nil, []Incomplete{{"files[0].content", BoundEntries}}},
	} {
		var parts []Part
		for i, p := range tc.parts {
			parts = append(parts, Part{Where: fmt.Sprintf("files[%d].content", i), Data: []byte(p), Whole: true})
		}
		res, sc, err := set.scan(context.Background(), parts)
		if err != nil {
			t.Fatal(err)
		}
		if got := labels(res.Found); !reflect.DeepEqual(got, tc.found) {
			t.Errorf("%s: found %v, want %v", tc.name, got, tc.found)
		}
		if !reflect.DeepEqual(res.Incomplete, tc.want) {
			t.Errorf("%s: incomplete %v, want %v", tc.name, res.Incomplete, tc.want)
		}
		if sc.decoded > MaxArchiveBytes || sc.hashed > MaxArchiveMemberBytes || sc.entries > MaxArchiveEntries {
			t.Errorf("%s: past a bound: %d decoded, %d hashed, %d entries", tc.name, sc.decoded, sc.hashed, sc.entries)
		}
	}
}

// A bzip2 stream is charged its block size when it starts, so streams of next to
// nothing cannot each make compress/bzip2 allocate its 3.6 MB.
func TestBzip2StreamsAreChargedTheirBlocks(t *testing.T) {
	set := archiveSet(t)
	one := unb64(tinyBz2) // level 9: 900,000 bytes charged
	var many []byte
	for range MaxArchiveBytes/900_000 + 2 {
		many = append(many, one...)
		many = append(many, '\n') // not one stream: each is its own archive
	}
	res, sc, err := set.scan(context.Background(), []Part{{Where: "code", Data: []byte(base64Lines(many))}})
	if err != nil {
		t.Fatal(err)
	}
	if want := []Incomplete{{"code", BoundArchiveBytes}}; !reflect.DeepEqual(res.Incomplete, want) {
		t.Fatalf("incomplete %v, want %v (decoded %d)", res.Incomplete, want, sc.decoded)
	}
}

// A stream that fails cannot hide the one after it: a signature after a broken or
// ended stream is read, whatever bytes sit between.
func TestABrokenStreamHidesNothing(t *testing.T) {
	set := archiveSet(t)
	gz := gzipOf([]byte(simPy))
	broken := slices.Clone(gzipOf([]byte("decoy, longer than the bytes the next header reads")))
	broken[len(broken)-6] ^= 0xff // its trailer's length no longer holds
	bz := unb64(simPyBz2)
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"gz after a gz and one byte", slices.Concat(gzipOf([]byte("x")), []byte("\n"), gz)},
		{"gz after a broken gz", slices.Concat(broken, gz)},
		{"gz right after a gz's trailer, one stream", slices.Concat(gzipOf([]byte(simPy[:9])), gzipOf([]byte(simPy[9:])))},
		{"bz2 after a bz2 and one byte", slices.Concat(unb64(tinyBz2), []byte("\n"), bz)},
		{"bz2 after a bz2 and two bytes", slices.Concat(unb64(tinyBz2), []byte("\n\n"), bz)},
		{"bz2 inside a broken bz2", slices.Concat(unb64(tinyBz2)[:20], bz)},
	} {
		if got := scanText(t, set, base64Lines(tc.data)); !slices.Contains(got, "harness/sim.py") {
			t.Errorf("%s: found %v", tc.name, got)
		}
	}
}

// An archive is read once: the escapes view of a stream holds the same gzip the written
// view does, unless an escape made it, and members written one after another are one
// stream, not one stream per member.
func TestArchivesAreReadOnce(t *testing.T) {
	set := archiveSet(t)
	inner := gzipOf([]byte("plain text, nothing withheld\n"))
	if bytes.ContainsAny(inner, `%\`) {
		t.Fatal("the inner gzip holds an escape character; change its text")
	}
	text := member{"notes.json", `{"say": "\"hi\"\n"}`} // escapes: the stream has an escapes view
	outer := gzipOf(tarOf(text, member{"inner.gz", string(inner)}))
	_, sc, err := set.scan(context.Background(), []Part{{Where: "code", Data: []byte(base64Lines(outer))}})
	if err != nil {
		t.Fatal(err)
	}
	tarLen := len(tarOf(text, member{"inner.gz", string(inner)}))
	// The bytes zlib false starts read are charged too, and are not a stream decoded.
	if want := tarLen + len("plain text, nothing withheld\n"); sc.decoded-sc.zlibIn != want {
		t.Fatalf("decoded %d bytes, want %d (the tar and the inner stream, once each)", sc.decoded-sc.zlibIn, want)
	}
	var parts []byte
	for i := range 200 {
		parts = append(parts, gzipOf([]byte(fmt.Sprintf("line %d\n", i)))...)
	}
	_, sc, err = set.scan(context.Background(), []Part{{Where: "code", Data: []byte(base64Lines(parts))}})
	if err != nil {
		t.Fatal(err)
	}
	want := 0
	for i := range 200 {
		want += len(fmt.Sprintf("line %d\n", i))
	}
	if sc.decoded-sc.zlibIn != want {
		t.Fatalf("decoded %d bytes from 200 gzip members, want %d (each once)", sc.decoded-sc.zlibIn, want)
	}
}

// A tar header the scan reads: the ustar magic of POSIX or GNU, a checksum in octal
// that holds (unsigned or signed); a regular file's content is its size bytes after.
func TestTarHeaders(t *testing.T) {
	set := setOf(t, ModeRefuse, nil, file(simPy, "harness/sim.py", ""))
	content := []byte(simPy)
	pad := make([]byte, 512-len(content)%512)
	posix := append(append(tarHeader("sim.py", len(content)), content...), pad...)
	gnu := slices.Clone(posix)
	copy(gnu[257:], "ustar  \x00")
	resum(gnu)
	bad := slices.Clone(posix)
	bad[0] = 'x' // the checksum no longer holds
	dir := slices.Clone(posix)
	dir[156] = '5'
	resum(dir)
	short := posix[:512+len(content)-1] // cut inside the content
	for _, tc := range []struct {
		name string
		data []byte
		want []string
	}{
		{"posix", posix, []string{"harness/sim.py"}},
		{"gnu", gnu, []string{"harness/sim.py"}},
		{"after other bytes", append([]byte("prefix bytes\n"), posix...), []string{"harness/sim.py"}},
		{"bad checksum", bad, nil},
		{"a directory", dir, nil},
		{"cut short", short, nil},
	} {
		res, err := set.Scan(context.Background(), []Part{{Where: "files[0].content", Data: tc.data}})
		if err != nil {
			t.Fatal(err)
		}
		if got := labels(res.Found); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: found %v, want %v", tc.name, got, tc.want)
		}
	}
	for _, tc := range []struct {
		in   string
		n    uint64
		want bool
	}{
		{"0000644\x00", 0o644, true}, {"  755 \x00", 0o755, true}, {"\x00\x00\x00", 0, false},
		{"12a\x00", 0, false}, {"8\x00", 0, false}, {"7777777777777777777777", 0, false},
	} {
		if n, ok := tarOctal([]byte(tc.in)); ok != tc.want || ok && n != tc.n {
			t.Errorf("tarOctal(%q) = %o, %v; want %o, %v", tc.in, n, ok, tc.n, tc.want)
		}
	}
}

// storedLater is one stored zip member, no central directory, whose sizes and CRC-32
// follow its data in a data descriptor (flag bit 3), as a streaming writer leaves one.
func storedLater(content string) []byte {
	le := binary.LittleEndian
	h := make([]byte, 30)
	copy(h, "PK\x03\x04")
	le.PutUint16(h[4:], 20)
	le.PutUint16(h[6:], 8)
	le.PutUint16(h[26:], 1)
	d := le.AppendUint32([]byte("PK\x07\x08"), crc32.ChecksumIEEE([]byte(content)))
	d = le.AppendUint32(le.AppendUint32(d, uint32(len(content))), uint32(len(content)))
	return slices.Concat(h, []byte("m"), []byte(content), d)
}

// tarBase256 is a tar of one member whose size field is in base 256 (a first byte of
// 0x80, then the size big-endian), which GNU tar writes for 8 GiB or more and GNU tar
// and Python read for any size.
func tarBase256(m member) []byte {
	h := tarHeader(m.name, len(m.content))
	clear(h[124:136])
	h[124] = 0x80
	binary.BigEndian.PutUint32(h[132:], uint32(len(m.content)))
	resum(h)
	return append(append(h, m.content...), make([]byte, (512-len(m.content)%512)%512+1024)...)
}

// resum rewrites a tar header's checksum after a test changed it.
func resum(h []byte) {
	copy(h[148:], "        ")
	sum := 0
	for _, c := range h[:512] {
		sum += int(c)
	}
	copy(h[148:], fmt.Sprintf("%06o\x00 ", sum))
}

// The scan stops when the call's context ends: before a part, and between archives.
func TestArchiveScanStopsWithTheContext(t *testing.T) {
	set := archiveSet(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := set.Scan(ctx, []Part{{Where: "code", Data: []byte("x")}}); err == nil {
		t.Fatal("a scan under an ended context must stop")
	}
	var many []byte
	for i := range 50 {
		many = append(many, gzipOf([]byte(fmt.Sprint(i)))...)
		many = append(many, '\n')
	}
	ctx = &endsAfter{Context: context.Background(), n: 10}
	if _, err := set.Scan(ctx, []Part{{Where: "code", Data: []byte(base64Lines(many))}}); err == nil {
		t.Fatal("a scan whose context ends between archives must stop")
	}
}

// endsAfter is a context that ends after its Err has been asked n times.
type endsAfter struct {
	context.Context
	n int
}

func (c *endsAfter) Err() error {
	if c.n--; c.n < 0 {
		return context.Canceled
	}
	return nil
}

// Ordinary text holds no archive and reaches no bound: this module's own source and
// documents, signatures in text and escapes included (archive.go spells each one).
func TestArchivesInOrdinaryText(t *testing.T) {
	// The tests and the docs hold the archive tests' seed, so this set's value is one
	// they do not.
	set := setOf(t, ModeRefuse, nil, file(simPy, "harness/sim.py", ""), value("q8x2v7k", "v", ModeAudit))
	var files []string
	for _, pattern := range []string{"*.go", "../rpc/*.go", "../../docs/*.md", "../../sandbox/*.go"} {
		m, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range m {
			if !strings.HasSuffix(f, "_test.go") {
				files = append(files, f)
			}
		}
	}
	if len(files) < 20 {
		t.Fatalf("only %d files", len(files))
	}
	var parts []Part
	for i, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, Part{Where: fmt.Sprintf("files[%d].content", i), Data: data, Whole: true})
	}
	res, sc, err := set.scan(context.Background(), parts)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Found) > 0 || len(res.Incomplete) > 0 {
		t.Fatalf("found %v, incomplete %v in ordinary text", labels(res.Found), res.Incomplete)
	}
	t.Logf("%d files: %d archives and members read, %d bytes decoded", len(files), sc.entries, sc.decoded)
}

// Any input: no panic, and every bound holds.
func FuzzScanArchives(f *testing.F) {
	sim := member{"sim.py", simPy}
	for _, seed := range [][]byte{
		tarOf(sim), gzipOf(tarOf(sim)), zipOf(zip.Deflate, sim), rawZip(nil, true, sim, member{"b.z", "x"}),
		rawZip([]byte("stub"), false, sim), unb64(simPyBz2), unb64(simPyZipBz2), unb64(simPyTarBz2),
		[]byte(base64Lines(gzipOf(tarOf(sim)))), []byte("FIXTURE = " + pyBytes(gzipOf([]byte(simPy)))),
		gzipOf(gzipOf(gzipOf(gzipOf(gzipOf([]byte(simPy)))))), tarHeader("f", 1<<20), []byte(harnessPy),
		unb64(encryptedZip), unb64(lzmaZip), unb64(simPyZst), unb64(simPyXz), sevenZip(), rar5(), rar4(),
		beforeDirectory(zipOf(zip.Store, sim)), tarBase256(sim), tarTyped('S', "s", simPy),
		zlibOf([]byte(simPy), 6), unb64(seedZlib), gzipOf(zlibOf(tarOf(sim), 9)), []byte("(See x^2, HK 8O.)"),
	} {
		f.Add(seed)
	}
	set := setOf(f, ModeRefuse, nil, file(simPy, "harness/sim.py", ""), value("731904", "seed", ModeAudit), sourceOf(harnessPy, "harness/plant.py", ""))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, sc, err := set.scan(context.Background(), []Part{{Where: "files[0].content", Data: data, Whole: true}})
		if err != nil {
			t.Fatal(err)
		}
		if sc.decoded > MaxArchiveBytes || sc.hashed > MaxArchiveMemberBytes || sc.entries > MaxArchiveEntries {
			t.Fatalf("past a bound: %d decoded, %d hashed, %d entries", sc.decoded, sc.hashed, sc.entries)
		}
	})
}

// The scan's cost on archives built to make it as costly as they can, each in one part
// as base64, against a set declaring every value length, a file and a source entry:
// the stream the scan reads most slowly, decompressed to the whole MaxArchiveBytes;
// deflate blocks of one byte each, whose tables are rebuilt per block; bzip2 streams of
// one byte, one after another, which one reader reads; the most zip members and the
// most gzip headers the entry bound allows; tar headers claiming overlapping members up
// to the member bound, with and without lines to hash; and, beside them, a .tar.gz of
// ordinary source. docs/ship-scan.md quotes the slowest.
func BenchmarkScanArchives(b *testing.B) {
	var es []map[string]any
	for n := MinValueBytes; n <= MaxValueBytes; n++ {
		es = append(es, value(strings.Repeat("q", n), fmt.Sprintf("q%d", n), ""))
	}
	es = append(es, file(simPy, "f", ""), sourceOf(harnessPy, "s", ""))
	s := setOf(b, ModeAudit, nil, es...)
	const most = 4 << 20 // a call's files, in all
	cases := map[string][]byte{
		"a.a%2E decompressed to the bound": gzipOf(bytes.Repeat([]byte("a.a%2E"), MaxArchiveBytes/6)),
		"ordinary source, tar.gz":          gzipOf(tarOf(member{"src.go", string(ordinaryText(MaxArchiveBytes - 2048))})),
	}
	var blocks bytes.Buffer
	w, _ := flate.NewWriter(&blocks, flate.HuffmanOnly)
	for i := 0; blocks.Len() < most*3/4; i++ {
		w.Write([]byte{byte(i)})
		w.Flush()
	}
	w.Close()
	cases["deflate blocks of one byte"] = slices.Concat(gzipHead, blocks.Bytes())
	var streams []byte
	for len(streams) < most*3/4 {
		streams = append(streams, unb64(tinyBz2)...)
	}
	cases["bzip2 streams of one byte"] = streams
	var ms []member
	for i := range MaxArchiveEntries - 1 {
		ms = append(ms, member{fmt.Sprintf("%x.z", i), ""})
	}
	cases["zip of 65,535 members"] = rawZip(nil, false, ms...)
	cases["zip of 65,535 members, no directory"] = beforeDirectory(rawZip(nil, false, ms...))
	// A stored member whose sizes follow it, and a data descriptor signature every four
	// bytes: every one is a place it could end, each checked, up to the member bound.
	ends := beforeDirectory(zipOf(zip.Store, member{"s", strings.Repeat("PK\x07\x08", most/8)}))
	cases["stored member that could end anywhere"] = ends
	var fakes []byte
	for range MaxArchiveEntries {
		fakes = append(fakes, 0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	}
	cases["gzip headers over nothing"] = fakes
	var overlap []byte // tar headers each claiming every byte after it: members up to their bound
	for k := range 1200 {
		overlap = append(overlap, tarHeader("f", (1200-k-1)*512)...)
	}
	cases["overlapping tar members"] = overlap
	// The same, with 494 bytes of 26-byte lines in every member for a source entry to hash.
	lines := bytes.Repeat([]byte("distinctive_line_number_x\n"), 19)
	var textual []byte
	for k := range 1200 {
		textual = append(textual, tarHeader("f", (1200-k-1)*1024+512)...)
		textual = append(textual, lines...)
		textual = append(textual, make([]byte, 512-len(lines))...)
	}
	cases["overlapping tar members of text lines"] = textual
	// zlib: the costliest stream believed, as for gzip; then false starts, which are tried
	// and not believed: the most tries the entry bound allows (empty streams whose
	// Adler-32 does not hold), the slowest input to inflate (the one-byte blocks behind a
	// zlib header, no Adler-32), and output inflated to the member bound (4 MiB of zeros
	// a stream, its Adler-32 altered).
	cases["zlib, a.a%2E decompressed to the bound"] = zlibOf(bytes.Repeat([]byte("a.a%2E"), MaxArchiveBytes/6), zlib.BestCompression)
	var empties []byte
	for range MaxArchiveEntries {
		empties = append(empties, 0x78, 0x9c, 0x03, 0x00, 0, 0, 0, 2)
	}
	cases["zlib false starts, the most tries"] = empties
	cases["zlib false start, deflate blocks of one byte"] = slices.Concat([]byte{0x78, 0x01}, blocks.Bytes())
	zeros := zlibOf(make([]byte, 4<<20), zlib.BestCompression)
	zeros[len(zeros)-1] ^= 1
	cases["zlib false starts, to the member bound"] = bytes.Repeat(zeros, MaxArchiveMemberBytes/(4<<20)+1)
	names := make([]string, 0, len(cases))
	for name := range cases {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		part := []byte(base64.StdEncoding.EncodeToString(cases[name]))
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(part)))
			var sc *scanner
			for b.Loop() {
				_, sc, _ = s.scan(context.Background(), []Part{{Where: "files[0].content", Data: part, Whole: true}})
			}
			b.ReportMetric(float64(len(cases[name])), "archive-bytes")
			b.ReportMetric(float64(sc.decoded), "decoded-bytes")
			b.ReportMetric(float64(sc.entries), "entries")
			b.ReportMetric(float64(sc.hashed), "member-bytes")
		})
	}
}

// gzipHead is a gzip header (no name, no extra field) for a deflate stream written
// after it.
var gzipHead = []byte{0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff}

// zlibFalseStartFiles is this module's own text and source as calls would carry them:
// every file of the usual text and source kinds under root, outside version control,
// dependencies and scratch (and a private directory, unless all).
func zlibFalseStartFiles(t *testing.T, root string, all bool) []string {
	t.Helper()
	kinds := map[string]bool{".go": true, ".md": true, ".py": true, ".ts": true, ".js": true, ".mjs": true, ".json": true,
		".yaml": true, ".yml": true, ".toml": true, ".txt": true, ".html": true, ".css": true, ".sh": true, ".proto": true,
		".c": true, ".h": true, ".svg": true, ".jsonl": true}
	skip := map[string]bool{".git": true, ".claude": true, "node_modules": true, "tmp": true, "dist": true, ".venv": true,
		"venv": true, "__pycache__": true}
	if !all {
		skip["private"] = true // a working copy's own notes: not part of the module, and 240 MB of them
	}
	var files []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if kinds[filepath.Ext(p)] && d.Type().IsRegular() {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// A zlib header is two bytes that ordinary text holds now and then ("x^", "(S", "HK"),
// so each is tried and believed only when it inflates to an Adler-32 that holds. Over
// this module's own text and source, each file scanned as a call of its own as the
// daemon would scan it (at most 4 MiB, UTF-8, as a call's files must be), no try is
// believed outside a test's fixtures and none makes a call incomplete; the counts are
// logged, and docs/ship-scan.md quotes them. A file may be incomplete for an archive it holds as a
// test fixture (an encrypted zip, xz), never for a bound. PLIMSOLL_ZLIB_ROOT starts the
// walk elsewhere, every directory included.
func TestZlibFalseStarts(t *testing.T) {
	root, all := "../..", false
	if r := os.Getenv("PLIMSOLL_ZLIB_ROOT"); r != "" {
		root, all = r, true
	}
	set := setOf(t, ModeRefuse, nil, file(simPy, "harness/sim.py", ""), value("q8x2v7k", "v", ModeAudit))
	var files, read, tried, fixtures, in, out, mostTried, mostIn, mostOut, mostEntries int
	var mostFile string
	for _, f := range zlibFalseStartFiles(t, root, all) {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) > 4<<20 || !utf8.Valid(data) {
			continue
		}
		res, sc, err := set.scan(context.Background(), []Part{{Where: "files[0].content", Data: data, Whole: true}})
		if err != nil {
			t.Fatal(err)
		}
		if sc.zlibRead > 0 && !strings.HasSuffix(f, "_test.go") { // a test may hold one as a fixture
			t.Errorf("%s: %d zlib streams believed in ordinary text", f, sc.zlibRead)
		}
		fixtures += sc.zlibRead
		for _, in := range res.Incomplete {
			if in.Bound == BoundArchiveBytes || in.Bound == BoundEntries || in.Bound == BoundDepth {
				t.Errorf("%s: incomplete %v", f, res.Incomplete)
			}
		}
		files++
		read += len(data)
		tried += sc.zlibTried
		in += sc.zlibIn
		out += sc.zlibOut
		if sc.zlibTried > mostTried {
			mostTried, mostFile = sc.zlibTried, f
		}
		mostIn, mostOut = max(mostIn, sc.zlibIn), max(mostOut, sc.zlibOut)
		mostEntries = max(mostEntries, sc.entries)
	}
	if files < 100 {
		t.Fatalf("only %d files under %s", files, root)
	}
	t.Logf("%d files, %d bytes: %d zlib headers tried, %d believed (test fixtures), the false starts reading %d bytes and writing %d; "+
		"in one file at most %d tries (%s), %d bytes read and %d written by false starts, %d entries in all",
		files, read, tried, fixtures, in, out, mostTried, mostFile, mostIn, mostOut, mostEntries)
}

// pngChunk is one PNG chunk: its length, type, data and the CRC-32 of type and data.
func pngChunk(kind string, data []byte) []byte {
	c := binary.BigEndian.AppendUint32(nil, uint32(len(data)))
	c = append(append(c, kind...), data...)
	return binary.BigEndian.AppendUint32(c, crc32.ChecksumIEEE(c[4:]))
}

// pngOf is an 8-bit grayscale PNG of rows (each row's filter byte 0 and its pixels),
// its pixel data one zlib stream cut into IDAT chunks of at most chunk bytes (0: one
// chunk), with the chunks in extra after IHDR.
func pngOf(width int, rows [][]byte, chunk int, extra ...[]byte) []byte {
	var raw []byte
	for _, r := range rows {
		raw = append(append(raw, 0), r...)
	}
	ihdr := binary.BigEndian.AppendUint32(nil, uint32(width))
	ihdr = binary.BigEndian.AppendUint32(ihdr, uint32(len(rows)))
	out := append([]byte("\x89PNG\r\n\x1a\n"), pngChunk("IHDR", append(ihdr, 8, 0, 0, 0, 0))...)
	for _, e := range extra {
		out = append(out, e...)
	}
	z := zlibOf(raw, zlib.DefaultCompression)
	for len(z) > 0 {
		n := len(z)
		if chunk > 0 {
			n = min(n, chunk)
		}
		out, z = append(out, pngChunk("IDAT", z[:n])...), z[n:]
	}
	return append(out, pngChunk("IEND", nil)...)
}

// TestPNGPixelsAreNotRead pins the decision of 2026-10-28 (docs/ship-scan.md, "Not
// read"): a PNG image's pixel data is never read for zlib streams, so a value hidden in
// pixels is not found, whether the image holds them in one IDAT chunk or many, and a
// large image no longer makes a harmless call incomplete. Text chunks are read as
// before, and a pixel chunk whose CRC-32 does not hold skips nothing.
func TestPNGPixelsAreNotRead(t *testing.T) {
	const secret = "q8x2v7k3m9"
	set := setOf(t, ModeRefuse, nil, value(secret, "s", ModeRefuse))
	rows := make([][]byte, 32)
	for i := range rows {
		rows[i] = make([]byte, 64)
	}
	copy(rows[3][10:], secret) // compressible pixels, so deflate does not store them as they are
	onePiece, chunked := pngOf(64, rows, 0), pngOf(64, rows, 16)
	ztxt := pngChunk("zTXt", append([]byte("Comment\x00\x00"), zlibOf([]byte("seed "+secret), zlib.DefaultCompression)...))
	withText := pngOf(64, rows[:1], 0, ztxt)
	frame := pngChunk("fdAT", append([]byte{0, 0, 0, 1}, zlibOf(append([]byte{0}, bytes.Join(rows, []byte{0})...), zlib.DefaultCompression)...))
	animated := pngOf(64, rows[:1], 0, frame)
	badCRC := bytes.Clone(onePiece)
	idat := bytes.Index(badCRC, []byte("IDAT"))
	n := int(binary.BigEndian.Uint32(badCRC[idat-4:]))
	badCRC[idat+4+n] ^= 0xff
	big := make([][]byte, 3000) // 9,003,000 bytes of pixels, past MaxArchiveBytes
	for i := range big {
		big[i] = make([]byte, 3000)
	}
	cases := []struct {
		name   string
		data   []byte
		found  bool
		pixels bool // some pixel data was skipped
	}{
		{"the pixels' zlib stream alone", zlibOf(append([]byte{0}, bytes.Join(rows, []byte{0})...), zlib.DefaultCompression), true, false},
		{"one IDAT chunk", onePiece, false, true},
		{"IDAT chunks of 16 bytes", chunked, false, true},
		{"one IDAT chunk in a data URI", []byte(`<svg><image href="data:image/png;base64,` + base64.StdEncoding.EncodeToString(onePiece) + `"/></svg>`), false, true},
		{"a zTXt chunk", withText, true, true},
		{"an animated PNG's fdAT frame", animated, false, true},
		{"one IDAT chunk whose CRC does not hold", badCRC, true, false},
		{"a 3000 by 3000 image in one chunk", pngOf(3000, big, 0), false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if bytes.Contains(c.data, []byte(secret)) {
				t.Fatal("the value is in the bytes as written: the case tests nothing")
			}
			res, sc, err := set.scan(context.Background(), []Part{{Where: "files[0].content", Data: c.data, Whole: true}})
			if err != nil {
				t.Fatal(err)
			}
			if got := len(res.Found) > 0; got != c.found {
				t.Errorf("found %v, want %v (%d zlib tries, %d believed)", res.Found, c.found, sc.zlibTried, sc.zlibRead)
			}
			if len(res.Incomplete) > 0 {
				t.Errorf("incomplete: %v", res.Incomplete)
			}
			if got := sc.pngPixelBytes > 0; got != c.pixels {
				t.Errorf("%d bytes of pixel data skipped, want some: %v", sc.pngPixelBytes, c.pixels)
			}
		})
	}
}
