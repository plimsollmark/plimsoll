package withheld

import (
	"bytes"
	"compress/bzip2"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"slices"
)

// Archives (docs/ship-scan.md, "Archives"). An archive is found by its content, at any
// offset of any view, never by its name, which is the caller's (and an archive inside a
// base64 blob or a byte string has none). What it holds comes in two kinds:
//
//   - a decompressed stream (a gzip, bzip2 or zlib stream, a compressed zip member) is
//     new bytes, scanned as a whole file: file entries, values in its views, and archives in
//     those, one level deeper;
//   - a stored member (a tar member, a stored zip member) is a slice of a view the scan
//     already reads, so its values and any archive inside it are found there; it adds
//     the file-entry check alone.
//
// Every bound is per call, shared by its parts, and a bound reached makes the scan
// incomplete for the part it was reached in (Result.Incomplete). So does an archive the
// scan recognizes and cannot read: an encrypted zip member, one of another compression
// method, a GNU sparse tar member or one whose size a PAX header sets, and an xz, zstd,
// 7z or rar archive. A `refuse` entry promises that a call carrying it does not run, and
// what the scan did not read could carry one. What the scan cannot recognize at all
// (raw deflate, a zlib stream whose Adler-32 does not hold) is neither read nor stated:
// the promise holds against mistakes and the shapes the scan can see, not against
// material packed on purpose to pass it.

const (
	// MaxArchiveBytes bounds the bytes a call's archives decompress to, in all: twice
	// the most a call's files may hold (sandbox.MaxProjectBytes). Each such byte gets
	// the full scan, the costly part (docs/ship-scan.md states the measured cost); at
	// 16 MiB a crafted gzip of about 24 KB cost 5.6 s of a core (load average 13).
	MaxArchiveBytes = 8 << 20
	// MaxArchiveMemberBytes bounds the bytes of stored members hashed for file entries,
	// in all. A member costs about 3 ms a megabyte (Normalize, then SHA-256), so this
	// is 0.2 s; the bound keeps headers that claim overlapping contents from making the
	// work quadratic.
	MaxArchiveMemberBytes = 64 << 20
	// MaxArchiveEntries bounds the archives and members a call's scan reads, in all:
	// each costs a header's parse.
	MaxArchiveEntries = 1 << 16
	// MaxArchiveDepth bounds how deep decompressed streams nest. A .tar.gz is one deep
	// (the tar is read in place), and a .tar.gz in a deflated zip member two.
	MaxArchiveDepth = 4
)

// Bound names why a part's archives were not read whole: a bound the scan reached, or an
// archive it recognized and cannot read.
type Bound string

const (
	BoundArchiveBytes Bound = "archive_bytes"
	BoundMemberBytes  Bound = "archive_member_bytes"
	BoundEntries      Bound = "archive_entries"
	BoundDepth        Bound = "archive_depth"

	BoundZipEncrypted Bound = "archive_zip_encrypted"
	BoundZipMethod    Bound = "archive_zip_method"
	BoundTarSparse    Bound = "archive_tar_sparse"
	BoundTarPax       Bound = "archive_tar_pax"
	BoundXZ           Bound = "archive_xz"
	BoundZstd         Bound = "archive_zstd"
	Bound7z           Bound = "archive_7z"
	BoundRar          Bound = "archive_rar"
)

// boundText says each bound in words a refusal can carry.
var boundText = map[Bound]string{
	BoundArchiveBytes: fmt.Sprintf("the call's archives decompress past the scan's %d MiB", MaxArchiveBytes>>20),
	BoundMemberBytes:  fmt.Sprintf("the call's archive members pass the scan's %d MiB", MaxArchiveMemberBytes>>20),
	BoundEntries:      fmt.Sprintf("the call holds more archives and members than the scan's %d", MaxArchiveEntries),
	BoundDepth:        fmt.Sprintf("compressed archives nest more than %d deep", MaxArchiveDepth),
	BoundZipEncrypted: "a zip member is encrypted, which the scan cannot read",
	BoundZipMethod:    "a zip member is compressed by a method the scan does not read (it reads stored, deflate and bzip2)",
	BoundTarSparse:    "a tar member is a GNU sparse file, which the scan does not read",
	BoundTarPax:       "a PAX header sets a tar member's size or layout, which the scan does not apply",
	BoundXZ:           "an xz stream, a format the scan does not read",
	BoundZstd:         "a zstd frame, a format the scan does not read",
	Bound7z:           "a 7z archive, a format the scan does not read",
	BoundRar:          "a rar archive, a format the scan does not read",
}

// Text says the bound in words a refusal can carry.
func (b Bound) Text() string {
	if t, ok := boundText[b]; ok {
		return t
	}
	return string(b)
}

// Incomplete is a part whose archives the scan could not read whole, and why.
type Incomplete struct {
	Where string
	Bound Bound
}

// scanner is one call's scan: the bounds' counts and the decoders, reused.
type scanner struct {
	set     *Set
	ctx     context.Context
	stopped bool        // ctx ended
	found   func(int)   // an entry found, in the current part
	hit     func(Bound) // a bound reached, in the current part
	decoded int         // bytes decompressed, against MaxArchiveBytes
	hashed  int         // member bytes hashed, against MaxArchiveMemberBytes
	entries int         // archives and members read, against MaxArchiveEntries
	gz      gzip.Reader
	fl      io.ReadCloser
	zl      io.ReadCloser // a zlib reader, reset for each try
	zsrc    bytes.Reader  // what a zlib try reads from
	scratch []byte        // what a zlib try longer than the room is read into, and dropped
	// zlibTried counts the zlib headers tried and zlibRead the streams among them that
	// inflated to an Adler-32 that holds; zlibIn and zlibOut are the bytes the rest, the
	// false starts, read and wrote (TestZlibFalseStarts).
	zlibTried, zlibRead, zlibIn, zlibOut int
	// pngPixelBytes counts the bytes of PNG pixel data no zlib try read (pngPixels).
	pngPixelBytes int
	// out is the stream decoded at each depth, reused: one more than the depth bound,
	// since a zlib header at the deepest level is tried before the bound is applied.
	out [MaxArchiveDepth + 2][]byte
	// Source entries (source.go): the whole file being checked (stamp), the stamp each
	// set line was last counted in, each source entry's count and the stamp it is of,
	// and a line normalized, reused.
	stamp              int
	lineSeen           []int
	srcCount, srcStamp []int
	norm               []byte
}

// file checks content, a whole file, against the file entries and the source entries.
func (sc *scanner) file(content []byte) {
	if len(sc.set.files) > 0 {
		if i, ok := sc.set.files[FileDigest(content)]; ok {
			sc.found(i)
		}
	}
	sc.source(content)
}

// wholeFiles reports whether the set has entries that file checks, so a stored archive
// member is worth reading as a file of its own. Every gate on member reading asks this,
// never one kind alone: a new whole-file kind added to file belongs here too, or its
// members go unread (a set of source entries alone was skipped until the 2026-10-29
// public-source scan, finding 1).
func (sc *scanner) wholeFiles() bool {
	return len(sc.set.files) > 0 || len(sc.set.sources) > 0
}

// views scans data, of the given depth, in its views, and looks for archives in each.
// A base64 blob is a file of its own, so the source entries are checked against it
// (scanViews checks the file entries).
func (sc *scanner) views(data []byte, depth int) {
	sc.set.scanViews(data, sc.found, func(v []byte, k viewKind, escaped bitset) {
		if k == viewBase64 {
			sc.source(v)
		}
		sc.archives(v, k, escaped, depth)
	})
}

// minArchive is the shortest archive but a zlib stream: a gzip stream of nothing is 20
// bytes, a zip's end record 22. minZlib is a zlib stream of nothing: its two header
// bytes, an empty final block of two and the Adler-32.
const (
	minArchive = 18
	minZlib    = 8
)

// archives reads the archives in v, a view of a stream of the given depth (a part is
// depth 0). In the escapes view, an archive is read only where an escape produced one
// of its first bytes: one that no escape touched is the same archive the written view
// holds, and reading it twice would spend the bounds on nothing. A tar header is read
// there only where an escape produced one of its 512 bytes: the escapes view of a tar
// written as text that holds an escape is the same tar with its members shifted, and
// its headers, which no escape touched, were read in the written view; a header an
// escape did touch either belongs to a tar written as escapes or no longer sums to its
// checksum.
func (sc *scanner) archives(v []byte, k viewKind, escaped bitset, depth int) {
	if len(v) < minZlib || sc.stopped {
		return
	}
	fresh := func(at int) bool { return escaped == nil || escaped.anyIn(at, min(at+16, len(v))) }
	if len(v) >= minArchive {
		sc.gzips(v, fresh, depth)
		sc.bzip2s(v, fresh, depth)
		sc.zips(v, fresh, depth)
	}
	// A zlib stream of a short value is shorter than any other archive: zlib.compress of
	// a six-digit seed is 14 bytes.
	sc.zlibs(v, fresh, sc.pngPixels(v), depth)
	if len(v) >= minArchive {
		sc.unreadable(v, fresh)
		if sc.wholeFiles() {
			sc.tars(v, func(h int) bool { return k != viewEscapes || escaped.anyIn(h, h+512) })
		}
	}
}

// entry counts one archive or member against MaxArchiveEntries and reports whether
// the scan reads it. It is false for good once the call's context has ended.
func (sc *scanner) entry() bool {
	if sc.stopped {
		return false
	}
	if sc.ctx.Err() != nil {
		sc.stopped = true
		return false
	}
	if sc.entries >= MaxArchiveEntries {
		sc.hit(BoundEntries)
		return false
	}
	sc.entries++
	return true
}

// deeper reports whether a stream decoded from a view of depth may be read, and
// records the bound when it may not.
func (sc *scanner) deeper(depth int) bool {
	if depth >= MaxArchiveDepth {
		sc.hit(BoundDepth)
		return false
	}
	return true
}

// charge counts n bytes against MaxArchiveBytes and reports whether they fit.
func (sc *scanner) charge(n int) bool {
	if n > MaxArchiveBytes-sc.decoded {
		sc.decoded = MaxArchiveBytes
		sc.hit(BoundArchiveBytes)
		return false
	}
	sc.decoded += n
	return true
}

// read decodes r into the stream buffer of depth, at most what is left of
// MaxArchiveBytes, and counts what it decoded. whole is false when the stream was cut
// at the bound. A stream that fails partway (corrupt, cut short) keeps what it decoded;
// err is the error that ended it (io.EOF for a clean end, nil when the bound did).
func (sc *scanner) read(r io.Reader, depth int) (out []byte, whole bool, err error) {
	room := MaxArchiveBytes - sc.decoded
	buf, err := sc.fill(r, depth, room)
	if len(buf) > room {
		sc.decoded = MaxArchiveBytes
		sc.hit(BoundArchiveBytes)
		return buf[:room], false, nil
	}
	sc.decoded += len(buf)
	return buf, true, err
}

// fill decodes r into the stream buffer of depth, at most room+1 bytes (one byte past
// the room says the stream is longer), and counts nothing. err is the error that ended
// it: io.EOF for a clean end, nil when the room did.
func (sc *scanner) fill(r io.Reader, depth, room int) (buf []byte, err error) {
	limit := room + 1
	buf = sc.out[depth][:0]
	for idle := 0; len(buf) < limit && idle < 64; {
		if len(buf) == cap(buf) {
			buf = slices.Grow(buf, min(max(cap(buf), 32<<10), limit-len(buf)))
		}
		var n int
		n, err = r.Read(buf[len(buf):min(cap(buf), limit)])
		buf = buf[:len(buf)+n]
		if err != nil {
			break
		}
		if n == 0 {
			idle++
		}
	}
	sc.out[depth] = buf[:0]
	return buf, err
}

// stream scans a decompressed stream of the given depth as a whole file: file entries
// (when it was not cut at the bound), values in its views, archives in those.
func (sc *scanner) stream(out []byte, whole bool, depth int) {
	if len(out) == 0 {
		return
	}
	if whole {
		sc.file(out)
	}
	sc.views(out, depth)
}

// member checks a stored member against the file and source entries, within
// MaxArchiveMemberBytes.
func (sc *scanner) member(content []byte) {
	if !sc.wholeFiles() || len(content) == 0 {
		return
	}
	if len(content) > MaxArchiveMemberBytes-sc.hashed {
		sc.hashed = MaxArchiveMemberBytes
		sc.hit(BoundMemberBytes)
		return
	}
	sc.hashed += len(content)
	sc.file(content)
}

var gzipMagic = []byte{0x1f, 0x8b, 0x08}

// gzips reads every gzip stream in v: members written one after another are one
// stream, as gunzip reads them. A signature inside a member that decoded cleanly is in
// its compressed bytes (by chance, or in a stored block, whose bytes are in the output
// anyway) and is not read again; one after a member that failed is, so a broken stream
// cannot hide the next one.
func (sc *scanner) gzips(v []byte, fresh func(int) bool, depth int) {
	for i, next := 0, 0; i < len(v); {
		j := bytes.Index(v[i:], gzipMagic)
		if j < 0 {
			return
		}
		at := i + j
		i = at + 1
		if at < next || len(v)-at < minArchive || !gzipHeader(v[at:]) || !fresh(at) {
			continue
		}
		if !sc.entry() {
			return
		}
		if !sc.deeper(depth) {
			continue
		}
		c := gzipChain{v: v, gz: &sc.gz, good: at, more: sc.entry}
		if !c.start(at) {
			continue
		}
		out, whole, _ := sc.read(&c, depth+1)
		next = c.good
		sc.stream(out, whole, depth+1)
	}
}

// gzipChain reads the gzip members that start at v[start:] one after another, each
// with Multistream off, so it knows where each member ends: good is the end of the
// last member that ended cleanly (its trailer checked). Each member after the first
// is one more entry (more), so a chain of empty members is bounded like separate ones.
type gzipChain struct {
	v    []byte
	src  bytes.Reader
	gz   *gzip.Reader
	good int
	more func() bool
}

// start begins a member at v[at:] and reports whether its header is one gzip reads.
func (c *gzipChain) start(at int) bool {
	c.src.Reset(c.v[at:])
	if c.gz.Reset(&c.src) != nil {
		return false
	}
	c.gz.Multistream(false)
	return true
}

func (c *gzipChain) Read(p []byte) (int, error) {
	for {
		n, err := c.gz.Read(p)
		if err != io.EOF {
			return n, err
		}
		c.good = len(c.v) - c.src.Len()
		if n > 0 {
			return n, nil
		}
		at := c.good
		if len(c.v)-at < minArchive || !bytes.HasPrefix(c.v[at:], gzipMagic) || !gzipHeader(c.v[at:]) || !c.more() || !c.start(at) {
			return 0, io.EOF
		}
	}
}

// gzipHeader reports whether h starts a gzip header the scan reads: the reserved flag
// bits clear, and an extra field, when there is one, within h (compress/gzip allocates
// its stated length before reading it).
func gzipHeader(h []byte) bool {
	flags := h[3]
	if flags&0xe0 != 0 {
		return false
	}
	if flags&0x04 != 0 {
		return len(h) >= 12 && 12+int(binary.LittleEndian.Uint16(h[10:])) <= len(h)
	}
	return true
}

// zlibs reads every zlib stream in v (RFC 1950: two header bytes, deflate data, the
// Adler-32 of what it inflates to), as Python's zlib.compress writes one. Two bytes are
// too short a signature to tell from text ("x^" is a valid header, and so is "(S"), so
// a stream is believed only once it has been read: a header with the deflate method, a
// window of at most 32 KiB, its check bits and no preset dictionary (which a reader
// without the dictionary cannot inflate), then deflate data that inflates to its end and
// an Adler-32 that holds, which compress/zlib checks. Anything else is a false start,
// neither read nor stated.
//
// Every try counts against the bounds. It is one entry. A stream believed is charged
// what it wrote against MaxArchiveBytes, as a gzip stream is, and scanned. A false
// start's output is never scanned, only inflated, which costs about what hashing a
// stored member does, so what it wrote counts against MaxArchiveMemberBytes, and what it
// read against MaxArchiveBytes (a stream of empty blocks writes nothing, and inflating
// such input is the slow kind). Without that split, a PNG image's pixels, a zlib stream
// cut into chunks that inflates almost to its end before it fails, took 2 MB of the 8
// MiB from a page of 114 KB. A try that a bound stops before it ends is the bound
// reached, since it could be a stream. A header inside a stream believed is part of it
// and is not tried again; one inside a false start is. No header inside a PNG image's
// pixel data (skip, from pngPixels) is tried.
func (sc *scanner) zlibs(v []byte, fresh func(int) bool, skip [][2]int, depth int) {
	for at, next, s := 0, 0, 0; at+minZlib <= len(v); at++ {
		for s < len(skip) && skip[s][1] <= at {
			s++
		}
		if s < len(skip) && at >= skip[s][0] {
			at = skip[s][1] - 1
			continue
		}
		if at < next || !zlibHeader(v[at:]) || !fresh(at) {
			continue
		}
		if !sc.entry() {
			return
		}
		room, spare := MaxArchiveBytes-sc.decoded, MaxArchiveMemberBytes-sc.hashed
		switch {
		case room < minZlib: // too little left to try even a stream of nothing
			sc.hit(BoundArchiveBytes)
			return
		case spare < minZlib:
			sc.hit(BoundMemberBytes)
			return
		}
		in := v[at:min(len(v), at+room)]
		sc.zsrc.Reset(in)
		var err error
		if sc.zl == nil {
			sc.zl, err = zlib.NewReader(&sc.zsrc)
		} else {
			err = sc.zl.(zlib.Resetter).Reset(&sc.zsrc, nil)
		}
		if err != nil {
			continue
		}
		sc.zlibTried++
		out, err := sc.fill(sc.zl, depth+1, room)
		wrote := len(out)
		if wrote > room && wrote <= spare {
			// Longer than the room: read on without keeping it, to learn whether it is a
			// stream, while what it writes still fits the member bound.
			var n int
			n, err = sc.drain(sc.zl, spare-wrote)
			wrote += n
		}
		used := len(in) - sc.zsrc.Len()
		switch {
		case err == io.EOF && wrote <= room: // believed, and read whole
			sc.zlibRead++
			next = at + used
			sc.decoded += wrote
			if sc.deeper(depth) {
				sc.stream(out, true, depth+1)
			}
		case err == io.EOF: // believed, and longer than the bound: what fits is scanned
			sc.zlibRead++
			next = at + used
			sc.decoded = MaxArchiveBytes
			sc.hashed += wrote - room - 1
			sc.hit(BoundArchiveBytes)
			if sc.deeper(depth) {
				sc.stream(out[:room], false, depth+1)
			}
		case wrote > room && err == nil:
			// Neither ended nor failed within the member bound: it may be a stream.
			sc.hashed = MaxArchiveMemberBytes
			sc.hit(BoundMemberBytes)
		case used == len(in) && len(in) < len(v)-at:
			// It wanted more input than the room left: it may be a stream.
			sc.decoded = MaxArchiveBytes
			sc.hit(BoundArchiveBytes)
		default: // a false start
			sc.decoded += used
			sc.zlibIn += used
			if wrote > spare {
				sc.hashed = MaxArchiveMemberBytes
				sc.hit(BoundMemberBytes)
			} else {
				sc.hashed += wrote
				sc.zlibOut += wrote
			}
		}
	}
}

var pngMagic = []byte("\x89PNG\r\n\x1a\n")

// pngPixels returns the spans of v that hold a PNG image's pixel data, in order: the data
// of each IDAT chunk, and of each fdAT chunk (an animated PNG's frames), whose CRC-32
// holds. The scan reads no zlib stream there (docs/ship-scan.md, "Not read"): pixels are
// one zlib stream cut across chunks, so the scan could read them only from an image
// written as one chunk, and there one large image made a harmless call incomplete. The
// image's other chunks are read as before, a compressed text chunk (zTXt, iTXt) among
// them. A chunk is walked only while its length fits what is left of v, and a span only
// where its CRC holds, so a signature in text, or a chunk cut short or altered, skips
// nothing. A signature inside an image already walked is not walked again, so the walk
// reads each byte of v at most once.
func (sc *scanner) pngPixels(v []byte) [][2]int {
	var spans [][2]int
	for from := 0; ; {
		i := bytes.Index(v[from:], pngMagic)
		if i < 0 {
			return spans
		}
		at := from + i + len(pngMagic)
		for at+12 <= len(v) {
			n := binary.BigEndian.Uint32(v[at:])
			if n > 1<<31-1 || int64(n) > int64(len(v)-at-12) {
				break
			}
			end := at + 12 + int(n)
			kind := string(v[at+4 : at+8])
			if kind == "IDAT" || kind == "fdAT" {
				if crc32.ChecksumIEEE(v[at+4:end-4]) != binary.BigEndian.Uint32(v[end-4:]) {
					break
				}
				spans = append(spans, [2]int{at + 8, end - 4})
				sc.pngPixelBytes += int(n)
			}
			at = end
			if kind == "IEND" {
				break
			}
		}
		from = at
	}
}

// drain reads r into a scratch buffer, keeping nothing, until it ends or writes more
// than limit bytes; err is the error that ended it, nil when the limit did.
func (sc *scanner) drain(r io.Reader, limit int) (n int, err error) {
	if sc.scratch == nil {
		sc.scratch = make([]byte, 32<<10)
	}
	for idle := 0; n <= limit && idle < 64; {
		var k int
		k, err = r.Read(sc.scratch[:min(len(sc.scratch), limit-n+1)])
		n += k
		if err != nil {
			return n, err
		}
		if k == 0 {
			idle++
		}
	}
	return n, nil
}

// zlibHeader reports whether h starts a zlib header the scan tries: CM 8 (deflate),
// CINFO at most 7, FDICT clear, and the two bytes a multiple of 31 (FCHECK).
func zlibHeader(h []byte) bool {
	return h[0]&0x0f == 8 && h[0]>>4 <= 7 && h[1]&0x20 == 0 && (uint16(h[0])<<8|uint16(h[1]))%31 == 0
}

var bzip2Magic = []byte("BZh")

// bzip2s reads every bzip2 stream in v (compress/bzip2 reads streams written one after
// another as one). A stream is charged its block size when it starts, since
// compress/bzip2 allocates four bytes for each byte of it whatever the stream holds. As
// for gzip, a signature inside a stream that decoded cleanly is not read again, and one
// after a stream that failed is.
func (sc *scanner) bzip2s(v []byte, fresh func(int) bool, depth int) {
	for i, next := 0, 0; i < len(v); {
		j := bytes.Index(v[i:], bzip2Magic)
		if j < 0 {
			return
		}
		at := i + j
		i = at + 1
		if at < next || !bzip2Header(v[at:]) || !fresh(at) {
			continue
		}
		if !sc.entry() {
			return
		}
		if !sc.deeper(depth) || !sc.charge(int(v[at+3]-'0')*100_000) {
			continue
		}
		src := bytes.NewReader(v[at:])
		out, whole, err := sc.read(bzip2.NewReader(src), depth+1)
		switch end := len(v) - src.Len(); {
		case err == io.EOF:
			next = end
		case err == errBzip2NextStream:
			next = end - 2 // the two bytes it read for the next stream's BZ are not its own
		}
		sc.stream(out, whole, depth+1)
	}
}

// errBzip2NextStream is compress/bzip2's error when the bytes after a whole stream do not
// start another (it reads two of them, for BZ).
const errBzip2NextStream = bzip2.StructuralError("bad magic value in continuation file")

// bzip2Header reports whether h starts a bzip2 stream holding a block: BZh, the level
// (1 to 9) and the block magic.
func bzip2Header(h []byte) bool {
	return len(h) >= 10 && h[3] >= '1' && h[3] <= '9' && string(h[4:10]) == "1AY&SY"
}

var zipEnd = []byte("PK\x05\x06")

// zips reads every zip in v through its central directory, as unzip, Python and Go
// read one: each end-of-central-directory record found is one archive. Then it reads
// each member that no directory it read lists from its local header (zipLocals).
func (sc *scanner) zips(v []byte, fresh func(int) bool, depth int) {
	var listed map[int]bool // the local headers the directories read list
	for i := 0; i < len(v); {
		j := bytes.Index(v[i:], zipEnd)
		if j < 0 {
			break
		}
		at := i + j
		i = at + 1
		if len(v)-at < 22 || !fresh(at) {
			continue
		}
		if listed == nil {
			listed = map[int]bool{}
		}
		if !sc.entry() || !sc.zip(v, at, depth, listed) {
			return // a bound or the context cut it: the part is incomplete already
		}
	}
	sc.zipLocals(v, fresh, depth, listed)
}

var zipLocal = []byte("PK\x03\x04")

// zipLocals reads every zip member in v that no central directory the scan read lists,
// from its local header, as readers that walk a zip's local headers one after another
// (bsdtar, Java's ZipInputStream) read it: the members of a zip cut short before its
// directory, of one whose directory is broken, or one its directory leaves out. Each is
// one entry. A member whose sizes follow its data (flag bit 3) is read to its end: a
// compressed stream ends itself, and a stored one at a data descriptor (zipStoredEnds).
func (sc *scanner) zipLocals(v []byte, fresh func(int) bool, depth int, listed map[int]bool) {
	le := binary.LittleEndian
	for i := 0; i < len(v); {
		j := bytes.Index(v[i:], zipLocal)
		if j < 0 {
			return
		}
		at := i + j
		i = at + 1
		if listed[at] || !fresh(at) || !zipLocalHeader(v[at:]) {
			continue
		}
		if !sc.entry() {
			return
		}
		h := v[at:]
		extra := at + 30 + int(le.Uint16(h[26:])) // after the name
		data := extra + int(le.Uint16(h[28:]))
		if data > len(v) {
			continue
		}
		m := zipEntry{flags: le.Uint16(h[6:]), method: le.Uint16(h[8:]), size: uint64(le.Uint32(h[18:]))}
		if m.size == 0xffffffff {
			m.zip64(v[extra:data], le.Uint32(h[22:]) == 0xffffffff)
		}
		later := m.flags&8 != 0 // the sizes are in a data descriptor after the data
		if !sc.zipReadable(m, later) {
			continue
		}
		if later {
			sc.zipData(v[data:], m.method, true, depth)
		} else if m.size <= uint64(len(v)-data) {
			sc.zipData(v[data:data+int(m.size)], m.method, false, depth)
		} else {
			sc.zipData(v[data:], m.method, true, depth)
		}
	}
}

// zipLocalHeader reports whether h starts a local file header a zip reader takes: its
// fixed 30 bytes, a version needed of at most 6.3 and a method under 256. Both put a
// zero byte where text holds none, so code that spells the signature in a string, even
// with its escapes decoded, is not taken for a zip.
func zipLocalHeader(h []byte) bool {
	return len(h) >= 30 && binary.LittleEndian.Uint16(h[4:]) <= 63 && binary.LittleEndian.Uint16(h[8:]) < 256
}

// zip reads the zip whose end record is at v[eocd:], and records in listed the local
// header of every member its directory lists. The central directory ends where the end
// record (or the zip64 end record) starts; bytes before the archive (a self-extracting
// stub) shift every offset, as archive/zip allows. It is false when a bound or the
// context stopped it partway.
func (sc *scanner) zip(v []byte, eocd, depth int, listed map[int]bool) bool {
	e := v[eocd:]
	cdSize := uint64(binary.LittleEndian.Uint32(e[12:]))
	cdOff := uint64(binary.LittleEndian.Uint32(e[16:]))
	cdEnd := eocd
	if binary.LittleEndian.Uint16(e[10:]) == 0xffff || cdSize == 0xffffffff || cdOff == 0xffffffff {
		// Perhaps zip64: a locator just before the end record points at the zip64 end
		// record. Without one, the 32-bit fields stand, as archive/zip reads them (a zip
		// of exactly 65,535 members states 0xffff and is not zip64).
		if eocd >= 20 && string(v[eocd-20:eocd-16]) == "PK\x06\x07" {
			at := binary.LittleEndian.Uint64(v[eocd-12:])
			if at > uint64(eocd-20) || uint64(eocd-20)-at < 56 || string(v[at:at+4]) != "PK\x06\x06" {
				return true
			}
			r := v[at:]
			cdSize = binary.LittleEndian.Uint64(r[40:])
			cdOff = binary.LittleEndian.Uint64(r[48:])
			cdEnd = int(at)
		}
	}
	if cdSize > uint64(cdEnd) {
		return true
	}
	cdStart := cdEnd - int(cdSize)
	if cdOff > uint64(cdStart) {
		return true
	}
	base := cdStart - int(cdOff)
	if base > 0 && zipCentral(v, int(cdOff)) {
		// archive/zip's rule for an end record that misstates the prefix: a directory
		// entry where the stated offset points, unshifted, wins.
		base, cdStart = 0, int(cdOff)
	}
	for p := cdStart; zipCentral(v, p); {
		if !sc.entry() {
			return false
		}
		h := v[p : p+46]
		end := p + 46 + int(binary.LittleEndian.Uint16(h[28:])) + int(binary.LittleEndian.Uint16(h[30:])) + int(binary.LittleEndian.Uint16(h[32:]))
		if end > len(v) {
			return true
		}
		m := zipEntry{
			flags:  binary.LittleEndian.Uint16(h[8:]),
			method: binary.LittleEndian.Uint16(h[10:]),
			size:   uint64(binary.LittleEndian.Uint32(h[20:])),
			local:  uint64(binary.LittleEndian.Uint32(h[42:])),
		}
		if m.size == 0xffffffff || m.local == 0xffffffff {
			nameEnd := p + 46 + int(binary.LittleEndian.Uint16(h[28:]))
			m.zip64(v[nameEnd:nameEnd+int(binary.LittleEndian.Uint16(h[30:]))], binary.LittleEndian.Uint32(h[24:]) == 0xffffffff)
		}
		sc.zipMember(v, base, m, depth, listed)
		p = end
	}
	return true
}

// zipCentral reports whether a central directory entry's fixed part is at v[p:].
func zipCentral(v []byte, p int) bool {
	return p >= 0 && len(v)-p >= 46 && string(v[p:p+4]) == "PK\x01\x02"
}

// zipEntry is what a central directory entry says of its member.
type zipEntry struct {
	flags, method uint16
	size, local   uint64 // compressed size; the local header's offset
}

// zip64 reads the 64-bit fields of a zip64 extra field (ID 1): each is there only when
// its 32-bit field is 0xffffffff, in the order uncompressed size, compressed size,
// local header offset.
func (m *zipEntry) zip64(extra []byte, usize bool) {
	for len(extra) >= 4 {
		id, n := binary.LittleEndian.Uint16(extra), int(binary.LittleEndian.Uint16(extra[2:]))
		if n > len(extra)-4 {
			return
		}
		f := extra[4 : 4+n]
		extra = extra[4+n:]
		if id != 1 {
			continue
		}
		take := func(v *uint64) {
			if *v == 0xffffffff && len(f) >= 8 {
				*v, f = binary.LittleEndian.Uint64(f), f[8:]
			}
		}
		if usize && len(f) >= 8 {
			f = f[8:]
		}
		take(&m.size)
		take(&m.local)
		return
	}
}

// zipMember reads one member its central directory lists: a stored one is checked
// against the file and source entries, a deflated or bzip2 one decompressed and scanned as a
// stream (zipData). Its local header, when there is one where the directory says, is
// listed. An encrypted member, or one of another method, is not read (zipReadable).
func (sc *scanner) zipMember(v []byte, base int, m zipEntry, depth int, listed map[int]bool) {
	readable := sc.zipReadable(m, false)
	if m.local > uint64(len(v)) {
		return
	}
	lh := base + int(m.local)
	if lh < 0 || len(v)-lh < 30 || string(v[lh:lh+4]) != "PK\x03\x04" {
		return
	}
	listed[lh] = true
	data := lh + 30 + int(binary.LittleEndian.Uint16(v[lh+26:])) + int(binary.LittleEndian.Uint16(v[lh+28:]))
	if !readable || data > len(v) {
		return
	}
	if m.size <= uint64(len(v)-data) {
		sc.zipData(v[data:data+int(m.size)], m.method, false, depth)
	} else {
		sc.zipData(v[data:], m.method, true, depth)
	}
}

// zipReadable reports whether the scan reads a member: not encrypted, and stored,
// deflate or bzip2. One it does not read makes the part incomplete, unless it holds no
// bytes (a size of 0 the reader goes by, not one that later says follows the data).
func (sc *scanner) zipReadable(m zipEntry, later bool) bool {
	switch {
	case m.flags&1 != 0:
		sc.hit(BoundZipEncrypted)
		return false
	case m.method == 0 || m.method == 8 || m.method == 12:
		return true
	case m.size > 0 || later:
		sc.hit(BoundZipMethod)
	}
	return false
}

// zipData reads a member's data: stored bytes are checked against the file and source entries,
// a deflate or bzip2 stream is decompressed and scanned as a stream. open says the data
// runs past what holds it (cut short, or its size not known): a compressed stream is
// read to its own end, and stored bytes are checked where a data descriptor ends them
// (zipStoredEnds).
func (sc *scanner) zipData(content []byte, method uint16, open bool, depth int) {
	switch method {
	case 0:
		if open {
			sc.zipStoredEnds(content)
		} else {
			sc.member(content)
		}
	case 8:
		if !sc.deeper(depth) {
			return
		}
		src := bytes.NewReader(content)
		if sc.fl == nil {
			sc.fl = flate.NewReader(src)
		} else if sc.fl.(flate.Resetter).Reset(src, nil) != nil {
			return
		}
		out, whole, _ := sc.read(sc.fl, depth+1)
		sc.stream(out, whole, depth+1)
	case 12:
		if !bzip2Header(content) || !sc.deeper(depth) || !sc.charge(int(content[3]-'0')*100_000) {
			return
		}
		out, whole, _ := sc.read(bzip2.NewReader(bytes.NewReader(content)), depth+1)
		sc.stream(out, whole, depth+1)
	}
}

var zipDescriptor = []byte("PK\x07\x08")

// zipStoredEnds checks a stored member whose size follows its data against the file
// entries where a reader ends it: libarchive (bsdtar) ends it at the first data
// descriptor whose CRC-32 is that of the bytes before it, or, told to ignore CRCs, at
// the first descriptor signature at all; both are checked. The bytes the CRC-32 is
// computed over count against MaxArchiveMemberBytes, as hashed bytes do.
func (sc *scanner) zipStoredEnds(content []byte) {
	var crc uint32
	done, first := 0, true
	for i := 0; i < len(content); {
		j := bytes.Index(content[i:], zipDescriptor)
		if j < 0 || len(content)-(i+j) < 8 {
			return
		}
		at := i + j
		i = at + 1
		if at-done > MaxArchiveMemberBytes-sc.hashed {
			sc.hashed = MaxArchiveMemberBytes
			sc.hit(BoundMemberBytes)
			return
		}
		sc.hashed += at - done
		crc = crc32.Update(crc, crc32.IEEETable, content[done:at])
		match := binary.LittleEndian.Uint32(content[at+4:]) == crc
		done = at
		if first || match {
			sc.member(content[:at])
		}
		if match {
			return
		}
		first = false
	}
}

// unreadFormats are the archives the scan recognizes and cannot read, since Go's
// standard library has no package for them a program can import (the toolchain's zstd
// decoder is internal to it) and the scan takes no dependency outside the library:
// each by its signature and the bytes after it that the format's own reader requires,
// so that code spelling a signature in a string (a format sniffer, this file) is not
// taken for an archive, even with its escapes decoded.
var unreadFormats = []struct {
	magic  []byte
	bound  Bound
	header func(h []byte) bool // h starts with magic
}{
	{[]byte("\xfd7zXZ\x00"), BoundXZ, xzHeader},
	{[]byte("\x28\xb5\x2f\xfd"), BoundZstd, zstdHeader},
	{[]byte("7z\xbc\xaf\x27\x1c"), Bound7z, sevenZipHeader},
	{[]byte("Rar!\x1a\x07"), BoundRar, rarHeader},
}

// unreadable marks the part incomplete for each format of unreadFormats found in v.
func (sc *scanner) unreadable(v []byte, fresh func(int) bool) {
	for _, f := range unreadFormats {
		for i := 0; i < len(v); {
			j := bytes.Index(v[i:], f.magic)
			if j < 0 {
				break
			}
			at := i + j
			i = at + 1
			if fresh(at) && f.header(v[at:]) {
				sc.hit(f.bound)
				break
			}
		}
	}
}

// xzHeader: the stream flags (a zero byte, then a check type of 0 to 15) and their
// CRC-32, which xz and liblzma check before reading on.
func xzHeader(h []byte) bool {
	return len(h) >= 12 && h[6] == 0 && h[7] < 16 && crc32.ChecksumIEEE(h[6:8]) == binary.LittleEndian.Uint32(h[8:])
}

// zstdHeader: a frame header descriptor with its reserved bit clear, and after the
// header the first block's: not of the reserved type, at most 128 KiB (RFC 8878).
func zstdHeader(h []byte) bool {
	if len(h) < 5 || h[4]&0x08 != 0 {
		return false
	}
	fhd := h[4]
	single := fhd&0x20 != 0
	n := 5 + []int{0, 1, 2, 4}[fhd&3]
	if !single {
		n++ // the window descriptor
	}
	switch fcs := fhd >> 6; {
	case fcs > 0:
		n += 1 << fcs // 2, 4 or 8 bytes
	case single:
		n++
	}
	if len(h) < n+3 {
		return false
	}
	block := uint32(h[n]) | uint32(h[n+1])<<8 | uint32(h[n+2])<<16
	return (block>>1)&3 != 3 && block>>3 <= 128<<10
}

// sevenZipHeader: the format's major version, 0 in every 7z archive, and the start
// header's CRC-32 over the 20 bytes after it, which 7-Zip checks before reading on, or
// those 20 bytes all zero, as an archive whose writing never finished leaves them.
func sevenZipHeader(h []byte) bool {
	if len(h) < 32 || h[6] != 0 {
		return false
	}
	return crc32.ChecksumIEEE(h[12:32]) == binary.LittleEndian.Uint32(h[8:]) || !slices.ContainsFunc(h[8:32], func(c byte) bool { return c != 0 })
}

// rarHeader: the rest of the signature and the first header's type: RAR 4 (signature
// ending 0x00, then the main archive header, type 0x73, whose size is under 8 KiB or
// whose 16-bit CRC holds, as one carrying a long comment does) or RAR 5 (ending 0x01
// 0x00, then a CRC-32, a header size of one to three bytes and type 1, the main archive
// header, or 4, the archive encryption header).
func rarHeader(h []byte) bool {
	if len(h) >= 14 && h[6] == 0 {
		if h[9] != 0x73 {
			return false
		}
		size := 7 + int(binary.LittleEndian.Uint16(h[12:]))
		return h[13] < 0x20 || size <= len(h) && uint16(crc32.ChecksumIEEE(h[9:size])) == binary.LittleEndian.Uint16(h[7:])
	}
	if len(h) < 14 || h[6] != 1 || h[7] != 0 {
		return false
	}
	p := 12
	for k := 0; k < 2 && h[p]&0x80 != 0 && p+1 < len(h); k++ {
		p++
	}
	return h[p]&0x80 == 0 && p+1 < len(h) && (h[p+1] == 1 || h[p+1] == 4)
}

var tarMagic = []byte("ustar")

// tars checks every tar member in v against the file and source entries: every 512-byte header
// with the ustar magic (POSIX's, GNU's) and a valid checksum, anywhere, is a member,
// and its content is the size bytes after it. So a tar inside a tar member, or one
// after other bytes, is read too. read says whether the header at an offset is read in
// this view. A GNU sparse member, and a PAX header that sets the next member's size or
// layout, make the part incomplete: tar extracts those members from bytes other than
// the size after the header.
func (sc *scanner) tars(v []byte, read func(h int) bool) {
	for i := 0; i < len(v); {
		j := bytes.Index(v[i:], tarMagic)
		if j < 0 {
			return
		}
		at := i + j
		i = at + 1
		h := at - 257
		if h < 0 || len(v)-h < 512 || !read(h) {
			continue
		}
		hdr := v[h : h+512]
		if hdr[262] != 0 && hdr[262] != ' ' {
			continue
		}
		sum, ok := tarOctal(hdr[148:156])
		if !ok {
			continue
		}
		if !sc.entry() {
			return
		}
		if !tarChecksum(hdr, sum) {
			continue
		}
		size, ok := tarSize(hdr[124:136])
		cut := !ok || size > uint64(len(v)-h-512) // one past the bytes is cut short
		switch typ := hdr[156]; typ {
		case '0', 0, '7':
			if !cut {
				sc.member(v[h+512 : h+512+int(size)])
			}
		case 'S':
			sc.hit(BoundTarSparse)
		case 'x', 'g':
			if !cut && tarPaxSetsSize(v[h+512:h+512+int(size)]) {
				sc.hit(BoundTarPax)
			}
		}
		// Anything else is not a regular file: a directory, a link, a GNU long name.
	}
}

// tarPaxSetsSize reports whether a PAX header's records set a member's size or its
// GNU sparse layout ("<length> size=<n>\n", "<length> GNU.sparse.map=..."). A record
// is read by the key after its length's space; a value holding such text is taken for
// one, which can only make the scan say it did not read a member it did.
func tarPaxSetsSize(records []byte) bool {
	return bytes.Contains(records, []byte(" size=")) || bytes.Contains(records, []byte(" GNU.sparse."))
}

// tarSize reads a tar header's size field: octal (tarOctal), or the base-256 form GNU
// tar writes for 8 GiB or more and GNU tar and Python read for any size: a first byte
// of 0x80, then the number big-endian.
func tarSize(f []byte) (uint64, bool) {
	if f[0] != 0x80 {
		return tarOctal(f)
	}
	var n uint64
	for _, c := range f[1:] {
		if n > 1<<52 {
			return 0, false
		}
		n = n<<8 | uint64(c)
	}
	return n, true
}

// tarOctal reads a tar header's octal number: digits after any spaces, ended by the
// field's end, a space or a NUL. ok is false for anything else, a size in base 256
// (8 GiB or more) included.
func tarOctal(f []byte) (n uint64, ok bool) {
	i := 0
	for i < len(f) && f[i] == ' ' {
		i++
	}
	digits := 0
	for ; i < len(f) && f[i] >= '0' && f[i] <= '7'; i++ {
		if n > 1<<60 {
			return 0, false
		}
		n = n<<3 | uint64(f[i]-'0')
		digits++
	}
	if digits == 0 {
		return 0, false
	}
	for ; i < len(f); i++ {
		if f[i] != ' ' && f[i] != 0 {
			return 0, false
		}
	}
	return n, true
}

// tarChecksum reports whether sum is hdr's checksum: the sum of its bytes with the
// checksum field read as spaces, unsigned or (as some old tars wrote it) signed.
func tarChecksum(hdr []byte, sum uint64) bool {
	var unsigned, signed int64
	for i, c := range hdr {
		if i >= 148 && i < 156 {
			c = ' '
		}
		unsigned += int64(c)
		signed += int64(int8(c))
	}
	return int64(sum) == unsigned || int64(sum) == signed
}
