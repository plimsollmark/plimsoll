package withheld

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
)

// The ship scan over a container image, as `docker save` writes it: one tar holding an
// OCI image layout (index.json, blobs/sha256/...) or Docker's older layout
// (manifest.json, <id>/layer.tar). Every member that is itself a tar, plain or gzip, is a
// layer, and every regular file in it is scanned on its own, as a call carrying that file
// would be; every other member (the image configuration with its environment, labels and
// build history, the manifests) is scanned whole. Each layer is read, not only the image's
// final filesystem, so a file a later layer deletes is still found: it is still in the
// image's bytes, and anyone holding the image can read it.

// MaxImageFileBytes bounds the bytes read of one file of an image (a layer's file, or a
// configuration or manifest member). A larger file is scanned up to the bound and
// reported incomplete. 64 MiB is the scan's bound on a call's hashed archive members
// (MaxArchiveMemberBytes): no call the daemon scans holds a file larger.
const MaxImageFileBytes = 64 << 20

// BoundImageFileBytes is a file of an image larger than MaxImageFileBytes.
const BoundImageFileBytes Bound = "image_file_bytes"

func init() {
	boundText[BoundImageFileBytes] = fmt.Sprintf("a file of the image is larger than the scan's %d MiB", MaxImageFileBytes>>20)
}

// ImageResult is what an image scan found, and how much it read.
type ImageResult struct {
	Result
	Layers int // layer archives read
	Files  int // regular files scanned, layers' and the archive's own
	// Unreadable holds, for every part of Result.Incomplete, the file that held it and
	// that file's whole size (known.go): the evidence a known-unreadable list is checked
	// against. A file the scan gave up on for two reasons is listed once for each.
	Unreadable []Unreadable
}

// ScanImage scans an image archive (`docker save`) against s: each layer's regular files
// on their own, each with its path, and every other member whole. A finding's Where names
// the archive member and, for a layer's file, its path in the layer ("blobs/sha256/ab12...:
// usr/src/harness/sim.py"). A layer compressed with zstd, which the scan does not read, is
// reported incomplete. It stops with ctx's error when ctx ends.
func (s *Set) ScanImage(ctx context.Context, archive io.Reader) (ImageResult, error) {
	var out ImageResult
	m := newMerge()
	tr := tar.NewReader(archive)
	for {
		if err := ctx.Err(); err != nil {
			return ImageResult{}, err
		}
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ImageResult{}, fmt.Errorf("reading the image archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		br := bufio.NewReaderSize(tr, 64<<10)
		layer, kind, err := openLayer(br)
		if err != nil {
			return ImageResult{}, fmt.Errorf("reading %s of the image archive: %w", CleanWhere(h.Name), err)
		}
		switch kind {
		case layerTar:
			out.Layers++
			if err := s.scanLayer(ctx, h.Name, layer, &out, m); err != nil {
				return ImageResult{}, err
			}
		case layerZstd:
			out.Layers++
			inc := []Incomplete{{Where: CleanWhere(h.Name), Bound: BoundZstd}}
			m.add(Result{Incomplete: inc})
			m.unreadable(unreadableKey(h.Name), h.Size, inc)
		default:
			if err := s.scanFile(ctx, CleanWhere(h.Name), unreadableKey(h.Name), h.Name, h.Size, layer, &out, m); err != nil {
				return ImageResult{}, err
			}
		}
	}
	seenUnread := map[unreadableID]bool{}
	for _, u := range m.unread {
		id := unreadableID{u.Key, u.Reason}
		if seenUnread[id] {
			return ImageResult{}, fmt.Errorf("image archive repeats unreadable file %s (%s)", CleanWhere(u.Key), u.Reason)
		}
		seenUnread[id] = true
	}
	out.Result = m.result()
	out.Unreadable = m.unread
	return out, nil
}

type layerKind int

const (
	notLayer layerKind = iota
	layerTar
	layerZstd
)

// openLayer reports whether r holds a layer (a tar, plain or gzip; or a zstd stream) and
// returns the reader to read it from: decompressed for gzip, r itself otherwise.
func openLayer(r *bufio.Reader) (io.Reader, layerKind, error) {
	head, _ := r.Peek(4)
	switch {
	case len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b:
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, notLayer, err
		}
		inner := bufio.NewReaderSize(gz, 64<<10)
		if isTar(inner) {
			return inner, layerTar, nil
		}
		return inner, notLayer, nil
	case len(head) == 4 && bytes.Equal(head, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return r, layerZstd, nil
	case isTar(r):
		return r, layerTar, nil
	}
	return r, notLayer, nil
}

// isTar reports whether r begins with a tar header (the ustar magic at offset 257).
func isTar(r *bufio.Reader) bool {
	head, _ := r.Peek(263)
	return len(head) == 263 && bytes.Equal(head[257:262], []byte("ustar"))
}

// scanLayer scans every regular file of one layer, and every other member's path (a
// symbolic link's target too, a deleted file's whiteout name). rawLayer is the layer's
// member name in the image archive, as written.
func (s *Set) scanLayer(ctx context.Context, rawLayer string, layer io.Reader, out *ImageResult, m *merge) error {
	layerName := CleanWhere(rawLayer)
	tr := tar.NewReader(layer)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading layer %s: %w", layerName, err)
		}
		where := layerName + ":" + CleanWhere(h.Name)
		key := unreadableKey(rawLayer, h.Name)
		switch h.Typeflag {
		case tar.TypeReg:
			if err := s.scanFile(ctx, where, key, h.Name, h.Size, tr, out, m); err != nil {
				return err
			}
		default:
			parts := []Part{{Where: where + " (path)", Data: []byte(h.Name)}}
			if h.Linkname != "" {
				parts = append(parts, Part{Where: where + " (link target)", Data: []byte(h.Linkname)})
			}
			res, err := s.Scan(ctx, parts)
			if err != nil {
				return err
			}
			m.add(res)
			m.unreadable(key, h.Size, res.Incomplete)
		}
	}
}

// scanFile scans one file of the image whole, with its path, reading at most
// MaxImageFileBytes of it. key and size name it in a known-unreadable list: size is the
// file's whole size from its header, also when only the first MaxImageFileBytes are read.
func (s *Set) scanFile(ctx context.Context, where, key, path string, size int64, r io.Reader, out *ImageResult, m *merge) error {
	data, err := io.ReadAll(io.LimitReader(r, MaxImageFileBytes+1))
	if err != nil {
		return fmt.Errorf("reading %s: %w", where, err)
	}
	cut := len(data) > MaxImageFileBytes
	if cut {
		data = data[:MaxImageFileBytes]
	}
	res, err := s.Scan(ctx, []Part{{Where: where + " (path)", Data: []byte(path)}, {Where: where, Data: data, Whole: !cut}})
	if err != nil {
		return err
	}
	if cut {
		res.Incomplete = append(res.Incomplete, Incomplete{Where: where, Bound: BoundImageFileBytes})
	}
	out.Files++
	m.add(res)
	m.unreadable(key, size, res.Incomplete)
	return nil
}

// merge gathers the results of many scans into one: each entry found once, in the order
// first found, with every place it was found.
type merge struct {
	at         map[string]int
	found      []Finding
	incomplete []Incomplete
	unread     []Unreadable
}

func newMerge() *merge { return &merge{at: map[string]int{}} }

// unreadable records each containing file once per reason. Duplicate archive paths
// with the same reason are rejected before the scan returns.
func (m *merge) unreadable(key string, size int64, incs []Incomplete) {
	seen := map[Bound]bool{} // one give-up per reason in this call, however many parts hit it
	for _, in := range incs {
		if seen[in.Bound] {
			continue
		}
		seen[in.Bound] = true
		m.unread = append(m.unread, Unreadable{Key: key, Where: in.Where, Reason: in.Bound, Size: size})
	}
}

func (m *merge) add(r Result) {
	for _, f := range r.Found {
		key := string(f.Mode) + "\x00" + f.Label
		i, ok := m.at[key]
		if !ok {
			m.at[key] = len(m.found)
			m.found = append(m.found, Finding{Label: f.Label, Mode: f.Mode})
			i = len(m.found) - 1
		}
		m.found[i].Where = append(m.found[i].Where, f.Where...)
	}
	m.incomplete = append(m.incomplete, r.Incomplete...)
}

func (m *merge) result() Result { return Result{Found: m.found, Incomplete: m.incomplete} }
