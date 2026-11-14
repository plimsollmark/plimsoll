package wslc

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"syscall"
	"unicode/utf16"
)

// The per-run mode's template disk is built by this package, never copied from a user's
// session: `wslc system session enter` opens a storage directory only if its storage.vhdx
// already exists (it passes WSLCSessionStorageFlagsNoCreate; WSLCSession.cpp and
// WSLCSessionManager.cpp at WSL tag 3.0.5), and the only CLI path that creates a fresh
// store is the default session's, through the user-wide session.storagePath setting. So
// the provider formats an empty ext4 filesystem in a sparse file on the Linux side
// (mkfs.ext4, as WSLC's own Ext4Format does inside the VM for a new store) and wraps it
// here in a dynamic VHDX, the disk format Hyper-V attaches.
//
// The layout follows Microsoft's open specification [MS-VHDX] (learn.microsoft.com,
// openspecs/windows_protocols/ms-vhdx): the file type identifier at 0, two headers at
// 64 and 128 KiB, two region tables at 192 and 256 KiB, an empty log at 1 MiB, the
// metadata region at 2 MiB and the block allocation table (BAT) at 3 MiB, then the
// payload blocks that hold a non-zero byte, each 1 MiB, in disk order. Every other block
// is "not present" and reads as zeros.

const (
	vhdxBlockSize     = 1 << 20 // the smallest the format allows, so an empty ext4 costs a few MiB
	vhdxLogicalSector = 512
	vhdxPhysSector    = 4096
	vhdxMiB           = 1 << 20
	vhdxLogOffset     = 1 * vhdxMiB
	vhdxLogLength     = 1 * vhdxMiB
	vhdxMetaOffset    = 2 * vhdxMiB
	vhdxMetaLength    = 1 * vhdxMiB
	vhdxBATOffset     = 3 * vhdxMiB
	// vhdxChunkRatio is how many payload blocks one sector bitmap block covers:
	// (2^23 * logical sector size) / block size.
	vhdxChunkRatio = (1 << 23) * vhdxLogicalSector / vhdxBlockSize

	batPayloadFullyPresent = 6

	seekData = 3 // lseek's SEEK_DATA on Linux
)

// GUIDs, in the specification's text form.
var (
	vhdxRegionBAT      = mustGUID("2DC27766-F623-4200-9D64-115E9BFD4A08")
	vhdxRegionMetadata = mustGUID("8B7CA206-4790-4B9A-B8FE-575F050F886E")
	vhdxFileParameters = mustGUID("CAA16737-FA36-4D43-B3B6-33F0AA44E76B")
	vhdxVirtualSize    = mustGUID("2FA54224-CD1B-4876-B211-5DBED83BF4B8")
	vhdxPage83         = mustGUID("BECA12AB-B2E6-4523-93EF-C309E000C746")
	vhdxLogicalSize    = mustGUID("8141BF1D-A96F-4709-BA47-F233A8FAAB5F")
	vhdxPhysicalSize   = mustGUID("CDA348C7-445D-4471-9CC9-E9885251C556")
)

// mustGUID encodes a GUID's text form as stored on disk: the first three fields little
// endian, the last eight bytes as written.
func mustGUID(s string) [16]byte {
	var g [16]byte
	var raw []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			continue
		}
		var v byte
		if _, err := fmt.Sscanf(s[i:i+2], "%02X", &v); err != nil {
			panic(err)
		}
		raw = append(raw, v)
		i++
	}
	if len(raw) != 16 {
		panic("bad GUID " + s)
	}
	g[0], g[1], g[2], g[3] = raw[3], raw[2], raw[1], raw[0]
	g[4], g[5] = raw[5], raw[4]
	g[6], g[7] = raw[7], raw[6]
	copy(g[8:], raw[8:])
	return g
}

func randomGUID() [16]byte {
	var g [16]byte
	if _, err := rand.Read(g[:]); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	g[7] = g[7]&0x0f | 0x40 // version 4 (Data3 is little endian: its high byte is g[7])
	g[8] = g[8]&0x3f | 0x80
	return g
}

var crc32c = crc32.MakeTable(crc32.Castagnoli)

// vhdxBATEntries is the BAT's length for a dynamic disk of n payload blocks: one entry per
// payload block and one sector bitmap entry after each full chunk but the last.
func vhdxBATEntries(n int64) int64 { return n + (n-1)/vhdxChunkRatio }

// vhdxBATIndex is payload block i's entry in the BAT.
func vhdxBATIndex(i int64) int64 { return i + i/vhdxChunkRatio }

func roundUp(n, to int64) int64 { return (n + to - 1) / to * to }

// writeVHDX writes to dst a dynamic VHDX whose virtual disk is raw, byte for byte. Only the
// 1 MiB blocks of raw that hold a non-zero byte are stored; raw's size must be a whole
// number of blocks. dst is emptied first. It returns how many blocks it stored.
//
// Its memory does not depend on raw's size: one block buffer and the fixed structures
// below. Each BAT entry is written to dst as its block is stored, never gathered in memory
// (a BAT is 8 bytes per MiB of virtual disk, 8 MiB for a 1 TiB disk), and every entry
// not written reads as zero, "not present", from the emptied file.
func writeVHDX(dst *os.File, raw *os.File) (int64, error) {
	st, err := raw.Stat()
	if err != nil {
		return 0, err
	}
	size := st.Size()
	if size <= 0 || size%vhdxBlockSize != 0 {
		return 0, fmt.Errorf("vhdx: the raw image is %d bytes, not a positive multiple of %d", size, vhdxBlockSize)
	}
	if err := dst.Truncate(0); err != nil {
		return 0, err
	}
	nblocks := size / vhdxBlockSize
	batLen := roundUp(vhdxBATEntries(nblocks)*8, vhdxMiB)
	next := int64(vhdxBATOffset) + batLen // where the next payload block goes

	buf := make([]byte, vhdxBlockSize)
	entry := make([]byte, 8)
	stored := int64(0)
	for i := int64(0); i < nblocks; i++ {
		off := i * vhdxBlockSize
		// Skip the holes of a sparse raw file without reading them (lseek SEEK_DATA: the
		// next offset at or after off that holds data; ENXIO when none does).
		data, err := raw.Seek(off, seekData)
		if errors.Is(err, syscall.ENXIO) {
			break
		}
		if err != nil {
			return 0, err
		}
		if data >= off+vhdxBlockSize {
			i = data/vhdxBlockSize - 1
			continue
		}
		// A short read is an error, never a block: the tail of buf would still hold the
		// previous block's bytes.
		if n, err := raw.ReadAt(buf, off); n != len(buf) {
			return 0, fmt.Errorf("vhdx: reading block %d of the raw image: %d of %d bytes: %w", i, n, len(buf), err)
		}
		if allZero(buf) {
			continue
		}
		if _, err := dst.WriteAt(buf, next); err != nil {
			return 0, err
		}
		binary.LittleEndian.PutUint64(entry, uint64(batPayloadFullyPresent)|uint64(next/vhdxMiB)<<20)
		if _, err := dst.WriteAt(entry, vhdxBATOffset+vhdxBATIndex(i)*8); err != nil {
			return 0, err
		}
		next += vhdxBlockSize
		stored++
	}

	// The file type identifier: the signature and the creator, in UTF-16.
	ident := make([]byte, 64<<10)
	copy(ident, "vhdxfile")
	for j, u := range utf16.Encode([]rune("plimsoll wslc template")) {
		binary.LittleEndian.PutUint16(ident[8+2*j:], u)
	}
	// Two headers, the second one sequence number ahead; both valid.
	fileWrite, dataWrite := randomGUID(), randomGUID()
	header := func(seq uint64) []byte {
		h := make([]byte, 4096)
		copy(h, "head")
		binary.LittleEndian.PutUint64(h[8:], seq)
		copy(h[16:], fileWrite[:])
		copy(h[32:], dataWrite[:])
		// h[48:64] LogGuid zero: the log is empty and is never replayed.
		binary.LittleEndian.PutUint16(h[64:], 0) // log version
		binary.LittleEndian.PutUint16(h[66:], 1) // format version
		binary.LittleEndian.PutUint32(h[68:], vhdxLogLength)
		binary.LittleEndian.PutUint64(h[72:], vhdxLogOffset)
		binary.LittleEndian.PutUint32(h[4:], crc32.Checksum(h, crc32c))
		return h
	}
	// The region table, twice: the BAT and the metadata region, both required.
	region := make([]byte, 64<<10)
	copy(region, "regi")
	binary.LittleEndian.PutUint32(region[8:], 2)
	putRegion := func(at int, g [16]byte, off, length int64) {
		copy(region[at:], g[:])
		binary.LittleEndian.PutUint64(region[at+16:], uint64(off))
		binary.LittleEndian.PutUint32(region[at+24:], uint32(length))
		binary.LittleEndian.PutUint32(region[at+28:], 1)
	}
	putRegion(16, vhdxRegionBAT, vhdxBATOffset, batLen)
	putRegion(48, vhdxRegionMetadata, vhdxMetaOffset, vhdxMetaLength)
	binary.LittleEndian.PutUint32(region[4:], crc32.Checksum(region, crc32c))
	// The metadata region: a table of five items, their values from 64 KiB on.
	meta := make([]byte, 64<<10+64)
	copy(meta, "metadata")
	binary.LittleEndian.PutUint16(meta[10:], 5)
	const isVirtualDisk, isRequired = 2, 4
	item := 0
	valueAt := 64 << 10
	putItem := func(g [16]byte, flags uint32, value []byte) {
		e := 32 + 32*item
		copy(meta[e:], g[:])
		binary.LittleEndian.PutUint32(meta[e+16:], uint32(valueAt))
		binary.LittleEndian.PutUint32(meta[e+20:], uint32(len(value)))
		binary.LittleEndian.PutUint32(meta[e+24:], flags)
		copy(meta[valueAt:], value)
		valueAt += len(value)
		item++
	}
	le32 := func(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }
	le64 := func(v uint64) []byte { return binary.LittleEndian.AppendUint64(nil, v) }
	diskID := randomGUID()
	putItem(vhdxFileParameters, isRequired, append(le32(vhdxBlockSize), le32(0)...)) // dynamic, no parent
	putItem(vhdxVirtualSize, isVirtualDisk|isRequired, le64(uint64(size)))
	putItem(vhdxPage83, isVirtualDisk|isRequired, diskID[:])
	putItem(vhdxLogicalSize, isVirtualDisk|isRequired, le32(vhdxLogicalSector))
	putItem(vhdxPhysicalSize, isVirtualDisk|isRequired, le32(vhdxPhysSector))

	// Size the file, so every byte not written (the log, the BAT's absent entries, the
	// space between structures) reads as zero, then write each structure at its offset.
	if err := dst.Truncate(next); err != nil {
		return 0, err
	}
	for _, w := range []struct {
		off  int64
		data []byte
	}{
		{0, ident}, {64 << 10, header(1)}, {128 << 10, header(2)},
		{192 << 10, region}, {256 << 10, region},
		{vhdxMetaOffset, meta},
	} {
		if _, err := dst.WriteAt(w.data, w.off); err != nil {
			return 0, err
		}
	}
	return stored, nil
}

func allZero(b []byte) bool {
	var zero [4096]byte
	for len(b) > 0 {
		n := min(len(b), len(zero))
		if !bytes.Equal(b[:n], zero[:n]) {
			return false
		}
		b = b[n:]
	}
	return true
}
