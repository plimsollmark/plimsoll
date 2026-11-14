package wslc

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The VHDX writer's output read back by the specification ([MS-VHDX]): the identifier,
// two headers and two region tables with valid CRC-32C checksums, the five metadata items,
// and a BAT whose present blocks hold exactly the raw image's non-zero blocks, with every
// other block not present. A reader of this test's own is not Hyper-V: the live suite is
// where Windows attaches the disk (the per-run smoke test boots from it).
//
// The raw image is a sparse 6,000 MiB file, and the test reads back from it only the
// blocks it compares, never the whole image (reading it whole held 6.2 GB, and over
// 8 GB under -race).
func TestWriteVHDXReadsBackBySpecification(t *testing.T) {
	dir := t.TempDir()
	const size = 6000 * vhdxBlockSize // more than one chunk, so a sector bitmap entry sits in the BAT
	raw, err := os.Create(filepath.Join(dir, "raw"))
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Truncate(size); err != nil {
		t.Fatal(err)
	}
	data := map[int64][]byte{
		0:    bytes.Repeat([]byte{0xA5}, 512),
		7:    []byte("superblock backup"),
		4096: []byte("past the first chunk"),
		5999: []byte("last block"),
	}
	for blk, b := range data {
		if _, err := raw.WriteAt(b, blk*vhdxBlockSize+100); err != nil {
			t.Fatal(err)
		}
	}
	// A block written with zeros holds no data: it must not be stored.
	if _, err := raw.WriteAt(make([]byte, vhdxBlockSize), 9*vhdxBlockSize); err != nil {
		t.Fatal(err)
	}
	// The destination already holds bytes where the BAT and the payload go, and runs past
	// where the disk ends: the writer must empty it, or a stale entry would read as present.
	out, err := os.Create(filepath.Join(dir, "disk.vhdx"))
	if err != nil {
		t.Fatal(err)
	}
	if err := out.Truncate(16 * vhdxMiB); err != nil {
		t.Fatal(err)
	}
	if _, err := out.WriteAt(bytes.Repeat([]byte{0xFF}, 2*vhdxMiB), vhdxBATOffset); err != nil {
		t.Fatal(err)
	}
	stored, err := writeVHDX(out, raw)
	if err != nil {
		t.Fatal(err)
	}
	out.Close()
	if stored != int64(len(data)) {
		t.Fatalf("stored %d blocks, want %d", stored, len(data))
	}
	// 6,000 blocks and one sector bitmap entry are 48,008 bytes of BAT, one MiB rounded up;
	// so the file is the BAT's offset, one MiB of BAT and the four stored blocks, exactly.
	// Checked before the file is read, so the read below is bounded.
	st, err := os.Stat(filepath.Join(dir, "disk.vhdx"))
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(vhdxBATOffset + vhdxMiB + len(data)*vhdxBlockSize); st.Size() != want {
		t.Fatalf("the file is %d bytes, want %d", st.Size(), want)
	}
	f, err := os.ReadFile(filepath.Join(dir, "disk.vhdx"))
	if err != nil {
		t.Fatal(err)
	}
	le32 := func(off int) uint32 { return binary.LittleEndian.Uint32(f[off:]) }
	le64 := func(off int) uint64 { return binary.LittleEndian.Uint64(f[off:]) }
	if string(f[:8]) != "vhdxfile" {
		t.Fatalf("signature %q", f[:8])
	}
	checksum := func(off, n int) {
		t.Helper()
		b := bytes.Clone(f[off : off+n])
		want := binary.LittleEndian.Uint32(b[4:])
		binary.LittleEndian.PutUint32(b[4:], 0)
		if got := crc32.Checksum(b, crc32c); got != want {
			t.Fatalf("the checksum at %d is %08x, computed %08x", off, want, got)
		}
	}
	for i, off := range []int{64 << 10, 128 << 10} {
		if string(f[off:off+4]) != "head" {
			t.Fatalf("header %d signature %q", i, f[off:off+4])
		}
		checksum(off, 4096)
		if le64(off+8) != uint64(i+1) || binary.LittleEndian.Uint16(f[off+66:]) != 1 || le32(off+68) != vhdxLogLength || le64(off+72) != vhdxLogOffset {
			t.Fatalf("header %d fields", i)
		}
		if !bytes.Equal(f[off+48:off+64], make([]byte, 16)) {
			t.Fatal("the log GUID is not zero: a reader would replay a log")
		}
	}
	if !bytes.Equal(f[192<<10:256<<10], f[256<<10:320<<10]) {
		t.Fatal("the two region tables differ")
	}
	rt := 192 << 10
	if string(f[rt:rt+4]) != "regi" || le32(rt+8) != 2 {
		t.Fatal("region table header")
	}
	checksum(rt, 64<<10)
	regions := map[[16]byte][2]uint64{}
	for i := 0; i < 2; i++ {
		e := rt + 16 + 32*i
		var g [16]byte
		copy(g[:], f[e:])
		if le32(e+28) != 1 {
			t.Fatal("a region is not required")
		}
		regions[g] = [2]uint64{le64(e + 16), uint64(le32(e + 24))}
	}
	bat, meta := regions[vhdxRegionBAT], regions[vhdxRegionMetadata]
	if bat[0] != vhdxBATOffset || meta[0] != vhdxMetaOffset || bat[1] != vhdxMiB || meta[1] != vhdxMetaLength {
		t.Fatalf("regions: %v", regions)
	}
	mt := int(meta[0])
	if string(f[mt:mt+8]) != "metadata" || binary.LittleEndian.Uint16(f[mt+10:]) != 5 {
		t.Fatal("metadata table header")
	}
	items := map[[16]byte][]byte{}
	flags := map[[16]byte]uint32{}
	for i := 0; i < 5; i++ {
		e := mt + 32 + 32*i
		var g [16]byte
		copy(g[:], f[e:])
		off, n := int(le32(e+16)), int(le32(e+20))
		if off < 64<<10 {
			t.Fatalf("metadata item %d at %d, below 64 KiB", i, off)
		}
		items[g], flags[g] = f[mt+off:mt+off+n], le32(e+24)
	}
	if binary.LittleEndian.Uint32(items[vhdxFileParameters]) != vhdxBlockSize || binary.LittleEndian.Uint32(items[vhdxFileParameters][4:]) != 0 ||
		binary.LittleEndian.Uint64(items[vhdxVirtualSize]) != size || binary.LittleEndian.Uint32(items[vhdxLogicalSize]) != 512 ||
		binary.LittleEndian.Uint32(items[vhdxPhysicalSize]) != 4096 || len(items[vhdxPage83]) != 16 {
		t.Fatalf("metadata items: %v", items)
	}
	if flags[vhdxFileParameters] != 4 || flags[vhdxVirtualSize] != 6 || flags[vhdxPage83] != 6 {
		t.Fatalf("metadata flags: %v", flags)
	}
	// Every payload block: present exactly where the raw image holds data, its content the
	// raw image's; the sector bitmap entry after the first chunk not present.
	if got := le64(int(bat[0]) + 8*vhdxChunkRatio); got != 0 {
		t.Fatalf("the sector bitmap entry is %x", got)
	}
	want := make([]byte, vhdxBlockSize)
	for blk := int64(0); blk < size/vhdxBlockSize; blk++ {
		e := le64(int(bat[0]) + 8*int(vhdxBATIndex(blk)))
		_, present := data[blk]
		switch {
		case !present && e != 0:
			t.Fatalf("block %d is stored (%x) but holds no data", blk, e)
		case present && e&7 != batPayloadFullyPresent:
			t.Fatalf("block %d state %d", blk, e&7)
		case present:
			if _, err := raw.ReadAt(want, blk*vhdxBlockSize); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(want[100:100+len(data[blk])], data[blk]) {
				t.Fatalf("the raw image's block %d does not hold what the test wrote", blk)
			}
			off := int(e>>20) * vhdxMiB
			if off < int(bat[0]+bat[1]) || off+vhdxBlockSize > len(f) {
				t.Fatalf("block %d stored at %d, outside the payload area", blk, off)
			}
			if !bytes.Equal(f[off:off+vhdxBlockSize], want) {
				t.Fatalf("block %d content differs", blk)
			}
		}
	}
}

// The other half: the writer's memory does not depend on the image's size. It
// allocates one block buffer and its fixed structures, about 1.3 MiB, whether the disk is
// 6,000 MiB or 1 TiB (a BAT gathered in memory would be 8 MiB at 1 TiB). Both raw images
// are sparse, so the test costs a few MiB of disk; TotalAlloc counts every byte the writer
// asks the Go heap for, whether or not it is still live when measured.
func TestWriteVHDXMemoryDoesNotGrowWithTheImage(t *testing.T) {
	const budget = 3 * vhdxMiB
	for _, size := range []int64{6000 * vhdxBlockSize, 1 << 40} {
		dir := t.TempDir()
		raw, err := os.Create(filepath.Join(dir, "raw"))
		if err != nil {
			t.Fatal(err)
		}
		if err := raw.Truncate(size); err != nil {
			t.Fatal(err)
		}
		nblocks := size / vhdxBlockSize
		for _, blk := range []int64{0, nblocks / 2, nblocks - 1} {
			if _, err := raw.WriteAt([]byte("data"), blk*vhdxBlockSize); err != nil {
				t.Fatal(err)
			}
		}
		out, err := os.Create(filepath.Join(dir, "disk.vhdx"))
		if err != nil {
			t.Fatal(err)
		}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		stored, err := writeVHDX(out, raw)
		runtime.ReadMemStats(&after)
		out.Close()
		raw.Close()
		if err != nil {
			t.Fatal(err)
		}
		if stored != 3 {
			t.Fatalf("%d bytes: stored %d blocks, want 3", size, stored)
		}
		alloc := after.TotalAlloc - before.TotalAlloc
		t.Logf("a %d MiB image: the writer allocated %d bytes", size/vhdxMiB, alloc)
		if alloc > budget {
			t.Fatalf("a %d MiB image: the writer allocated %d bytes, over %d", size/vhdxMiB, alloc, budget)
		}
	}
}

func TestGUIDEncoding(t *testing.T) {
	// The specification's byte order: the first three fields little endian.
	want := []byte{0x24, 0x42, 0xa5, 0x2f, 0x1b, 0xcd, 0x76, 0x48, 0xb2, 0x11, 0x5d, 0xbe, 0xd8, 0x3b, 0xf4, 0xb8}
	if g := vhdxVirtualSize; !bytes.Equal(g[:], want) {
		t.Fatalf("%x", g)
	}
}
