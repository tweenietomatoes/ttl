package crypto

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
	"io"
	"math/rand/v2"
	"strings"
	"testing"
)

type zipTestFile struct {
	name string
	data []byte
}

// pageZip lays files out as ttl.space's pages do (upload-worker.src.js
// zipLayout, zipPieces, zipCentral), with ZIP64 records from z64At on
// (0xFFFFFFFF there; tests lower it).
func pageZip(files []zipTestFile, z64At uint64) []byte {
	const block = 65535
	var out []byte
	p16 := func(v int) { out = binary.LittleEndian.AppendUint16(out, uint16(v)) }    //nolint:gosec // test values
	p32 := func(v uint64) { out = binary.LittleEndian.AppendUint32(out, uint32(v)) } //nolint:gosec // test values
	p64 := func(v uint64) { out = binary.LittleEndian.AppendUint64(out, v) }
	b2i := func(b bool) uint64 {
		if b {
			return 1
		}
		return 0
	}
	type item struct {
		off, packed, size uint64
		d64               bool
		crc               uint32
	}
	items := make([]item, len(files))
	for k, f := range files {
		n := uint64(len(f.data))
		packed := n + 5*max(1, (n+block-1)/block)
		it := item{off: uint64(len(out)), packed: packed, size: n, d64: packed > z64At, crc: crc32.ChecksumIEEE(f.data)}
		items[k] = it
		ver, top, x := 20, uint64(0), 0
		if it.d64 {
			ver, top, x = 45, 0xffffffff, 20
		}
		p32(0x04034b50)
		p16(ver)
		p16(0x0808)
		p16(8)
		p16(0x6000) // time
		p16(0x5b5e) // date
		p32(0)
		p32(top)
		p32(top)
		p16(len(f.name))
		p16(x)
		out = append(out, f.name...)
		if it.d64 {
			p16(1)
			p16(16)
			p64(0)
			p64(0)
		}
		for pos := 0; ; {
			l := min(block, len(f.data)-pos)
			final := byte(0)
			if pos+l >= len(f.data) {
				final = 1
			}
			out = append(out, final, byte(l), byte(l>>8), byte(^l), byte(^l>>8))
			out = append(out, f.data[pos:pos+l]...)
			pos += l
			if final == 1 {
				break
			}
		}
		p32(0x08074b50)
		p32(uint64(it.crc))
		if it.d64 {
			p64(packed)
			p64(n)
		} else {
			p32(packed)
			p32(n)
		}
	}
	cdStart := uint64(len(out))
	for k, f := range files {
		it := items[k]
		bigU, bigC, bigO := it.size >= z64At, it.packed >= z64At, it.off >= z64At
		n64 := b2i(bigU) + b2i(bigC) + b2i(bigO)
		pick := func(big bool, v uint64) uint64 {
			if big {
				return 0xffffffff
			}
			return v
		}
		p32(0x02014b50)
		p16(3<<8 | 45)
		if n64 > 0 || it.d64 {
			p16(45)
		} else {
			p16(20)
		}
		p16(0x0808)
		p16(8)
		p16(0x6000)
		p16(0x5b5e)
		p32(uint64(it.crc))
		p32(pick(bigC, it.packed))
		p32(pick(bigU, it.size))
		p16(len(f.name))
		if n64 > 0 {
			p16(int(4 + 8*n64)) //nolint:gosec // at most 28
		} else {
			p16(0)
		}
		p16(0)
		p16(0)
		p16(0)
		p32(0o100644 << 16)
		p32(pick(bigO, it.off))
		out = append(out, f.name...)
		if n64 > 0 {
			p16(1)
			p16(int(8 * n64)) //nolint:gosec // at most 24
			if bigU {
				p64(it.size)
			}
			if bigC {
				p64(it.packed)
			}
			if bigO {
				p64(it.off)
			}
		}
	}
	cdSize := uint64(len(out)) - cdStart
	count := uint64(len(files))
	if count >= 0xffff || cdStart >= z64At || cdSize >= z64At {
		end64 := uint64(len(out))
		p32(0x06064b50)
		p64(44)
		p16(3<<8 | 45)
		p16(45)
		p32(0)
		p32(0)
		p64(count)
		p64(count)
		p64(cdSize)
		p64(cdStart)
		p32(0x07064b50)
		p32(0)
		p64(end64)
		p32(1)
	}
	p32(0x06054b50)
	p16(0)
	p16(0)
	p16(int(min(count, 0xffff))) //nolint:gosec // at most 0xffff
	p16(int(min(count, 0xffff))) //nolint:gosec // at most 0xffff
	p32(min(cdSize, 0xffffffff))
	if cdSize >= z64At {
		out = out[:len(out)-4]
		p32(0xffffffff)
	}
	if cdStart >= z64At {
		p32(0xffffffff)
	} else {
		p32(cdStart)
	}
	p16(0)
	return out
}

func testFiles() []zipTestFile {
	r := rand.New(rand.NewPCG(1, 2))
	fill := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = 'a' + byte(r.IntN(26)) //nolint:gosec // test data: letters, no signature in them
		}
		return b
	}
	return []zipTestFile{
		{"a.txt", []byte("hello\n")},
		{"empty", nil},
		{"dir/one block exactly.bin", fill(65535)},
		{"two blocks.bin", fill(65536)},
		{"نیم\u200cفاصله.txt", fill(200000)},
	}
}

// packageSums feeds z to a package fingerprint in pieces of the sizes
// split gives.
func packageSums(z []byte, count int, split func() int) ([][]byte, []string, bool) {
	fp := NewPackageFingerprint(count)
	for p := 0; p < len(z); {
		n := min(max(split(), 1), len(z)-p)
		if k, err := fp.Write(z[p : p+n]); k != n || err != nil {
			panic("a fingerprint's Write failed")
		}
		p += n
	}
	return fp.Sums()
}

func whole() int { return 1 << 30 }

// What the package fingerprint gives is what archive/zip, another reader,
// and sha256 give of each file, under its name, however the bytes come.
func TestPackageFingerprint(t *testing.T) {
	files := testFiles()
	for _, z64At := range []uint64{0xffffffff, 100, 1} {
		z := pageZip(files, z64At)
		zr, err := zip.NewReader(bytes.NewReader(z), int64(len(z)))
		if err != nil || len(zr.File) != len(files) {
			t.Fatalf("z64At %d: archive/zip: %v", z64At, err)
		}
		r := rand.New(rand.NewPCG(3, z64At))
		for name, split := range map[string]func() int{
			"whole":  whole,
			"bytes":  func() int { return 1 },
			"random": func() int { return r.IntN(70000) },
		} {
			if name == "bytes" && z64At != 1 {
				continue
			}
			sums, names, ok := packageSums(z, len(files), split)
			if !ok || len(sums) != len(files) || len(names) != len(files) {
				t.Fatalf("z64At %d, %s: ok %v, %d sums", z64At, name, ok, len(sums))
			}
			for i, f := range files {
				want := sha256.Sum256(f.data)
				rc, err := zr.File[i].Open()
				if err != nil {
					t.Fatal(err)
				}
				h := sha256.New()
				if _, err := io.Copy(h, rc); err != nil {
					t.Fatalf("archive/zip %s: %v", f.name, err)
				}
				rc.Close()
				if !bytes.Equal(sums[i], want[:]) || !bytes.Equal(h.Sum(nil), want[:]) || names[i] != f.name || zr.File[i].Name != f.name {
					t.Errorf("z64At %d, %s: file %d (%q)", z64At, name, i, names[i])
				}
			}
		}
	}
}

// Any layout but the pages' gives no fingerprints, never wrong ones.
func TestPackageFingerprintRefuses(t *testing.T) {
	files := testFiles()[:2] // "a.txt" (6 bytes), "empty"
	z := pageZip(files, 0xffffffff)
	cd := bytes.Index(z, []byte("PK\x01\x02"))
	cd2 := cd + 46 + len(files[0].name)
	end := len(z) - 22
	desc := 30 + len(files[0].name) + 5 + 6 // after a.txt's one block
	set := func(at int, v ...byte) []byte {
		b := bytes.Clone(z)
		copy(b[at:], v)
		return b
	}
	for name, b := range map[string][]byte{
		"a byte after the end":       append(bytes.Clone(z), 0),
		"cut short":                  z[:len(z)-1],
		"no end record":              z[:end],
		"a compressed block":         set(30+len(files[0].name), 2),
		"NLEN":                       set(30+len(files[0].name)+3, 0),
		"local flags":                set(6, 0x08, 0x00),
		"local method":               set(8, 0),
		"local CRC":                  set(14, 1),
		"local sizes":                set(18, 1),
		"descriptor signature":       set(desc, 'X'),
		"descriptor size":            set(desc+12, 7),
		"descriptor packed":          set(desc+8, 12),
		"directory flags":            set(cd+8, 0x00, 0x08),
		"directory method":           set(cd+10, 0),
		"directory CRC":              set(cd+16, 0),
		"directory size":             set(cd+24, 7),
		"directory name":             set(cd+46, 'b'),
		"directory offset":           set(cd2+42, 1),
		"directory comment":          set(cd+32, 1),
		"directory disk":             set(cd+34, 1),
		"a link":                     set(cd+38+2, 0xff, 0xa1),
		"a directory":                set(cd+38+2, 0xed, 0x41),
		"end record entries":         set(end+8, 1),
		"end record directory size":  set(end+12, 1),
		"end record directory start": set(end+16, 1),
		"end record comment":         set(end+20, 1),
	} {
		if _, _, ok := packageSums(b, len(files), whole); ok {
			t.Errorf("%s: fingerprints", name)
		}
	}
	if _, _, ok := packageSums(z, 1, whole); ok {
		t.Error("more files than the manifest has: fingerprints")
	}
	if _, _, ok := packageSums(z, len(files), whole); !ok {
		t.Error("the pages' own: none")
	}

	// ZIP64: the local extra's sizes are zero.
	z64 := pageZip(files, 1)
	at := 30 + len(files[0].name) + 4
	b := bytes.Clone(z64)
	b[at] = 1
	if _, _, ok := packageSums(b, len(files), whole); ok {
		t.Error("ZIP64 extra with a size: fingerprints")
	}
	if _, _, ok := packageSums(z64, len(files), whole); !ok {
		t.Error("the pages' ZIP64: none")
	}
	// ZIP64 in the directory and the end records: each field held to what
	// was read.
	cd64 := bytes.Index(z64, []byte("PK\x01\x02"))
	x64 := cd64 + 46 + len(files[0].name) // a.txt's ZIP64 extra: its size and packed size
	e64 := bytes.LastIndex(z64, []byte("PK\x06\x06"))
	l64 := bytes.LastIndex(z64, []byte("PK\x06\x07"))
	if cd64 < 0 || e64 < 0 || l64 < 0 || binary.LittleEndian.Uint16(z64[x64:]) != 1 {
		t.Fatal("no ZIP64 records")
	}
	for name, at := range map[string]int{
		"directory ZIP64 extra id":   x64,
		"directory ZIP64 extra size": x64 + 2,
		"directory ZIP64 size":       x64 + 4,
		"end64 record size":          e64 + 4,
		"end64 entries":              e64 + 32,
		"end64 directory size":       e64 + 40,
		"end64 directory start":      e64 + 48,
		"locator end64 offset":       l64 + 8,
		"locator disks":              l64 + 16,
	} {
		b := bytes.Clone(z64)
		b[at]++
		if _, _, ok := packageSums(b, len(files), whole); ok {
			t.Errorf("ZIP64 %s: fingerprints", name)
		}
	}

	// A block header that is not a stored block's, the rest of the
	// archive as it was (a first block of two: an inflater would read
	// other bytes than the ones hashed).
	two := []zipTestFile{{"big", bytes.Repeat([]byte{'z'}, 65536)}, {"b", nil}}
	z2 := pageZip(two, 0xffffffff)
	for _, v := range []byte{2, 4, 6, 0x80} {
		b := bytes.Clone(z2)
		b[30+len("big")] = v
		if _, _, ok := packageSums(b, 2, whole); ok {
			t.Errorf("first block header %#x: fingerprints", v)
		}
	}
	if _, _, ok := packageSums(z2, 2, whole); !ok {
		t.Error("two blocks: none")
	}

	// A name up to ZipNameMax.
	long := []zipTestFile{{strings.Repeat("n", ZipNameMax), []byte("x")}, {"b", nil}}
	if _, _, ok := packageSums(pageZip(long, 0xffffffff), 2, whole); !ok {
		t.Error("a name of ZipNameMax: none")
	}
	long[0].name += "n"
	if _, _, ok := packageSums(pageZip(long, 0xffffffff), 2, whole); ok {
		t.Error("a name past ZipNameMax: fingerprints")
	}
}

func TestFileFingerprint(t *testing.T) {
	fp := NewFileFingerprint()
	fp.Write([]byte("hel"))
	fp.Write([]byte("lo\n"))
	want := sha256.Sum256([]byte("hello\n"))
	if sums, names, ok := fp.Sums(); !ok || len(sums) != 1 || !bytes.Equal(sums[0], want[:]) || names != nil {
		t.Fatalf("%x %v %v", sums, names, ok)
	}
}
