package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"io"
)

// A Fingerprint takes a download's bytes as DecryptStreamTap writes them,
// in one pass, and says at the end what they hash to (the manifest,
// manifest.go, holds the sender's). Write never fails: a package laid out
// otherwise than expected only leaves no fingerprints.
type Fingerprint interface {
	io.Writer
	// Sums is the file's SHA-256, or each packaged file's in ZIP order
	// with its name as the package has it; ok false: none.
	Sums() (sums [][]byte, names []string, ok bool)
}

// NewFileFingerprint takes the SHA-256 of the file as a whole.
func NewFileFingerprint() Fingerprint {
	return &fileFingerprint{h: sha256.New()}
}

type fileFingerprint struct{ h hash.Hash }

func (f *fileFingerprint) Write(p []byte) (int, error) { return f.h.Write(p) }

func (f *fileFingerprint) Sums() ([][]byte, []string, bool) {
	return [][]byte{f.h.Sum(nil)}, nil, true
}

// NewPackageFingerprint takes the SHA-256 of each file of a package as
// ttl.space's pages write one (upload-worker.src.js zipPieces), at most
// count files: each file a local header (a ZIP64 extra in it when its
// descriptor's sizes take 8 bytes), stored deflate blocks and a data
// descriptor; then the central directory, its ZIP64 end records where
// needed, and the end record, nothing after. A file's SHA-256 is of the
// bytes its blocks carry: what an unzip tool writes out. Most unzip tools
// go by the central directory, found from the end record; streaming ones
// by the local headers. The directory must list exactly the files read
// here, in their order, at their offsets, with their sizes and names
// (regular files), the local headers say nothing else (their CRC and sizes
// come after the data), and the end records must point at the directory:
// each digest is the one sha256sum gives of the file unpacked either way,
// under the name shown. Any other layout gives none (never a wrong one),
// and so does a name longer than ZipNameMax.
//
// It is the browser's own reader of a package (decrypt-worker.src.js
// zipHasher) step for step, so that both clients take the same package
// the same way.
func NewPackageFingerprint(count int) Fingerprint {
	z := &zipFingerprint{count: count, end64At: -1, hb: make([]byte, 64)}
	z.gather(4, z.sig)
	return z
}

// ZipNameMax bounds a packaged file's name (no file system takes a longer
// path).
const ZipNameMax = 4096

const (
	zipLocal   = 0x04034b50
	zipDesc    = 0x08074b50
	zipCentral = 0x02014b50
	zipEnd64   = 0x06064b50
	zipLoc64   = 0x07064b50
	zipEnd     = 0x06054b50
	zipTop     = 0xffffffff
)

type zipFile struct {
	off, packed, size uint64
	crc               uint32
	n                 int
	d64               bool
	name              []byte
}

type zipFingerprint struct {
	count int
	files []zipFile
	sums  [][]byte
	names []string
	pos   uint64 // archive bytes taken
	// The next want bytes are gathered into hb for step (nil: after the
	// end record).
	hb        []byte
	want, got int
	step      func([]byte) bool
	f         *zipFile
	st        hash.Hash
	left      int // bytes of the stored block still to come
	last      bool
	ce        struct {
		comp, uncomp, lho uint64
		n, x              int
	} // the directory's entry being read
	cd      int // directory entries read
	cdStart uint64
	cdEnd   uint64
	end64At int64
	bad     bool
}

func le16(b []byte, o int) int    { return int(binary.LittleEndian.Uint16(b[o:])) }
func le32(b []byte, o int) uint32 { return binary.LittleEndian.Uint32(b[o:]) }
func le64(b []byte, o int) uint64 { return binary.LittleEndian.Uint64(b[o:]) }

func (z *zipFingerprint) Write(p []byte) (int, error) {
	for i := 0; i < len(p) && !z.bad; {
		if z.step == nil { // after the end record
			z.bad = true
			break
		}
		if z.left > 0 {
			n := min(z.left, len(p)-i)
			z.st.Write(p[i : i+n])
			i += n
			z.pos += uint64(n)
			z.left -= n
			z.f.packed += uint64(n)
			z.f.size += uint64(n)
			if z.left == 0 && !z.blockDone() {
				z.bad = true
			}
			continue
		}
		n := min(z.want-z.got, len(p)-i)
		copy(z.hb[z.got:], p[i:i+n])
		z.got += n
		i += n
		z.pos += uint64(n) //nolint:gosec // n >= 0
		if z.got == z.want && !z.step(z.hb[:z.want]) {
			z.bad = true
		}
	}
	return len(p), nil
}

func (z *zipFingerprint) Sums() ([][]byte, []string, bool) {
	if z.bad || z.step != nil {
		return nil, nil, false
	}
	return z.sums, z.names, true
}

// gather has the next n bytes go to then (at once when there are none).
func (z *zipFingerprint) gather(n int, then func([]byte) bool) bool {
	if len(z.hb) < n {
		z.hb = make([]byte, n)
	}
	z.want, z.got, z.step = n, 0, then
	if n == 0 {
		return then(z.hb[:0])
	}
	return true
}

// sig: four bytes, what comes next.
func (z *zipFingerprint) sig(b []byte) bool {
	v := le32(b, 0)
	switch {
	case v == zipLocal && z.cd == 0:
		if len(z.files) >= z.count {
			return false
		}
		z.f = &zipFile{off: z.pos - 4}
		return z.gather(26, z.local)
	case v == zipCentral && len(z.files) > 0 && z.cd < len(z.files) && z.end64At < 0:
		if z.cd == 0 {
			z.cdStart = z.pos - 4
		}
		return z.gather(42, z.central)
	case v == zipEnd64 && z.cd > 0 && z.cd == len(z.files) && z.end64At < 0:
		z.cdEnd = z.pos - 4
		z.end64At = int64(z.cdEnd) //nolint:gosec // an archive's offset, far below 2^63
		return z.gather(52, z.end64)
	case v == zipEnd && z.cd > 0 && z.cd == len(z.files):
		if z.end64At < 0 {
			z.cdEnd = z.pos - 4
		}
		return z.gather(18, z.end)
	}
	return false
}

// local: a local header from its byte 4. Flags: data descriptor, UTF-8
// names, nothing else; deflate; CRC and sizes zero (they follow the data),
// or with a ZIP64 extra its sentinel.
func (z *zipFingerprint) local(b []byte) bool {
	x := le16(b, 24)
	var top uint32
	if x != 0 {
		top = zipTop
	}
	if le16(b, 2) != 0x0808 || le16(b, 4) != 8 || le32(b, 10) != 0 || le32(b, 14) != top || le32(b, 18) != top {
		return false
	}
	if x != 0 && x != 20 {
		return false
	}
	z.f.n = le16(b, 22)
	if z.f.n > ZipNameMax {
		return false
	}
	return z.gather(z.f.n+x, z.name)
}

func (z *zipFingerprint) name(b []byte) bool {
	n := z.f.n
	if len(b) > n {
		// ZIP64, its two sizes zero as well.
		if le16(b, n) != 0x0001 || le16(b, n+2) != 16 || !allZero(b[n+4:n+20]) {
			return false
		}
		z.f.d64 = true
	}
	z.f.name = bytes.Clone(b[:n])
	z.st = sha256.New()
	return z.gather(5, z.block)
}

// block: BFINAL, BTYPE 00 (stored), the rest of the byte zero; LEN, NLEN.
func (z *zipFingerprint) block(b []byte) bool {
	if b[0] > 1 || le16(b, 1)^le16(b, 3) != 0xffff {
		return false
	}
	z.last = b[0] == 1
	z.left = le16(b, 1)
	z.f.packed += 5
	if z.left == 0 {
		return z.blockDone()
	}
	return true
}

func (z *zipFingerprint) blockDone() bool {
	if !z.last {
		return z.gather(5, z.block)
	}
	if z.f.d64 {
		return z.gather(24, z.desc)
	}
	return z.gather(16, z.desc)
}

func (z *zipFingerprint) desc(b []byte) bool {
	packed, size := uint64(le32(b, 8)), uint64(le32(b, 12))
	if z.f.d64 {
		packed, size = le64(b, 8), le64(b, 16)
	}
	if le32(b, 0) != zipDesc || packed != z.f.packed || size != z.f.size {
		return false
	}
	z.f.crc = le32(b, 4)
	z.sums = append(z.sums, z.st.Sum(nil))
	z.st = nil
	z.files = append(z.files, *z.f)
	return z.gather(4, z.sig)
}

// central: a directory entry from its byte 4. Flags, method, CRC, sizes,
// name, extra and comment lengths (no comment), disk 0, attributes (a
// regular file, not a link), offset.
func (z *zipFingerprint) central(b []byte) bool {
	g := &z.files[z.cd]
	if le16(b, 4) != 0x0808 || le16(b, 6) != 8 || le32(b, 12) != g.crc || le16(b, 28) != 0 || le16(b, 30) != 0 ||
		(le32(b, 34)>>16)&0o170000 != 0o100000 {
		return false
	}
	z.ce.comp, z.ce.uncomp, z.ce.lho = uint64(le32(b, 16)), uint64(le32(b, 20)), uint64(le32(b, 38))
	z.ce.n, z.ce.x = le16(b, 24), le16(b, 26)
	if z.ce.n != g.n || z.ce.x > 28 {
		return false
	}
	return z.gather(z.ce.n+z.ce.x, z.centralRest)
}

func (z *zipFingerprint) centralRest(b []byte) bool {
	g := &z.files[z.cd]
	ce := &z.ce
	end := ce.n + ce.x
	// The one extra field there is: ZIP64, with exactly the fields that
	// are 0xFFFFFFFF above, in this order.
	for q := ce.n; q < end; {
		if q+4 > end {
			return false
		}
		id, sz := le16(b, q), le16(b, q+2)
		if id != 0x0001 || q+4+sz > end {
			return false
		}
		r, ok := q+4, true
		take := func() uint64 {
			if r+8 > q+4+sz {
				ok = false
				return 0
			}
			v := le64(b, r)
			r += 8
			return v
		}
		if ce.uncomp == zipTop {
			ce.uncomp = take()
		}
		if ok && ce.comp == zipTop {
			ce.comp = take()
		}
		if ok && ce.lho == zipTop {
			ce.lho = take()
		}
		if !ok || r != q+4+sz {
			return false
		}
		q += 4 + sz
	}
	if ce.lho != g.off || ce.comp != g.packed || ce.uncomp != g.size || !bytes.Equal(b[:ce.n], g.name) {
		return false
	}
	z.names = append(z.names, string(g.name))
	z.cd++
	return z.gather(4, z.sig)
}

// end64: the ZIP64 end record from its byte 4. Record size, versions,
// disks, entries (this disk, all), directory size, directory offset.
func (z *zipFingerprint) end64(b []byte) bool {
	cd := uint64(z.cd) //nolint:gosec // at most count
	if le64(b, 0) != 44 || le32(b, 12) != 0 || le32(b, 16) != 0 || le64(b, 20) != cd || le64(b, 28) != cd ||
		le64(b, 36) != z.cdEnd-z.cdStart || le64(b, 44) != z.cdStart {
		return false
	}
	return z.gather(20, z.loc64)
}

func (z *zipFingerprint) loc64(b []byte) bool {
	if le32(b, 0) != zipLoc64 || le32(b, 4) != 0 || le64(b, 8) != uint64(z.end64At) || le32(b, 16) != 1 { //nolint:gosec // set: not negative
		return false
	}
	return z.gather(4, z.sig)
}

// end: the end record from its byte 4. A field that overflows carries the
// sentinel (then the ZIP64 record above says it); no comment.
func (z *zipFingerprint) end(b []byte) bool {
	z64 := z.end64At >= 0
	is := func(v, want, top uint64) bool { return v == want || (z64 && v == top) }
	cd := uint64(z.cd)                                                                                                     //nolint:gosec // at most count
	if le16(b, 0) != 0 || le16(b, 2) != 0 || !is(uint64(le16(b, 4)), cd, 0xffff) || !is(uint64(le16(b, 6)), cd, 0xffff) || //nolint:gosec // a uint16
		!is(uint64(le32(b, 8)), z.cdEnd-z.cdStart, zipTop) || !is(uint64(le32(b, 12)), z.cdStart, zipTop) || le16(b, 16) != 0 {
		return false
	}
	z.step = nil
	return true
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
