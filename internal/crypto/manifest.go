package crypto

// An upload's manifest, version 1, says what the upload holds: the SHA-256
// of the file, or of each file of a package in its ZIP order, sealed with a
// key only the file's password reaches, so the server keeps it beside the
// file without learning a digest. The uploading client sends it once the
// upload is recorded; a downloading client opens it and holds what it
// computed to it. It is advisory: AEAD already keeps every byte of the file
// as it was sent, and a manifest that is missing or cannot be read only
// means there is nothing to compare with.
//
//	"TTLMAN1\n"              8 bytes
//	nonce                   24 bytes, random
//	XChaCha20-Poly1305       the padded records and a 16-byte tag; the
//	                         additional data is "ttl.space manifest v1"
//	                         and the link's token
//
// The manifest key is HKDF-SHA-256's Expand of the file key (the password's
// Argon2id output) with the info "ttl.space manifest v1", as the download
// token is its Expand with "ttl-download-token" (the file key is already a
// uniform key, RFC 5869 §3.3). Padded is the records' length (uint32,
// big-endian), the records and zeros: 256·2^j bytes when sealed here, any
// multiple of 256 up to 64 KiB when opened, so the stored length tells no
// more than a rough count of a package's files. A record is its type
// (1 byte), its length (uint32, big-endian) and its value. Type 1 is the
// SHA-256 list, 32 bytes a file; type 2 is the reply key's SHA3-256. An
// opener skips a type it does not know; type 0, a type twice, a record past
// the length or a padding byte that is not zero refuses the whole manifest.
//
// This is the server repository's reference (internal/accountcrypto's
// manifest.go) for the CLI; testdata/manifest-vectors.json is a copy of its
// golden vectors, which the browser's workers are held to as well.

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// ManifestMagic begins a sealed manifest: the format and its version.
	ManifestMagic     = "TTLMAN1\n"
	manifestLabel     = "ttl.space manifest v1"
	manifestUnit      = 256
	manifestMaxPadded = 64 << 10
	// ManifestMin is the shortest sealed manifest: the magic, the nonce,
	// 256 bytes of records and the tag.
	ManifestMin = len(ManifestMagic) + chacha20poly1305.NonceSizeX + manifestUnit + chacha20poly1305.Overhead
	// ManifestMax is the longest: 64 KiB of records.
	ManifestMax = ManifestMin - manifestUnit + manifestMaxPadded

	// ManifestSHA256 is the record of the files' SHA-256s.
	ManifestSHA256 byte = 1
	// ManifestReply is the record of the upload's reply key, SHA3-256 of
	// it: 32 bytes, or the manifest is refused. Not used here.
	ManifestReply byte = 2
)

var errManifest = errors.New("manifest refused")

// ManifestRecord is one record of a manifest.
type ManifestRecord struct {
	Type  byte
	Value []byte
}

// Manifest is what an opened manifest says.
type Manifest struct {
	SHA256 [][]byte // a file's, or each packaged file's in ZIP order; 32 bytes each
}

// manifestKey is a file's manifest key, from its file key.
func manifestKey(fileKey []byte) ([]byte, error) {
	if len(fileKey) != KeySize {
		return nil, errManifest
	}
	return hkdf.Expand(sha256.New, fileKey, manifestLabel, chacha20poly1305.KeySize)
}

func manifestAD(token string) []byte {
	return append([]byte(manifestLabel), token...)
}

// SealManifest seals records, in their order, for the file whose file key
// and link token these are, with a 24-byte nonce (random: randomBytes). A
// record an opener would refuse is not sealed.
func SealManifest(fileKey []byte, token string, nonce []byte, records ...ManifestRecord) ([]byte, error) {
	n := 0
	for _, r := range records {
		n += 5 + len(r.Value)
	}
	size := manifestUnit
	for size < 4+n {
		size *= 2
	}
	if size > manifestMaxPadded {
		return nil, errManifest
	}
	plain := make([]byte, size)
	binary.BigEndian.PutUint32(plain, uint32(n)) //nolint:gosec // n < size <= 64 KiB
	p := 4
	for _, r := range records {
		plain[p] = r.Type
		binary.BigEndian.PutUint32(plain[p+1:], uint32(len(r.Value))) //nolint:gosec // within the 64 KiB above
		p += 5 + copy(plain[p+5:], r.Value)
	}
	if _, err := manifestRecords(plain); err != nil {
		return nil, err
	}
	return sealManifestPadded(fileKey, token, nonce, plain)
}

// sealManifestPadded seals padded as it is (the vectors' refused cases).
func sealManifestPadded(fileKey []byte, token string, nonce, padded []byte) ([]byte, error) {
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, errManifest
	}
	key, err := manifestKey(fileKey)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	out := append([]byte(ManifestMagic), nonce...)
	return aead.Seal(out, nonce, padded, manifestAD(token)), nil
}

// manifestShape is all a server can check of a manifest: its magic and a
// length the format allows.
func manifestShape(sealed []byte) bool {
	return len(sealed) >= ManifestMin && len(sealed) <= ManifestMax &&
		(len(sealed)-ManifestMin)%manifestUnit == 0 && string(sealed[:len(ManifestMagic)]) == ManifestMagic
}

// OpenManifest opens the manifest of the file whose file key and link token
// these are.
func OpenManifest(fileKey []byte, token string, sealed []byte) (Manifest, error) {
	if !manifestShape(sealed) {
		return Manifest{}, errManifest
	}
	key, err := manifestKey(fileKey)
	if err != nil {
		return Manifest{}, err
	}
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return Manifest{}, err
	}
	at := len(ManifestMagic)
	plain, err := aead.Open(nil, sealed[at:at+chacha20poly1305.NonceSizeX], sealed[at+chacha20poly1305.NonceSizeX:], manifestAD(token))
	if err != nil {
		return Manifest{}, errManifest
	}
	return manifestRecords(plain)
}

// manifestRecords reads padded records, as OpenManifest refuses them.
func manifestRecords(plain []byte) (Manifest, error) {
	var m Manifest
	if len(plain) < 4 {
		return m, errManifest
	}
	n := binary.BigEndian.Uint32(plain)
	if uint64(n) > uint64(len(plain)-4) { //nolint:gosec // len(plain) >= 4 above
		return m, errManifest
	}
	end := 4 + int(n)
	for _, b := range plain[end:] {
		if b != 0 {
			return m, errManifest
		}
	}
	var seen [256]bool
	for p := 4; p < end; {
		if end-p < 5 {
			return m, errManifest
		}
		t, l := plain[p], binary.BigEndian.Uint32(plain[p+1:])
		if t == 0 || seen[t] || uint64(l) > uint64(end-p-5) { //nolint:gosec // end-p >= 5 above
			return m, errManifest
		}
		seen[t] = true
		v := plain[p+5 : p+5+int(l)]
		if t == ManifestSHA256 {
			if len(v) == 0 || len(v)%sha256.Size != 0 {
				return m, errManifest
			}
			for i := 0; i < len(v); i += sha256.Size {
				m.SHA256 = append(m.SHA256, bytes.Clone(v[i:i+sha256.Size]))
			}
		}
		if t == ManifestReply && len(v) != 32 {
			return m, errManifest
		}
		p += 5 + int(l)
	}
	return m, nil
}

// ProbeTail is what a probe's answer carries after the header and the
// metadata: the upload's manifest when it was asked for (manifest=1) and
// there is one, else nothing. probeData has passed VerifyProbe.
func ProbeTail(probeData []byte) []byte {
	if len(probeData) < HeaderSize {
		return nil
	}
	at := HeaderSize + int(binary.BigEndian.Uint16(probeData[MetaLenOffset:HeaderSize]))
	if len(probeData) <= at {
		return nil
	}
	return probeData[at:]
}
