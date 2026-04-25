// Package crypto implements the TTL on-disk format: an authenticated header
// followed by chunked XChaCha20-Poly1305 ciphertext. It also covers key
// derivation (Argon2id), metadata sealing, and the bearer-token derivation
// used by the two-phase download flow.
package crypto

import (
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

// Wire-format constants. Magic identifies a TTL stream; the *Size constants
// give byte lengths; the *Offset constants give field positions inside the
// fixed-size header. Bumping any of these is a wire-format break.
const (
	Magic        = "TTL\x01"
	MagicSize    = 4 // len(Magic)
	SaltSize     = 16
	NonceSize    = 24
	KeySize      = 32
	TagSize      = 16
	MetaLenSize  = 2           // 2 bytes, big-endian uint16
	ChunkSize    = 65536       // 64 KB per plaintext chunk
	MaxFilename  = 239         // keeps max encrypted metadata at 268 bytes
	MaxFileBytes = 268_435_456 // 256 MB
	ArgonTime    = 3
	ArgonMemory  = 64 * 1024 // 64 MB of RAM
	ArgonThreads = 1

	// MinMetaEncLen / MaxMetaEncLen bound the encrypted metadata block.
	MinMetaEncLen = 30  // fnLen=1: plain=1+1+8+4=14, cipher=14+16=30
	MaxMetaEncLen = 268 // fnLen=239: plain=1+239+8+4=252, cipher=252+16=268

	// MaxChunkSize is the largest chunk the parser will accept (forward-compat
	// guard). The encryptor always writes ChunkSize (64 KiB), but the parser
	// tolerates up to 1 MiB so future versions can grow ChunkSize.
	MaxChunkSize = 1 << 20 // 1 MiB

	// ProbeMaxBytes is the maximum bytes a probe response can contain:
	// header + max encrypted metadata (no data chunks).
	ProbeMaxBytes = HeaderSize + MaxMetaEncLen // 314 bytes

	// DownloadTokenSize is the bearer token length in bytes; TokenHexLen is
	// its hex-encoded length on the wire.
	DownloadTokenSize = 32
	TokenHexLen       = 64 // hex.EncodedLen(DownloadTokenSize)

	// SaltOffset / NonceOffset / MetaLenOffset / HeaderSize describe the
	// fixed header layout, each starting where the previous field ends.
	SaltOffset    = MagicSize                   // 4
	NonceOffset   = SaltOffset + SaltSize       // 20
	MetaLenOffset = NonceOffset + NonceSize     // 44
	HeaderSize    = MetaLenOffset + MetaLenSize // 46
)

// truncatedFilenameLen returns the byte length of a filename after capping
// at MaxFilename and trimming to a clean rune boundary. This must match the
// truncation in buildMetadata exactly.
func truncatedFilenameLen(filename string) int {
	n := len(filename)
	if n <= MaxFilename {
		return n
	}
	fn := []byte(filename)[:MaxFilename]
	for len(fn) > 0 && !utf8.RuneStart(fn[len(fn)-1]) {
		fn = fn[:len(fn)-1]
	}
	if len(fn) > 0 && !utf8.Valid(fn[len(fn)-1:]) {
		fn = fn[:len(fn)-1]
	}
	return len(fn)
}

// EncryptedSize returns the total byte count of the encrypted stream.
// Used to set Content-Length before upload.
func EncryptedSize(fileSize uint64, filename string) int64 {
	fnLen := truncatedFilenameLen(filename)
	metaPlainLen := 1 + fnLen + 8 + 4
	metaCipherLen := metaPlainLen + TagSize

	numChunks := fileSize / ChunkSize
	if fileSize%ChunkSize > 0 {
		numChunks++
	}
	// A zero-byte file has zero chunks. fileSize is bounded by MaxFileBytes
	// (256 MB), so the int64 conversions are guaranteed not to overflow.
	return int64(HeaderSize) + int64(metaCipherLen) +
		int64(fileSize) + int64(numChunks)*int64(TagSize) //nolint:gosec
}

func xorNonce(base [NonceSize]byte, index uint64) []byte {
	n := make([]byte, NonceSize)
	copy(n, base[:])
	for i := 0; i < 8; i++ {
		n[NonceSize-8+i] ^= byte(index >> (i * 8)) //nolint:gosec // shifted+masked byte by definition
	}
	return n
}

func buildMetadata(filename string, filesize uint64) []byte {
	fn := []byte(filename)
	if len(fn) > MaxFilename {
		fn = fn[:truncatedFilenameLen(filename)]
	}
	meta := make([]byte, 1+len(fn)+8+4)
	meta[0] = byte(len(fn)) //nolint:gosec // len(fn) <= MaxFilename (239), fits byte
	copy(meta[1:], fn)
	binary.LittleEndian.PutUint64(meta[1+len(fn):], filesize)
	binary.LittleEndian.PutUint32(meta[1+len(fn)+8:], ChunkSize)
	return meta
}

func parseMetadata(data []byte) (string, uint64, uint32, error) {
	if len(data) < 14 { // minimum: 1 (fnLen) + 1 (char) + 8 (size) + 4 (chunk)
		return "", 0, 0, fmt.Errorf("Invalid metadata")
	}
	fnLen := int(data[0])
	if fnLen == 0 || 1+fnLen+8+4 != len(data) {
		return "", 0, 0, fmt.Errorf("Invalid metadata")
	}
	filename := string(data[1 : 1+fnLen])
	filesize := binary.LittleEndian.Uint64(data[1+fnLen:])
	if filesize > 1<<40 { // 1 TB sanity cap
		return "", 0, 0, fmt.Errorf("File size too large: %d", filesize)
	}
	chunkSize := binary.LittleEndian.Uint32(data[1+fnLen+8:])
	if chunkSize == 0 || chunkSize > MaxChunkSize {
		return "", 0, 0, fmt.Errorf("Invalid chunk size: %d", chunkSize)
	}
	return filename, filesize, chunkSize, nil
}
