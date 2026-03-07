package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// --- Decryption attacks ---

// TestAttack_Decrypt_BitFlipEveryHeaderByte flips each byte in the header and checks that decryption fails.
func TestAttack_Decrypt_BitFlipEveryHeaderByte(t *testing.T) {
	_ = withDir(t)

	original := []byte("secret attack test data for bitflip")
	encrypted := encryptToBuffer(t, original, "bitflip.txt", "password")

	// Try flipping every byte in the header
	for i := 0; i < HeaderSize && i < len(encrypted); i++ {
		corrupted := make([]byte, len(encrypted))
		copy(corrupted, encrypted)
		corrupted[i] ^= 0xff

		_, _, err := DecryptStream(bytes.NewReader(corrupted), "password", ".")
		if err == nil {
			t.Fatalf("flipping header byte %d should cause error", i)
		}
	}
}

// TestAttack_Decrypt_BitFlipMetaCiphertext flips each byte in the encrypted metadata.
func TestAttack_Decrypt_BitFlipMetaCiphertext(t *testing.T) {
	_ = withDir(t)

	original := []byte("metadata bitflip attack test")
	encrypted := encryptToBuffer(t, original, "metaflip.txt", "password")

	// Encrypted metadata starts right after the header
	metaStart := HeaderSize
	metaLen := int(binary.BigEndian.Uint16(encrypted[MetaLenOffset:HeaderSize]))

	for i := metaStart; i < metaStart+metaLen && i < len(encrypted); i++ {
		corrupted := make([]byte, len(encrypted))
		copy(corrupted, encrypted)
		corrupted[i] ^= 0x01 // flip one bit

		_, _, err := DecryptStream(bytes.NewReader(corrupted), "password", ".")
		if err == nil {
			t.Fatalf("flipping metadata byte %d should cause auth failure", i)
		}
	}
}

// TestAttack_Decrypt_BitFlipDataChunk flips a bit in a data chunk's auth tag.
func TestAttack_Decrypt_BitFlipDataChunk(t *testing.T) {
	_ = withDir(t)

	// Use a file that spans multiple chunks
	original := make([]byte, ChunkSize*2+100)
	rand.Read(original)
	encrypted := encryptToBuffer(t, original, "chunkflip.bin", "password")

	metaLen := int(binary.BigEndian.Uint16(encrypted[MetaLenOffset:HeaderSize]))
	dataStart := HeaderSize + metaLen

	// Flip the last byte of the first chunk's auth tag
	if dataStart+ChunkSize+TagSize <= len(encrypted) {
		corrupted := make([]byte, len(encrypted))
		copy(corrupted, encrypted)
		corrupted[dataStart+ChunkSize+TagSize-1] ^= 0x01

		_, _, err := DecryptStream(bytes.NewReader(corrupted), "password", ".")
		if err == nil {
			t.Fatal("flipping data chunk auth tag should cause error")
		}
	}
}

// TestAttack_Decrypt_TruncateAtEveryBoundary cuts the file at each boundary and checks for errors.
func TestAttack_Decrypt_TruncateAtEveryBoundary(t *testing.T) {
	_ = withDir(t)

	original := make([]byte, ChunkSize+500)
	rand.Read(original)
	encrypted := encryptToBuffer(t, original, "trunc.bin", "password")

	boundaries := []int{
		0,
		5,
		HeaderSize - 1,
		HeaderSize,
		HeaderSize + 1,
	}

	metaLen := int(binary.BigEndian.Uint16(encrypted[MetaLenOffset:HeaderSize]))
	boundaries = append(boundaries,
		HeaderSize+metaLen-1,
		HeaderSize+metaLen,
		HeaderSize+metaLen+1,
		HeaderSize+metaLen+ChunkSize+TagSize-1,
		len(encrypted)-1,
	)

	for _, cutoff := range boundaries {
		if cutoff > len(encrypted) || cutoff < 0 {
			continue
		}
		truncated := encrypted[:cutoff]
		_, _, err := DecryptStream(bytes.NewReader(truncated), "password", ".")
		if err == nil {
			t.Fatalf("truncation at byte %d should cause error", cutoff)
		}
	}
}

// TestAttack_Decrypt_ReorderedChunks swaps two chunks and checks that auth fails.
func TestAttack_Decrypt_ReorderedChunks(t *testing.T) {
	_ = withDir(t)

	// Need at least 3 chunks to swap
	original := make([]byte, ChunkSize*3)
	rand.Read(original)
	encrypted := encryptToBuffer(t, original, "reorder.bin", "password")

	metaLen := int(binary.BigEndian.Uint16(encrypted[MetaLenOffset:HeaderSize]))
	dataStart := HeaderSize + metaLen
	chunkCipherSize := ChunkSize + TagSize

	// Swap chunk 1 and chunk 2
	if dataStart+chunkCipherSize*3 <= len(encrypted) {
		swapped := make([]byte, len(encrypted))
		copy(swapped, encrypted)

		chunk1 := make([]byte, chunkCipherSize)
		chunk2 := make([]byte, chunkCipherSize)
		copy(chunk1, swapped[dataStart:dataStart+chunkCipherSize])
		copy(chunk2, swapped[dataStart+chunkCipherSize:dataStart+chunkCipherSize*2])
		copy(swapped[dataStart:], chunk2)
		copy(swapped[dataStart+chunkCipherSize:], chunk1)

		_, _, err := DecryptStream(bytes.NewReader(swapped), "password", ".")
		if err == nil {
			t.Fatal("chunk reordering should cause authentication failure")
		}
	}
}

// TestAttack_Decrypt_DuplicatedChunk copies chunk 1 over chunk 2 and checks that auth fails.
func TestAttack_Decrypt_DuplicatedChunk(t *testing.T) {
	_ = withDir(t)

	original := make([]byte, ChunkSize*2)
	rand.Read(original)
	encrypted := encryptToBuffer(t, original, "dupchunk.bin", "password")

	metaLen := int(binary.BigEndian.Uint16(encrypted[MetaLenOffset:HeaderSize]))
	dataStart := HeaderSize + metaLen
	chunkCipherSize := ChunkSize + TagSize

	if dataStart+chunkCipherSize*2 <= len(encrypted) {
		// Replace chunk 2 with chunk 1
		duplicated := make([]byte, len(encrypted))
		copy(duplicated, encrypted)
		copy(duplicated[dataStart+chunkCipherSize:dataStart+chunkCipherSize*2],
			duplicated[dataStart:dataStart+chunkCipherSize])

		_, _, err := DecryptStream(bytes.NewReader(duplicated), "password", ".")
		if err == nil {
			t.Fatal("chunk duplication should cause authentication failure")
		}
	}
}

// TestAttack_Decrypt_WrongPasswordVariations tries passwords that are close to the real one.
func TestAttack_Decrypt_WrongPasswordVariations(t *testing.T) {
	_ = withDir(t)

	original := []byte("top secret data")
	encrypted := encryptToBuffer(t, original, "nearpass.txt", "MyPassword123!")

	passwords := []string{
		"mypassword123!",           // lowercase
		"MYPASSWORD123!",           // uppercase
		"MyPassword123",            // missing !
		"MyPassword123!!",          // extra !
		"MyPassword123! ",          // trailing space
		" MyPassword123!",          // leading space
		"MyPassword123!\x00",       // null terminator
		"MyPassword123!\n",         // newline
		"MyPassword124!",           // one digit off
		"",                         // empty
		"x",                        // too short
		strings.Repeat("A", 10000), // very long
	}

	for _, pass := range passwords {
		_, _, err := DecryptStream(bytes.NewReader(encrypted), pass, ".")
		if err == nil {
			t.Fatalf("password %q should fail decryption", pass)
		}
	}
}

// --- Metadata forgery ---

// TestAttack_ForgedMetadata_OversizeFilesize builds metadata with file sizes above the limit.
func TestAttack_ForgedMetadata_OversizeFilesize(t *testing.T) {
	cases := []uint64{
		MaxFileBytes + 1,     // just over limit
		MaxFileBytes + 1<<20, // 1 MB over
		1 << 40,              // 1 TB
		^uint64(0),           // max uint64
		^uint64(0) - 1,       // near max uint64
	}

	for _, size := range cases {
		meta := buildMetadata("evil.bin", size)
		_, _, _, err := parseMetadata(meta)
		if err == nil {
			t.Fatalf("filesize %d should be rejected", size)
		}
	}
}

// TestAttack_ForgedMetadata_InvalidChunkSize builds metadata with invalid chunk sizes.
func TestAttack_ForgedMetadata_InvalidChunkSize(t *testing.T) {
	// Manually build metadata with bad chunk sizes
	chunkSizes := []uint32{0, 1<<20 + 1, 1 << 21, 1 << 30, ^uint32(0)}
	for _, cs := range chunkSizes {
		fn := []byte("test.bin")
		meta := make([]byte, 1+len(fn)+8+4)
		meta[0] = byte(len(fn))
		copy(meta[1:], fn)
		binary.LittleEndian.PutUint64(meta[1+len(fn):], 1024)
		binary.LittleEndian.PutUint32(meta[1+len(fn)+8:], cs)

		_, _, _, err := parseMetadata(meta)
		if err == nil {
			t.Fatalf("chunkSize %d should be rejected", cs)
		}
	}
}

// TestAttack_ForgedMetadata_ZeroFilenameLen checks that a zero-length filename is rejected.
func TestAttack_ForgedMetadata_ZeroFilenameLen(t *testing.T) {
	meta := make([]byte, 1+0+8+4)
	meta[0] = 0
	binary.LittleEndian.PutUint64(meta[1:], 1024)
	binary.LittleEndian.PutUint32(meta[1+8:], ChunkSize)

	_, _, _, err := parseMetadata(meta)
	if err == nil {
		t.Fatal("fnLen=0 should be rejected")
	}
}

// TestAttack_ForgedMetadata_MismatchedFnLen sets fnLen to 10 but only puts 5 filename bytes.
func TestAttack_ForgedMetadata_MismatchedFnLen(t *testing.T) {
	meta := make([]byte, 1+5+8+4)
	meta[0] = 10 // says 10 but only 5 bytes follow
	copy(meta[1:], "hello")
	binary.LittleEndian.PutUint64(meta[1+5:], 1024)
	binary.LittleEndian.PutUint32(meta[1+5+8:], ChunkSize)

	_, _, _, err := parseMetadata(meta)
	if err == nil {
		t.Fatal("mismatched fnLen should be rejected")
	}
}

// TestAttack_ForgedMetadata_TooShort tries metadata shorter than the 14-byte minimum.
func TestAttack_ForgedMetadata_TooShort(t *testing.T) {
	shortData := [][]byte{
		nil,
		{},
		{1},
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, // 13 bytes, one short of minimum
	}

	for _, data := range shortData {
		_, _, _, err := parseMetadata(data)
		if err == nil {
			t.Fatalf("metadata of length %d should be rejected", len(data))
		}
	}
}

// --- Filename sanitisation ---

// TestAttack_Sanitize_DeepPathTraversal checks that directory traversal paths are stripped down to the base name.
func TestAttack_Sanitize_DeepPathTraversal(t *testing.T) {
	attacks := []struct {
		input    string
		expected string
	}{
		{"../../../../../../../etc/passwd", "passwd"},
		{"..\\..\\..\\..\\Windows\\System32\\config\\SAM", "SAM"},
		{"./../.../../.../etc/shadow", "shadow"},
		{"foo/../bar/../../../etc/passwd", "passwd"},
		{"../../../.hidden", "hidden"},
	}

	for _, tc := range attacks {
		got := sanitizeFilename(tc.input)
		if got != tc.expected {
			t.Errorf("sanitize(%q) = %q, want %q", tc.input, got, tc.expected)
		}
		// Must not contain path separators
		if strings.Contains(got, "/") || strings.Contains(got, "\\") {
			t.Errorf("sanitize(%q) = %q contains path separator", tc.input, got)
		}
		// Must not contain ".."
		if strings.Contains(got, "..") {
			t.Errorf("sanitize(%q) = %q contains '..' traversal", tc.input, got)
		}
		// Must not start with "."
		if strings.HasPrefix(got, ".") {
			t.Errorf("sanitize(%q) = %q starts with '.' (hidden file)", tc.input, got)
		}
	}
}

// TestAttack_Sanitize_UnicodeAttacks tries to bypass sanitisation with Unicode tricks.
func TestAttack_Sanitize_UnicodeAttacks(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		// Fullwidth dots and slashes
		{"\uFF0E\uFF0E/test.txt", "test.txt"},
		// RTL override character (stripped as Unicode format character)
		{"test\u202Etxt.exe", "testtxt.exe"},
		// Zero-width space (stripped as Unicode format character)
		{"test\u200B.txt", "test.txt"},
		// Combining accent
		{"te\u0301st.txt", "te\u0301st.txt"},
		// Null byte is stripped
		{"test\x00.txt", "test.txt"},
		// CJK
		{"日本語ファイル.txt", "日本語ファイル.txt"},
		// Emoji
		{"🔒secret🔑.pdf", "🔒secret🔑.pdf"},
		// Control chars mixed with unicode
		{"\x01\x02日本語\x03.txt", "日本語.txt"},
	}

	for _, tc := range cases {
		got := sanitizeFilename(tc.input)
		if got != tc.expected {
			t.Errorf("sanitize(%q) = %q, want %q", tc.input, got, tc.expected)
		}
		// Result must not contain control chars
		for _, r := range got {
			if r < 0x20 {
				t.Errorf("sanitize(%q) result contains control char U+%04X", tc.input, r)
			}
		}
	}
}

// TestAttack_Sanitize_WindowsReservedNames checks that Windows reserved names don't crash.
func TestAttack_Sanitize_WindowsReservedNames(t *testing.T) {
	reserved := []string{
		"CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
		"CON.txt", "NUL.bin",
	}

	for _, name := range reserved {
		got := sanitizeFilename(name)
		// These are valid on Linux; just make sure nothing crashes
		if got == "" {
			t.Errorf("sanitize(%q) returned empty", name)
		}
	}
}

// TestAttack_Sanitize_ExtremelyLongFilename checks that very long filenames don't cause problems.
func TestAttack_Sanitize_ExtremelyLongFilename(t *testing.T) {
	longNames := []string{
		strings.Repeat("A", 1000),
		strings.Repeat("日", 1000),
		strings.Repeat("A", 10000) + ".txt",
		strings.Repeat("/", 1000) + "file.txt",
		strings.Repeat("../", 500) + "etc/passwd",
	}

	for _, name := range longNames {
		got := sanitizeFilename(name)
		if got == "" {
			t.Errorf("sanitize(%q...) returned empty for long name", name[:20])
		}
		// Must not contain path separators
		if strings.Contains(got, "/") || strings.Contains(got, "\\") {
			t.Errorf("sanitize of long name contains path separator")
		}
	}
}

// TestAttack_Sanitize_HiddenFileVariations checks that leading dots are stripped.
func TestAttack_Sanitize_HiddenFileVariations(t *testing.T) {
	cases := []struct {
		input            string
		mustNotStartWith string
	}{
		{".hidden", "."},
		{"..hidden", "."},
		{"...hidden", "."},
		{".bashrc", "."},
		{".ssh/authorized_keys", "."},
		{"path/.hidden", "."},
		{"..", "."},
	}

	for _, tc := range cases {
		got := sanitizeFilename(tc.input)
		if strings.HasPrefix(got, tc.mustNotStartWith) && got != "download.bin" {
			t.Errorf("sanitize(%q) = %q starts with %q (hidden file)", tc.input, got, tc.mustNotStartWith)
		}
	}
}

// --- Encrypt/decrypt edge cases ---

// TestAttack_EncryptDecrypt_ExactlyMaxFilename uses a filename at the 239-char limit.
func TestAttack_EncryptDecrypt_ExactlyMaxFilename(t *testing.T) {
	dir := withDir(t)

	maxName := strings.Repeat("A", MaxFilename)
	original := []byte("data for max filename test")
	encrypted := encryptToBuffer(t, original, maxName, "password")

	filename, written, err := DecryptStream(bytes.NewReader(encrypted), "password", ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(filename) != MaxFilename {
		t.Fatalf("expected filename length %d, got %d", MaxFilename, len(filename))
	}
	if written != int64(len(original)) {
		t.Fatalf("written mismatch")
	}
	got, _ := os.ReadFile(filepath.Join(dir, filename))
	if !bytes.Equal(got, original) {
		t.Fatal("content mismatch")
	}
}

// TestAttack_EncryptDecrypt_OverMaxFilename checks that filenames over 239 chars are clamped.
func TestAttack_EncryptDecrypt_OverMaxFilename(t *testing.T) {
	_ = withDir(t)

	overName := strings.Repeat("B", MaxFilename+100)
	original := []byte("data for over-max filename")
	encrypted := encryptToBuffer(t, original, overName, "password")

	filename, written, err := DecryptStream(bytes.NewReader(encrypted), "password", ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(filename) > MaxFilename {
		t.Fatalf("filename not clamped: length %d > %d", len(filename), MaxFilename)
	}
	if written != int64(len(original)) {
		t.Fatalf("written mismatch")
	}
}

// TestAttack_EncryptDecrypt_ExactChunkBoundaries tests files at sizes around chunk boundaries.
func TestAttack_EncryptDecrypt_ExactChunkBoundaries(t *testing.T) {
	sizes := []int{
		0,
		1,
		ChunkSize - 1,
		ChunkSize,
		ChunkSize + 1,
		ChunkSize * 2,
		ChunkSize*2 + 1,
		ChunkSize * 10,
		ChunkSize*10 + ChunkSize/2,
	}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			dir := withDir(t)

			original := make([]byte, size)
			if size > 0 {
				rand.Read(original)
			}
			encrypted := encryptToBuffer(t, original, "boundary.bin", "password")

			filename, written, err := DecryptStream(bytes.NewReader(encrypted), "password", ".")
			if err != nil {
				t.Fatal(err)
			}
			if written != int64(size) {
				t.Fatalf("written %d, expected %d", written, size)
			}

			got, _ := os.ReadFile(filepath.Join(dir, filename))
			if !bytes.Equal(got, original) {
				t.Fatal("content mismatch")
			}
		})
	}
}

// TestAttack_EncryptDecrypt_FileOverwriteProtection checks that an existing file is never overwritten.
// With auto-rename, the second decrypt should succeed with a renamed file,
// and the original must remain untouched.
func TestAttack_EncryptDecrypt_FileOverwriteProtection(t *testing.T) {
	dir := withDir(t)

	original := []byte("original content")
	encrypted := encryptToBuffer(t, original, "exists.txt", "password")

	// First decrypt succeeds
	fn1, _, err := DecryptStream(bytes.NewReader(encrypted), "password", ".")
	if err != nil {
		t.Fatal(err)
	}
	if fn1 != "exists.txt" {
		t.Fatalf("first decrypt: expected 'exists.txt', got %q", fn1)
	}

	// Second decrypt should auto-rename, NOT overwrite
	fn2, _, err := DecryptStream(bytes.NewReader(encrypted), "password", ".")
	if err != nil {
		t.Fatalf("second decrypt should auto-rename, got error: %v", err)
	}
	if fn2 != "exists (1).txt" {
		t.Fatalf("second decrypt: expected 'exists (1).txt', got %q", fn2)
	}

	// Verify original file is untouched
	got, _ := os.ReadFile(filepath.Join(dir, "exists.txt"))
	if !bytes.Equal(got, original) {
		t.Fatal("original file was corrupted")
	}

	// Verify renamed copy also has correct content
	got2, _ := os.ReadFile(filepath.Join(dir, "exists (1).txt"))
	if !bytes.Equal(got2, original) {
		t.Fatal("renamed copy has wrong content")
	}
}

// TestAttack_DecryptCleanupOnFailure checks that partial files are deleted when decryption fails.
func TestAttack_DecryptCleanupOnFailure(t *testing.T) {
	dir := withDir(t)

	original := make([]byte, ChunkSize*2)
	rand.Read(original)
	encrypted := encryptToBuffer(t, original, "cleanup.bin", "password")

	// Truncate so decryption fails mid-stream
	truncated := encrypted[:len(encrypted)-100]
	_, _, err := DecryptStream(bytes.NewReader(truncated), "password", ".")
	if err == nil {
		t.Fatal("truncated file should fail")
	}

	// Verify partial file was cleaned up
	_, statErr := os.Stat(filepath.Join(dir, "cleanup.bin"))
	if statErr == nil {
		t.Fatal("partial file should have been removed on error")
	}
}

// --- Nonce uniqueness ---

// TestAttack_XorNonce_AllIndices checks that 10000 different indices give 10000 different nonces.
func TestAttack_XorNonce_AllIndices(t *testing.T) {
	var base [NonceSize]byte
	rand.Read(base[:])

	// 10000 indices covers files up to 640 MB at 64 KB chunks
	seen := make(map[string]bool)
	for i := uint64(0); i < 10000; i++ {
		n := xorNonce(base, i)
		key := string(n)
		if seen[key] {
			t.Fatalf("nonce collision at index %d", i)
		}
		seen[key] = true
	}
}

// TestAttack_XorNonce_ZeroBase checks behaviour when the base nonce is all zeros.
func TestAttack_XorNonce_ZeroBase(t *testing.T) {
	var base [NonceSize]byte

	// Index 0 with a zero base should give a zero nonce
	n0 := xorNonce(base, 0)
	for _, b := range n0 {
		if b != 0 {
			t.Fatal("xorNonce(zero, 0) should be zero")
		}
	}

	// Index 1 should give a non-zero nonce
	n1 := xorNonce(base, 1)
	allZero := true
	for _, b := range n1 {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("xorNonce(zero, 1) should be non-zero")
	}
}

// TestAttack_XorNonce_MaxIndex checks that max uint64 values don't panic.
func TestAttack_XorNonce_MaxIndex(t *testing.T) {
	var base [NonceSize]byte
	rand.Read(base[:])

	// Must not panic
	_ = xorNonce(base, ^uint64(0))
	_ = xorNonce(base, ^uint64(0)-1)
	_ = xorNonce(base, 1<<63)
}

// --- EncryptedSize accuracy ---

// TestAttack_EncryptedSize_ConsistencyCheck compares predicted size to actual encrypted size.
func TestAttack_EncryptedSize_ConsistencyCheck(t *testing.T) {
	sizes := []uint64{
		0, 1, 2, 100, 1000,
		ChunkSize - 1, ChunkSize, ChunkSize + 1,
		ChunkSize * 2, ChunkSize*2 - 1, ChunkSize*2 + 1,
		ChunkSize * 100,
		MaxFileBytes - 1, MaxFileBytes,
	}
	filenames := []string{
		"x",
		"test.txt",
		strings.Repeat("x", 100),
		strings.Repeat("x", MaxFilename),
		strings.Repeat("x", MaxFilename+100),
		strings.Repeat("a", 238) + "日.txt",  // 3-byte rune at 239 boundary
		strings.Repeat("a", 236) + "𐍈.dat",   // 4-byte rune at boundary
	}

	for _, size := range sizes {
		for _, fn := range filenames {
			predicted := EncryptedSize(size, fn)
			if predicted <= 0 {
				t.Fatalf("EncryptedSize(%d, %q) = %d (non-positive)", size, fn[:min(len(fn), 20)], predicted)
			}

			// Only encrypt sizes small enough to test quickly
			if size <= ChunkSize*3 {
				data := make([]byte, size)
				if size > 0 {
					rand.Read(data)
				}
				salt := make([]byte, SaltSize)
				rand.Read(salt)
				key := argon2.IDKey([]byte("test"), salt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)

				var buf bytes.Buffer
				EncryptStream(&buf, bytes.NewReader(data), fn, size, key, salt)

				actual := int64(buf.Len())
				if predicted != actual {
					t.Fatalf("EncryptedSize(%d, len=%d) = %d, actual = %d",
						size, len(fn), predicted, actual)
				}
			}
		}
	}
}

// --- Key derivation ---

// TestAttack_ArgonKeyDeriv_DifferentSalts checks that two salts give two different keys.
func TestAttack_ArgonKeyDeriv_DifferentSalts(t *testing.T) {
	password := "testpassword"
	salt1 := make([]byte, SaltSize)
	salt2 := make([]byte, SaltSize)
	rand.Read(salt1)
	rand.Read(salt2)

	key1 := argon2.IDKey([]byte(password), salt1, ArgonTime, ArgonMemory, ArgonThreads, KeySize)
	key2 := argon2.IDKey([]byte(password), salt2, ArgonTime, ArgonMemory, ArgonThreads, KeySize)

	if bytes.Equal(key1, key2) {
		t.Fatal("different salts should produce different keys")
	}
}

// TestAttack_ArgonKeyDeriv_DifferentPasswords checks that two passwords give two different keys.
func TestAttack_ArgonKeyDeriv_DifferentPasswords(t *testing.T) {
	salt := make([]byte, SaltSize)
	rand.Read(salt)

	key1 := argon2.IDKey([]byte("password1"), salt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)
	key2 := argon2.IDKey([]byte("password2"), salt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)

	if bytes.Equal(key1, key2) {
		t.Fatal("different passwords should produce different keys")
	}
}

// TestAttack_XChaCha20_KeySize checks that our constants match the library's constants.
func TestAttack_XChaCha20_KeySize(t *testing.T) {
	if KeySize != chacha20poly1305.KeySize {
		t.Fatalf("KeySize %d != chacha20poly1305.KeySize %d", KeySize, chacha20poly1305.KeySize)
	}
	if NonceSize != chacha20poly1305.NonceSizeX {
		t.Fatalf("NonceSize %d != chacha20poly1305.NonceSizeX %d", NonceSize, chacha20poly1305.NonceSizeX)
	}
}

// --- Metadata boundaries ---

// TestAttack_BuildMetadata_AllFilenameLen round-trips every valid filename length (1 to 239).
func TestAttack_BuildMetadata_AllFilenameLen(t *testing.T) {
	for fnLen := 1; fnLen <= MaxFilename; fnLen++ {
		fn := strings.Repeat("x", fnLen)
		meta := buildMetadata(fn, 1024)
		parsedFn, parsedSize, parsedCS, err := parseMetadata(meta)
		if err != nil {
			t.Fatalf("fnLen=%d: %v", fnLen, err)
		}
		if parsedFn != fn {
			t.Fatalf("fnLen=%d: filename mismatch", fnLen)
		}
		if parsedSize != 1024 {
			t.Fatalf("fnLen=%d: size mismatch", fnLen)
		}
		if parsedCS != ChunkSize {
			t.Fatalf("fnLen=%d: chunkSize mismatch", fnLen)
		}
	}
}

// TestAttack_BuildMetadata_LongFilenameClamp checks that a 500-char filename is clamped to 239.
func TestAttack_BuildMetadata_LongFilenameClamp(t *testing.T) {
	longFn := strings.Repeat("A", 500)
	meta := buildMetadata(longFn, 1024)
	parsedFn, _, _, err := parseMetadata(meta)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsedFn) != MaxFilename {
		t.Fatalf("expected clamped to %d, got %d", MaxFilename, len(parsedFn))
	}
}

// TestAttack_BuildMetadata_SpecialCharsPreserved checks that special characters survive a round-trip.
func TestAttack_BuildMetadata_SpecialCharsPreserved(t *testing.T) {
	specialNames := []string{
		"file with spaces.txt",
		"über-résumé.pdf",
		"日本語.doc",
		"emoji🔒file.bin",
		"file(1).txt",
		"file [copy].txt",
		"name=value&key=val.html",
		"file;semicolon.txt",
		"file'quote.txt",
		"file\"doublequote.txt",
	}

	for _, fn := range specialNames {
		meta := buildMetadata(fn, 512)
		parsedFn, _, _, err := parseMetadata(meta)
		if err != nil {
			t.Fatalf("filename %q failed round-trip: %v", fn, err)
		}
		if parsedFn != fn {
			t.Fatalf("filename %q != %q after round-trip", fn, parsedFn)
		}
	}
}

// --- Format constants ---

// TestAttack_FormatConstants checks that all format constants have the right values.
func TestAttack_FormatConstants(t *testing.T) {
	if HeaderSize != MagicSize+SaltSize+NonceSize+MetaLenSize {
		t.Fatalf("HeaderSize mismatch: %d != %d+%d+%d+%d", HeaderSize, MagicSize, SaltSize, NonceSize, MetaLenSize)
	}
	if SaltOffset != MagicSize {
		t.Fatalf("SaltOffset mismatch: %d != %d", SaltOffset, MagicSize)
	}
	if NonceOffset != SaltOffset+SaltSize {
		t.Fatalf("NonceOffset mismatch: %d != %d", NonceOffset, SaltOffset+SaltSize)
	}
	if MetaLenOffset != NonceOffset+NonceSize {
		t.Fatalf("MetaLenOffset mismatch: %d != %d", MetaLenOffset, NonceOffset+NonceSize)
	}
	if SaltSize != 16 {
		t.Fatalf("SaltSize should be 16, got %d", SaltSize)
	}
	if NonceSize != 24 {
		t.Fatalf("NonceSize should be 24, got %d", NonceSize)
	}
	if KeySize != 32 {
		t.Fatalf("KeySize should be 32, got %d", KeySize)
	}
	if TagSize != 16 {
		t.Fatalf("TagSize should be 16, got %d", TagSize)
	}
	if ChunkSize != 65536 {
		t.Fatalf("ChunkSize should be 65536, got %d", ChunkSize)
	}
	if MaxFilename != 239 {
		t.Fatalf("MaxFilename should be 239, got %d", MaxFilename)
	}
	if MaxFileBytes != 268_435_456 {
		t.Fatalf("MaxFileBytes should be 256MB, got %d", MaxFileBytes)
	}
	if ArgonTime != 3 {
		t.Fatalf("ArgonTime should be 3, got %d", ArgonTime)
	}
	if ArgonMemory != 64*1024 {
		t.Fatalf("ArgonMemory should be 64MB, got %d", ArgonMemory)
	}
	if ArgonThreads != 1 {
		t.Fatalf("ArgonThreads should be 1, got %d", ArgonThreads)
	}
	if Magic != "TTL\x01" {
		t.Fatalf("Magic mismatch")
	}
}

// --- Crafted binaries ---

// TestAttack_CraftedBinary_ValidMinimal encrypts and decrypts a zero-byte file.
func TestAttack_CraftedBinary_ValidMinimal(t *testing.T) {
	dir := withDir(t)

	// Encrypt an empty file
	password := "testpassword"
	salt := make([]byte, SaltSize)
	rand.Read(salt)
	key := argon2.IDKey([]byte(password), salt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)

	var buf bytes.Buffer
	err := EncryptStream(&buf, bytes.NewReader(nil), "minimal.txt", 0, key, salt)
	if err != nil {
		t.Fatal(err)
	}

	filename, written, err := DecryptStream(bytes.NewReader(buf.Bytes()), password, ".")
	if err != nil {
		t.Fatal(err)
	}
	if filename != "minimal.txt" {
		t.Fatalf("expected minimal.txt, got %s", filename)
	}
	if written != 0 {
		t.Fatalf("expected 0 bytes, got %d", written)
	}

	// Verify file exists and is empty
	stat, err := os.Stat(filepath.Join(dir, "minimal.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if stat.Size() != 0 {
		t.Fatalf("expected 0-byte file, got %d", stat.Size())
	}
}

// TestAttack_CraftedBinary_AppendGarbageAfterValid appends junk after a valid stream.
func TestAttack_CraftedBinary_AppendGarbageAfterValid(t *testing.T) {
	_ = withDir(t)

	original := []byte("clean data")
	encrypted := encryptToBuffer(t, original, "garbage.txt", "password")

	// Try different kinds of trailing junk
	garbages := [][]byte{
		{0x00},
		{0xff},
		{0x00, 0x00, 0x00, 0x00},
		bytes.Repeat([]byte{0xff}, 1000),
		[]byte("TTL\x01"), // a second header
	}

	for i, garbage := range garbages {
		combined := append(append([]byte{}, encrypted...), garbage...)
		_, _, err := DecryptStream(bytes.NewReader(combined), "password", ".")
		if err == nil {
			t.Fatalf("garbage[%d]: should detect trailing data", i)
		}
	}
}

// TestAttack_CraftedBinary_EmptyReader tries to decrypt with no data at all.
func TestAttack_CraftedBinary_EmptyReader(t *testing.T) {
	_ = withDir(t)
	_, _, err := DecryptStream(bytes.NewReader(nil), "password", ".")
	if err == nil {
		t.Fatal("empty reader should fail")
	}
}

// TestAttack_CraftedBinary_AllZeroFile tries to decrypt 1000 zero bytes (wrong magic).
func TestAttack_CraftedBinary_AllZeroFile(t *testing.T) {
	_ = withDir(t)
	zeros := make([]byte, 1000)
	_, _, err := DecryptStream(bytes.NewReader(zeros), "password", ".")
	if err == nil {
		t.Fatal("all-zero file should fail (wrong magic)")
	}
}

// TestAttack_CraftedBinary_RandomNoise puts random bytes with a valid header and checks that auth fails.
func TestAttack_CraftedBinary_RandomNoise(t *testing.T) {
	_ = withDir(t)
	noise := make([]byte, 10000)
	rand.Read(noise)
	// Set valid magic so the header check passes
	copy(noise, Magic)
	// Fill salt and nonce with random bytes
	rand.Read(noise[SaltOffset:NonceOffset])
	rand.Read(noise[NonceOffset:MetaLenOffset])
	// Set a plausible metadata length
	binary.BigEndian.PutUint16(noise[MetaLenOffset:HeaderSize], 56)

	_, _, err := DecryptStream(bytes.NewReader(noise), "password", ".")
	if err == nil {
		t.Fatal("random noise should fail decryption (auth tag verification)")
	}
}
