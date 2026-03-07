package crypto

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// withDir creates a temp directory, moves into it, and restores the old directory on cleanup.
func withDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(orig) })
	return dir
}

func encryptToBuffer(t *testing.T, data []byte, filename, password string) []byte {
	t.Helper()
	salt := make([]byte, SaltSize)
	rand.Read(salt)
	key := argon2.IDKey([]byte(password), salt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)

	var buf bytes.Buffer
	err := EncryptStream(&buf, bytes.NewReader(data), filename, uint64(len(data)), key, salt)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	original := []byte("Hello, ttl.space!")
	password := "testpassword"

	dir := withDir(t)

	encrypted := encryptToBuffer(t, original, "hello.txt", password)

	filename, written, err := DecryptStream(bytes.NewReader(encrypted), password, ".")
	if err != nil {
		t.Fatal(err)
	}
	if filename != "hello.txt" {
		t.Fatalf("filename: %s", filename)
	}
	if written != int64(len(original)) {
		t.Fatalf("written: %d", written)
	}

	got, _ := os.ReadFile(filepath.Join(dir, "hello.txt"))
	if !bytes.Equal(got, original) {
		t.Fatal("content mismatch")
	}
}

func TestEncryptDecrypt_0Byte(t *testing.T) {
	password := "testpassword"

	_ = withDir(t)

	encrypted := encryptToBuffer(t, []byte{}, "empty.txt", password)

	filename, written, err := DecryptStream(bytes.NewReader(encrypted), password, ".")
	if err != nil {
		t.Fatal(err)
	}
	if filename != "empty.txt" {
		t.Fatalf("filename: %s", filename)
	}
	if written != 0 {
		t.Fatalf("written: %d", written)
	}
}

func TestEncryptDecrypt_ExactChunk(t *testing.T) {
	original := make([]byte, ChunkSize)
	rand.Read(original)
	password := "testpassword"

	dir := withDir(t)

	encrypted := encryptToBuffer(t, original, "exact.bin", password)

	filename, written, err := DecryptStream(bytes.NewReader(encrypted), password, ".")
	if err != nil {
		t.Fatal(err)
	}
	if filename != "exact.bin" || written != int64(ChunkSize) {
		t.Fatalf("unexpected: %s %d", filename, written)
	}

	got, _ := os.ReadFile(filepath.Join(dir, "exact.bin"))
	if !bytes.Equal(got, original) {
		t.Fatal("content mismatch")
	}
}

func TestEncryptDecrypt_MultiChunk(t *testing.T) {
	original := make([]byte, ChunkSize*3+1000)
	rand.Read(original)
	password := "testpassword"

	dir := withDir(t)

	encrypted := encryptToBuffer(t, original, "multi.bin", password)

	filename, written, err := DecryptStream(bytes.NewReader(encrypted), password, ".")
	if err != nil {
		t.Fatal(err)
	}
	if filename != "multi.bin" || written != int64(len(original)) {
		t.Fatalf("unexpected: %s %d", filename, written)
	}

	got, _ := os.ReadFile(filepath.Join(dir, "multi.bin"))
	if !bytes.Equal(got, original) {
		t.Fatal("content mismatch")
	}
}

func TestEncryptedSize_MatchesActual(t *testing.T) {
	sizes := []uint64{0, 1, 100, ChunkSize, ChunkSize + 1, ChunkSize*2 + 500}
	for _, size := range sizes {
		data := make([]byte, size)
		if size > 0 {
			rand.Read(data)
		}
		filename := "test.txt"
		predicted := EncryptedSize(size, filename)

		salt := make([]byte, SaltSize)
		rand.Read(salt)
		key := argon2.IDKey([]byte("password"), salt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)

		var buf bytes.Buffer
		EncryptStream(&buf, bytes.NewReader(data), filename, size, key, salt)

		actual := int64(buf.Len())
		if predicted != actual {
			t.Fatalf("size %d: predicted %d, actual %d", size, predicted, actual)
		}
	}
}

func TestEncryptedSize_LongFilenameActual(t *testing.T) {
	data := make([]byte, 1024)
	rand.Read(data)
	longName := strings.Repeat("A", 500) + ".pdf"

	predicted := EncryptedSize(1024, longName)

	salt := make([]byte, SaltSize)
	rand.Read(salt)
	key := argon2.IDKey([]byte("password"), salt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)

	var buf bytes.Buffer
	EncryptStream(&buf, bytes.NewReader(data), longName, 1024, key, salt)

	actual := int64(buf.Len())
	if predicted != actual {
		t.Fatalf("long filename: predicted %d, actual %d", predicted, actual)
	}
}

func TestEncryptedSize_UTF8BoundaryActual(t *testing.T) {
	data := make([]byte, 512)
	rand.Read(data)

	// Multi-byte rune straddling the 239-byte MaxFilename boundary.
	// "日" is 3 bytes; 238 ASCII + "日" = 241 bytes total, so truncation
	// must drop the partial rune and produce a 238-byte filename.
	names := []string{
		strings.Repeat("a", 238) + "日.txt",  // 3-byte rune at boundary
		strings.Repeat("a", 237) + "€€.bin",  // 3-byte rune pair
		strings.Repeat("a", 236) + "𐍈.dat",   // 4-byte rune at boundary
		strings.Repeat("a", 235) + "日本語.pdf", // multiple 3-byte runes
	}

	for _, name := range names {
		predicted := EncryptedSize(512, name)

		salt := make([]byte, SaltSize)
		rand.Read(salt)
		key := argon2.IDKey([]byte("password"), salt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)

		var buf bytes.Buffer
		EncryptStream(&buf, bytes.NewReader(data), name, 512, key, salt)

		actual := int64(buf.Len())
		if predicted != actual {
			t.Fatalf("UTF-8 filename %q: predicted %d, actual %d", name[:20], predicted, actual)
		}
	}
}
