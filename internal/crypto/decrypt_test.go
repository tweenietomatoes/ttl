package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecrypt_WrongPassword(t *testing.T) {
	_ = withDir(t)

	encrypted := encryptToBuffer(t, []byte("secret data"), "test.txt", "correctpass1")

	_, _, err := DecryptStream(bytes.NewReader(encrypted), "wrongpass", ".")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestDecrypt_Truncated(t *testing.T) {
	_ = withDir(t)

	encrypted := encryptToBuffer(t, make([]byte, ChunkSize+100), "test.bin", "password")

	truncated := encrypted[:len(encrypted)-50]
	_, _, err := DecryptStream(bytes.NewReader(truncated), "password", ".")
	if err == nil {
		t.Fatal("expected error for truncated file")
	}
}

func TestDecrypt_Corrupted(t *testing.T) {
	_ = withDir(t)

	encrypted := encryptToBuffer(t, []byte("hello world test data"), "test.txt", "password")

	corrupted := make([]byte, len(encrypted))
	copy(corrupted, encrypted)
	if len(corrupted) > 100 {
		corrupted[len(corrupted)-20] ^= 0xff
	}

	_, _, err := DecryptStream(bytes.NewReader(corrupted), "password", ".")
	if err == nil {
		t.Fatal("expected error for corrupted data")
	}
}

func TestDecrypt_TrailingData(t *testing.T) {
	_ = withDir(t)

	encrypted := encryptToBuffer(t, []byte("datatata"), "test.txt", "password")

	withTrailing := append(encrypted, 0xff, 0xff)
	_, _, err := DecryptStream(bytes.NewReader(withTrailing), "password", ".")
	if err == nil {
		t.Fatal("expected error for trailing data")
	}
}

func TestDecrypt_FileAlreadyExists_AutoRenames(t *testing.T) {
	dir := withDir(t)

	encrypted := encryptToBuffer(t, []byte("new content"), "existing.txt", "password")

	// Create the file first so it already exists
	os.WriteFile(filepath.Join(dir, "existing.txt"), []byte("original"), 0644)

	filename, written, err := DecryptStream(bytes.NewReader(encrypted), "password", ".")
	if err != nil {
		t.Fatalf("expected auto-rename, got error: %v", err)
	}
	if filename != "existing (1).txt" {
		t.Fatalf("expected 'existing (1).txt', got %q", filename)
	}
	if written != 11 {
		t.Fatalf("expected 11 bytes written, got %d", written)
	}

	// Verify original file was NOT overwritten
	got, _ := os.ReadFile(filepath.Join(dir, "existing.txt"))
	if string(got) != "original" {
		t.Fatal("original file was overwritten!")
	}

	// Verify new file was created with correct content
	got, _ = os.ReadFile(filepath.Join(dir, "existing (1).txt"))
	if string(got) != "new content" {
		t.Fatalf("renamed file has wrong content: %q", string(got))
	}
}

func TestDecrypt_DirAlreadyExistsAsFilename(t *testing.T) {
	dir := withDir(t)

	encrypted := encryptToBuffer(t, []byte("data"), "subdir", "password")

	// Create a directory with the same name as the expected filename
	os.Mkdir(filepath.Join(dir, "subdir"), 0755)

	_, _, err := DecryptStream(bytes.NewReader(encrypted), "password", ".")
	if err == nil {
		t.Fatal("expected error when directory exists with same name as file")
	}
	if !strings.Contains(err.Error(), "directory already exists") {
		t.Fatalf("expected 'directory already exists', got: %v", err)
	}
}

func TestDecrypt_SymlinkAlreadyExists_AutoRenames(t *testing.T) {
	dir := withDir(t)

	encrypted := encryptToBuffer(t, []byte("data"), "link.txt", "password")

	// Create a symlink at the target path
	target := filepath.Join(dir, "target.txt")
	os.WriteFile(target, []byte("target data"), 0644)
	os.Symlink(target, filepath.Join(dir, "link.txt"))

	filename, _, err := DecryptStream(bytes.NewReader(encrypted), "password", ".")
	if err != nil {
		t.Fatalf("expected auto-rename, got error: %v", err)
	}
	if filename != "link (1).txt" {
		t.Fatalf("expected 'link (1).txt', got %q", filename)
	}

	// Verify symlink target was NOT modified
	got, _ := os.ReadFile(target)
	if string(got) != "target data" {
		t.Fatal("target file behind symlink was modified!")
	}

	// Verify renamed file has correct content
	got, _ = os.ReadFile(filepath.Join(dir, "link (1).txt"))
	if string(got) != "data" {
		t.Fatalf("renamed file has wrong content: %q", string(got))
	}
}

func TestDecrypt_OutDir_WritesToCorrectDir(t *testing.T) {
	dir := withDir(t)
	outDir := filepath.Join(dir, "output")
	os.Mkdir(outDir, 0755)

	encrypted := encryptToBuffer(t, []byte("hello output"), "out.txt", "password")

	filename, written, err := DecryptStream(bytes.NewReader(encrypted), "password", outDir)
	if err != nil {
		t.Fatal(err)
	}
	if filename != "out.txt" || written != 12 {
		t.Fatalf("unexpected: %s %d", filename, written)
	}

	// File should be in outDir, not in cwd
	got, err := os.ReadFile(filepath.Join(outDir, "out.txt"))
	if err != nil {
		t.Fatal("file not created in output directory")
	}
	if string(got) != "hello output" {
		t.Fatal("content mismatch")
	}

	// File should NOT be in cwd
	if _, err := os.Stat(filepath.Join(dir, "out.txt")); err == nil {
		t.Fatal("file should not exist in cwd when outDir is specified")
	}
}

func TestDecrypt_AutoRename_MultipleConflicts(t *testing.T) {
	dir := withDir(t)

	encrypted := encryptToBuffer(t, []byte("third copy"), "report.pdf", "password")

	// Create original and (1) so it should land on (2)
	os.WriteFile(filepath.Join(dir, "report.pdf"), []byte("first"), 0644)
	os.WriteFile(filepath.Join(dir, "report (1).pdf"), []byte("second"), 0644)

	filename, _, err := DecryptStream(bytes.NewReader(encrypted), "password", ".")
	if err != nil {
		t.Fatalf("expected auto-rename, got error: %v", err)
	}
	if filename != "report (2).pdf" {
		t.Fatalf("expected 'report (2).pdf', got %q", filename)
	}

	// All three files should exist with correct content
	got, _ := os.ReadFile(filepath.Join(dir, "report.pdf"))
	if string(got) != "first" {
		t.Fatal("original was modified")
	}
	got, _ = os.ReadFile(filepath.Join(dir, "report (1).pdf"))
	if string(got) != "second" {
		t.Fatal("copy (1) was modified")
	}
	got, _ = os.ReadFile(filepath.Join(dir, "report (2).pdf"))
	if string(got) != "third copy" {
		t.Fatal("copy (2) has wrong content")
	}
}

func TestDecrypt_AutoRename_NoExtension(t *testing.T) {
	dir := withDir(t)

	encrypted := encryptToBuffer(t, []byte("new"), "Makefile", "password")

	os.WriteFile(filepath.Join(dir, "Makefile"), []byte("original"), 0644)

	filename, _, err := DecryptStream(bytes.NewReader(encrypted), "password", ".")
	if err != nil {
		t.Fatalf("expected auto-rename, got error: %v", err)
	}
	if filename != "Makefile (1)" {
		t.Fatalf("expected 'Makefile (1)', got %q", filename)
	}

	got, _ := os.ReadFile(filepath.Join(dir, "Makefile"))
	if string(got) != "original" {
		t.Fatal("original was modified")
	}
	got, _ = os.ReadFile(filepath.Join(dir, "Makefile (1)"))
	if string(got) != "new" {
		t.Fatal("renamed file has wrong content")
	}
}

func TestDecrypt_AutoRename_SymlinkConflictChain(t *testing.T) {
	dir := withDir(t)

	encrypted := encryptToBuffer(t, []byte("payload"), "data.bin", "password")

	// Original is a symlink, (1) is a regular file — should land on (2)
	target := filepath.Join(dir, "target.bin")
	os.WriteFile(target, []byte("symlink target"), 0644)
	os.Symlink(target, filepath.Join(dir, "data.bin"))
	os.WriteFile(filepath.Join(dir, "data (1).bin"), []byte("copy1"), 0644)

	filename, _, err := DecryptStream(bytes.NewReader(encrypted), "password", ".")
	if err != nil {
		t.Fatalf("expected auto-rename, got error: %v", err)
	}
	if filename != "data (2).bin" {
		t.Fatalf("expected 'data (2).bin', got %q", filename)
	}

	// Verify symlink target untouched
	got, _ := os.ReadFile(target)
	if string(got) != "symlink target" {
		t.Fatal("symlink target was modified")
	}

	got, _ = os.ReadFile(filepath.Join(dir, "data (2).bin"))
	if string(got) != "payload" {
		t.Fatal("renamed file has wrong content")
	}
}

func TestDecrypt_AutoRename_SymlinkAtCandidatePath(t *testing.T) {
	dir := withDir(t)

	encrypted := encryptToBuffer(t, []byte("payload"), "notes.txt", "password")

	// Both original and (1) are symlinks — should skip both and land on (2)
	target := filepath.Join(dir, "real.txt")
	os.WriteFile(target, []byte("real"), 0644)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("orig"), 0644)
	os.Symlink(target, filepath.Join(dir, "notes (1).txt"))

	filename, _, err := DecryptStream(bytes.NewReader(encrypted), "password", ".")
	if err != nil {
		t.Fatalf("expected auto-rename, got error: %v", err)
	}
	if filename != "notes (2).txt" {
		t.Fatalf("expected 'notes (2).txt', got %q", filename)
	}
}

func TestDecrypt_AutoRename_DanglingSymlinkBlocks(t *testing.T) {
	dir := withDir(t)

	encrypted := encryptToBuffer(t, []byte("payload"), "doc.txt", "password")

	// Original is a regular file, (1) is a dangling symlink
	// Lstat succeeds on dangling symlinks, so (1) should be skipped too
	os.WriteFile(filepath.Join(dir, "doc.txt"), []byte("orig"), 0644)
	os.Symlink("/nonexistent/target", filepath.Join(dir, "doc (1).txt"))

	filename, _, err := DecryptStream(bytes.NewReader(encrypted), "password", ".")
	if err != nil {
		t.Fatalf("expected auto-rename, got error: %v", err)
	}
	if filename != "doc (2).txt" {
		t.Fatalf("expected 'doc (2).txt', got %q", filename)
	}
}

func TestDecrypt_NoConflict_UsesOriginalName(t *testing.T) {
	_ = withDir(t)

	encrypted := encryptToBuffer(t, []byte("fresh file"), "brand-new.txt", "password")

	filename, written, err := DecryptStream(bytes.NewReader(encrypted), "password", ".")
	if err != nil {
		t.Fatal(err)
	}
	if filename != "brand-new.txt" {
		t.Fatalf("expected original name, got %q", filename)
	}
	if written != 10 {
		t.Fatalf("expected 10 bytes, got %d", written)
	}
}

func TestDecrypt_MetaEncLenBoundary(t *testing.T) {
	// 269 is above the allowed max of 268
	header := make([]byte, HeaderSize)
	copy(header, Magic)
	rand.Read(header[SaltOffset:NonceOffset])    // salt
	rand.Read(header[NonceOffset:MetaLenOffset]) // nonce
	binary.BigEndian.PutUint16(header[MetaLenOffset:], 269)

	_ = withDir(t)
	_, _, err := DecryptStream(bytes.NewReader(header), "password", ".")
	if err == nil {
		t.Fatal("expected error for metaEncLen=269")
	}
}

func TestTruncatedCandidate_UTF8RuneBoundary(t *testing.T) {
	// "日" is 3 bytes in UTF-8. Build a base that's all multi-byte chars.
	// 80 × "日" = 240 bytes base, suffix " (1)" = 4 bytes, ext ".txt" = 4 bytes
	// total = 248, fits in 255. No truncation needed.
	base80 := strings.Repeat("日", 80)
	got := truncatedCandidate(base80, " (1)", ".txt")
	if got != base80+" (1).txt" {
		t.Fatalf("expected no truncation, got %q", got)
	}

	// 85 × "日" = 255 bytes base, suffix " (1)" = 4, ext ".txt" = 4
	// total = 263 > 255 → must truncate base to 255-4-4=247 bytes
	// 247/3 = 82 full runes (246 bytes), byte 247 is mid-rune → back up to 246
	base85 := strings.Repeat("日", 85)
	got = truncatedCandidate(base85, " (1)", ".txt")
	if !strings.HasSuffix(got, " (1).txt") {
		t.Fatalf("expected suffix, got %q", got)
	}
	// Verify valid UTF-8: base part should be exactly 82 runes (246 bytes)
	basepart := strings.TrimSuffix(got, " (1).txt")
	if len(basepart) != 246 {
		t.Fatalf("expected 246 bytes base, got %d", len(basepart))
	}
	for i, r := range basepart {
		if r == '\uFFFD' {
			t.Fatalf("invalid UTF-8 at byte %d", i)
		}
	}
}
