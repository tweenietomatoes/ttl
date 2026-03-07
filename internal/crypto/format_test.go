package crypto

import (
	"strings"
	"testing"
)

// metaCipherLen returns the encrypted metadata length for a given filename byte length.
func metaCipherLen(fnLen int) int64 {
	return int64(1 + fnLen + 8 + 4 + TagSize)
}

func TestEncryptedSize_0B(t *testing.T) {
	fn := "test.txt"
	got := EncryptedSize(0, fn)
	expected := int64(HeaderSize) + metaCipherLen(len(fn))
	if got != expected {
		t.Fatalf("0B: expected %d, got %d", expected, got)
	}
}

func TestEncryptedSize_1B(t *testing.T) {
	fn := "test.txt"
	got := EncryptedSize(1, fn)
	expected := int64(HeaderSize) + metaCipherLen(len(fn)) + 1 + int64(TagSize)
	if got != expected {
		t.Fatalf("1B: expected %d, got %d", expected, got)
	}
}

func TestEncryptedSize_64KB(t *testing.T) {
	fn := "test.txt"
	got := EncryptedSize(ChunkSize, fn)
	expected := int64(HeaderSize) + metaCipherLen(len(fn)) + int64(ChunkSize) + int64(TagSize)
	if got != expected {
		t.Fatalf("64KB: expected %d, got %d", expected, got)
	}
}

func TestEncryptedSize_64KBPlus1(t *testing.T) {
	fn := "test.txt"
	got := EncryptedSize(ChunkSize+1, fn)
	expected := int64(HeaderSize) + metaCipherLen(len(fn)) + int64(ChunkSize) + 1 + 2*int64(TagSize)
	if got != expected {
		t.Fatalf("64KB+1: expected %d, got %d", expected, got)
	}
}

func TestEncryptedSize_256MB(t *testing.T) {
	fn := "test.txt"
	got := EncryptedSize(MaxFileBytes, fn)
	numChunks := int64(MaxFileBytes) / int64(ChunkSize)
	expected := int64(HeaderSize) + metaCipherLen(len(fn)) + int64(MaxFileBytes) + numChunks*int64(TagSize)
	if got != expected {
		t.Fatalf("256MB: expected %d, got %d", expected, got)
	}
}

func TestEncryptedSize_LongFilename(t *testing.T) {
	longFn := strings.Repeat("a", 500) + ".txt"
	maxFn := strings.Repeat("a", MaxFilename)
	got := EncryptedSize(100, longFn)
	expected := EncryptedSize(100, maxFn)
	if got != expected {
		t.Fatalf("long filename: expected %d, got %d", expected, got)
	}
}

func TestMetadata_RoundTrip(t *testing.T) {
	meta := buildMetadata("secret.pdf", 12345)
	name, size, cs, err := parseMetadata(meta)
	if err != nil {
		t.Fatal(err)
	}
	if name != "secret.pdf" || size != 12345 || cs != ChunkSize {
		t.Fatalf("mismatch: %s %d %d", name, size, cs)
	}
}

func TestParseMetadata_RejectsOversizeFile(t *testing.T) {
	tooBig := uint64(MaxFileBytes + 1)
	meta := buildMetadata("x.bin", tooBig)
	_, _, _, err := parseMetadata(meta)
	if err == nil {
		t.Fatal("expected error for oversize file metadata")
	}
}

func TestParseMetadata_AcceptsMaxFile(t *testing.T) {
	meta := buildMetadata("x.bin", MaxFileBytes)
	_, size, _, err := parseMetadata(meta)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if size != MaxFileBytes {
		t.Fatalf("expected %d, got %d", MaxFileBytes, size)
	}
}
