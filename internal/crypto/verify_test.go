package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// probeFromBuffer builds probe data (header + metadata only) from an encrypted blob.
func probeFromBuffer(t *testing.T, encrypted []byte) []byte {
	t.Helper()
	if len(encrypted) < HeaderSize {
		t.Fatal("encrypted too short for header")
	}
	metaEncLen := int(binary.BigEndian.Uint16(encrypted[MetaLenOffset:HeaderSize]))
	end := HeaderSize + metaEncLen
	if end > len(encrypted) {
		t.Fatal("encrypted too short for metadata")
	}
	return encrypted[:end]
}

func TestVerifyProbe_Success(t *testing.T) {
	data := []byte("hello verify probe!")
	encrypted := encryptToBuffer(t, data, "test.txt", "password")
	probe := probeFromBuffer(t, encrypted)

	salt := probe[SaltOffset:NonceOffset]
	key := argon2.IDKey([]byte("password"), salt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)

	if err := VerifyProbe(probe, key); err != nil {
		t.Fatalf("VerifyProbe should succeed: %v", err)
	}
}

func TestVerifyProbe_WrongPassword(t *testing.T) {
	encrypted := encryptToBuffer(t, []byte("secret"), "test.txt", "correctpass1")
	probe := probeFromBuffer(t, encrypted)

	salt := probe[SaltOffset:NonceOffset]
	key := argon2.IDKey([]byte("wrongpasswd1"), salt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)

	err := VerifyProbe(probe, key)
	if err == nil {
		t.Fatal("wrong password should fail")
	}
	if !strings.Contains(err.Error(), "wrong password") {
		t.Fatalf("expected 'wrong password' error, got: %v", err)
	}
}

func TestVerifyProbe_ZeroByteFile(t *testing.T) {
	encrypted := encryptToBuffer(t, []byte{}, "empty.txt", "password")
	probe := probeFromBuffer(t, encrypted)

	salt := probe[SaltOffset:NonceOffset]
	key := argon2.IDKey([]byte("password"), salt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)

	if err := VerifyProbe(probe, key); err != nil {
		t.Fatalf("zero-byte file probe should succeed: %v", err)
	}
}

func TestVerifyProbe_MultiChunkFile(t *testing.T) {
	// File larger than one chunk — probe only has header + metadata
	data := make([]byte, ChunkSize+500)
	rand.Read(data)
	encrypted := encryptToBuffer(t, data, "big.bin", "password")
	probe := probeFromBuffer(t, encrypted)

	salt := probe[SaltOffset:NonceOffset]
	key := argon2.IDKey([]byte("password"), salt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)

	if err := VerifyProbe(probe, key); err != nil {
		t.Fatalf("multi-chunk probe should succeed: %v", err)
	}
}

func TestVerifyProbe_ExactChunkBoundary(t *testing.T) {
	data := make([]byte, ChunkSize)
	rand.Read(data)
	encrypted := encryptToBuffer(t, data, "exact.bin", "password")
	probe := probeFromBuffer(t, encrypted)

	salt := probe[SaltOffset:NonceOffset]
	key := argon2.IDKey([]byte("password"), salt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)

	if err := VerifyProbe(probe, key); err != nil {
		t.Fatalf("exact chunk boundary probe should succeed: %v", err)
	}
}

func TestVerifyProbe_TooShort(t *testing.T) {
	err := VerifyProbe([]byte("short"), make([]byte, KeySize))
	if err == nil {
		t.Fatal("too short should fail")
	}
}

func TestVerifyProbe_BadMagic(t *testing.T) {
	probe := make([]byte, HeaderSize+50)
	copy(probe, "XXXX") // wrong magic
	err := VerifyProbe(probe, make([]byte, KeySize))
	if err == nil {
		t.Fatal("bad magic should fail")
	}
}

func TestVerifyProbe_BadMetaEncLen(t *testing.T) {
	// Build a header with metaEncLen = 269 (above max)
	probe := make([]byte, HeaderSize+300)
	copy(probe, Magic)
	rand.Read(probe[SaltOffset:NonceOffset])
	rand.Read(probe[NonceOffset:MetaLenOffset])
	binary.BigEndian.PutUint16(probe[MetaLenOffset:], 269)

	err := VerifyProbe(probe, make([]byte, KeySize))
	if err == nil {
		t.Fatal("metaEncLen=269 should fail")
	}
}

func TestVerifyProbe_MetaEncLenTooSmall(t *testing.T) {
	probe := make([]byte, HeaderSize+50)
	copy(probe, Magic)
	rand.Read(probe[SaltOffset:NonceOffset])
	rand.Read(probe[NonceOffset:MetaLenOffset])
	binary.BigEndian.PutUint16(probe[MetaLenOffset:], 29) // below min

	err := VerifyProbe(probe, make([]byte, KeySize))
	if err == nil {
		t.Fatal("metaEncLen=29 should fail")
	}
}

func TestVerifyProbe_IncompleteMetadata(t *testing.T) {
	// Header says metaEncLen=50 but probe only has header + 10 bytes
	probe := make([]byte, HeaderSize+10)
	copy(probe, Magic)
	rand.Read(probe[SaltOffset:NonceOffset])
	rand.Read(probe[NonceOffset:MetaLenOffset])
	binary.BigEndian.PutUint16(probe[MetaLenOffset:], 50)

	err := VerifyProbe(probe, make([]byte, KeySize))
	if err == nil {
		t.Fatal("incomplete metadata should fail")
	}
}

func TestVerifyProbe_CorruptedMetadata(t *testing.T) {
	data := []byte("some data for corruption test!")
	encrypted := encryptToBuffer(t, data, "test.txt", "password")
	probe := probeFromBuffer(t, encrypted)

	// Corrupt a byte in the encrypted metadata (auth tag area)
	probe[len(probe)-1] ^= 0xff

	salt := probe[SaltOffset:NonceOffset]
	key := argon2.IDKey([]byte("password"), salt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)

	err := VerifyProbe(probe, key)
	if err == nil {
		t.Fatal("corrupted metadata should fail")
	}
	if !strings.Contains(err.Error(), "wrong password") {
		t.Fatalf("expected 'wrong password' error, got: %v", err)
	}
}

func TestVerifyProbe_BitFlipEveryHeaderByte(t *testing.T) {
	data := []byte("bitflip probe test data")
	encrypted := encryptToBuffer(t, data, "flip.txt", "password")
	probe := probeFromBuffer(t, encrypted)

	salt := encrypted[SaltOffset:NonceOffset]
	key := argon2.IDKey([]byte("password"), salt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)

	for i := 0; i < HeaderSize && i < len(probe); i++ {
		corrupted := make([]byte, len(probe))
		copy(corrupted, probe)
		corrupted[i] ^= 0xff

		// Re-derive key with potentially corrupted salt
		corruptedSalt := corrupted[SaltOffset:NonceOffset]
		corruptedKey := argon2.IDKey([]byte("password"), corruptedSalt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)

		if bytes.Equal(corruptedSalt, salt) {
			// Salt unchanged — use original key, nonce is corrupted
			if err := VerifyProbe(corrupted, key); err == nil {
				t.Fatalf("flipping header byte %d should cause error", i)
			}
		} else {
			// Salt corrupted — key is different, will fail
			if err := VerifyProbe(corrupted, corruptedKey); err == nil {
				t.Fatalf("flipping salt byte %d should cause error (different key)", i)
			}
		}
	}
}

func TestVerifyProbe_ExtraTrailingDataIgnored(t *testing.T) {
	// Probe with extra bytes after metadata should still work
	// (forward-compat: older server might send more data)
	data := []byte("hello")
	encrypted := encryptToBuffer(t, data, "test.txt", "password")
	probe := probeFromBuffer(t, encrypted)

	// Append some junk bytes
	probe = append(probe, []byte("extrajunk")...)

	salt := probe[SaltOffset:NonceOffset]
	key := argon2.IDKey([]byte("password"), salt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)

	if err := VerifyProbe(probe, key); err != nil {
		t.Fatalf("extra trailing data should be ignored: %v", err)
	}
}
