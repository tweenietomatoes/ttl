package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestDeriveEncKey_MatchesArgon2id(t *testing.T) {
	salt := make([]byte, SaltSize)
	rand.Read(salt)
	password := "testpassword"

	got := DeriveEncKey(password, salt)
	want := argon2.IDKey([]byte(password), salt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)

	if !bytes.Equal(got, want) {
		t.Fatal("DeriveEncKey does not match direct argon2.IDKey call")
	}
}

func TestDeriveEncKey_Length(t *testing.T) {
	salt := make([]byte, SaltSize)
	rand.Read(salt)
	key := DeriveEncKey("password", salt)
	if len(key) != KeySize {
		t.Fatalf("expected %d bytes, got %d", KeySize, len(key))
	}
}

func TestDeriveEncKey_DifferentPasswords(t *testing.T) {
	salt := make([]byte, SaltSize)
	rand.Read(salt)
	k1 := DeriveEncKey("password1!", salt)
	k2 := DeriveEncKey("password2!", salt)
	if bytes.Equal(k1, k2) {
		t.Fatal("different passwords should produce different keys")
	}
}

func TestDeriveEncKey_DifferentSalts(t *testing.T) {
	s1 := make([]byte, SaltSize)
	s2 := make([]byte, SaltSize)
	rand.Read(s1)
	rand.Read(s2)
	k1 := DeriveEncKey("password", s1)
	k2 := DeriveEncKey("password", s2)
	if bytes.Equal(k1, k2) {
		t.Fatal("different salts should produce different keys")
	}
}

func TestDeriveDownloadToken_Length(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)
	token := DeriveDownloadToken(key)
	if len(token) != DownloadTokenSize {
		t.Fatalf("expected %d bytes, got %d", DownloadTokenSize, len(token))
	}
}

func TestDeriveDownloadToken_Deterministic(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)
	t1 := DeriveDownloadToken(key)
	t2 := DeriveDownloadToken(key)
	if !bytes.Equal(t1, t2) {
		t.Fatal("same key should produce same download token")
	}
}

func TestDeriveDownloadToken_DifferentKeys(t *testing.T) {
	k1 := make([]byte, KeySize)
	k2 := make([]byte, KeySize)
	rand.Read(k1)
	rand.Read(k2)
	t1 := DeriveDownloadToken(k1)
	t2 := DeriveDownloadToken(k2)
	if bytes.Equal(t1, t2) {
		t.Fatal("different keys should produce different tokens")
	}
}

func TestDeriveDownloadToken_DiffersFromKey(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)
	token := DeriveDownloadToken(key)
	if bytes.Equal(token, key) {
		t.Fatal("download token must differ from encryption key")
	}
}

func TestTokenHash_MatchesSHA256(t *testing.T) {
	token := make([]byte, DownloadTokenSize)
	rand.Read(token)

	got := TokenHash(token)
	h := sha256.Sum256(token)
	want := hex.EncodeToString(h[:])

	if got != want {
		t.Fatalf("TokenHash mismatch: got %q, want %q", got, want)
	}
}

func TestTokenHash_LowercaseHex(t *testing.T) {
	token := make([]byte, DownloadTokenSize)
	rand.Read(token)
	h := TokenHash(token)
	if len(h) != TokenHexLen {
		t.Fatalf("expected %d hex chars, got %d", TokenHexLen, len(h))
	}
	for _, c := range h {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("non-lowercase hex char: %c", c)
		}
	}
}

func TestTokenHash_DifferentTokens(t *testing.T) {
	t1 := make([]byte, DownloadTokenSize)
	t2 := make([]byte, DownloadTokenSize)
	rand.Read(t1)
	rand.Read(t2)
	if TokenHash(t1) == TokenHash(t2) {
		t.Fatal("different tokens should produce different hashes")
	}
}

func TestTokenHash_Deterministic(t *testing.T) {
	token := make([]byte, DownloadTokenSize)
	rand.Read(token)
	h1 := TokenHash(token)
	h2 := TokenHash(token)
	if h1 != h2 {
		t.Fatal("same token should produce same hash")
	}
}

// TestFullDerivationChain verifies password → encKey → downloadToken → tokenHash
// is deterministic and each step produces a different value.
func TestFullDerivationChain(t *testing.T) {
	salt := make([]byte, SaltSize)
	rand.Read(salt)
	password := "strongpassword!"

	encKey := DeriveEncKey(password, salt)
	dlToken := DeriveDownloadToken(encKey)
	hash := TokenHash(dlToken)

	// Determinism
	encKey2 := DeriveEncKey(password, salt)
	dlToken2 := DeriveDownloadToken(encKey2)
	hash2 := TokenHash(dlToken2)

	if !bytes.Equal(encKey, encKey2) {
		t.Fatal("encKey not deterministic")
	}
	if !bytes.Equal(dlToken, dlToken2) {
		t.Fatal("dlToken not deterministic")
	}
	if hash != hash2 {
		t.Fatal("tokenHash not deterministic")
	}

	// Each step differs
	if bytes.Equal(encKey, dlToken) {
		t.Fatal("encKey == dlToken")
	}
	if hex.EncodeToString(dlToken) == hash {
		t.Fatal("dlToken hex == tokenHash (hash should differ from raw hex)")
	}
}
