package crypto

import (
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// DeriveEncKey derives the encryption key from password and salt using Argon2id.
func DeriveEncKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt,
		ArgonTime, ArgonMemory, ArgonThreads, KeySize)
}

// DeriveDownloadToken derives a download bearer token from the encryption key
// using HKDF-Expand (SHA-256). This is one-way: the token cannot reveal the key.
func DeriveDownloadToken(encKey []byte) []byte {
	r := hkdf.Expand(sha256.New, encKey, []byte("ttl-download-token"))
	token := make([]byte, DownloadTokenSize)
	r.Read(token) // 32 bytes from SHA-256 HKDF: 1 iteration, cannot fail
	return token
}

// TokenHash returns the SHA-256 hash of the download token as hex.
// The server stores only this hash; at download time it receives the raw
// token via X-Download-Token for comparison.
func TokenHash(downloadToken []byte) string {
	h := sha256.Sum256(downloadToken)
	return hex.EncodeToString(h[:])
}
