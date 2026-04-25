package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

func DeriveEncKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt,
		ArgonTime, ArgonMemory, ArgonThreads, KeySize)
}

// DeriveDownloadToken derives a download bearer token from the encryption key
// via HKDF-Expand (SHA-256). One-way: the token does not reveal the key.
func DeriveDownloadToken(encKey []byte) ([]byte, error) {
	r := hkdf.Expand(sha256.New, encKey, []byte("ttl-download-token"))
	token := make([]byte, DownloadTokenSize)
	if _, err := io.ReadFull(r, token); err != nil {
		return nil, err
	}
	return token, nil
}

// TokenHash returns the SHA-256 hash of the download token as hex.
// The server stores only this hash; at download time it receives the raw
// token via X-Download-Token for comparison.
func TokenHash(downloadToken []byte) string {
	h := sha256.Sum256(downloadToken)
	return hex.EncodeToString(h[:])
}
