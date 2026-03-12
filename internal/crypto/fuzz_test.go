package crypto

import (
	"bytes"
	"os"
	"testing"
)

// FuzzDecrypt_NoPanic feeds random bytes to DecryptStream.
// It should never panic or hang. Errors are expected.
func FuzzDecrypt_NoPanic(f *testing.F) {
	// Starting inputs
	f.Add([]byte("TTL\x01"))
	f.Add([]byte{})
	f.Add(make([]byte, HeaderSize))
	f.Add(make([]byte, 1000))

	// Also seed with a real encrypted blob
	valid := func() []byte {
		salt := make([]byte, SaltSize)
		copy(salt, "deterministic!!")
		key := make([]byte, KeySize)
		copy(key, "32bytekeyfortestingfuzzingnow!!")
		var buf bytes.Buffer
		EncryptStream(&buf, bytes.NewReader([]byte("fuzz seed data")), "seed.txt", 14, key, salt)
		return buf.Bytes()
	}()
	f.Add(valid)

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		orig, _ := os.Getwd()
		os.Chdir(dir)
		defer os.Chdir(orig)
		_, _, _, _ = DecryptStream(bytes.NewReader(data), "password", ".")
	})
}
