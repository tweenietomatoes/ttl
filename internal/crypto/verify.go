package crypto

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// VerifyProbe reads the probe data (header + encrypted metadata) and verifies
// that the encryption key is correct by decrypting the metadata AEAD tag.
// Returns the filename and file size from the metadata on success.
// Does not write anything to disk.
func VerifyProbe(probeData []byte, encKey []byte) (string, uint64, error) {
	if len(probeData) < HeaderSize {
		return "", 0, fmt.Errorf("Not a TTL file: too short")
	}
	if !bytes.Equal(probeData[:MagicSize], []byte(Magic)) {
		return "", 0, fmt.Errorf("Not a TTL file")
	}

	var nonce [NonceSize]byte
	copy(nonce[:], probeData[NonceOffset:MetaLenOffset])
	metaEncLen := int(binary.BigEndian.Uint16(probeData[MetaLenOffset:HeaderSize]))
	if metaEncLen < MinMetaEncLen || metaEncLen > MaxMetaEncLen {
		return "", 0, fmt.Errorf("Invalid metadata length: %d", metaEncLen)
	}

	if len(probeData) < HeaderSize+metaEncLen {
		return "", 0, fmt.Errorf("Incomplete metadata")
	}

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return "", 0, err
	}

	// Decrypt metadata — the AEAD tag verifies the password is correct
	metaCipher := probeData[HeaderSize : HeaderSize+metaEncLen]
	metaPlain, err := aead.Open(nil, xorNonce(nonce, 0), metaCipher, nil)
	if err != nil {
		return "", 0, fmt.Errorf("Decryption failed (wrong password?)")
	}

	filename, fileSize, _, err := parseMetadata(metaPlain)
	if err != nil {
		return "", 0, fmt.Errorf("Invalid metadata: %w", err)
	}

	return filename, fileSize, nil
}
