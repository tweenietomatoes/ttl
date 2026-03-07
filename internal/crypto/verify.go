package crypto

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// VerifyProbe reads the probe data (header + encrypted metadata) and verifies
// that the encryption key is correct by decrypting the metadata AEAD tag.
// Returns nil on success. Does not write anything to disk.
func VerifyProbe(probeData []byte, encKey []byte) error {
	if len(probeData) < HeaderSize {
		return fmt.Errorf("not a ttl file: too short")
	}
	if !bytes.Equal(probeData[:MagicSize], []byte(Magic)) {
		return fmt.Errorf("not a ttl file")
	}

	var nonce [NonceSize]byte
	copy(nonce[:], probeData[NonceOffset:MetaLenOffset])
	metaEncLen := int(binary.BigEndian.Uint16(probeData[MetaLenOffset:HeaderSize]))
	if metaEncLen < MinMetaEncLen || metaEncLen > MaxMetaEncLen {
		return fmt.Errorf("invalid metadata length: %d", metaEncLen)
	}

	if len(probeData) < HeaderSize+metaEncLen {
		return fmt.Errorf("incomplete metadata")
	}

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return err
	}

	// Decrypt metadata — the AEAD tag verifies the password is correct
	metaCipher := probeData[HeaderSize : HeaderSize+metaEncLen]
	metaPlain, err := aead.Open(nil, xorNonce(nonce, 0), metaCipher, nil)
	if err != nil {
		return fmt.Errorf("decryption failed (wrong password?)")
	}

	_, _, _, err = parseMetadata(metaPlain)
	if err != nil {
		return fmt.Errorf("invalid metadata: %w", err)
	}

	return nil
}
