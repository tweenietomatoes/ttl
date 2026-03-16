package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

func EncryptStream(w io.Writer, file io.Reader, filename string,
	fileSize uint64, key, salt []byte) error {

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	var nonce [NonceSize]byte
	io.ReadFull(rand.Reader, nonce[:])

	metaPlain := buildMetadata(filename, fileSize)
	metaCipher := aead.Seal(nil, xorNonce(nonce, 0), metaPlain, nil)

	// Write the header (not encrypted)
	if _, err := w.Write([]byte(Magic)); err != nil {
		return err
	}
	if _, err := w.Write(salt); err != nil {
		return err
	}
	if _, err := w.Write(nonce[:]); err != nil {
		return err
	}

	var metaLen [MetaLenSize]byte
	binary.BigEndian.PutUint16(metaLen[:], uint16(len(metaCipher)))
	if _, err := w.Write(metaLen[:]); err != nil {
		return err
	}

	// Write the encrypted metadata
	if _, err := w.Write(metaCipher); err != nil {
		return err
	}

	// Encrypt and write the file data chunk by chunk
	buf := make([]byte, ChunkSize)
	chunkIndex := uint64(1)
	for {
		n, readErr := io.ReadFull(file, buf)
		if n > 0 {
			ct := aead.Seal(nil, xorNonce(nonce, chunkIndex), buf[:n], nil)
			if _, err := w.Write(ct); err != nil {
				return err
			}
			chunkIndex++
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	return nil
}
