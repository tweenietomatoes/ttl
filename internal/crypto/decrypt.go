package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/chacha20poly1305"
)

// DecryptStream decrypts the TTL stream from r and writes the file to outDir.
// It derives the encryption key from the password internally.
// outDir must be a valid directory path; use "." for the current directory.
// Returns the original filename from metadata, the actual saved filename
// (which may differ due to auto-rename), the number of bytes written, and any error.
func DecryptStream(r io.Reader, password string, outDir string) (string, string, int64, error) {
	// Read the header to extract the salt for key derivation
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return "", "", 0, fmt.Errorf("Not a TTL file: too short")
	}
	if !bytes.Equal(header[:MagicSize], []byte(Magic)) {
		return "", "", 0, fmt.Errorf("Not a TTL file")
	}

	salt := header[SaltOffset:NonceOffset]
	key := DeriveEncKey(password, salt)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// Prepend the already-consumed header so DecryptStreamWithKey sees the full stream
	combined := io.MultiReader(bytes.NewReader(header), r)
	return DecryptStreamWithKey(combined, key, outDir)
}

// DecryptStreamWithKey decrypts the TTL stream using a pre-derived key.
// Used by the two-phase download flow where the key is already known.
// Returns the original filename from metadata, the actual saved filename
// (which may differ due to auto-rename), the number of bytes written, and any error.
func DecryptStreamWithKey(r io.Reader, key []byte, outDir string) (string, string, int64, error) {
	// Read and check the header
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return "", "", 0, fmt.Errorf("Not a TTL file: too short")
	}
	if !bytes.Equal(header[:MagicSize], []byte(Magic)) {
		return "", "", 0, fmt.Errorf("Not a TTL file")
	}

	var nonce [NonceSize]byte
	copy(nonce[:], header[NonceOffset:MetaLenOffset])
	metaEncLen := int(binary.BigEndian.Uint16(header[MetaLenOffset:HeaderSize]))
	if metaEncLen < MinMetaEncLen || metaEncLen > MaxMetaEncLen {
		return "", "", 0, fmt.Errorf("Invalid metadata length: %d", metaEncLen)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", "", 0, err
	}

	// Decrypt the metadata (filename, file size, chunk size)
	metaCipher := make([]byte, metaEncLen)
	if _, err := io.ReadFull(r, metaCipher); err != nil {
		return "", "", 0, fmt.Errorf("Incomplete metadata")
	}
	metaPlain, err := aead.Open(nil, xorNonce(nonce, 0), metaCipher, nil)
	if err != nil {
		return "", "", 0, fmt.Errorf("Decryption failed (wrong password?)")
	}

	filename, fileSize, chunkSize, err := parseMetadata(metaPlain)
	if err != nil {
		return "", "", 0, fmt.Errorf("Invalid metadata: %w", err)
	}

	// Clean the filename to prevent path traversal
	filename = sanitizeFilename(filename)

	// Build the full output path and verify it stays within outDir
	outPath := filepath.Join(outDir, filename)
	absOut, err := filepath.Abs(outPath)
	if err != nil {
		return "", "", 0, fmt.Errorf("Invalid output path: %w", err)
	}
	absDir, err := filepath.Abs(outDir)
	if err != nil {
		return "", "", 0, fmt.Errorf("Invalid output directory: %w", err)
	}
	// Use filepath.Rel instead of a prefix check to avoid false positives
	// like "/tmp" erroneously matching "/tmpevil".
	rel, relErr := filepath.Rel(absDir, absOut)
	if relErr != nil || strings.HasPrefix(rel, "..") {
		return "", "", 0, fmt.Errorf("Path traversal blocked: %s", filename)
	}

	// Verify the first data chunk before creating any file on disk.
	// If decryption fails here, we abort without touching the filesystem.
	cs := uint64(chunkSize)
	fullChunks := fileSize / cs
	lastPlainLen := fileSize % cs
	var totalChunks uint64
	if lastPlainLen > 0 {
		totalChunks = fullChunks + 1
	} else {
		totalChunks = fullChunks
	}

	// Safe to cast: parseMetadata already checked that chunkSize <= MaxChunkSize
	buf := make([]byte, int(cs)+TagSize)

	var firstPlain []byte
	if totalChunks > 0 {
		// Decrypt the first data chunk in memory (no file created yet)
		var cipherLen int
		if fullChunks > 0 {
			cipherLen = int(chunkSize) + TagSize
		} else {
			cipherLen = int(lastPlainLen) + TagSize
		}
		if _, err = io.ReadFull(r, buf[:cipherLen]); err != nil {
			return "", "", 0, fmt.Errorf("File truncated at chunk 1")
		}
		firstPlain, err = aead.Open(nil,
			xorNonce(nonce, 1), buf[:cipherLen], nil)
		if err != nil {
			return "", "", 0, fmt.Errorf("Corrupted or tampered data at chunk 1")
		}
	} else {
		// Zero-byte file: verify EOF before creating any file
		probe := make([]byte, 1)
		n, readErr := r.Read(probe)
		if n > 0 {
			return "", "", 0, fmt.Errorf("Unexpected trailing data")
		}
		if readErr != nil && readErr != io.EOF {
			return "", "", 0, fmt.Errorf("Error reading stream: %w", readErr)
		}
	}

	// First chunk (or EOF for 0-byte) verified — safe to create the output file
	originalFilename := filename
	outPath, filename, err = findAvailablePath(outDir, filename)
	if err != nil {
		return "", "", 0, err
	}
	out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return "", "", 0, fmt.Errorf("Cannot create file: %w", err)
	}
	var success bool
	defer func() {
		if !success {
			out.Close()
			os.Remove(outPath)
		}
	}()

	// Write the already-decrypted first chunk
	var written int64
	if len(firstPlain) > 0 {
		if _, err = out.Write(firstPlain); err != nil {
			return "", "", 0, fmt.Errorf("Write failed: %w", err)
		}
		written += int64(len(firstPlain))
	}

	// Decrypt and write remaining chunks
	var plaintext []byte
	for i := uint64(1); i < totalChunks; i++ {
		chunkIndex := i + 1
		var cipherLen int
		if i < fullChunks {
			cipherLen = int(chunkSize) + TagSize
		} else {
			cipherLen = int(lastPlainLen) + TagSize
		}
		if _, err = io.ReadFull(r, buf[:cipherLen]); err != nil {
			return "", "", 0, fmt.Errorf("File truncated at chunk %d", chunkIndex)
		}
		plaintext, err = aead.Open(plaintext[:0],
			xorNonce(nonce, chunkIndex), buf[:cipherLen], nil)
		if err != nil {
			return "", "", 0, fmt.Errorf("Corrupted or tampered data at chunk %d", chunkIndex)
		}
		if _, err = out.Write(plaintext); err != nil {
			return "", "", 0, fmt.Errorf("Write failed: %w", err)
		}
		written += int64(len(plaintext))
	}

	// Make sure there is no extra data after the last chunk
	trail := make([]byte, 1)
	n, readErr := r.Read(trail)
	if n > 0 {
		return "", "", 0, fmt.Errorf("Unexpected trailing data")
	}
	if readErr != nil && readErr != io.EOF {
		return "", "", 0, fmt.Errorf("Error reading stream tail: %w", readErr)
	}

	// Check that the total bytes written match the expected file size
	if uint64(written) != fileSize {
		return "", "", 0, fmt.Errorf("Size mismatch: expected %d, got %d",
			fileSize, written)
	}

	// Flush to disk and close before reporting success
	if err := out.Sync(); err != nil {
		return "", "", 0, fmt.Errorf("Sync failed: %w", err)
	}
	if err := out.Close(); err != nil {
		return "", "", 0, fmt.Errorf("Close failed: %w", err)
	}
	success = true
	return originalFilename, filename, written, nil
}

// findAvailablePath returns a path that doesn't conflict with existing files.
// If the original filename is available, it is returned as-is.
// If a file or symlink exists, it tries "name (1).ext" through "name (99).ext".
// Directories block the name entirely (cannot auto-rename around them).
func findAvailablePath(dir, filename string) (outPath string, actualName string, err error) {
	outPath = filepath.Join(dir, filename)

	fi, statErr := os.Lstat(outPath)
	if statErr != nil {
		if !os.IsNotExist(statErr) {
			return "", "", fmt.Errorf("Cannot check path: %w", statErr)
		}
		// Path doesn't exist — use original name
		return outPath, filename, nil
	}
	if fi.IsDir() {
		return "", "", fmt.Errorf("Directory already exists: %s", filename)
	}

	// File or symlink exists — try sequential suffixes
	ext := filepath.Ext(filename)
	base := strings.TrimSuffix(filename, ext)

	for i := 1; i <= 99; i++ {
		suffix := fmt.Sprintf(" (%d)", i)
		candidate := truncatedCandidate(base, suffix, ext)
		if candidate == "" {
			return "", "", fmt.Errorf("Filename too long to rename: %s", filename)
		}

		candidatePath := filepath.Join(dir, candidate)
		if _, lErr := os.Lstat(candidatePath); lErr != nil {
			if !os.IsNotExist(lErr) {
				return "", "", fmt.Errorf("Cannot check path: %w", lErr)
			}
			return candidatePath, candidate, nil
		}
	}

	// All (1)–(99) taken: use a random 2-byte hex suffix
	var rnd [2]byte
	rand.Read(rnd[:])
	suffix := fmt.Sprintf(" (%x)", rnd)
	candidate := truncatedCandidate(base, suffix, ext)
	if candidate == "" {
		return "", "", fmt.Errorf("Filename too long to rename: %s", filename)
	}
	candidatePath := filepath.Join(dir, candidate)
	if _, lErr := os.Lstat(candidatePath); lErr == nil {
		return "", "", fmt.Errorf("Cannot find available name for: %s", filename)
	} else if !os.IsNotExist(lErr) {
		return "", "", fmt.Errorf("Cannot check path: %w", lErr)
	}
	return candidatePath, candidate, nil
}

// truncatedCandidate builds "base + suffix + ext", truncating base if needed
// to keep the total filename at or below 255 bytes. Returns "" if impossible.
func truncatedCandidate(base, suffix, ext string) string {
	candidate := base + suffix + ext
	if len(candidate) <= 255 {
		return candidate
	}
	maxBase := 255 - len(suffix) - len(ext)
	if maxBase <= 0 {
		return ""
	}
	// Don't split a multi-byte UTF-8 rune
	for maxBase > 0 && !utf8.RuneStart(base[maxBase]) {
		maxBase--
	}
	if maxBase <= 0 {
		return ""
	}
	return base[:maxBase] + suffix + ext
}

// sanitizeFilename removes dangerous parts from a filename.
// It strips control characters, Unicode format characters (bidi overrides),
// and Windows-invalid characters (for cross-platform safety).
// It normalises slashes, takes the base name, removes leading dots,
// strips trailing dots and spaces, blocks Windows reserved device names,
// and falls back to "download.bin" if nothing is left.
func sanitizeFilename(name string) string {
	// Remove control characters (C0, DEL, C1) and Unicode format characters (bidi overrides, etc.)
	var clean strings.Builder
	for _, r := range name {
		if r >= 0x20 && !(r >= 0x7f && r <= 0x9f) && !unicode.Is(unicode.Cf, r) {
			clean.WriteRune(r)
		}
	}
	name = clean.String()
	name = strings.ReplaceAll(name, "\\", "/")
	name = filepath.Base(name)
	// Strip characters that are invalid on Windows (NTFS ADS, wildcards, etc.)
	name = strings.Map(func(r rune) rune {
		switch r {
		case ':', '*', '?', '"', '<', '>', '|':
			return -1
		}
		return r
	}, name)
	name = strings.TrimLeft(name, ".")
	name = strings.TrimRight(name, ". ")
	if name == "" || name == "." {
		name = "download.bin"
	}
	// Block Windows reserved device names (CON, PRN, NUL, AUX, COM1–9, LPT1–9)
	base := strings.ToUpper(name)
	if dot := strings.IndexByte(base, '.'); dot >= 0 {
		base = base[:dot]
	}
	switch base {
	case "CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		name = "_" + name
	}
	return name
}
