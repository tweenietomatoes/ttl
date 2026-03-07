package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tweenietomatoes/ttl/internal/crypto"
)

func runGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)

	var passwordVal string
	fs.StringVar(&passwordVal, "password", "", "decryption password")
	fs.StringVar(&passwordVal, "p", "", "decryption password")

	var passwordStdinVal bool
	fs.BoolVar(&passwordStdinVal, "password-stdin", false, "read from stdin")

	var passwordFileVal string
	fs.StringVar(&passwordFileVal, "password-file", "", "read from file")

	var timeoutVal string
	fs.StringVar(&timeoutVal, "timeout", "", "transfer timeout (e.g. 5m, 1h, auto)")

	var outDirVal string
	fs.StringVar(&outDirVal, "o", "", "output directory")
	fs.StringVar(&outDirVal, "output", "", "output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() != 1 {
		return fmt.Errorf("usage: ttl get [-p PASS] [-o DIR] URL or TOKEN")
	}

	// Validate output directory if specified
	outputDir, err := resolveOutDir(outDirVal)
	if err != nil {
		return err
	}

	pass, _, err := resolvePassword(passwordVal, passwordStdinVal, passwordFileVal, false)
	if err != nil {
		return err
	}

	rawURL := fs.Arg(0)
	// Allow bare token (10 alphanumeric chars) as shorthand for https://ttl.space/TOKEN
	if isToken(rawURL) {
		rawURL = "https://ttl.space/" + rawURL
	}
	token, baseURL, err := parseURL(rawURL)
	if err != nil {
		return err
	}

	// --- probe: fetch header + metadata, verify password ---
	const probeTimeout = 30 * time.Second
	probeCtx, probeCancel := context.WithTimeout(context.Background(), probeTimeout)
	defer probeCancel()

	probeURL, err := url.JoinPath(baseURL, "v1", "probe", token)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	doProbe := func(client *http.Client) (*http.Response, error) {
		req, reqErr := http.NewRequestWithContext(probeCtx, "GET", probeURL, nil)
		if reqErr != nil {
			return nil, fmt.Errorf("invalid URL: %w", reqErr)
		}
		return client.Do(req)
	}

	var probeResp *http.Response
	if forceH3 {
		probeResp, err = doProbe(newH3Client())
		if err != nil {
			if probeResp != nil {
				probeResp.Body.Close()
			}
			fmt.Fprintln(os.Stderr, "\nh3: falling back to tcp")
			probeCancel()
			probeCtx, probeCancel = context.WithTimeout(context.Background(), probeTimeout)
			defer probeCancel()
			probeResp, err = doProbe(newTCPClient(probeTimeout))
		}
	} else {
		probeResp, err = doProbe(newTCPClient(probeTimeout))
	}
	if err != nil {
		if probeResp != nil {
			probeResp.Body.Close()
		}
		return fmt.Errorf("probe failed: %w", err)
	}

	// Check status BEFORE closing body (body needed for handleHTTPError)
	if probeResp.StatusCode != http.StatusOK {
		defer probeResp.Body.Close()
		return handleHTTPError(probeResp)
	}

	// Read probe data into memory (header + metadata, max 314 bytes)
	probeData, err := io.ReadAll(io.LimitReader(probeResp.Body, int64(crypto.ProbeMaxBytes)+1))
	probeResp.Body.Close()
	if err != nil {
		return fmt.Errorf("probe read failed: %w", err)
	}

	// Derive key from password + salt in probe header
	if len(probeData) < crypto.HeaderSize {
		return fmt.Errorf("not a ttl file: too short")
	}
	salt := probeData[crypto.SaltOffset:crypto.NonceOffset]
	encKey := crypto.DeriveEncKey(pass, salt)
	defer func() {
		for i := range encKey {
			encKey[i] = 0
		}
	}()

	// Verify the password by decrypting the metadata AEAD tag
	if err := crypto.VerifyProbe(probeData, encKey); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "password verified")

	// Derive download token for the authenticated download
	downloadToken := crypto.DeriveDownloadToken(encKey)
	defer func() {
		for i := range downloadToken {
			downloadToken[i] = 0
		}
	}()
	tokenHex := hex.EncodeToString(downloadToken)

	// --- download: full file, authenticated with bearer token ---
	xferTimeout := resolveTimeout(timeoutVal, crypto.EncryptedSize(crypto.MaxFileBytes, strings.Repeat("x", 255)))
	dlCtx, dlCancel := context.WithTimeout(context.Background(), xferTimeout)
	defer dlCancel()

	downloadURL, err := url.JoinPath(baseURL, token)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	doGet := func(client *http.Client) (*http.Response, error) {
		req, reqErr := http.NewRequestWithContext(dlCtx, "GET", downloadURL, nil)
		if reqErr != nil {
			return nil, fmt.Errorf("invalid URL: %w", reqErr)
		}
		req.Header.Set("X-Download-Token", tokenHex)
		req.Header.Set("X-Confirm-Burn", "true")
		return client.Do(req)
	}

	var resp *http.Response
	if forceH3 {
		resp, err = doGet(newH3Client())
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			fmt.Fprintln(os.Stderr, "\nh3: falling back to tcp")
			dlCancel()
			dlCtx, dlCancel = context.WithTimeout(context.Background(), xferTimeout)
			defer dlCancel()
			resp, err = doGet(newTCPClient(xferTimeout))
		}
	} else {
		resp, err = doGet(newTCPClient(xferTimeout))
	}
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return handleHTTPError(resp)
	}

	filename, written, err := crypto.DecryptStreamWithKey(
		newProgressReader(resp.Body, 0, 0), encKey, outputDir)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "◉★✧· phew, %s landed safe and sound (%s)\n", filename, humanBytes(written))
	return nil
}

// isToken returns true if s is exactly 10 alphanumeric characters (a bare token).
func isToken(s string) bool {
	if len(s) != 10 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}
	return true
}

// resolveOutDir validates and resolves the output directory.
// Returns "." if dir is empty.
func resolveOutDir(dir string) (string, error) {
	if dir == "" {
		return ".", nil
	}
	// Resolve symlinks so the path traversal check uses the real
	// filesystem path, not a symlink alias.
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("output directory does not exist: %s", dir)
	}
	abs, err := filepath.Abs(real)
	if err != nil {
		return "", fmt.Errorf("invalid output directory: %w", err)
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("output directory does not exist: %s", abs)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("not a directory: %s", abs)
	}
	// Check write permission by attempting to create a temp file
	tmp, err := os.CreateTemp(abs, ".ttl-write-test-*")
	if err != nil {
		return "", fmt.Errorf("output directory not writable: %s", abs)
	}
	tmp.Close()
	os.Remove(tmp.Name())
	return abs, nil
}

// parseURL splits a URL into its token and base, and checks that the scheme and format are valid.
func parseURL(raw string) (token, baseURL string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("invalid URL: %s", raw)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", fmt.Errorf("invalid URL scheme: %s (http/https only)", u.Scheme)
	}

	if u.Host == "" {
		return "", "", fmt.Errorf("invalid URL: missing host")
	}

	if u.User != nil {
		return "", "", fmt.Errorf("invalid URL: userinfo not allowed")
	}

	token = strings.TrimPrefix(u.Path, "/")
	if len(token) != 10 {
		return "", "", fmt.Errorf("invalid token in URL")
	}
	for _, c := range token {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			return "", "", fmt.Errorf("invalid token in URL")
		}
	}
	baseURL = u.Scheme + "://" + u.Host
	return token, baseURL, nil
}

func handleHTTPError(resp *http.Response) error {
	var p struct {
		Detail string `json:"detail"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&p)
	switch resp.StatusCode {
	case 404:
		return fmt.Errorf("link not found")
	case 429:
		return fmt.Errorf("rate limit exceeded — max 30 requests per 10s\ntry again later or see: https://ttl.space/usage")
	default:
		if p.Detail != "" {
			clean := strings.Map(func(r rune) rune {
				if r < 0x20 || r == 0x7f {
					return -1
				}
				return r
			}, p.Detail)
			return fmt.Errorf("server error: %s", clean)
		}
		return fmt.Errorf("server error: %d", resp.StatusCode)
	}
}
