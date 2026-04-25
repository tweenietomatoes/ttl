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
	fs.Usage = func() {
		if !jsonMode {
			printUsage()
		}
	}
	if jsonMode {
		fs.SetOutput(io.Discard)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() != 1 {
		return fmt.Errorf("Usage: ttl get [-p PASS] [-o DIR] URL or TOKEN")
	}

	// Validate output directory if specified
	outputDir, err := resolveOutDir(outDirVal)
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

	pass, _, err := resolvePassword(passwordVal, passwordStdinVal, passwordFileVal, false)
	if err != nil {
		return err
	}

	// --- probe: fetch header + metadata, verify password ---
	const probeTimeout = 30 * time.Second
	probeCtx, probeCancel := context.WithTimeout(context.Background(), probeTimeout)
	defer probeCancel()

	probeURL, err := url.JoinPath(baseURL, "v1", "probe", token)
	if err != nil {
		return fmt.Errorf("Invalid URL: %w", err)
	}

	// Sent on probe + download; needed for uploader-only files, harmless otherwise.
	apiKey := loadAPIKey()

	doProbe := func(client *http.Client) (*http.Response, error) {
		req, reqErr := http.NewRequestWithContext(probeCtx, "GET", probeURL, nil)
		if reqErr != nil {
			return nil, fmt.Errorf("Invalid URL: %w", reqErr)
		}
		setAPIKeyHeader(req.Header, apiKey)
		return client.Do(req)
	}

	var probeResp *http.Response
	if forceH3 {
		probeResp, err = doProbe(newH3Client())
		if err != nil {
			if probeResp != nil {
				_ = probeResp.Body.Close()
			}
			if !jsonMode {
				fmt.Fprintf(os.Stderr, "\n%sH3: Falling back to TCP%s\n", c(cGray), c(cReset))
			}
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
			_ = probeResp.Body.Close()
		}
		return fmt.Errorf("Probe failed: %w", err)
	}

	// Check status before closing body: handleHTTPError reads it
	if probeResp.StatusCode != http.StatusOK {
		defer probeResp.Body.Close()
		return handleHTTPError(probeResp)
	}

	// Read probe data into memory (header + metadata, max 314 bytes)
	probeData, err := io.ReadAll(io.LimitReader(probeResp.Body, int64(crypto.ProbeMaxBytes)+1))
	_ = probeResp.Body.Close()
	if err != nil {
		return fmt.Errorf("Probe read failed: %w", err)
	}

	// Derive key from password + salt in probe header
	if len(probeData) < crypto.HeaderSize {
		return fmt.Errorf("Not a TTL file: too short")
	}
	salt := probeData[crypto.SaltOffset:crypto.NonceOffset]
	encKey := crypto.DeriveEncKey(pass, salt)
	defer func() {
		for i := range encKey {
			encKey[i] = 0
		}
	}()

	// Verify the password by decrypting the metadata AEAD tag
	probeFilename, probeFileSize, err := crypto.VerifyProbe(probeData, encKey)
	if err != nil {
		return err
	}
	if !jsonMode {
		fmt.Fprintf(os.Stderr, "%sPassword verified%s\n", c(cGreen), c(cReset))
	}

	// Derive download token for the authenticated download
	downloadToken, err := crypto.DeriveDownloadToken(encKey)
	if err != nil {
		return fmt.Errorf("Token derivation failed: %w", err)
	}
	defer func() {
		for i := range downloadToken {
			downloadToken[i] = 0
		}
	}()
	tokenHex := hex.EncodeToString(downloadToken)

	// --- download: full file, authenticated with bearer token ---
	xferTimeout, err := resolveTimeout(timeoutVal, crypto.EncryptedSize(probeFileSize, probeFilename))
	if err != nil {
		return err
	}
	dlCtx, dlCancel := context.WithTimeout(context.Background(), xferTimeout)
	defer dlCancel()

	downloadURL, err := url.JoinPath(baseURL, token)
	if err != nil {
		return fmt.Errorf("Invalid URL: %w", err)
	}
	doGet := func(client *http.Client) (*http.Response, error) {
		req, reqErr := http.NewRequestWithContext(dlCtx, "GET", downloadURL, nil)
		if reqErr != nil {
			return nil, fmt.Errorf("Invalid URL: %w", reqErr)
		}
		req.Header.Set("X-Download-Token", tokenHex)
		req.Header.Set("X-Confirm-Burn", "true")
		setAPIKeyHeader(req.Header, apiKey)
		return client.Do(req)
	}

	var resp *http.Response
	if forceH3 {
		resp, err = doGet(newH3Client())
		if err != nil {
			if resp != nil {
				_ = resp.Body.Close()
			}
			if !jsonMode {
				fmt.Fprintf(os.Stderr, "\n%sH3: Falling back to TCP%s\n", c(cGray), c(cReset))
			}
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
			_ = resp.Body.Close()
		}
		return fmt.Errorf("Download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return handleHTTPError(resp)
	}

	encTotal := crypto.EncryptedSize(probeFileSize, probeFilename)
	origName, filename, written, err := crypto.DecryptStreamWithKey(
		newProgressReader(resp.Body, encTotal, int64(probeFileSize), jsonMode), //nolint:gosec // file size <= MaxFileBytes (256 MB), fits int64
		encKey, outputDir)
	if err != nil {
		return err
	}

	if jsonMode {
		savedTo, _ := filepath.Abs(filepath.Join(outputDir, filename))
		result := map[string]any{
			"ok":       true,
			"filename": filename,
			"size":     written,
			"saved_to": savedTo,
		}
		if filename != origName {
			result["original_filename"] = origName
		}
		_ = json.NewEncoder(os.Stdout).Encode(result)
	} else {
		if filename != origName {
			fmt.Fprintf(os.Stderr, "%s⚠ %s already exists — saving as %s%s\n", c(cAmber), origName, filename, c(cReset))
		}
		fmt.Fprintf(os.Stderr, "%s◉★✧·%s Phew, %s%s%s landed safe and sound %s(%s)%s\n",
			c(cGold), c(cReset),
			c(cBold, cTeal), filename, c(cReset),
			c(cGray), humanBytes(written), c(cReset))
	}
	return nil
}

func isToken(s string) bool {
	if len(s) != 10 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

func resolveOutDir(dir string) (string, error) {
	if dir == "" {
		return ".", nil
	}
	// Resolve symlinks so the path traversal check uses the real
	// filesystem path, not a symlink alias.
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("Output directory does not exist: %s", dir)
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("Invalid output directory: %w", err)
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("Output directory does not exist: %s", abs)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("Not a directory: %s", abs)
	}
	// Check write permission by attempting to create a temp file
	tmp, err := os.CreateTemp(abs, ".ttl-write-test-*")
	if err != nil {
		return "", fmt.Errorf("Output directory not writable: %s", abs)
	}
	_ = tmp.Close()
	_ = os.Remove(tmp.Name())
	return abs, nil
}

func parseURL(raw string) (token, baseURL string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("Invalid URL: %s", raw)
	}

	if u.Host == "" {
		return "", "", fmt.Errorf("Invalid URL: missing host")
	}

	if u.User != nil {
		return "", "", fmt.Errorf("Invalid URL: userinfo not allowed")
	}

	// X-Download-Token and X-API-Key go over plain HTTP otherwise.
	// Loopback is allowed for httptest and local dev.
	if err := requireSecureScheme(u); err != nil {
		return "", "", err
	}

	token = strings.TrimPrefix(u.Path, "/")
	if !isToken(token) {
		return "", "", fmt.Errorf("Invalid token in URL")
	}
	baseURL = u.Scheme + "://" + u.Host
	return token, baseURL, nil
}

// requireSecureScheme requires https for non-loopback hosts. http is
// allowed only for localhost / 127.0.0.1 / ::1.
func requireSecureScheme(u *url.URL) error {
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return fmt.Errorf("Refusing http:// for non-local host %q (use https)", host)
	default:
		return fmt.Errorf("Invalid URL scheme: %s (https only, http allowed for localhost)", u.Scheme)
	}
}

// validateServerURL applies the same scheme + userinfo policy as parseURL
// to a `-server` flag value.
func validateServerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("Invalid server URL: %w", err)
	}
	if u.Host == "" {
		return fmt.Errorf("Invalid server URL: missing host")
	}
	if u.User != nil {
		return fmt.Errorf("Invalid server URL: userinfo not allowed")
	}
	return requireSecureScheme(u)
}

func handleHTTPError(resp *http.Response) error {
	var p struct {
		Detail string `json:"detail"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&p)
	switch resp.StatusCode {
	case 404:
		return fmt.Errorf("Link not found")
	case 429:
		return fmt.Errorf("Rate limit exceeded — max 30 requests per 10s\nTry again later or see: https://ttl.space/usage")
	default:
		if p.Detail != "" {
			return fmt.Errorf("Server error: %s", stripControl(p.Detail))
		}
		return fmt.Errorf("Server error: %d", resp.StatusCode)
	}
}
