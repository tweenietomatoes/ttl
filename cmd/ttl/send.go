package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/tweenietomatoes/ttl/internal/crypto"
)

var forceH3 bool // set by the -h3 flag in main

const maxFileBytes = crypto.MaxFileBytes

var labelToSeconds = map[string]int{
	"5m": 300, "10m": 600, "15m": 900, "30m": 1800,
	"1h": 3600, "2h": 7200, "3h": 10800, "6h": 21600,
	"12h": 43200, "24h": 86400, "1d": 86400, "2d": 172800,
	"3d": 259200, "4d": 345600, "5d": 432000, "6d": 518400,
	"7d": 604800,
}

func runSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)

	var passwordVal string
	fs.StringVar(&passwordVal, "password", "", "encryption password")
	fs.StringVar(&passwordVal, "p", "", "encryption password")

	var passwordStdinVal bool
	fs.BoolVar(&passwordStdinVal, "password-stdin", false, "read from stdin")

	var passwordFileVal string
	fs.StringVar(&passwordFileVal, "password-file", "", "read from file")

	var ttlVal string
	fs.StringVar(&ttlVal, "t", "7d", "time to live")
	fs.StringVar(&ttlVal, "ttl", "7d", "time to live")

	var burnVal bool
	fs.BoolVar(&burnVal, "b", false, "burn after reading (single download)")
	fs.BoolVar(&burnVal, "burn", false, "burn after reading (single download)")

	var serverVal string
	fs.StringVar(&serverVal, "server", "https://ttl.space", "server URL")

	var timeoutVal string
	fs.StringVar(&timeoutVal, "timeout", "", "transfer timeout (e.g. 5m, 1h, auto)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() != 1 {
		return fmt.Errorf("usage: ttl send [-p PASS] [-t DUR] [-b] FILE")
	}

	// Validate the file before prompting for a password, so the user
	// is not asked for input when the file path is already invalid.
	path := fs.Arg(0)
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("cannot stat file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("cannot send a directory: %s", path)
	}
	if info.Size() == 0 {
		return fmt.Errorf("file is empty")
	}
	if info.Size() > maxFileBytes {
		return fmt.Errorf("file too large (%s, max 256 MB)\nsee limits: https://ttl.space/usage", humanBytes(info.Size()))
	}

	pass, generated, err := resolvePassword(passwordVal, passwordStdinVal, passwordFileVal, true)
	if err != nil {
		return err
	}

	ttlSeconds, err := parseTTL(ttlVal)
	if err != nil {
		return err
	}

	salt, err := randomBytes(crypto.SaltSize)
	if err != nil {
		return err
	}
	key := crypto.DeriveEncKey(pass, salt)
	downloadToken := crypto.DeriveDownloadToken(key)
	tokenHash := crypto.TokenHash(downloadToken)
	defer func() {
		for i := range key {
			key[i] = 0
		}
		for i := range downloadToken {
			downloadToken[i] = 0
		}
	}()

	encSize := crypto.EncryptedSize(uint64(info.Size()), filepath.Base(path))
	xferTimeout := resolveTimeout(timeoutVal, encSize)

	ctx, cancel := context.WithTimeout(context.Background(), xferTimeout)
	defer cancel()

	uploadURL, err := url.JoinPath(serverVal, "/v1/files")
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}

	pr, pw := io.Pipe()
	errCh := make(chan error, 1)
	go func() {
		err := crypto.EncryptStream(pw, f,
			filepath.Base(path), uint64(info.Size()), key, salt)
		pw.CloseWithError(err)
		errCh <- err
	}()

	doUpload := func(client *http.Client) (*http.Response, error) {
		req, reqErr := http.NewRequestWithContext(ctx, "PUT",
			uploadURL, newProgressReader(pr, encSize, info.Size()))
		if reqErr != nil {
			return nil, fmt.Errorf("invalid server URL: %w", reqErr)
		}
		req.ContentLength = encSize
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("X-TTL", strconv.Itoa(ttlSeconds))
		req.Header.Set("X-Token-Hash", tokenHash)
		if burnVal {
			req.Header.Set("X-Burn-After-Reading", "true")
		}
		return client.Do(req)
	}

	var resp *http.Response
	if forceH3 {
		resp, err = doUpload(newH3Client())
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			// QUIC failed, fall back to TCP
			fmt.Fprintln(os.Stderr, "\nh3: falling back to tcp")
			// The first pipe is used up, make a new one
			cancel()
			pw.CloseWithError(err)
			<-errCh

			ctx, cancel = context.WithTimeout(context.Background(), xferTimeout)
			defer cancel()
			pr, pw = io.Pipe()
			errCh = make(chan error, 1)
			if _, seekErr := f.Seek(0, io.SeekStart); seekErr != nil {
				return fmt.Errorf("cannot retry: %w", seekErr)
			}
			go func() {
				err := crypto.EncryptStream(pw, f,
					filepath.Base(path), uint64(info.Size()), key, salt)
				pw.CloseWithError(err)
				errCh <- err
			}()
			resp, err = doUpload(newTCPClient(xferTimeout))
		}
	} else {
		resp, err = doUpload(newTCPClient(xferTimeout))
	}
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		cancel()
		pw.CloseWithError(err)
		<-errCh
		return fmt.Errorf("upload failed: %w", err)
	}
	defer resp.Body.Close()

	if encErr := <-errCh; encErr != nil {
		return fmt.Errorf("encryption failed: %w", encErr)
	}

	if resp.StatusCode != http.StatusCreated {
		return handleUploadError(resp)
	}

	var result struct {
		Link string `json:"link"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&result); err != nil {
		return fmt.Errorf("invalid server response: %w", err)
	}
	if result.Link == "" {
		return fmt.Errorf("server returned empty link")
	}
	// Strip control characters from the link to prevent terminal injection
	clean := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, result.Link)
	fmt.Fprintf(os.Stderr, "·✧★◉ thank goodness, %s is in orbit (%s", filepath.Base(path), humanBytes(info.Size()))
	if burnVal {
		fmt.Fprint(os.Stderr, ", self-destructs after download")
	}
	fmt.Fprintln(os.Stderr, ")")
	fmt.Fprintln(os.Stderr, "IMPORTANT! save your password — required to download and decrypt the file.")
	if generated {
		fmt.Fprintf(os.Stderr, "password: %s\n", pass)
	}
	fmt.Println(clean)
	return nil
}

const minPasswordLength = 8

func resolvePassword(flagValue string, fromStdin bool, fromFile string,
	allowGenerate bool) (string, bool, error) {

	// Only one password source is allowed at a time
	sources := 0
	if flagValue != "" {
		sources++
	}
	if fromStdin {
		sources++
	}
	if fromFile != "" {
		sources++
	}
	if sources > 1 {
		return "", false, fmt.Errorf("use only one of: --password, --password-stdin, --password-file")
	}

	// From the --password flag
	if flagValue != "" {
		if utf8.RuneCountInString(flagValue) < minPasswordLength {
			return "", false, fmt.Errorf("password too short (min %d characters)", minPasswordLength)
		}
		return flagValue, false, nil
	}

	// From stdin
	if fromStdin {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			return "", false, fmt.Errorf("failed to read password from stdin")
		}
		pass := scanner.Text()
		if pass == "" {
			return "", false, fmt.Errorf("empty password from stdin")
		}
		if utf8.RuneCountInString(pass) < minPasswordLength {
			return "", false, fmt.Errorf("password too short (min %d characters)", minPasswordLength)
		}
		return pass, false, nil
	}

	// From a file (reads only the first line)
	if fromFile != "" {
		f, err := os.Open(fromFile)
		if err != nil {
			return "", false, fmt.Errorf("cannot read password file: %w", err)
		}
		scanner := bufio.NewScanner(f)
		if !scanner.Scan() {
			f.Close()
			return "", false, fmt.Errorf("empty password file")
		}
		pass := strings.TrimRight(scanner.Text(), "\r")
		f.Close()
		if pass == "" {
			return "", false, fmt.Errorf("empty password file")
		}
		if utf8.RuneCountInString(pass) < minPasswordLength {
			return "", false, fmt.Errorf("password too short (min %d characters)", minPasswordLength)
		}
		return pass, false, nil
	}

	// No terminal and no password given — cannot prompt
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", false, fmt.Errorf("no password provided; use --password-stdin or --password-file")
	}

	// Terminal is available — offer to generate a password
	if allowGenerate {
		fmt.Fprint(os.Stderr, "No password provided. Generate one? [Y/n]: ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer == "" || answer == "y" || answer == "yes" {
			pass, err := generatePassword(8)
			if err != nil {
				return "", false, err
			}
			fmt.Fprintf(os.Stderr, "Generated password: %s\n", pass)
			return pass, true, nil
		}
	}

	// Prompt the user to type a password
	fmt.Fprint(os.Stderr, "Enter password: ")
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", false, fmt.Errorf("failed to read password")
	}
	pass := string(passBytes)
	for i := range passBytes {
		passBytes[i] = 0
	}
	if pass == "" {
		return "", false, fmt.Errorf("password required")
	}
	if utf8.RuneCountInString(pass) < minPasswordLength {
		return "", false, fmt.Errorf("password too short (min %d characters)", minPasswordLength)
	}
	if allowGenerate {
		fmt.Fprint(os.Stderr, "Confirm password: ")
		confirmBytes, confirmErr := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if confirmErr != nil {
			return "", false, fmt.Errorf("failed to read password")
		}
		match := string(confirmBytes) == pass
		for i := range confirmBytes {
			confirmBytes[i] = 0
		}
		if !match {
			return "", false, fmt.Errorf("passwords do not match")
		}
	}
	return pass, false, nil
}

const passwordChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func generatePassword(length int) (string, error) {
	result := make([]byte, length)
	max := big.NewInt(int64(len(passwordChars)))
	for i := range result {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("random generation failed: %w", err)
		}
		result[i] = passwordChars[n.Int64()]
	}
	return string(result), nil
}

func parseTTL(label string) (int, error) {
	seconds, ok := labelToSeconds[label]
	if !ok {
		return 0, fmt.Errorf("invalid duration: %s (use 5m,10m,15m,30m,1h,2h,3h,6h,12h,24h,1d,2d,3d,4d,5d,6d,7d)", label)
	}
	return seconds, nil
}

func humanBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("random generation failed: %w", err)
	}
	return b, nil
}

// handleUploadError maps HTTP error responses to upload-specific messages.
func handleUploadError(resp *http.Response) error {
	var p struct {
		Detail string `json:"detail"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&p)
	switch resp.StatusCode {
	case 404:
		return fmt.Errorf("upload endpoint not found (server may be misconfigured)")
	case 413:
		return fmt.Errorf("file too large — max 256 MB per file\nsee limits: https://ttl.space/usage")
	case 429:
		return fmt.Errorf("rate limit exceeded — max 10 uploads/day, min 3s between uploads, 30 req/10s\ntry again later or see: https://ttl.space/usage")
	default:
		if p.Detail != "" {
			clean := strings.Map(func(r rune) rune {
				if r < 0x20 || r == 0x7f {
					return -1
				}
				return r
			}, p.Detail)
			return fmt.Errorf("upload failed: %s", clean)
		}
		return fmt.Errorf("upload failed: server returned %d", resp.StatusCode)
	}
}

// resolveTimeout picks the transfer timeout.
// If the user gave a duration like "5m" or "1h", use that.
// Otherwise, estimate based on 1 Mbps speed plus a 2 min buffer (min 5 min).
func resolveTimeout(flag string, transferBytes int64) time.Duration {
	if flag != "" && flag != "auto" {
		d, err := time.ParseDuration(flag)
		if err == nil && d > 0 {
			return d
		}
		fmt.Fprintf(os.Stderr, "warning: invalid timeout %q, using auto\n", flag)
	}
	// 1 Mbps = 125000 bytes/sec
	seconds := float64(transferBytes) / 125000
	d := time.Duration(seconds)*time.Second + 2*time.Minute
	if d < 5*time.Minute {
		d = 5 * time.Minute
	}
	return d
}
