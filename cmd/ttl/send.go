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

var labelToSeconds = map[string]int{
	"5m": 300, "10m": 600, "15m": 900, "30m": 1800,
	"1h": 3600, "2h": 7200, "3h": 10800, "6h": 21600,
	"12h": 43200, "24h": 86400, "1d": 86400, "2d": 172800,
	"3d": 259200, "4d": 345600, "5d": 432000, "6d": 518400,
	"7d":  604800,
	"14d": 1209600, "15d": 1296000, "28d": 2419200, "30d": 2592000,
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
		return fmt.Errorf("Usage: ttl send [-p PASS] [-t DUR] [-b] FILE")
	}

	// Validate the file before prompting for a password, so the user
	// is not asked for input when the file path is already invalid.
	path := fs.Arg(0)
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("Not a regular file: %s", path)
	}
	if info.Size() == 0 {
		return fmt.Errorf("File is empty")
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Validate TTL syntax locally before any network call
	ttlSeconds, err := parseTTL(ttlVal)
	if err != nil {
		return err
	}

	// Load API key (empty = free tier)
	apiKey := loadAPIKey()

	// Fetch server-side limits (respects plan tier)
	serverLimits, limitsErr := fetchLimits(serverVal, apiKey)
	if limitsErr != nil {
		return fmt.Errorf("Cannot reach server: %w", limitsErr)
	}
	maxFileBytes := int64(crypto.MaxFileBytes)
	if mfb := jsonInt64(serverLimits["max_file_bytes"]); mfb > 0 {
		maxFileBytes = mfb
	}

	if info.Size() > maxFileBytes {
		return fmt.Errorf("File too large (%s, max %s)\nSee limits: https://ttl.space/usage",
			humanBytes(info.Size()), humanBytes(maxFileBytes))
	}

	// In JSON mode without explicit password, auto-generate one
	var pass string
	var generated bool
	if jsonMode && passwordVal == "" && !passwordStdinVal && passwordFileVal == "" {
		pass, err = generatePassword(8)
		if err != nil {
			return err
		}
		generated = true
	} else {
		pass, generated, err = resolvePassword(passwordVal, passwordStdinVal, passwordFileVal, true)
		if err != nil {
			return err
		}
	}

	// Pre-validate TTL against server's allowed values
	if allowed, ok := serverLimits["allowed_ttl_seconds"].([]any); ok {
		found := false
		for _, v := range allowed {
			if int(jsonInt64(v)) == ttlSeconds {
				found = true
				break
			}
		}
		if !found {
			plan, _ := serverLimits["plan"].(string)
			if plan == "free" {
				return fmt.Errorf("TTL %s is not available on the free plan (max 7d)\nUpgrade to Orbit for up to 30 days: https://ttl.space", ttlVal)
			}
			return fmt.Errorf("Invalid TTL %s for your plan", ttlVal)
		}
	}

	salt := randomBytes(crypto.SaltSize)
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
	xferTimeout, err := resolveTimeout(timeoutVal, encSize)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), xferTimeout)
	defer cancel()

	uploadURL, err := url.JoinPath(serverVal, "/v1/files")
	if err != nil {
		return fmt.Errorf("Invalid server URL: %w", err)
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
			uploadURL, newProgressReader(pr, encSize, info.Size(), jsonMode))
		if reqErr != nil {
			return nil, fmt.Errorf("Invalid server URL: %w", reqErr)
		}
		req.ContentLength = encSize
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("X-TTL", strconv.Itoa(ttlSeconds))
		req.Header.Set("X-Token-Hash", tokenHash)
		setAPIKeyHeader(req.Header, apiKey)
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
			if !jsonMode {
				fmt.Fprintf(os.Stderr, "\n%sH3: Falling back to TCP%s\n", c(cGray), c(cReset))
			}
			// Clean up the failed attempt and retry over TCP
			cancel()
			pw.CloseWithError(err)
			<-errCh

			ctx, cancel = context.WithTimeout(context.Background(), xferTimeout)
			defer cancel()
			pr, pw = io.Pipe()
			errCh = make(chan error, 1)
			if _, seekErr := f.Seek(0, io.SeekStart); seekErr != nil {
				return fmt.Errorf("Cannot retry: %w", seekErr)
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
		return fmt.Errorf("Upload failed: %w", err)
	}
	defer resp.Body.Close()

	if encErr := <-errCh; encErr != nil {
		return fmt.Errorf("Encryption failed: %w", encErr)
	}

	if resp.StatusCode != http.StatusCreated {
		return handleUploadError(resp)
	}

	var result struct {
		Link string `json:"link"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&result); err != nil {
		return fmt.Errorf("Invalid server response: %w", err)
	}
	if result.Link == "" {
		return fmt.Errorf("Server returned empty link")
	}
	// Strip control characters from the link to prevent terminal injection
	clean := stripControl(result.Link)
	if jsonMode {
		result := map[string]any{
			"ok":       true,
			"link":     clean,
			"filename": filepath.Base(path),
			"size":     info.Size(),
			"ttl":      ttlVal,
			"burn":     burnVal,
		}
		if generated {
			result["password"] = pass
		}
		json.NewEncoder(os.Stdout).Encode(result)
	} else {
		fmt.Fprintf(os.Stderr, "%s·✧★◉%s Thank goodness, %s%s%s is in orbit %s(%s%s",
			c(cGold), c(cReset),
			c(cBold, cTeal), filepath.Base(path), c(cReset),
			c(cGray), humanBytes(info.Size()), c(cReset))
		if burnVal {
			fmt.Fprintf(os.Stderr, "%s, self-destructs after download%s", c(cAmber), c(cReset))
		}
		fmt.Fprintf(os.Stderr, "%s)%s\n", c(cGray), c(cReset))
		fmt.Fprintf(os.Stderr, "%s%sIMPORTANT!%s %sSave your password — required to download and decrypt the file.%s\n",
			c(cAmber), c(cBold), c(cReset), c(cAmber), c(cReset))
		if generated {
			fmt.Fprintf(os.Stderr, "%sPassword:%s %s%s%s\n", c(cGray), c(cReset), c(cBold, cWhite), pass, c(cReset))
		}
		fmt.Println(clean)
	}
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
		return "", false, fmt.Errorf("Use only one of: --password, --password-stdin, --password-file")
	}

	// From the --password flag
	if flagValue != "" {
		if utf8.RuneCountInString(flagValue) < minPasswordLength {
			return "", false, fmt.Errorf("Password too short (min %d characters)", minPasswordLength)
		}
		return flagValue, false, nil
	}

	// From stdin
	if fromStdin {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			return "", false, fmt.Errorf("Failed to read password from stdin")
		}
		pass := scanner.Text()
		if pass == "" {
			return "", false, fmt.Errorf("Empty password from stdin")
		}
		if utf8.RuneCountInString(pass) < minPasswordLength {
			return "", false, fmt.Errorf("Password too short (min %d characters)", minPasswordLength)
		}
		return pass, false, nil
	}

	// From a file (reads only the first line)
	if fromFile != "" {
		f, err := os.Open(fromFile)
		if err != nil {
			return "", false, fmt.Errorf("Cannot read password file: %w", err)
		}
		scanner := bufio.NewScanner(f)
		if !scanner.Scan() {
			f.Close()
			return "", false, fmt.Errorf("Empty password file")
		}
		pass := strings.TrimRight(scanner.Text(), "\r")
		f.Close()
		if pass == "" {
			return "", false, fmt.Errorf("Empty password file")
		}
		if utf8.RuneCountInString(pass) < minPasswordLength {
			return "", false, fmt.Errorf("Password too short (min %d characters)", minPasswordLength)
		}
		return pass, false, nil
	}

	// Check for ttl.password file (binary-adjacent, then ~/.ttl/password)
	for _, p := range passwordFilePaths() {
		if raw, err := os.ReadFile(p); err == nil {
			pass := strings.TrimSpace(string(raw))
			if pass != "" && utf8.RuneCountInString(pass) >= minPasswordLength {
				return pass, false, nil
			}
		}
	}

	// No terminal and no password given — cannot prompt
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", false, fmt.Errorf("No password provided; use --password-stdin or --password-file")
	}

	// Terminal is available — offer to generate a password
	if allowGenerate {
		fmt.Fprintf(os.Stderr, "%sNo password provided. Generate one?%s %s[Y/n]%s: ", c(cGray), c(cReset), c(cBold), c(cReset))
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer == "" || answer == "y" || answer == "yes" {
			pass, err := generatePassword(8)
			if err != nil {
				return "", false, err
			}
			fmt.Fprintf(os.Stderr, "%sGenerated password:%s %s%s%s\n", c(cGray), c(cReset), c(cBold, cWhite), pass, c(cReset))
			return pass, true, nil
		}
	}

	// Prompt the user to type a password
	fmt.Fprintf(os.Stderr, "%sEnter password:%s ", c(cGray), c(cReset))
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", false, fmt.Errorf("Failed to read password")
	}
	pass := string(passBytes)
	for i := range passBytes {
		passBytes[i] = 0
	}
	if pass == "" {
		return "", false, fmt.Errorf("Password required")
	}
	if utf8.RuneCountInString(pass) < minPasswordLength {
		return "", false, fmt.Errorf("Password too short (min %d characters)", minPasswordLength)
	}
	if allowGenerate {
		fmt.Fprintf(os.Stderr, "%sConfirm password:%s ", c(cGray), c(cReset))
		confirmBytes, confirmErr := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if confirmErr != nil {
			return "", false, fmt.Errorf("Failed to read password")
		}
		match := string(confirmBytes) == pass
		for i := range confirmBytes {
			confirmBytes[i] = 0
		}
		if !match {
			return "", false, fmt.Errorf("Passwords do not match")
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
			return "", fmt.Errorf("Random generation failed: %w", err)
		}
		result[i] = passwordChars[n.Int64()]
	}
	return string(result), nil
}

func parseTTL(label string) (int, error) {
	seconds, ok := labelToSeconds[label]
	if !ok {
		return 0, fmt.Errorf("Invalid duration: %s (use 5m,10m,15m,30m,1h,2h,3h,6h,12h,24h,1d,2d,3d,4d,5d,6d,7d,14d,15d,28d,30d)", label)
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

func passwordFilePaths() []string {
	var paths []string
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, filepath.Join(filepath.Dir(exe), "ttl.password"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".ttl", "password"))
	}
	return paths
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	io.ReadFull(rand.Reader, b)
	return b
}

func stripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return -1
		}
		return r
	}, s)
}

func handleUploadError(resp *http.Response) error {
	var p struct {
		Detail string `json:"detail"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&p)
	switch resp.StatusCode {
	case 404:
		return fmt.Errorf("Upload endpoint not found (server may be misconfigured)")
	case 413:
		if p.Detail != "" {
			return fmt.Errorf("%s\nSee limits: https://ttl.space/usage", stripControl(p.Detail))
		}
		return fmt.Errorf("File too large\nSee limits: https://ttl.space/usage")
	case 429:
		if p.Detail != "" {
			return fmt.Errorf("%s\nTry again later or see: https://ttl.space/usage", stripControl(p.Detail))
		}
		return fmt.Errorf("Rate limit exceeded\nTry again later or see: https://ttl.space/usage")
	default:
		if p.Detail != "" {
			return fmt.Errorf("Upload failed: %s", stripControl(p.Detail))
		}
		return fmt.Errorf("Upload failed: server returned %d", resp.StatusCode)
	}
}

// Estimates based on 1 Mbps speed plus a 2-minute buffer (minimum 5 minutes).
func resolveTimeout(flag string, transferBytes int64) (time.Duration, error) {
	if flag != "" && flag != "auto" {
		d, err := time.ParseDuration(flag)
		if err == nil && d > 0 {
			return d, nil
		}
		if jsonMode {
			return 0, fmt.Errorf("Invalid timeout: %s", flag)
		}
		fmt.Fprintf(os.Stderr, "%sWarning:%s Invalid timeout %q, using auto\n", c(cAmber, cBold), c(cReset), flag)
	}
	// 1 Mbps = 125000 bytes/sec
	seconds := float64(transferBytes) / 125000
	d := time.Duration(seconds)*time.Second + 2*time.Minute
	if d < 5*time.Minute {
		d = 5 * time.Minute
	}
	return d, nil
}
