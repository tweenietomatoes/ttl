package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
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

	var serverVal string
	fs.StringVar(&serverVal, "server", "https://ttl.space", "server URL for a bare token")
	fs.Usage = func() {
		if !jsonMode {
			printUsage()
		}
	}
	if jsonMode {
		fs.SetOutput(io.Discard)
	}
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("Usage: ttl get [-p PASS] [-o DIR] URL or TOKEN")
	}

	// Validate output directory if specified
	outputDir, err := resolveOutDir(outDirVal)
	if err != nil {
		return err
	}

	rawURL := pos[0]
	// Allow bare token (10 alphanumeric chars) as shorthand for https://ttl.space/TOKEN
	if isToken(rawURL) {
		if err := validateServerURL(serverVal); err != nil {
			return err
		}
		rawURL = strings.TrimRight(serverVal, "/") + "/" + rawURL
	}
	token, baseURL, err := parseURL(rawURL)
	if err != nil {
		return err
	}

	pass, _, err := resolvePassword(passwordVal, passwordStdinVal, passwordFileVal, false)
	if err != nil {
		return err
	}

	// Sent on probe + download; needed for uploader-only files, harmless otherwise.
	apiKey := loadAPIKey()
	hc := newConn()

	// --- probe: fetch header + metadata, verify password ---
	const probeTimeout = 30 * time.Second
	probeCtx, probeCancel := context.WithTimeout(context.Background(), probeTimeout)
	defer probeCancel()

	probeURL, err := url.JoinPath(baseURL, "v1", "probe", token)
	if err != nil {
		return fmt.Errorf("Invalid URL: %w", err)
	}
	probeReq, err := newRequest(probeCtx, http.MethodGet, probeURL, nil)
	if err != nil {
		return err
	}
	setAPIKeyHeader(probeReq.Header, apiKey)
	probeResp, err := hc.do(probeReq)
	if err != nil {
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
	encTotal := crypto.EncryptedSize(probeFileSize, probeFilename)
	xferTimeout, err := resolveTimeout(timeoutVal)
	if err != nil {
		return err
	}
	dlCtx, dlCancel := transferContext(xferTimeout)
	defer dlCancel()
	// Ctrl-C ends the download cleanly: the partial file is removed.
	dlCtx, stop := signal.NotifyContext(dlCtx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	downloadURL, err := url.JoinPath(baseURL, token)
	if err != nil {
		return fmt.Errorf("Invalid URL: %w", err)
	}
	// A one-time file is used up the moment its download starts. The answer
	// then carries a resume ticket: only with it does the server hand out
	// the rest after a broken connection (for a few minutes). It stays in
	// memory, never printed or stored. With a ticket every request after the
	// first is a range, from byte 0 too.
	open := func(ctx context.Context, from int64, ticket string) (*http.Response, error) {
		req, reqErr := newRequest(ctx, http.MethodGet, downloadURL, nil)
		if reqErr != nil {
			return nil, reqErr
		}
		req.Header.Set("X-Download-Token", tokenHex)
		req.Header.Set("X-Confirm-Burn", "true")
		setAPIKeyHeader(req.Header, apiKey)
		if from > 0 || ticket != "" {
			req.Header.Set("Range", "bytes="+strconv.FormatInt(from, 10)+"-")
		}
		if ticket != "" {
			req.Header.Set("X-Resume-Ticket", ticket)
		}
		return hc.do(req)
	}

	resp, err := open(dlCtx, 0, "")
	if err != nil {
		return fmt.Errorf("Download failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return handleHTTPError(resp)
	}

	prog := newProgress(encTotal, int64(probeFileSize), jsonMode) //nolint:gosec // file size is capped at 1 TB by parseMetadata, fits int64
	ticket := resp.Header.Get("X-Resume-Ticket")
	body := &resumingBody{ctx: dlCtx, open: open, body: resp.Body, total: encTotal, prog: prog, ticket: ticket, oneTime: ticket != ""}
	defer func() { _ = body.Close() }()
	origName, filename, written, err := crypto.DecryptStreamWithKey(prog.reader(body), encKey, outputDir)
	prog.finish()
	if err != nil {
		if body.failure != nil {
			return body.failure
		}
		return err
	}

	if jsonMode {
		savedTo, _ := filepath.Abs(filepath.Join(outputDir, filename))
		out := struct {
			OK               bool   `json:"ok"`
			Token            string `json:"token"`
			Filename         string `json:"filename"`
			Size             int64  `json:"size"`
			SavedTo          string `json:"saved_to"`
			OriginalFilename string `json:"original_filename,omitempty"`
		}{true, token, filename, written, savedTo, ""}
		if filename != origName {
			out.OriginalFilename = origName
		}
		writeJSON(out)
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

// ── Resumable download ──

const maxResumes = 8

// downloadIdle: a download read that brings no byte for this long is taken
// for a connection that died silently; the body is closed and the rest is
// asked for from the same byte. Only a read waiting for the network is
// timed. A variable for tests.
var downloadIdle = time.Minute

// resumingBody reads a download and, when the connection breaks before
// all total bytes arrived, asks the server for the rest with a Range
// request and carries on where it stopped. Every 64 KiB chunk is its own
// authenticated block, so the decryptor sees one continuous stream. A
// server that ignores Range (200) has the bytes already received skipped.
// A one-time file resumes only with the ticket its first answer carried
// (see open in runGet); an older server refuses ranges for it.
type resumingBody struct {
	ctx       context.Context
	open      func(ctx context.Context, from int64, ticket string) (*http.Response, error)
	body      io.ReadCloser
	off       int64 // bytes delivered so far
	total     int64 // bytes expected on the wire
	tries     int   // attempts since bytes last arrived
	resumedAt int64 // off at the last resume
	ticket    string
	oneTime   bool  // a ticket was seen: a failure loses the file for good
	broken    error // a body error still to be handled on the next Read
	failure   error // why resuming was given up
	prog      *progress
}

func (b *resumingBody) Read(p []byte) (int, error) {
	if b.broken != nil {
		cause := b.broken
		b.broken = nil
		if err := b.resume(cause); err != nil {
			return 0, err
		}
	}
	for {
		n, err := b.readIdle(p)
		b.off += int64(n)
		if err == nil {
			return n, nil
		}
		// Everything expected has arrived: whatever broke after the last byte
		// (a stream reset before its end flag) does not matter, since the
		// decryptor checks every chunk, the last one included.
		if b.off >= b.total {
			return n, io.EOF
		}
		// The body ended early: a broken connection, or a clean end short
		// of the size. Hand over what arrived first; resume on the next call.
		if n > 0 {
			b.broken = err
			return n, nil
		}
		if rErr := b.resume(err); rErr != nil {
			return 0, rErr
		}
	}
}

// resume reopens the download from b.off. A busy or failing server (408,
// 429, 5xx) is asked again after a pause, like a lost connection. It gives
// up after maxResumes attempts in a row without a byte, when the transfer's
// deadline passed, or when the server refuses (a link gone meanwhile, a
// one-time file whose resume window closed).
func (b *resumingBody) resume(cause error) error {
	_ = b.body.Close()
	if b.off > b.resumedAt {
		b.tries = 0 // bytes came since the last resume: a new break, a new budget
	}
	b.resumedAt = b.off
	fail := func(err error) error {
		// Before its first byte, the server may have rolled the download
		// back: the file is called lost only once bytes came.
		if b.oneTime && b.off > 0 {
			err = fmt.Errorf("%w\nThis one-time file was used up when the download started, and its transfer could not be resumed: it cannot be downloaded again", err)
		}
		b.failure = err
		return err
	}
	for {
		if b.ctx.Err() != nil {
			return fail(ctxError(b.ctx, "Download"))
		}
		if b.tries >= maxResumes {
			return fail(fmt.Errorf("Download failed after %d resume attempts: %v", b.tries, cause))
		}
		b.tries++
		wait := jittered(min(retryBase<<(b.tries-1), maxRetryPause))
		b.prog.note(fmt.Sprintf("Connection lost at %s (%v), resuming in %s", humanBytes(b.off), cause, wait.Round(time.Millisecond)))
		if sleepCtx(b.ctx, wait) != nil {
			return fail(ctxError(b.ctx, "Download"))
		}
		resp, err := b.open(b.ctx, b.off, b.ticket)
		if err != nil {
			cause = err
			continue
		}
		switch {
		case resp.StatusCode == http.StatusNotFound && b.off == 0 && b.ticket != "":
			// Broken before its first byte: the server may have rolled the
			// download back (the file is not used up, the ticket is gone).
			// Ask once more without the ticket, as a fresh download; the
			// file is not lost unless a new answer says it is used up.
			_ = resp.Body.Close()
			b.ticket = ""
			b.oneTime = false
			b.tries--
			continue
		case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			cause = statusCause(resp.StatusCode, readDetail(resp))
			if ra := retryAfterSeconds(resp.Header.Get("Retry-After")); ra > 0 {
				if sleepCtx(b.ctx, retryAfterPause(resp.Header.Get("Retry-After"))) != nil {
					_ = resp.Body.Close()
					return fail(ctxError(b.ctx, "Download"))
				}
			}
			_ = resp.Body.Close()
			continue
		case resp.StatusCode == http.StatusPartialContent:
			start, ok := contentRangeStart(resp.Header.Get("Content-Range"))
			if !ok || start != b.off {
				_ = resp.Body.Close()
				return fail(fmt.Errorf("Download failed: server answered with an unexpected byte range"))
			}
			b.body = resp.Body
			return nil
		case resp.StatusCode == http.StatusOK:
			// A fresh download (after a roll-back) brings a ticket of its own.
			if t := resp.Header.Get("X-Resume-Ticket"); t != "" {
				b.ticket, b.oneTime = t, true
			}
			// Range not honoured: skip what is already on disk.
			if _, err := io.CopyN(io.Discard, resp.Body, b.off); err != nil {
				_ = resp.Body.Close()
				cause = err
				continue
			}
			b.body = resp.Body
			return nil
		default:
			err := handleHTTPError(resp)
			_ = resp.Body.Close()
			return fail(err)
		}
	}
}

// readIdle is one read of the current body, which is closed if the read
// waits longer than downloadIdle.
func (b *resumingBody) readIdle(p []byte) (int, error) {
	body := b.body
	var stalled atomic.Bool
	t := time.AfterFunc(downloadIdle, func() {
		stalled.Store(true)
		_ = body.Close()
	})
	n, err := body.Read(p)
	t.Stop()
	if err != nil && stalled.Load() && !errors.Is(err, io.EOF) {
		err = fmt.Errorf("no data for %s", downloadIdle)
	}
	return n, err
}

func (b *resumingBody) Close() error {
	return b.body.Close()
}

// contentRangeStart reads the first byte position out of "bytes a-b/n".
func contentRangeStart(h string) (int64, bool) {
	spec, ok := strings.CutPrefix(strings.TrimSpace(h), "bytes ")
	if !ok {
		return 0, false
	}
	a, _, ok := strings.Cut(spec, "-")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(a), 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// ── Helpers ──

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

// readDetail returns the server's problem+json "detail", control
// characters stripped, or "" when the body carries none. Reads at most
// 4 KiB; the caller closes the body.
func readDetail(resp *http.Response) string {
	var p struct {
		Detail string `json:"detail"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&p)
	return stripControl(p.Detail)
}

// handleHTTPError words a refused probe or download. The server answers
// every missing, expired, burned or locked link with the same 404 and a
// wrong token with the same 403 as a locked file, so the messages name
// all the possibilities rather than guess.
func handleHTTPError(resp *http.Response) error {
	detail := readDetail(resp)
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("Invalid or expired API key\nRun: ttl activate <key> with a valid key, or ttl deactivate to use the free plan")
	case http.StatusForbidden:
		if detail == "" {
			detail = "Invalid download token"
		}
		return fmt.Errorf("Download refused: %s\nIf this is a private (uploader-only) file, the uploader's Orbit key must be active: ttl activate <key>", detail)
	case http.StatusNotFound:
		return fmt.Errorf("Link not found. The file may have expired, been downloaded already (burn after reading), or be private (uploader-only)")
	case http.StatusRequestTimeout:
		return fmt.Errorf("Server timed out waiting for the client; try again")
	case http.StatusTooManyRequests:
		msg := "Rate limit exceeded — max 30 requests per 10s"
		if detail != "" {
			msg = detail
		}
		if ra := retryAfterSeconds(resp.Header.Get("Retry-After")); ra > 0 {
			msg += fmt.Sprintf(" (retry after %ds)", ra)
		}
		return fmt.Errorf("%s\nTry again later or see: https://ttl.space/usage", msg)
	case http.StatusBadGateway, http.StatusServiceUnavailable:
		return fmt.Errorf("Storage temporarily unavailable, try again later")
	default:
		if detail != "" {
			return fmt.Errorf("Server error: %s", detail)
		}
		return fmt.Errorf("Server error: %d", resp.StatusCode)
	}
}
