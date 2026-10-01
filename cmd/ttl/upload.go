package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/tweenietomatoes/ttl/internal/crypto"
)

// Uploads.
//
// A file whose encrypted size exceeds multipartMinBytes goes through the
// server's resumable upload API: POST /v1/uploads opens a session, each
// part of the server's part_size is one PUT with its SHA-256 in
// Content-Digest, and POST …/complete assembles the object and answers
// like PUT /v1/files. A part that fails (a dropped connection, a 5xx, a
// digest mismatch on the way) is sent again from memory, so a broken
// transfer continues where it stopped instead of starting over. Smaller
// files go in one PUT /v1/files, sent again in full when the connection
// breaks. A server without sessions (501) gets the single PUT for every
// size.

const (
	minPartSize    = 64 << 10  // sanity bounds on the server's part_size;
	maxPartSize    = 128 << 20 // one part is held in memory
	resumeGiveUp   = 15 * time.Minute
	maxRetryPause  = 30 * time.Second
	rateLimitPause = 2 * time.Second
	digestRetries  = 3
	wholeAttempts  = 3
	createAttempts = 3
)

// Tunable in tests.
var (
	multipartMinBytes int64 = 16 << 20 // above one server part (uploadPartSize on the server)
	retryBase               = time.Second
	partMinGap              = 400 * time.Millisecond // between requests: the edge allows 30 per 10 s
)

var (
	errNoSessions  = errors.New("resumable uploads unavailable")
	errAborted     = errors.New("transfer aborted")
	errSessionLost = errors.New("Upload session expired on the server (idle too long, or the server restarted); run the command again")
)

// uploadResult is the 201 body of PUT /v1/files and of
// POST /v1/uploads/{id}/complete. Only link is required; the rest came
// with later server versions.
type uploadResult struct {
	Link                string `json:"link"`
	Token               string `json:"token"`
	ExpiresIn           int64  `json:"expires_in"`
	SizeBytes           int64  `json:"size_bytes"`
	ManageKey           string `json:"manage_key"`
	UploaderOnly        bool   `json:"uploader_only"`
	DailyBytesRemaining *int64 `json:"daily_bytes_remaining"`
}

type uploadSession struct {
	ID       string `json:"id"`
	PartSize int64  `json:"part_size"`
	Parts    int    `json:"parts"`
}

type uploader struct {
	hc           *httpConn
	ctx          context.Context
	server       string
	apiKey       string
	file         *os.File
	fileSize     int64
	name         string
	key, salt    []byte
	encSize      int64
	tokenHash    string
	ttl          string // X-TTL value: seconds, or "permanent"
	burn         bool
	uploaderOnly bool
	prog         *progress
	lastLanded   time.Time // when the server last accepted something
	nextStart    time.Time // earliest start of the next request (partMinGap)
}

func (u *uploader) run() (*uploadResult, error) {
	if u.encSize > multipartMinBytes {
		res, err := u.putParts()
		if !errors.Is(err, errNoSessions) {
			return res, err
		}
	}
	return u.putWhole()
}

// setHeaders sets the upload headers shared by PUT /v1/files and
// POST /v1/uploads.
func (u *uploader) setHeaders(h http.Header) {
	h.Set("X-Token-Hash", u.tokenHash)
	h.Set("X-TTL", u.ttl)
	h.Set("X-File-Size", strconv.FormatInt(u.encSize, 10))
	if u.burn {
		h.Set("X-Burn-After-Reading", "true")
	}
	if u.uploaderOnly {
		h.Set("X-Uploader-Only", "true")
	}
	setAPIKeyHeader(h, u.apiKey)
}

// encryptTo writes the encrypted stream into pw and closes it with the
// outcome. The file is read up to its size at start: one that grew is cut
// there, one that shrank fails the upload.
func (u *uploader) encryptTo(pw *io.PipeWriter) error {
	cr := &countingReader{r: io.LimitReader(u.file, u.fileSize)}
	err := crypto.EncryptStream(pw, cr, u.name, uint64(u.fileSize), u.key, u.salt) //nolint:gosec // non-negative file size
	if err == nil && cr.n != u.fileSize {
		err = fmt.Errorf("File changed while uploading (expected %d bytes, read %d)", u.fileSize, cr.n)
	}
	_ = pw.CloseWithError(err)
	return err
}

// startEncrypt rewinds the file and runs encryptTo in the background.
func (u *uploader) startEncrypt() (*io.PipeReader, <-chan error, error) {
	if _, err := u.file.Seek(0, io.SeekStart); err != nil {
		return nil, nil, fmt.Errorf("Cannot read file: %w", err)
	}
	pr, pw := io.Pipe()
	errCh := make(chan error, 1)
	go func() { errCh <- u.encryptTo(pw) }()
	return pr, errCh, nil
}

// stopEncrypt closes the pipe so a blocked encryptor exits, and returns
// its own error if it had one (a changed file), else nil.
func stopEncrypt(pr *io.PipeReader, errCh <-chan error) error {
	_ = pr.CloseWithError(errAborted)
	err := <-errCh
	if err == nil || errors.Is(err, errAborted) || errors.Is(err, io.ErrClosedPipe) {
		return nil
	}
	return err
}

// ── One request ──

// putWhole sends the file in one PUT /v1/files. A transport failure
// (including the HTTP/3 fallback) re-encrypts and sends again, up to
// wholeAttempts times.
func (u *uploader) putWhole() (*uploadResult, error) {
	var lastErr error
	for attempt := 1; attempt <= wholeAttempts; attempt++ {
		res, retry, err := u.putWholeOnce()
		if err == nil {
			return res, nil
		}
		if !retry {
			return nil, err
		}
		if u.ctx.Err() != nil {
			return nil, ctxError(u.ctx, "Upload")
		}
		lastErr = err
		if attempt < wholeAttempts {
			pause := jittered(retryBase << (attempt - 1))
			u.prog.note(fmt.Sprintf("Upload interrupted (%v), retrying in %s", err, pause.Round(time.Millisecond)))
			if sleepCtx(u.ctx, pause) != nil {
				return nil, ctxError(u.ctx, "Upload")
			}
		}
	}
	return nil, lastErr
}

// putWholeOnce reports retry=true for a transport-level failure.
func (u *uploader) putWholeOnce() (*uploadResult, bool, error) {
	pr, errCh, err := u.startEncrypt()
	if err != nil {
		return nil, false, err
	}
	u.prog.set(0)
	req, err := newRequest(u.ctx, http.MethodPut, u.server+"/v1/files", u.prog.reader(pr))
	if err != nil {
		_ = stopEncrypt(pr, errCh)
		return nil, false, err
	}
	req.ContentLength = u.encSize
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Upload-Path", "stream")
	u.setHeaders(req.Header)
	resp, err := u.hc.do(req)
	if err != nil {
		if encErr := stopEncrypt(pr, errCh); encErr != nil {
			return nil, false, fmt.Errorf("Encryption failed: %w", encErr)
		}
		return nil, true, fmt.Errorf("Upload failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		// The server answered before reading everything; free the encryptor.
		_ = stopEncrypt(pr, errCh)
		return nil, false, handleUploadError(resp)
	}
	// A 201 means the server took the whole stream, so the encryptor is
	// done or about to close the pipe; closing the read side too cannot
	// hurt it then. It does catch a server that answered early: the writer
	// would still be blocked, and what was stored is not the file.
	_ = pr.CloseWithError(errAborted)
	encErr := <-errCh
	if errors.Is(encErr, errAborted) || errors.Is(encErr, io.ErrClosedPipe) {
		return nil, false, fmt.Errorf("Upload failed: the server answered before the whole file was sent")
	}
	if encErr != nil {
		return nil, false, fmt.Errorf("Encryption failed: %w", encErr)
	}
	u.prog.finish()
	res, err := parseUploadResult(resp.Body)
	return res, false, err
}

// ── Resumable session ──

func (u *uploader) putParts() (*uploadResult, error) {
	sess, err := u.createSession()
	if err != nil {
		return nil, err
	}
	base := u.server + "/v1/uploads/" + url.PathEscape(sess.ID)

	pr, errCh, err := u.startEncrypt()
	if err != nil {
		u.abortSession(base)
		return nil, err
	}
	u.prog.set(0)
	u.lastLanded = time.Now()
	buf := make([]byte, sess.PartSize)
	var offset int64
	for n := 1; n <= sess.Parts; n++ {
		want := sess.PartSize
		if n == sess.Parts {
			want = u.encSize - int64(sess.Parts-1)*sess.PartSize
		}
		if _, readErr := io.ReadFull(pr, buf[:want]); readErr != nil {
			encErr := stopEncrypt(pr, errCh)
			u.abortSession(base)
			if encErr != nil {
				return nil, fmt.Errorf("Encryption failed: %w", encErr)
			}
			return nil, fmt.Errorf("Encryption failed: %w", readErr)
		}
		if err := u.sendPart(base, n, buf[:want], offset); err != nil {
			_ = stopEncrypt(pr, errCh)
			u.abortSession(base)
			return nil, err
		}
		offset += want
	}
	// The stream must end exactly here.
	var extra [1]byte
	if k, _ := pr.Read(extra[:]); k > 0 {
		_ = stopEncrypt(pr, errCh)
		u.abortSession(base)
		return nil, fmt.Errorf("Encryption failed: stream longer than expected")
	}
	if encErr := <-errCh; encErr != nil {
		u.abortSession(base)
		return nil, fmt.Errorf("Encryption failed: %w", encErr)
	}
	res, err := u.complete(base)
	if err != nil {
		u.abortSession(base)
		return nil, err
	}
	u.prog.finish()
	return res, nil
}

// createSession opens a session; 5xx and network errors are tried again
// a few times, a server without sessions answers errNoSessions.
func (u *uploader) createSession() (*uploadSession, error) {
	pause := retryBase
	for attempt := 1; ; attempt++ {
		ctx, cancel := context.WithTimeout(u.ctx, 30*time.Second)
		req, err := newRequest(ctx, http.MethodPost, u.server+"/v1/uploads", nil)
		if err != nil {
			cancel()
			return nil, err
		}
		u.setHeaders(req.Header)
		resp, err := u.hc.do(req)
		if err == nil {
			sess, final, perr := u.parseSession(resp)
			_ = resp.Body.Close()
			cancel()
			if final {
				return sess, perr
			}
			err = perr
		} else {
			cancel()
		}
		if u.ctx.Err() != nil {
			return nil, ctxError(u.ctx, "Upload")
		}
		if attempt >= createAttempts {
			return nil, fmt.Errorf("Upload failed: %w", err)
		}
		wait := jittered(pause)
		u.prog.note(fmt.Sprintf("Cannot open upload session (%v), retrying in %s", err, wait.Round(time.Millisecond)))
		if sleepCtx(u.ctx, wait) != nil {
			return nil, ctxError(u.ctx, "Upload")
		}
		pause = min(pause*2, maxRetryPause)
	}
}

// parseSession reads the POST /v1/uploads answer. final=false means a
// 5xx worth another try.
func (u *uploader) parseSession(resp *http.Response) (*uploadSession, bool, error) {
	switch resp.StatusCode {
	case http.StatusCreated:
	case http.StatusNotImplemented, http.StatusNotFound, http.StatusMethodNotAllowed:
		return nil, true, errNoSessions
	default:
		if resp.StatusCode >= 500 {
			return nil, false, statusCause(resp.StatusCode, readDetail(resp))
		}
		return nil, true, handleUploadError(resp)
	}
	var sess uploadSession
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&sess); err != nil {
		return nil, true, fmt.Errorf("Invalid server response: %w", err)
	}
	if validateManageKey(sess.ID) != nil || sess.PartSize < minPartSize || sess.PartSize > maxPartSize || sess.Parts < 1 {
		return nil, true, fmt.Errorf("Invalid upload session from server")
	}
	if want := int((u.encSize + sess.PartSize - 1) / sess.PartSize); sess.Parts != want {
		u.abortSession(u.server + "/v1/uploads/" + url.PathEscape(sess.ID))
		return nil, true, fmt.Errorf("Invalid upload session from server: %d parts for %d bytes", sess.Parts, u.encSize)
	}
	return &sess, true, nil
}

// sendPart sends part n until the server has it. A network error, a stall
// (408) or a 5xx is tried again with a growing pause; a 429 is waited out;
// a 422 (the bytes arrived altered) is resent at once; a 404 means the
// session is gone; any other refusal is final.
func (u *uploader) sendPart(base string, n int, data []byte, offset int64) error {
	sum := sha256.Sum256(data)
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	partURL := base + "/parts/" + strconv.Itoa(n)
	body := func() io.ReadCloser {
		u.prog.set(offset)
		return io.NopCloser(u.prog.reader(bytes.NewReader(data)))
	}
	pause := retryBase
	mismatches := 0
	for {
		if err := u.pace(); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(u.ctx, partTimeout(int64(len(data))))
		req, err := newRequest(ctx, http.MethodPut, partURL, body())
		if err != nil {
			cancel()
			return err
		}
		req.ContentLength = int64(len(data))
		req.GetBody = func() (io.ReadCloser, error) { return body(), nil }
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Digest", digest)
		setAPIKeyHeader(req.Header, u.apiKey)
		resp, err := u.hc.do(req)
		status := 0
		var detail, retryAfter string
		if err == nil {
			status = resp.StatusCode
			detail = readDetail(resp)
			retryAfter = resp.Header.Get("Retry-After")
			_ = resp.Body.Close()
		}
		cancel()

		wait := jittered(pause)
		backoff := true
		switch {
		case err == nil && status == http.StatusNoContent:
			u.lastLanded = time.Now()
			u.prog.set(offset + int64(len(data)))
			return nil
		case err == nil && status == http.StatusNotFound:
			return errSessionLost
		case err == nil && status == http.StatusUnprocessableEntity:
			mismatches++
			if mismatches >= digestRetries {
				return fmt.Errorf("Upload failed: part %d keeps arriving altered (digest mismatch)", n)
			}
			continue
		case err == nil && status == http.StatusTooManyRequests:
			wait = retryAfterPause(retryAfter)
			backoff = false
		case err == nil && status < 500 && status != http.StatusRequestTimeout:
			return uploadStatusError(status, detail, retryAfter)
		}
		cause := errorCause(err, status, detail)
		if u.ctx.Err() != nil {
			return ctxError(u.ctx, "Upload")
		}
		if time.Since(u.lastLanded) > resumeGiveUp {
			return fmt.Errorf("Upload failed: no progress for %s (part %d: %s)", resumeGiveUp, n, cause)
		}
		u.prog.note(fmt.Sprintf("Upload interrupted at part %d (%s), retrying in %s", n, cause, wait.Round(time.Millisecond)))
		if sleepCtx(u.ctx, wait) != nil {
			return ctxError(u.ctx, "Upload")
		}
		if backoff {
			pause = min(pause*2, maxRetryPause)
		}
	}
}

// complete asks the server to assemble the parts. A 429, a 503 and a 409
// that names no missing part ("not yet") are waited out; a 5xx and a
// network error are tried again; a 409 naming parts is final.
func (u *uploader) complete(base string) (*uploadResult, error) {
	pause := retryBase
	for {
		if err := u.pace(); err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(u.ctx, 2*time.Minute)
		req, err := newRequest(ctx, http.MethodPost, base+"/complete", nil)
		if err != nil {
			cancel()
			return nil, err
		}
		setAPIKeyHeader(req.Header, u.apiKey)
		resp, err := u.hc.do(req)
		wait := jittered(pause)
		backoff := true
		cause := ""
		if err == nil {
			switch resp.StatusCode {
			case http.StatusCreated:
				res, perr := parseUploadResult(resp.Body)
				_ = resp.Body.Close()
				cancel()
				return res, perr
			case http.StatusNotFound:
				_ = resp.Body.Close()
				cancel()
				return nil, errSessionLost
			case http.StatusConflict:
				var conflict struct {
					Detail  string `json:"detail"`
					Missing []int  `json:"missing"`
				}
				_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&conflict)
				_ = resp.Body.Close()
				if len(conflict.Missing) > 0 {
					cancel()
					return nil, fmt.Errorf("Upload failed: the server is missing part(s) %v; run the command again", conflict.Missing)
				}
				cause = errorCause(nil, resp.StatusCode, stripControl(conflict.Detail))
				wait, backoff = rateLimitPause, false
			case http.StatusTooManyRequests, http.StatusServiceUnavailable:
				cause = errorCause(nil, resp.StatusCode, readDetail(resp))
				wait, backoff = retryAfterPause(resp.Header.Get("Retry-After")), false
				_ = resp.Body.Close()
			default:
				if resp.StatusCode < 500 {
					uerr := handleUploadError(resp)
					_ = resp.Body.Close()
					cancel()
					return nil, uerr
				}
				cause = errorCause(nil, resp.StatusCode, readDetail(resp))
				_ = resp.Body.Close()
			}
		} else {
			cause = err.Error()
		}
		cancel()
		if u.ctx.Err() != nil {
			return nil, ctxError(u.ctx, "Upload")
		}
		if time.Since(u.lastLanded) > resumeGiveUp {
			return nil, fmt.Errorf("Upload failed: could not finish the upload for %s (%s)", resumeGiveUp, cause)
		}
		u.prog.note(fmt.Sprintf("Finishing upload (%s), retrying in %s", cause, wait.Round(time.Millisecond)))
		if sleepCtx(u.ctx, wait) != nil {
			return nil, ctxError(u.ctx, "Upload")
		}
		if backoff {
			pause = min(pause*2, maxRetryPause)
		}
	}
}

// abortSession hands the session back so the server frees its share of
// the daily limits now rather than at its idle sweep. Best effort.
func (u *uploader) abortSession(base string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := newRequest(ctx, http.MethodDelete, base, nil)
	if err != nil {
		return
	}
	setAPIKeyHeader(req.Header, u.apiKey)
	resp, err := u.hc.do(req)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
}

// pace keeps partMinGap between request starts.
func (u *uploader) pace() error {
	if wait := time.Until(u.nextStart); wait > 0 {
		if err := sleepCtx(u.ctx, wait); err != nil {
			return ctxError(u.ctx, "Upload")
		}
	}
	u.nextStart = time.Now().Add(partMinGap)
	return nil
}

// ── Helpers ──

func parseUploadResult(r io.Reader) (*uploadResult, error) {
	var res uploadResult
	if err := json.NewDecoder(io.LimitReader(r, 4096)).Decode(&res); err != nil {
		return nil, fmt.Errorf("Invalid server response: %w", err)
	}
	if res.Link == "" {
		return nil, fmt.Errorf("Server returned empty link")
	}
	return &res, nil
}

func handleUploadError(resp *http.Response) error {
	return uploadStatusError(resp.StatusCode, readDetail(resp), resp.Header.Get("Retry-After"))
}

// uploadStatusError words a refused upload. The server's detail says why
// (an invalid header, a quota, a file that is not encrypted) and is shown
// when it has one.
func uploadStatusError(status int, detail, retryAfter string) error {
	switch status {
	case http.StatusBadRequest:
		if detail != "" {
			return fmt.Errorf("Upload rejected: %s", detail)
		}
		return fmt.Errorf("Upload rejected by the server (400)")
	case http.StatusUnauthorized:
		return fmt.Errorf("Invalid or expired API key\nRun: ttl activate <key> with a valid key, or ttl deactivate to use the free plan")
	case http.StatusNotFound:
		return fmt.Errorf("Upload endpoint not found (server may be misconfigured)")
	case http.StatusRequestTimeout:
		if detail != "" {
			return fmt.Errorf("Upload timed out: %s", detail)
		}
		return fmt.Errorf("Upload timed out: the server received no data")
	case http.StatusRequestEntityTooLarge:
		if detail != "" {
			return fmt.Errorf("%s\nSee limits: https://ttl.space/usage", detail)
		}
		return fmt.Errorf("File too large\nSee limits: https://ttl.space/usage")
	case http.StatusTooManyRequests:
		msg := "Rate limit exceeded"
		if detail != "" {
			msg = detail
		}
		if ra := retryAfterSeconds(retryAfter); ra > 0 {
			msg += fmt.Sprintf(" (retry after %ds)", ra)
		}
		return fmt.Errorf("%s\nTry again later or see: https://ttl.space/usage", msg)
	case http.StatusBadGateway, http.StatusServiceUnavailable:
		return fmt.Errorf("Storage temporarily unavailable, try again later")
	default:
		if detail != "" {
			return fmt.Errorf("Upload failed: %s", detail)
		}
		return fmt.Errorf("Upload failed: server returned %d", status)
	}
}

// statusCause is a retryable server answer as an error.
func statusCause(status int, detail string) error {
	return errors.New(errorCause(nil, status, detail))
}

// errorCause words what went wrong for a retry note.
func errorCause(err error, status int, detail string) string {
	if err != nil {
		return err.Error()
	}
	s := fmt.Sprintf("server returned %d", status)
	if detail != "" {
		s += ": " + detail
	}
	return s
}

// ctxError says why a cancelled transfer stopped.
func ctxError(ctx context.Context, what string) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%s timed out (use --timeout to allow more time)", what)
	}
	return fmt.Errorf("%s cancelled", what)
}

// jittered spreads a pause by up to ±20 %, so retries from many clients
// do not line up on the server.
func jittered(d time.Duration) time.Duration {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return d + time.Duration((float64(b[0])/255-0.5)*0.4*float64(d))
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// partTimeout is the time allowed for one request of n bytes (1 Mbps plus
// a margin, at least 5 minutes).
func partTimeout(n int64) time.Duration {
	d, _ := resolveTimeout("", n)
	return d
}

// retryAfterSeconds parses a Retry-After header given in seconds (0 when
// absent or not a number).
func retryAfterSeconds(h string) int {
	n, err := strconv.Atoi(h)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// retryAfterPause turns Retry-After into a pause between 1 s and 60 s,
// defaulting to rateLimitPause.
func retryAfterPause(h string) time.Duration {
	n := retryAfterSeconds(h)
	if n <= 0 {
		return rateLimitPause
	}
	if n > 60 {
		n = 60
	}
	return time.Duration(n) * time.Second
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
