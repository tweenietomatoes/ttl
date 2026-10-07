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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tweenietomatoes/ttl/internal/crypto"
)

// Uploads.
//
// A file whose encrypted size fits in one part (singleMaxBytes) goes in one
// request: PUT /v1/files with its SHA-256 in Content-Digest, stored only if
// what arrived matches. A larger file goes through the server's resumable
// upload API, as the web page's do: POST /v1/uploads opens a session, each
// part of the server's part_size is one PUT with its SHA-256, and
// POST …/complete assembles the object and answers as PUT /v1/files does.
// Either way the bytes go from memory: a request that fails (a dropped
// connection, a 5xx, a digest mismatch on the way) is sent again, so a
// broken transfer continues where it stopped instead of starting over.

const (
	minPartSize    = 64 << 10  // sanity bounds on the server's part_size;
	maxPartSize    = 128 << 20 // one part is held in memory
	maxRetryPause  = 30 * time.Second
	rateLimitPause = 2 * time.Second
	digestRetries  = 3
	cutRetries     = 3    // a 201 whose body broke off is asked for again this often
	maxAnswer      = 4096 // the largest 201 body taken as an answer
	createAttempts = 3
	// Parts on the way at once: the next part goes up while the server
	// writes the last one to storage, which would otherwise leave the
	// connection idle for that long after every part. After a failed or
	// slow part the rest go one at a time (oneAtATime): on a weak link two
	// parts only share it, and a break loses both.
	partsInFlight = 2
	slowPart      = time.Minute
)

// Tunable in tests.
var (
	// Files up to this size (encrypted) go in one request: the server's
	// part size, the most it takes at once. A test lowers it to send small
	// files in parts.
	singleMaxBytes int64 = 16 << 20
	retryBase            = time.Second
	partMinGap           = 400 * time.Millisecond // between requests: the edge allows 30 per 10 s
	resumeGiveUp         = 15 * time.Minute       // an upload with no progress this long gives up
	// An attempt whose bytes stopped moving for partIdle is given up (the
	// connection died without saying so; the server drops a silent request
	// at 90 s with 408, which usually comes first), and so is one whose
	// answer has not come partReply after all of it went out. A slow but
	// moving attempt is never cut, however long it takes.
	partIdle  = 2 * time.Minute
	partReply = 5 * time.Minute
)

var (
	errAborted     = errors.New("transfer aborted")
	errSessionLost = errors.New("Upload session expired on the server (idle too long, or the server restarted); run the command again")
	// errAnswerCut: the 201 body broke off on the way. The server gives the
	// request sent again the same answer, so it is worth asking again; a
	// body that arrived whole but is not a valid answer is final.
	errAnswerCut = errors.New("answer cut off")
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
	mu           sync.Mutex // guards nextStart: parts go up concurrently
	nextStart    time.Time  // earliest start of the next request (partMinGap)
	oneAtATime   atomic.Bool
	// The last progress, as time since progressClock: something landed, or
	// an attempt got further into its bytes than any before it (a slow link
	// moving a part for minutes is progress; sending the same bytes again
	// is not).
	lastProgress atomic.Int64
}

// progressClock is read on the monotonic clock: a laptop's sleep or a clock
// change is not taken for time without progress.
var progressClock = time.Now()

func (u *uploader) markProgress() { u.lastProgress.Store(int64(time.Since(progressClock))) }

func (u *uploader) sinceProgress() time.Duration {
	return time.Since(progressClock) - time.Duration(u.lastProgress.Load())
}

func (u *uploader) run() (*uploadResult, error) {
	if u.encSize <= singleMaxBytes {
		return u.putSingle()
	}
	return u.putParts()
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

// putSingle sends a file of one part in one PUT /v1/files.
func (u *uploader) putSingle() (*uploadResult, error) {
	data, err := u.encryptAll()
	if err != nil {
		return nil, err
	}
	u.prog.set(0)
	u.markProgress()
	var res *uploadResult
	err = u.send(u.ctx, sendTarget{
		url:    u.server + "/v1/files",
		what:   "the file",
		header: u.setHeaders,
		ok:     http.StatusCreated,
		result: func(r io.Reader) (err error) {
			res, err = parseUploadResult(r)
			return err
		},
	}, data)
	if err != nil {
		return nil, err
	}
	u.prog.finish()
	return res, nil
}

// encryptAll encrypts the whole file into memory, for the single request.
func (u *uploader) encryptAll() ([]byte, error) {
	pr, errCh, err := u.startEncrypt()
	if err != nil {
		return nil, err
	}
	data := make([]byte, u.encSize)
	if _, err := io.ReadFull(pr, data); err != nil {
		if encErr := stopEncrypt(pr, errCh); encErr != nil {
			return nil, fmt.Errorf("Encryption failed: %w", encErr)
		}
		return nil, fmt.Errorf("Encryption failed: %w", err)
	}
	// The stream must end exactly here.
	var extra [1]byte
	if k, _ := pr.Read(extra[:]); k > 0 {
		_ = stopEncrypt(pr, errCh)
		return nil, fmt.Errorf("Encryption failed: stream longer than expected")
	}
	if encErr := <-errCh; encErr != nil {
		return nil, fmt.Errorf("Encryption failed: %w", encErr)
	}
	return data, nil
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
	u.markProgress()

	// The encrypted stream is cut into parts here, and partsInFlight
	// senders put them up; each part keeps its buffer until the server has
	// it. The first part that fails for good stops the others.
	ctx, cancel := context.WithCancel(u.ctx)
	defer cancel()
	var (
		wg       sync.WaitGroup
		failOnce sync.Once
		partErr  error
	)
	fail := func(err error) {
		failOnce.Do(func() {
			partErr = err
			cancel()
		})
	}
	type job struct {
		n    int
		data []byte
	}
	jobs := make(chan job)
	free := make(chan []byte, partsInFlight)
	for range partsInFlight {
		free <- make([]byte, sess.PartSize)
	}
	for i := range partsInFlight {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if i > 0 && u.oneAtATime.Load() {
					return
				}
				j, ok := <-jobs
				if !ok {
					return
				}
				if ctx.Err() != nil { // another part has failed
					continue
				}
				if err := u.sendPart(ctx, base, j.n, j.data); err != nil {
					// Not reused: the transport may still be reading a
					// request it gave up on (http.RoundTripper closes the
					// body in its own time), and the upload ends anyway.
					fail(err)
					continue
				}
				free <- j.data[:cap(j.data)]
			}
		}()
	}
	var readErr error
produce:
	for n := 1; n <= sess.Parts; n++ {
		var buf []byte
		select {
		case buf = <-free:
		case <-ctx.Done():
			break produce
		}
		want := sess.PartSize
		if n == sess.Parts {
			want = u.encSize - int64(sess.Parts-1)*sess.PartSize
		}
		if _, err := io.ReadFull(pr, buf[:want]); err != nil {
			// Stops the part on the way too: the upload is lost anyway.
			readErr = err
			fail(fmt.Errorf("Encryption failed: %w", err))
			break
		}
		select {
		case jobs <- job{n, buf[:want]}:
		case <-ctx.Done():
			break produce
		}
	}
	close(jobs)
	wg.Wait()
	if readErr != nil || partErr != nil || ctx.Err() != nil {
		encErr := stopEncrypt(pr, errCh)
		u.abortSession(base)
		switch {
		case encErr != nil:
			return nil, fmt.Errorf("Encryption failed: %w", encErr)
		case partErr != nil:
			return nil, partErr
		case readErr != nil:
			return nil, fmt.Errorf("Encryption failed: %w", readErr)
		default:
			return nil, ctxError(u.ctx, "Upload")
		}
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
// a few times.
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
	case http.StatusNotImplemented:
		return nil, true, handleUploadError(resp)
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

// sendPart sends part n of the session at base until the server has it.
func (u *uploader) sendPart(pctx context.Context, base string, n int, data []byte) error {
	return u.send(pctx, sendTarget{
		url:  base + "/parts/" + strconv.Itoa(n),
		what: "part " + strconv.Itoa(n),
		ok:   http.StatusNoContent,
		gone: errSessionLost,
	}, data)
}

// sendTarget is where send puts its bytes: a part of a session, or a whole
// file of one part.
type sendTarget struct {
	url    string
	what   string                // "part 3", "the file": for notes and errors
	header func(http.Header)     // headers besides the digest and the API key
	ok     int                   // the answer that means stored
	result func(io.Reader) error // reads that answer's body
	gone   error                 // what a 404 means; nil: a refusal like any other
}

// send puts data at t until the server has it. A network error, a stall
// (408), a takeover by a newer request (409) or a 5xx is tried again with
// a growing pause, and so is an answer whose body was cut off, up to
// cutRetries times (the server keeps it for a request sent again); a 429
// is waited out; a 422 (the bytes arrived altered) is resent at once; an
// answer that arrived whole but cannot be read, and any other refusal,
// is final.
func (u *uploader) send(pctx context.Context, t sendTarget, data []byte) error {
	sum := sha256.Sum256(data)
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	// The bar counts the bytes as they go; an attempt sent again first
	// gives back what the one before counted. reached is the furthest any
	// attempt got: going beyond it is progress.
	var counted, reached atomic.Int64
	body := func() io.ReadCloser {
		u.prog.back(counted.Swap(0))
		return io.NopCloser(&partReader{r: bytes.NewReader(data), p: u.prog, n: &counted, reached: &reached, moved: u.markProgress})
	}
	pause := retryBase
	mismatches, cuts := 0, 0
	for {
		if err := u.pace(pctx); err != nil {
			return err
		}
		ctx, cancel := context.WithCancel(pctx)
		started := time.Now()
		req, err := newRequest(ctx, http.MethodPut, t.url, body())
		if err != nil {
			cancel()
			return err
		}
		why, stopWatch := watchAttempt(&counted, int64(len(data)), cancel)
		req.ContentLength = int64(len(data))
		req.GetBody = func() (io.ReadCloser, error) { return body(), nil }
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Digest", digest)
		if t.header != nil {
			t.header(req.Header)
		}
		setAPIKeyHeader(req.Header, u.apiKey)
		resp, err := u.hc.do(req)
		status := 0
		cut := false
		var detail, retryAfter string
		if err == nil {
			status = resp.StatusCode
			retryAfter = resp.Header.Get("Retry-After")
			if status == t.ok && t.result != nil {
				err = t.result(resp.Body)
				cut = errors.Is(err, errAnswerCut)
			} else if status != t.ok {
				detail = readDetail(resp)
			}
			_ = resp.Body.Close()
		}
		stopWatch()
		cancel()
		if err != nil && status == t.ok && !cut {
			return err // a whole answer that cannot be read: asking again gets the same
		}
		if cut {
			if cuts++; cuts > cutRetries {
				return answerLost(err)
			}
		}
		if err != nil {
			if w := why(); w != "" {
				err = errors.New(w)
			}
			status = 0
		}

		wait := jittered(pause)
		backoff := true
		switch {
		case err == nil && status == t.ok:
			if time.Since(started) > slowPart {
				u.oneAtATime.Store(true)
			}
			u.markProgress()
			u.prog.back(counted.Load() - int64(len(data))) // exactly the bytes, whatever was read
			return nil
		case err == nil && status == http.StatusNotFound && t.gone != nil:
			return t.gone
		case err == nil && status == http.StatusUnprocessableEntity:
			mismatches++
			if mismatches >= digestRetries {
				return fmt.Errorf("Upload failed: %s keeps arriving altered (digest mismatch)", t.what)
			}
			continue
		case err == nil && status == http.StatusTooManyRequests:
			if quotaRefusal(detail) {
				return uploadStatusError(status, detail, retryAfter) // waiting minutes does not lift a daily limit
			}
			wait = retryAfterPause(retryAfter)
			backoff = false
		case err == nil && status < 500 && status != http.StatusRequestTimeout && status != http.StatusConflict:
			// 408: the server dropped a silent request; 409: a newer request
			// for the same bytes took over. Both mean "send it again".
			return uploadStatusError(status, detail, retryAfter)
		}
		cause := errorCause(err, status, detail)
		if pctx.Err() != nil {
			return ctxError(u.ctx, "Upload")
		}
		if status != http.StatusTooManyRequests {
			u.oneAtATime.Store(true) // a link that fails: one part at a time from now on
		}
		if u.sinceProgress() > resumeGiveUp {
			return fmt.Errorf("Upload failed: no progress for %s (%s: %s)", resumeGiveUp, t.what, cause)
		}
		u.prog.note(fmt.Sprintf("Upload interrupted at %s (%s), retrying in %s", t.what, cause, wait.Round(time.Millisecond)))
		if sleepCtx(pctx, wait) != nil {
			return ctxError(u.ctx, "Upload")
		}
		if backoff {
			pause = min(pause*2, maxRetryPause)
		}
	}
}

// complete asks the server to assemble the parts. A 429, a 503 and a 409
// that names no missing part ("not yet") are waited out; a 5xx, a network
// error and an answer cut off on the way (up to cutRetries times) are
// tried again; a 409 naming parts and an answer that arrived whole but
// cannot be read are final.
func (u *uploader) complete(base string) (*uploadResult, error) {
	pause := retryBase
	cuts := 0
	for {
		if err := u.pace(u.ctx); err != nil {
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
				if perr == nil {
					cancel()
					return res, nil
				}
				if !errors.Is(perr, errAnswerCut) {
					cancel()
					return nil, perr
				}
				if cuts++; cuts > cutRetries {
					cancel()
					return nil, answerLost(perr)
				}
				// Cut off on the way: the server answers a repeated
				// complete with the same link.
				cause = perr.Error()
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
		if u.sinceProgress() > resumeGiveUp {
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

// pace keeps partMinGap between request starts, across the parts on the
// way: each request takes the next free start time.
func (u *uploader) pace(ctx context.Context) error {
	u.mu.Lock()
	now := time.Now()
	start := now
	if u.nextStart.After(now) {
		start = u.nextStart
	}
	u.nextStart = start.Add(partMinGap)
	u.mu.Unlock()
	if wait := start.Sub(now); wait > 0 {
		if err := sleepCtx(ctx, wait); err != nil {
			return ctxError(u.ctx, "Upload")
		}
	}
	return nil
}

// ── Helpers ──

func parseUploadResult(r io.Reader) (*uploadResult, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxAnswer+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errAnswerCut, err)
	}
	if len(b) > maxAnswer {
		return nil, fmt.Errorf("Invalid server response: longer than %d bytes", maxAnswer)
	}
	var res uploadResult
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, fmt.Errorf("Invalid server response: %w", err)
	}
	if res.Link == "" {
		return nil, fmt.Errorf("Server returned empty link")
	}
	return &res, nil
}

// quotaRefusal tells a daily-limit 429 ("Upload limit reached", "Daily
// upload quota reached"), which holds until the day turns, from a passing
// one: the same bytes or part still on the way, or the edge's request rate.
// answerLost: the upload may be stored, but its answer, with the link, kept
// breaking off on the way back.
func answerLost(err error) error {
	return fmt.Errorf("Upload failed: the answer with the link kept breaking off (%v); the file may be stored, but nobody can open it without the link; run the command again", err)
}

func quotaRefusal(detail string) bool {
	d := strings.ToLower(detail)
	return strings.Contains(d, "quota") || strings.Contains(d, "limit reached")
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

// watchAttempt cancels an attempt whose body has not moved for partIdle,
// or whose answer has not come partReply after all of it went out. why
// says which, or "" while neither happened; stop ends the watch.
func watchAttempt(counted *atomic.Int64, size int64, cancel context.CancelFunc) (why func() string, stop func()) {
	var reason atomic.Pointer[string]
	done := make(chan struct{})
	step := min(max(partIdle/8, 10*time.Millisecond), time.Second)
	go func() {
		t := time.NewTicker(step)
		defer t.Stop()
		last, since := counted.Load(), time.Now()
		for {
			select {
			case <-done:
				return
			case now := <-t.C:
				n := counted.Load()
				if n != last {
					last, since = n, now
					continue
				}
				limit, msg := partIdle, fmt.Sprintf("no data moved for %s", partIdle)
				if n >= size {
					limit, msg = partReply, fmt.Sprintf("no answer %s after it was all sent", partReply)
				}
				if now.Sub(since) > limit {
					reason.Store(&msg)
					cancel()
					return
				}
			}
		}
	}()
	why = func() string {
		if p := reason.Load(); p != nil {
			return *p
		}
		return ""
	}
	return why, func() { close(done) }
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

// partReader counts what the transport reads of an attempt's bytes into
// the bar and into the attempt's counter n. Getting further than any
// attempt before it (reached) calls moved.
type partReader struct {
	r       io.Reader
	p       *progress
	n       *atomic.Int64
	reached *atomic.Int64
	moved   func()
}

func (pr *partReader) Read(buf []byte) (int, error) {
	n, err := pr.r.Read(buf)
	if n > 0 {
		c := pr.n.Add(int64(n))
		pr.p.add(n)
		for r := pr.reached.Load(); c > r; r = pr.reached.Load() {
			if pr.reached.CompareAndSwap(r, c) {
				pr.moved()
				break
			}
		}
	}
	return n, err
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
