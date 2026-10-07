package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// largePayload is bigger than the test multipart threshold (256 KiB) and
// spans several 64 KiB mock parts.
func largePayload(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 300<<10+123)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// sendAndGet uploads src through the mock and downloads it again into a
// fresh directory, returning the downloaded bytes.
func sendAndGet(t *testing.T, m *mockAPI, src string, sendArgs ...string) []byte {
	t.Helper()
	args := append([]string{"-p", "roundtrip-pass", "-server", m.URL}, sendArgs...)
	if err := runSend(append(args, src)); err != nil {
		t.Fatalf("send: %v", err)
	}
	outDir := t.TempDir()
	if err := runGet([]string{"-p", "roundtrip-pass", "-o", outDir, m.URL + "/aBcDeFgHiJ"}); err != nil {
		t.Fatalf("get: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(outDir, filepath.Base(src)))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestUpload_Parts_RoundTrip(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	payload := largePayload(t)
	src := tempFileBytes(t, "big.bin", payload)

	got := sendAndGet(t, m, src)
	if !bytes.Equal(got, payload) {
		t.Fatal("downloaded content differs from the original")
	}
	if m.sessionCalls != 1 || m.putCalls != 0 || m.completeCalls != 1 {
		t.Fatalf("sessions=%d puts=%d completes=%d, want 1/0/1", m.sessionCalls, m.putCalls, m.completeCalls)
	}
	if m.abortCalls != 0 {
		t.Fatalf("a successful upload must not abort its session (got %d aborts)", m.abortCalls)
	}
	wantParts := int((int64(len(m.blob)) + m.partSize - 1) / m.partSize)
	if len(m.partAttempts) != wantParts {
		t.Fatalf("parts sent = %d, want %d", len(m.partAttempts), wantParts)
	}
	if got := m.lastUploadHeaders.Get("X-File-Size"); got != strconv.Itoa(len(m.blob)) {
		t.Fatalf("X-File-Size on session = %q, want %d", got, len(m.blob))
	}
	if got := m.lastUploadHeaders.Get("X-TTL"); got != "604800" {
		t.Fatalf("X-TTL on session = %q", got)
	}
	if ua := m.lastUploadHeaders.Get("User-Agent"); !strings.HasPrefix(ua, "ttl-cli/") {
		t.Fatalf("User-Agent = %q, want ttl-cli/…", ua)
	}
}

func TestUpload_Parts_ForwardsFlags(t *testing.T) {
	key := keyPrefix + strings.Repeat("u", 48)
	t.Setenv("TTL_API_KEY", key)
	t.Setenv("HOME", t.TempDir())
	m := newMockAPI(t)
	m.plan = "orbit"
	src := tempFileBytes(t, "big.bin", largePayload(t))

	if err := runSend([]string{"-p", "roundtrip-pass", "-b", "-u", "-t", "permanent", "-server", m.URL, src}); err != nil {
		t.Fatalf("send: %v", err)
	}
	h := m.lastUploadHeaders
	if h.Get("X-Burn-After-Reading") != "true" || h.Get("X-Uploader-Only") != "true" || h.Get("X-TTL") != "permanent" {
		t.Fatalf("session headers = %v", h)
	}
	if h.Get("X-API-Key") != key {
		t.Fatalf("X-API-Key not forwarded on session create")
	}
}

func TestUpload_Parts_SendsContentDigest(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	src := tempFileBytes(t, "big.bin", largePayload(t))
	if err := runSend([]string{"-p", "roundtrip-pass", "-server", m.URL, src}); err != nil {
		t.Fatalf("send: %v", err)
	}
	first := m.blob[:m.partSize]
	want := "sha-256=:" + base64.StdEncoding.EncodeToString(sha256Sum(first)) + ":"
	if got := m.partDigests[1]; got != want {
		t.Fatalf("Content-Digest of part 1 = %q, want %q", got, want)
	}
}

func TestUpload_Parts_RetriesPartOn502(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	m.partHook = func(n, attempt int) (int, string) {
		if n == 3 && attempt == 1 {
			return 502, "Storage unavailable"
		}
		return 0, ""
	}
	payload := largePayload(t)
	src := tempFileBytes(t, "big.bin", payload)
	if got := sendAndGet(t, m, src); !bytes.Equal(got, payload) {
		t.Fatal("content differs after a retried part")
	}
	if m.partAttempts[3] != 2 {
		t.Fatalf("part 3 attempts = %d, want 2", m.partAttempts[3])
	}
	if m.partAttempts[2] != 1 || m.partAttempts[4] != 1 {
		t.Fatalf("other parts must be sent once: %v", m.partAttempts)
	}
}

func TestUpload_Parts_RetriesPartOn408Stall(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	m.partHook = func(n, attempt int) (int, string) {
		if n == 1 && attempt == 1 {
			return 408, "No data received for 90s; send it again"
		}
		return 0, ""
	}
	src := tempFileBytes(t, "big.bin", largePayload(t))
	if err := runSend([]string{"-p", "roundtrip-pass", "-server", m.URL, src}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if m.partAttempts[1] != 2 {
		t.Fatalf("part 1 attempts = %d, want 2", m.partAttempts[1])
	}
}

// 409: a newer request for the part took over on the server (one the
// transport retried, say): the part is simply sent again.
func TestUpload_Parts_RetriesPartOn409Takeover(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	m.partHook = func(n, attempt int) (int, string) {
		if n == 2 && attempt == 1 {
			return 409, "A newer request for this part took over; send it again"
		}
		return 0, ""
	}
	src := tempFileBytes(t, "big.bin", largePayload(t))
	if err := runSend([]string{"-p", "roundtrip-pass", "-server", m.URL, src}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if m.partAttempts[2] != 2 {
		t.Fatalf("part 2 attempts = %d, want 2", m.partAttempts[2])
	}
}

// The next part goes up while the server is still storing the last one:
// "storing" part 1 here lasts until part 2 has arrived.
func TestUpload_Parts_NextPartGoesUpWhileOneIsStored(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	second := make(chan struct{})
	var overlapped atomic.Bool
	m.partHook = func(n, attempt int) (int, string) {
		switch {
		case n == 1:
			select {
			case <-second:
				overlapped.Store(true)
			case <-time.After(3 * time.Second):
			}
		case n == 2 && attempt == 1:
			close(second)
		}
		return 0, ""
	}
	payload := largePayload(t)
	src := tempFileBytes(t, "big.bin", payload)
	if got := sendAndGet(t, m, src); !bytes.Equal(got, payload) {
		t.Fatal("content differs")
	}
	if !overlapped.Load() {
		t.Fatal("part 2 did not go up while part 1 was being stored")
	}
}

// A part refused for good stops the upload while another part is still on
// the way: no complete, the session handed back, nothing left hanging.
func TestUpload_Parts_FinalRefusalStopsTheOtherPart(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	m.partHook = func(n, attempt int) (int, string) {
		switch n {
		case 1:
			time.Sleep(300 * time.Millisecond) // still being stored when part 2 is refused
		case 2:
			return 413, "Storage quota exceeded (500 GB limit)"
		}
		return 0, ""
	}
	src := tempFileBytes(t, "big.bin", largePayload(t))
	done := make(chan error, 1)
	go func() { done <- runSend([]string{"-p", "roundtrip-pass", "-server", m.URL, src}) }()
	var err error
	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the upload hung after a refused part")
	}
	if err == nil || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("expected the quota refusal, got %v", err)
	}
	if m.completeCalls != 0 {
		t.Fatal("completed after a refused part")
	}
	if m.abortCalls != 1 {
		t.Fatalf("session aborts = %d, want 1", m.abortCalls)
	}
	if m.partAttempts[4] != 0 || m.partAttempts[5] != 0 {
		t.Fatalf("parts after the refusal were sent: %v", m.partAttempts)
	}
}

func setPartWatch(t *testing.T, idle, reply time.Duration) {
	t.Helper()
	oldIdle, oldReply := partIdle, partReply
	partIdle, partReply = idle, reply
	t.Cleanup(func() { partIdle, partReply = oldIdle, oldReply })
}

// Two parts sharing a slow link take far longer than the idle limit, but
// their bytes keep moving, so neither is cut; nor is the wait for the
// server's answer once a whole part is sent.
func TestUpload_Parts_SlowSharedLinkStillLands(t *testing.T) {
	noKeys(t)
	setPartWatch(t, 300*time.Millisecond, 3*time.Second)
	m := newMockAPI(t)
	m.bodyRate = 100 << 10 // two 64 KiB parts at once: about 1.3 s each
	m.partHook = func(n, attempt int) (int, string) {
		time.Sleep(500 * time.Millisecond) // storing, after the whole body arrived
		return 0, ""
	}
	payload := largePayload(t)
	src := tempFileBytes(t, "big.bin", payload)
	if got := sendAndGet(t, m, src); !bytes.Equal(got, payload) {
		t.Fatal("content differs")
	}
	for n, a := range m.partAttempts {
		if a != 1 {
			t.Fatalf("part %d took %d attempts on a slow but moving link", n, a)
		}
	}
}

// A part the server drops for silence (408) is sent again, and the rest go
// one at a time.
func TestUpload_Parts_SilentPartResent(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	m.stallPart = 2
	payload := largePayload(t)
	src := tempFileBytes(t, "big.bin", payload)
	if got := sendAndGet(t, m, src); !bytes.Equal(got, payload) {
		t.Fatal("content differs")
	}
	if m.partAttempts[2] != 2 {
		t.Fatalf("part 2 attempts = %d, want 2", m.partAttempts[2])
	}
}

// The attempt watch cuts only an attempt whose bytes stopped moving, or one
// whose answer is overdue after all of it went out.
func TestWatchAttempt_CutsOnlyIdleAttempts(t *testing.T) {
	setPartWatch(t, 200*time.Millisecond, 600*time.Millisecond)
	var lastWhy string
	run := func(advance func(c *atomic.Int64)) (cut bool, after time.Duration) {
		var counted atomic.Int64
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		why, stop := watchAttempt(&counted, 1000, cancel)
		defer stop()
		t0 := time.Now()
		go advance(&counted)
		select {
		case <-ctx.Done():
			lastWhy = why()
			return lastWhy != "", time.Since(t0)
		case <-time.After(1500 * time.Millisecond):
			return false, time.Since(t0)
		}
	}
	// Moving slowly (a byte every 50 ms) for 1.5 s: never cut.
	if cut, _ := run(func(c *atomic.Int64) {
		for i := 0; i < 30; i++ {
			time.Sleep(50 * time.Millisecond)
			c.Add(1)
		}
	}); cut {
		t.Fatal("a slow but moving attempt was cut")
	}
	// Stuck halfway: cut after about partIdle.
	if cut, after := run(func(c *atomic.Int64) { c.Store(500) }); !cut || after > time.Second || !strings.Contains(lastWhy, "no data moved") {
		t.Fatalf("a stuck attempt: cut=%v after %s (%q)", cut, after, lastWhy)
	}
	// All sent, answer pending: waits partReply, not partIdle, and says so.
	if cut, after := run(func(c *atomic.Int64) { c.Store(1000) }); !cut || after < 500*time.Millisecond || !strings.Contains(lastWhy, "no answer") {
		t.Fatalf("an attempt waiting for its answer: cut=%v after %s (%q)", cut, after, lastWhy)
	}
}

func TestUpload_Parts_ResendsOn422(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	m.partHook = func(n, attempt int) (int, string) {
		if n == 2 && attempt == 1 {
			return 422, "Part digest mismatch"
		}
		return 0, ""
	}
	payload := largePayload(t)
	src := tempFileBytes(t, "big.bin", payload)
	if got := sendAndGet(t, m, src); !bytes.Equal(got, payload) {
		t.Fatal("content differs after a resent part")
	}
	if m.partAttempts[2] != 2 {
		t.Fatalf("part 2 attempts = %d, want 2", m.partAttempts[2])
	}
}

func TestUpload_Parts_GivesUpOnRepeatedDigestMismatch(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	m.partHook = func(n, attempt int) (int, string) {
		if n == 2 {
			return 422, "Part digest mismatch"
		}
		return 0, ""
	}
	src := tempFileBytes(t, "big.bin", largePayload(t))
	err := runSend([]string{"-p", "roundtrip-pass", "-server", m.URL, src})
	if err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("expected a digest error, got %v", err)
	}
	if m.partAttempts[2] != digestRetries {
		t.Fatalf("part 2 attempts = %d, want %d", m.partAttempts[2], digestRetries)
	}
	if m.abortCalls != 1 {
		t.Fatalf("a failed upload must hand its session back (aborts=%d)", m.abortCalls)
	}
}

func TestUpload_Parts_SessionLost(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	m.partHook = func(n, attempt int) (int, string) {
		if n == 2 {
			return 404, "Upload session not found"
		}
		return 0, ""
	}
	src := tempFileBytes(t, "big.bin", largePayload(t))
	err := runSend([]string{"-p", "roundtrip-pass", "-server", m.URL, src})
	if err == nil || !strings.Contains(err.Error(), "session") {
		t.Fatalf("expected a session error, got %v", err)
	}
	if m.partAttempts[2] != 1 {
		t.Fatalf("a lost session must not be retried (attempts=%d)", m.partAttempts[2])
	}
}

func TestUpload_Parts_FinalRefusalIsNotRetried(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	m.partHook = func(n, attempt int) (int, string) {
		if n == 2 {
			return 400, "File does not appear to be encrypted"
		}
		return 0, ""
	}
	src := tempFileBytes(t, "big.bin", largePayload(t))
	err := runSend([]string{"-p", "roundtrip-pass", "-server", m.URL, src})
	if err == nil || !strings.Contains(err.Error(), "does not appear to be encrypted") {
		t.Fatalf("expected the server's detail, got %v", err)
	}
	if m.partAttempts[2] != 1 {
		t.Fatalf("a 400 must not be retried (attempts=%d)", m.partAttempts[2])
	}
	if m.abortCalls != 1 {
		t.Fatalf("aborts=%d, want 1", m.abortCalls)
	}
}

func TestUpload_Parts_Complete502ThenOK(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	m.completeHook = func(attempt int) (int, string) {
		if attempt == 1 {
			return 502, `{"detail":"Storage unavailable"}`
		}
		return 0, ""
	}
	payload := largePayload(t)
	src := tempFileBytes(t, "big.bin", payload)
	if got := sendAndGet(t, m, src); !bytes.Equal(got, payload) {
		t.Fatal("content differs")
	}
	if m.completeCalls != 2 {
		t.Fatalf("complete calls = %d, want 2", m.completeCalls)
	}
}

func TestUpload_Parts_CompleteWaitsOut409WithoutMissing(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	m.completeHook = func(attempt int) (int, string) {
		if attempt == 1 {
			return 409, `{"detail":"Parts missing","missing":[]}`
		}
		return 0, ""
	}
	src := tempFileBytes(t, "big.bin", largePayload(t))
	if err := runSend([]string{"-p", "roundtrip-pass", "-server", m.URL, src}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if m.completeCalls != 2 {
		t.Fatalf("complete calls = %d, want 2", m.completeCalls)
	}
}

func TestUpload_Parts_CompleteMissingPartsIsFinal(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	m.completeHook = func(attempt int) (int, string) {
		return 409, `{"detail":"Parts missing","missing":[2,3]}`
	}
	src := tempFileBytes(t, "big.bin", largePayload(t))
	err := runSend([]string{"-p", "roundtrip-pass", "-server", m.URL, src})
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("expected a missing-parts error, got %v", err)
	}
	if m.completeCalls != 1 {
		t.Fatalf("complete calls = %d, want 1", m.completeCalls)
	}
	if m.abortCalls != 1 {
		t.Fatalf("aborts=%d, want 1", m.abortCalls)
	}
}

// A complete answer cut off on the way is asked for again: the server
// answers a repeated complete with the same link.
func TestUpload_Parts_CompleteCutAnswerAskedAgain(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	m.cutCompletes = 1
	payload := largePayload(t)
	src := tempFileBytes(t, "big.bin", payload)
	if got := sendAndGet(t, m, src); !bytes.Equal(got, payload) {
		t.Fatal("content differs")
	}
	if m.completeCalls != 2 {
		t.Fatalf("complete calls = %d, want 2", m.completeCalls)
	}
}

// An answer that keeps breaking off is given up on after cutRetries more
// tries, saying that the file may be stored.
func TestUpload_Parts_CompleteAnswerKeptBreakingOff(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	m.cutCompletes = 1 << 20
	src := tempFileBytes(t, "big.bin", largePayload(t))
	err := runSend([]string{"-p", "roundtrip-pass", "-server", m.URL, src})
	if err == nil || !strings.Contains(err.Error(), "may be stored") {
		t.Fatalf("expected the lost-answer error, got %v", err)
	}
	if m.completeCalls != cutRetries+1 {
		t.Fatalf("complete calls = %d, want %d", m.completeCalls, cutRetries+1)
	}
}

// A whole answer that cannot be read is final: asking again gets the same.
func TestUpload_Parts_CompleteMalformedAnswerIsFinal(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	m.completeHook = func(attempt int) (int, string) {
		return 201, `{"link":12345}`
	}
	src := tempFileBytes(t, "big.bin", largePayload(t))
	err := runSend([]string{"-p", "roundtrip-pass", "-server", m.URL, src})
	if err == nil || !strings.Contains(err.Error(), "Invalid server response") {
		t.Fatalf("expected an invalid-response error, got %v", err)
	}
	if m.completeCalls != 1 {
		t.Fatalf("complete calls = %d, want 1", m.completeCalls)
	}
}

// A server without sessions takes only files of one part: a larger one is
// refused with its reason, not sent some other way.
func TestUpload_NoSessions_LargeFileRefused(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	m.noSessions = true
	src := tempFileBytes(t, "big.bin", largePayload(t))
	err := runSend([]string{"-p", "roundtrip-pass", "-server", m.URL, src})
	if err == nil || !strings.Contains(err.Error(), "Resumable uploads are not available") {
		t.Fatalf("expected the server's reason, got %v", err)
	}
	if m.sessionCalls != 1 || m.putCalls != 0 {
		t.Fatalf("sessions=%d puts=%d, want 1/0", m.sessionCalls, m.putCalls)
	}
}

// Over the single-request size (lowered here), even a tiny file goes in a
// verified part of a session.
func TestUpload_Small_PartsWhenOverTheSingleSize(t *testing.T) {
	noKeys(t)
	old := singleMaxBytes
	singleMaxBytes = 0
	t.Cleanup(func() { singleMaxBytes = old })
	m := newMockAPI(t)
	payload := []byte("small enough for one request")
	src := tempFileBytes(t, "small.txt", payload)
	if got := sendAndGet(t, m, src, "-b"); !bytes.Equal(got, payload) {
		t.Fatal("content differs")
	}
	if m.sessionCalls != 1 || m.putCalls != 0 {
		t.Fatalf("sessions=%d puts=%d, want 1/0", m.sessionCalls, m.putCalls)
	}
	if len(m.partDigests) != 1 || m.partDigests[1] == "" {
		t.Fatalf("part digests = %v, want one for part 1", m.partDigests)
	}
	if h := m.lastUploadHeaders; h.Get("X-Burn-After-Reading") != "true" || h.Get("X-File-Size") != strconv.Itoa(len(m.blob)) {
		t.Fatalf("session headers: burn=%q size=%q", h.Get("X-Burn-After-Reading"), h.Get("X-File-Size"))
	}
}

// The default for a file of one part: a single PUT /v1/files with the
// whole file's SHA-256, which the server checks before it stores it.
func TestUpload_Small_GoesInOneRequest(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	payload := []byte("small enough for one request")
	src := tempFileBytes(t, "small.txt", payload)
	if got := sendAndGet(t, m, src, "-b"); !bytes.Equal(got, payload) {
		t.Fatal("content differs")
	}
	if m.sessionCalls != 0 || m.putCalls != 1 {
		t.Fatalf("sessions=%d puts=%d, want 0/1", m.sessionCalls, m.putCalls)
	}
	h := m.lastUploadHeaders
	sum := sha256.Sum256(m.blob)
	if got := h.Get("Content-Digest"); got != "sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":" {
		t.Fatalf("Content-Digest = %q", got)
	}
	if got := h.Get("X-File-Size"); got != strconv.Itoa(len(m.blob)) {
		t.Fatalf("X-File-Size = %q, want %d", got, len(m.blob))
	}
	if h.Get("X-Burn-After-Reading") != "true" || h.Get("X-Token-Hash") == "" {
		t.Fatalf("headers: burn=%q token hash=%q", h.Get("X-Burn-After-Reading"), h.Get("X-Token-Hash"))
	}
	if ua := h.Get("User-Agent"); !strings.HasPrefix(ua, "ttl-cli/") {
		t.Fatalf("User-Agent = %q", ua)
	}
}

// Bytes altered on the way (422) are sent again at once; a busy or failing
// server (429, 503) is asked again after a pause.
func TestUpload_Single_RetriesLikeAPart(t *testing.T) {
	for _, status := range []int{422, 429, 503, 408, 409} {
		noKeys(t)
		m := newMockAPI(t)
		m.fileHook = func(attempt int) (int, string) {
			if attempt == 1 {
				return status, "once"
			}
			return 0, ""
		}
		src := tempFileBytes(t, "small.txt", []byte("retry me"))
		if got := sendAndGet(t, m, src); string(got) != "retry me" {
			t.Fatalf("%d: content differs", status)
		}
		if m.putCalls != 2 {
			t.Fatalf("%d: PUT attempts = %d, want 2", status, m.putCalls)
		}
	}
}

// An answer cut off on the way is asked for again: the server gives the
// same bytes the same answer.
func TestUpload_Single_CutOffAnswerAskedAgain(t *testing.T) {
	noKeys(t)
	var puts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/limits" {
			writeMockLimits(w)
			return
		}
		io.Copy(io.Discard, r.Body)
		puts++
		w.Header().Set("Content-Length", "200")
		w.WriteHeader(http.StatusCreated)
		if puts == 1 {
			w.Write([]byte(`{"link":"https://ttl.space/aB`)) // then the connection goes
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					conn.Close()
				}
			}
			return
		}
		b, _ := json.Marshal(map[string]any{"link": "https://ttl.space/aBcDeFgHiJ", "token": "aBcDeFgHiJ", "manage_key": mockManageKey})
		w.Write(append(b, bytes.Repeat([]byte(" "), 200-len(b))...))
	}))
	defer srv.Close()
	src := tempFile(t, "x.txt", "answer lost")
	if err := runSend([]string{"-p", "12345678", "-server", srv.URL, src}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if puts != 2 {
		t.Fatalf("PUT attempts = %d, want 2", puts)
	}
}

// An answer that keeps breaking off is given up on after cutRetries more
// tries, saying that the file may be stored.
func TestUpload_Single_AnswerKeptBreakingOff(t *testing.T) {
	noKeys(t)
	var puts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/limits" {
			writeMockLimits(w)
			return
		}
		io.Copy(io.Discard, r.Body)
		puts.Add(1)
		w.Header().Set("Content-Length", "200")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"link":"https://ttl.space/aB`))
		w.(http.Flusher).Flush()
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				conn.Close()
			}
		}
	}))
	defer srv.Close()
	src := tempFile(t, "x.txt", "answer lost")
	err := runSend([]string{"-p", "12345678", "-server", srv.URL, src})
	if err == nil || !strings.Contains(err.Error(), "may be stored") {
		t.Fatalf("expected the lost-answer error, got %v", err)
	}
	if puts.Load() != cutRetries+1 {
		t.Fatalf("PUT attempts = %d, want %d", puts.Load(), cutRetries+1)
	}
}

// A daily-limit 429 is final at once: waiting cannot lift it.
func TestUpload_Single_QuotaRefusalIsFinal(t *testing.T) {
	noKeys(t)
	var puts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/limits" {
			writeMockLimits(w)
			return
		}
		io.Copy(io.Discard, r.Body)
		puts++
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"detail":"Upload limit reached (10 per day)"}`))
	}))
	defer srv.Close()
	src := tempFile(t, "x.txt", "over the limit")
	err := runSend([]string{"-p", "12345678", "-server", srv.URL, src})
	if err == nil || !strings.Contains(err.Error(), "Upload limit reached") {
		t.Fatalf("err = %v, want the server's limit message", err)
	}
	if puts != 1 {
		t.Fatalf("PUT attempts = %d, want 1", puts)
	}
}

func TestUpload_Single_RetriesAfterConnectionDrop(t *testing.T) {
	noKeys(t)
	var puts int
	var stored []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/limits" {
			writeMockLimits(w)
			return
		}
		puts++
		if puts == 1 {
			// Drop the connection mid-body.
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, _ := hj.Hijack()
				conn.Close()
			}
			return
		}
		stored, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"link": "https://ttl.space/aBcDeFgHiJ"})
	}))
	defer srv.Close()

	src := tempFile(t, "x.txt", "retry me please")
	if err := runSend([]string{"-p", "12345678", "-server", srv.URL, src}); err != nil {
		t.Fatalf("send should succeed on the second attempt: %v", err)
	}
	if puts != 2 {
		t.Fatalf("PUT attempts = %d, want 2", puts)
	}
	if len(stored) < 46 || string(stored[:4]) != "TTL\x01" {
		t.Fatal("second attempt did not carry a full TTL stream")
	}
}

// A connection that never lets the file through ends the upload once
// nothing has got further for resumeGiveUp.
func TestUpload_Single_GivesUpWithoutProgress(t *testing.T) {
	noKeys(t)
	old := resumeGiveUp
	resumeGiveUp = 300 * time.Millisecond
	t.Cleanup(func() { resumeGiveUp = old })
	var puts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/limits" {
			writeMockLimits(w)
			return
		}
		puts.Add(1)
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
		}
	}))
	defer srv.Close()

	src := tempFile(t, "x.txt", "never lands")
	err := runSend([]string{"-p", "12345678", "-server", srv.URL, src})
	if err == nil || !strings.Contains(err.Error(), "no progress") {
		t.Fatalf("expected no progress, got %v", err)
	}
	if puts.Load() < 2 {
		t.Fatalf("PUT attempts = %d, want retries before giving up", puts.Load())
	}
}

// slowUplink sends request bodies at rate bytes per second, as a slow
// link does: the CLI sees its bytes leave little by little.
type slowUplink struct{ rate int64 }

func (s slowUplink) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil && req.Body != http.NoBody {
		req = req.Clone(req.Context())
		req.Body = io.NopCloser(&rateReader{ctx: req.Context(), r: req.Body, rate: s.rate})
	}
	return http.DefaultTransport.RoundTrip(req)
}

type rateReader struct {
	ctx  context.Context
	r    io.Reader
	rate int64
	next time.Time
}

func (s *rateReader) Read(p []byte) (int, error) {
	if len(p) > 4096 {
		p = p[:4096]
	}
	if d := time.Until(s.next); d > 0 {
		select {
		case <-time.After(d):
		case <-s.ctx.Done():
			return 0, s.ctx.Err()
		}
	}
	if s.next.IsZero() {
		s.next = time.Now()
	}
	n, err := s.r.Read(p)
	s.next = s.next.Add(time.Duration(int64(n) * int64(time.Second) / s.rate))
	return n, err
}

// A part that moves slowly for longer than resumeGiveUp and then fails
// once is sent again: its bytes going further than ever was progress.
func TestUpload_Parts_SlowPartThenErrorIsRetried(t *testing.T) {
	noKeys(t)
	old := resumeGiveUp
	resumeGiveUp = 300 * time.Millisecond
	testTransport = slowUplink{rate: 64 << 10} // a 64 KiB part: about a second
	t.Cleanup(func() { resumeGiveUp, testTransport = old, nil })
	m := newMockAPI(t)
	m.partHook = func(n, attempt int) (int, string) {
		if n == 1 && attempt == 1 {
			return 503, "transient"
		}
		return 0, ""
	}
	payload := largePayload(t)
	src := tempFileBytes(t, "big.bin", payload)
	if got := sendAndGet(t, m, src); !bytes.Equal(got, payload) {
		t.Fatal("content differs")
	}
	if m.partAttempts[1] != 2 {
		t.Fatalf("part 1 attempts = %d, want 2", m.partAttempts[1])
	}
}

func TestUpload_Single_ServerRefusalIsNotRetried(t *testing.T) {
	noKeys(t)
	var puts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/limits" {
			writeMockLimits(w)
			return
		}
		puts++
		// Answer before reading the body, as the server does for a bad header.
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]any{"detail": "invalid X-TTL header (allowed: 300,600)"})
	}))
	defer srv.Close()

	src := tempFile(t, "x.txt", "refused")
	err := runSend([]string{"-p", "12345678", "-server", srv.URL, src})
	if err == nil || !strings.Contains(err.Error(), "Upload rejected: invalid X-TTL header") {
		t.Fatalf("expected the server's detail, got %v", err)
	}
	if puts != 1 {
		t.Fatalf("PUT attempts = %d, want 1", puts)
	}
}

func TestUpload_JSON_HasTokenManageKeyAndExpiry(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	src := tempFile(t, "report.txt", "json fields")
	var out []byte
	var err error
	withJSON(t, func() {
		out = captureStdout(t, func() {
			err = runSend([]string{"-server", m.URL, src})
		})
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	var res map[string]any
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("invalid JSON %q: %v", out, err)
	}
	if res["token"] != "aBcDeFgHiJ" {
		t.Fatalf("token = %v", res["token"])
	}
	if res["manage_key"] != mockManageKey {
		t.Fatalf("manage_key = %v", res["manage_key"])
	}
	if res["expires_in"] != float64(604800) {
		t.Fatalf("expires_in = %v", res["expires_in"])
	}
	if _, ok := res["expires_at"].(float64); !ok {
		t.Fatalf("expires_at missing: %v", res)
	}
	if pw, _ := res["password"].(string); len(pw) != generatedPasswordLength {
		t.Fatalf("password = %q", pw)
	}
}

func TestUpload_JSON_OlderServerWithoutExtras(t *testing.T) {
	noKeys(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/limits" {
			writeMockLimits(w)
			return
		}
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"link":"https://ttl.space/zYxWvUtSrQ"}`))
	}))
	defer srv.Close()
	src := tempFile(t, "old.txt", "older server")
	var out []byte
	var err error
	withJSON(t, func() {
		out = captureStdout(t, func() {
			err = runSend([]string{"-p", "12345678", "-server", srv.URL, src})
		})
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	var res map[string]any
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	// The token comes from the link when the server sends none.
	if res["token"] != "zYxWvUtSrQ" {
		t.Fatalf("token = %v", res["token"])
	}
	for _, absent := range []string{"manage_key", "expires_in", "expires_at"} {
		if _, ok := res[absent]; ok {
			t.Fatalf("%s should be absent for an older server", absent)
		}
	}
}

func TestSend_RejectedKeyIsNotReportedAsUnreachable(t *testing.T) {
	t.Setenv("TTL_API_KEY", keyPrefix+strings.Repeat("r", 48))
	t.Setenv("HOME", t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]any{"detail": "Invalid or expired API key"})
	}))
	defer srv.Close()
	src := tempFile(t, "x.txt", "data")
	err := runSend([]string{"-p", "12345678", "-server", srv.URL, src})
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "Cannot reach server") {
		t.Fatalf("a rejected key is not a network error: %v", err)
	}
	if !strings.Contains(err.Error(), "API key") {
		t.Fatalf("error should name the API key: %v", err)
	}
}

func TestSend_FileShrinkingDuringUploadFails(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	src := tempFileBytes(t, "shrink.bin", largePayload(t))
	// Truncate the file once the first part has been read: the encryptor's
	// LimitReader stops short and the upload must fail, not store a
	// corrupt object.
	first := true
	m.partHook = func(n, attempt int) (int, string) {
		if first {
			first = false
			os.Truncate(src, 10)
		}
		return 0, ""
	}
	err := runSend([]string{"-p", "roundtrip-pass", "-server", m.URL, src})
	if err == nil || !strings.Contains(err.Error(), "changed while uploading") {
		t.Fatalf("expected a file-changed error, got %v", err)
	}
	if m.completeCalls != 0 {
		t.Fatal("a broken stream must never be completed")
	}
}

func TestFallbackToTCP_SwitchesClient(t *testing.T) {
	h := &httpConn{client: newH3Client(), h3: true}
	failed := h.client
	h.fallbackToTCP(failed)
	tcp := h.client
	// A second request that failed on the same HTTP/3 client meanwhile
	// (two parts on the way) leaves the switch as it is.
	h.fallbackToTCP(failed)
	if h.client != tcp {
		t.Fatal("a second fallback replaced the TCP client again")
	}
	if h.h3 {
		t.Fatal("still marked as HTTP/3")
	}
	if _, ok := h.client.Transport.(*http.Transport); !ok {
		t.Fatalf("transport after fallback = %T", h.client.Transport)
	}
	if h.client.CheckRedirect == nil {
		t.Fatal("TCP client must refuse redirects")
	}
}

func TestNewRequest_SetsUserAgent(t *testing.T) {
	req, err := newRequest(t.Context(), http.MethodGet, "https://ttl.space/v1/limits", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ua := req.Header.Get("User-Agent"); !strings.HasPrefix(ua, "ttl-cli/") || !strings.Contains(ua, version) {
		t.Fatalf("User-Agent = %q", ua)
	}
}

func TestClients_RefuseRedirects(t *testing.T) {
	hops := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops++
		http.Redirect(w, r, "http://127.0.0.1:1/elsewhere", http.StatusFound)
	}))
	defer srv.Close()
	req, _ := newRequest(t.Context(), http.MethodGet, srv.URL+"/v1/limits", nil)
	resp, err := newConn().do(req)
	if err != nil {
		t.Fatalf("a 3xx must come back as a response, got %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || hops != 1 {
		t.Fatalf("status=%d hops=%d", resp.StatusCode, hops)
	}
}
