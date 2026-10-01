package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
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

func TestUpload_NoSessions_FallsBackToSinglePUT(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	m.noSessions = true
	payload := largePayload(t)
	src := tempFileBytes(t, "big.bin", payload)
	if got := sendAndGet(t, m, src); !bytes.Equal(got, payload) {
		t.Fatal("content differs")
	}
	if m.sessionCalls != 1 || m.putCalls != 1 {
		t.Fatalf("sessions=%d puts=%d, want 1/1", m.sessionCalls, m.putCalls)
	}
}

func TestUpload_Small_UsesSinglePUT(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	payload := []byte("small enough for one request")
	src := tempFileBytes(t, "small.txt", payload)
	if got := sendAndGet(t, m, src); !bytes.Equal(got, payload) {
		t.Fatal("content differs")
	}
	if m.sessionCalls != 0 || m.putCalls != 1 {
		t.Fatalf("sessions=%d puts=%d, want 0/1", m.sessionCalls, m.putCalls)
	}
	h := m.lastUploadHeaders
	if got := h.Get("X-File-Size"); got != strconv.Itoa(len(m.blob)) {
		t.Fatalf("X-File-Size = %q, want %d", got, len(m.blob))
	}
	if h.Get("X-Upload-Path") != "stream" {
		t.Fatalf("X-Upload-Path = %q", h.Get("X-Upload-Path"))
	}
	if ua := h.Get("User-Agent"); !strings.HasPrefix(ua, "ttl-cli/") {
		t.Fatalf("User-Agent = %q", ua)
	}
}

func TestUpload_Whole_RetriesAfterConnectionDrop(t *testing.T) {
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

func TestUpload_Whole_GivesUpAfterAttempts(t *testing.T) {
	noKeys(t)
	var puts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/limits" {
			writeMockLimits(w)
			return
		}
		puts++
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
		}
	}))
	defer srv.Close()

	src := tempFile(t, "x.txt", "never lands")
	err := runSend([]string{"-p", "12345678", "-server", srv.URL, src})
	if err == nil || !strings.Contains(err.Error(), "Upload failed") {
		t.Fatalf("expected Upload failed, got %v", err)
	}
	if puts != wholeAttempts {
		t.Fatalf("PUT attempts = %d, want %d", puts, wholeAttempts)
	}
}

func TestUpload_Whole_ServerRefusalIsNotRetried(t *testing.T) {
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
	h.fallbackToTCP()
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
