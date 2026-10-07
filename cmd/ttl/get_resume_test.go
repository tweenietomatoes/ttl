package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGet_ResumesAfterConnectionDrop(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	payload := largePayload(t)
	src := tempFileBytes(t, "big.bin", payload)
	if err := runSend([]string{"-p", "resume-pass", "-server", m.URL, src}); err != nil {
		t.Fatalf("send: %v", err)
	}
	m.dropAfter = 100_000

	outDir := t.TempDir()
	if err := runGet([]string{"-p", "resume-pass", "-o", outDir, m.URL + "/aBcDeFgHiJ"}); err != nil {
		t.Fatalf("get should resume after the drop: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(outDir, "big.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("resumed download differs from the original")
	}
	if len(m.rangeRequests) != 1 || m.rangeRequests[0] != "bytes=100000-" {
		t.Fatalf("range requests = %v, want [bytes=100000-]", m.rangeRequests)
	}
	if m.downloadHeaders.Get("X-Download-Token") == "" {
		t.Fatal("the resumed request must carry X-Download-Token")
	}
}

func TestGet_Resume_ServerIgnoresRange(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	payload := largePayload(t)
	src := tempFileBytes(t, "big.bin", payload)
	if err := runSend([]string{"-p", "resume-pass", "-server", m.URL, src}); err != nil {
		t.Fatalf("send: %v", err)
	}
	m.dropAfter = 70_000
	m.ignoreRange = true

	outDir := t.TempDir()
	if err := runGet([]string{"-p", "resume-pass", "-o", outDir, m.URL + "/aBcDeFgHiJ"}); err != nil {
		t.Fatalf("get should cope with a 200 on resume: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(outDir, "big.bin"))
	if !bytes.Equal(got, payload) {
		t.Fatal("content differs")
	}
}

func TestGet_Resume_OneTimeFileCannotResume(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	src := tempFileBytes(t, "big.bin", largePayload(t))
	if err := runSend([]string{"-p", "resume-pass", "-server", m.URL, src}); err != nil {
		t.Fatalf("send: %v", err)
	}
	m.dropAfter = 100_000
	m.burn = true

	outDir := t.TempDir()
	err := runGet([]string{"-p", "resume-pass", "-o", outDir, m.URL + "/aBcDeFgHiJ"})
	if err == nil || !strings.Contains(err.Error(), "one-time") {
		t.Fatalf("expected the server's refusal, got %v", err)
	}
	if entries, _ := os.ReadDir(outDir); len(entries) != 0 {
		t.Fatalf("a failed download must leave no file behind: %v", entries)
	}
}

// A one-time file whose first answer carried a resume ticket gets the rest
// after a drop, with the ticket on the range request only.
func TestGet_Resume_OneTimeFileWithTicket(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	payload := largePayload(t)
	src := tempFileBytes(t, "big.bin", payload)
	if err := runSend([]string{"-p", "resume-pass", "-server", m.URL, src}); err != nil {
		t.Fatalf("send: %v", err)
	}
	m.dropAfter = 100_000
	m.burn = true
	m.ticket = "rt_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"

	outDir := t.TempDir()
	if err := runGet([]string{"-p", "resume-pass", "-o", outDir, m.URL + "/aBcDeFgHiJ"}); err != nil {
		t.Fatalf("a one-time download should resume with its ticket: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(outDir, "big.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("resumed one-time download differs from the original")
	}
	if len(m.rangeRequests) != 1 || m.rangeRequests[0] != "bytes=100000-" {
		t.Fatalf("range requests = %v, want [bytes=100000-]", m.rangeRequests)
	}
	if got := m.downloadHeaders.Get("X-Resume-Ticket"); got != m.ticket {
		t.Fatalf("the resumed request carried ticket %q", got)
	}
}

func burnMock(t *testing.T) (*mockAPI, []byte) {
	t.Helper()
	noKeys(t)
	m := newMockAPI(t)
	payload := largePayload(t)
	src := tempFileBytes(t, "big.bin", payload)
	if err := runSend([]string{"-p", "resume-pass", "-server", m.URL, src}); err != nil {
		t.Fatalf("send: %v", err)
	}
	m.burn = true
	m.ticket = "rt_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
	return m, payload
}

func getInto(t *testing.T, m *mockAPI) ([]byte, error) {
	t.Helper()
	outDir := t.TempDir()
	err := runGet([]string{"-p", "resume-pass", "-o", outDir, m.URL + "/aBcDeFgHiJ"})
	got, _ := os.ReadFile(filepath.Join(outDir, "big.bin"))
	return got, err
}

// A busy server during a ticketed resume (503, 429) is asked again: one
// such answer must not cost a one-time file.
func TestGet_Resume_OneTimeRetriesBusyServer(t *testing.T) {
	m, payload := burnMock(t)
	m.dropAfter = 100_000
	m.rangeHook = func(attempt int) int {
		switch attempt {
		case 1:
			return 503
		case 2:
			return 429
		}
		return 0
	}
	got, err := getInto(t, m)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("resume through busy answers: err=%v, %d bytes", err, len(got))
	}
	if len(m.rangeRequests) != 3 {
		t.Fatalf("range requests = %d, want 3", len(m.rangeRequests))
	}
}

// Every resume that brings bytes starts a new budget: ten breaks in one
// download, more than maxResumes, still finish.
func TestGet_Resume_BudgetResetsAfterProgress(t *testing.T) {
	m, payload := burnMock(t)
	m.dropAfter = 20_000
	m.dropRanges = maxResumes + 2
	got, err := getInto(t, m)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("download with %d breaks: err=%v, %d bytes", m.dropRanges, err, len(got))
	}
	if len(m.rangeRequests) <= maxResumes {
		t.Fatalf("range requests = %d, want more than %d", len(m.rangeRequests), maxResumes)
	}
}

// Broken before its first byte: the resume asks from byte 0 with the ticket.
func TestGet_Resume_OneTimeBrokenBeforeFirstByte(t *testing.T) {
	m, payload := burnMock(t)
	m.dropAtStart = true
	got, err := getInto(t, m)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("err=%v, %d bytes", err, len(got))
	}
	if len(m.rangeRequests) != 1 || m.rangeRequests[0] != "bytes=0-" || m.downloadHeaders.Get("X-Resume-Ticket") != m.ticket {
		t.Fatalf("range requests %v, ticket %q", m.rangeRequests, m.downloadHeaders.Get("X-Resume-Ticket"))
	}
}

// The server rolled a download without a byte back and dropped its ticket:
// the CLI asks once more as a fresh download and takes the new ticket.
func TestGet_Resume_OneTimeRolledBack(t *testing.T) {
	m, payload := burnMock(t)
	m.dropAtStart = true
	m.rangeHook = func(attempt int) int {
		if attempt == 1 {
			return 404
		}
		return 0
	}
	m.newTicket = "rt_ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkj"
	got, err := getInto(t, m)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("err=%v, %d bytes", err, len(got))
	}
}

// Rolled back, then the fresh downloads keep failing: the file was never
// used up, so the error must not say it is lost.
func TestGet_Resume_RolledBackFailureIsNotLoss(t *testing.T) {
	m, _ := burnMock(t)
	m.dropAtStart = true
	m.rangeHook = func(int) int { return 404 }
	m.fullHook = func(attempt int) int {
		if attempt == 1 {
			return 0 // the first answer: headers and a ticket, then nothing
		}
		return 502
	}
	_, err := getInto(t, m)
	if err == nil {
		t.Fatal("expected the download to fail")
	}
	if strings.Contains(err.Error(), "cannot be downloaded again") {
		t.Fatalf("a rolled-back one-time file reported lost: %v", err)
	}
}

// Broken before its first byte, then no answer that says more: whether the
// server rolled the download back is unknown, so the error must not say
// the file is lost.
func TestGet_Resume_UnreachableBeforeFirstByteIsNotLoss(t *testing.T) {
	m, _ := burnMock(t)
	m.dropAtStart = true
	m.rangeHook = func(int) int { return 503 }
	_, err := getInto(t, m)
	if err == nil {
		t.Fatal("expected the download to fail")
	}
	if strings.Contains(err.Error(), "cannot be downloaded again") {
		t.Fatalf("a one-time file with no byte received reported lost: %v", err)
	}
}

// Every byte arrived, then the stream broke before its end: the file is
// whole (each chunk is authenticated), so it is kept, not resumed.
func TestGet_Resume_BreakAfterLastByte(t *testing.T) {
	m, payload := burnMock(t)
	m.cutAfterLast = true
	got, err := getInto(t, m)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("err=%v, %d bytes", err, len(got))
	}
	if len(m.rangeRequests) != 0 {
		t.Fatalf("resumed a complete download: %v", m.rangeRequests)
	}
}

// The resume window closed: the error says plainly that the file is gone.
func TestGet_Resume_OneTimeWindowClosed(t *testing.T) {
	m, _ := burnMock(t)
	m.dropAfter = 100_000
	m.rangeHook = func(int) int { return 404 }
	_, err := getInto(t, m)
	if err == nil || !strings.Contains(err.Error(), "cannot be downloaded again") {
		t.Fatalf("expected the lost-file message, got %v", err)
	}
}

// A download whose bytes stop coming while the connection stays open is
// resumed after downloadIdle from the byte where it stopped.
func TestGet_Resume_SilentConnection(t *testing.T) {
	noKeys(t)
	old := downloadIdle
	downloadIdle = 300 * time.Millisecond
	t.Cleanup(func() { downloadIdle = old })
	m := newMockAPI(t)
	payload := largePayload(t)
	src := tempFileBytes(t, "big.bin", payload)
	if err := runSend([]string{"-p", "resume-pass", "-server", m.URL, src}); err != nil {
		t.Fatalf("send: %v", err)
	}
	m.silentAfter = 100_000
	t0 := time.Now()
	got, err := getInto(t, m)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("err=%v, %d bytes", err, len(got))
	}
	if len(m.rangeRequests) != 1 || m.rangeRequests[0] != "bytes=100000-" {
		t.Fatalf("range requests = %v", m.rangeRequests)
	}
	if took := time.Since(t0); took > 10*time.Second {
		t.Fatalf("took %s", took)
	}
}

func TestGet_Resume_GivesUpOnRepeatedShortBodies(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	src := tempFileBytes(t, "big.bin", largePayload(t))
	if err := runSend([]string{"-p", "resume-pass", "-server", m.URL, src}); err != nil {
		t.Fatalf("send: %v", err)
	}
	// Every answer is short: the range handler serves only a slice.
	short := m.blob[:120_000]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/probe/") {
			w.Write(m.blob[:314])
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(short)
	}))
	defer srv.Close()

	outDir := t.TempDir()
	err := runGet([]string{"-p", "resume-pass", "-o", outDir, srv.URL + "/aBcDeFgHiJ"})
	if err == nil || !strings.Contains(err.Error(), "resume attempts") {
		t.Fatalf("expected to give up after resume attempts, got %v", err)
	}
}

func TestGet_403_MentionsPrivateFiles(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	src := tempFile(t, "x.txt", "locked to a key")
	if err := runSend([]string{"-p", "resume-pass", "-server", m.URL, src}); err != nil {
		t.Fatalf("send: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/probe/") {
			w.Write(m.blob)
			return
		}
		w.WriteHeader(403)
		json.NewEncoder(w).Encode(map[string]any{"detail": "Invalid download token"})
	}))
	defer srv.Close()

	err := runGet([]string{"-p", "resume-pass", "-o", t.TempDir(), srv.URL + "/aBcDeFgHiJ"})
	if err == nil || !strings.Contains(err.Error(), "private") || !strings.Contains(err.Error(), "Invalid download token") {
		t.Fatalf("403 should explain private files and carry the detail, got %v", err)
	}
}

func TestGet_JSON_IncludesToken(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	src := tempFile(t, "x.txt", "json token")
	if err := runSend([]string{"-p", "resume-pass", "-server", m.URL, src}); err != nil {
		t.Fatalf("send: %v", err)
	}
	var out []byte
	var err error
	withJSON(t, func() {
		out = captureStdout(t, func() {
			err = runGet([]string{"-p", "resume-pass", "-o", t.TempDir(), m.URL + "/aBcDeFgHiJ"})
		})
	})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var res map[string]any
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	if res["token"] != "aBcDeFgHiJ" || res["filename"] != "x.txt" {
		t.Fatalf("unexpected JSON: %s", out)
	}
}

func TestGet_SendsUserAgentAndKey(t *testing.T) {
	key := keyPrefix + strings.Repeat("g", 48)
	t.Setenv("TTL_API_KEY", key)
	t.Setenv("HOME", t.TempDir())
	m := newMockAPI(t)
	m.plan = "orbit"
	src := tempFile(t, "x.txt", "headers")
	if err := runSend([]string{"-p", "resume-pass", "-server", m.URL, src}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := runGet([]string{"-p", "resume-pass", "-o", t.TempDir(), m.URL + "/aBcDeFgHiJ"}); err != nil {
		t.Fatalf("get: %v", err)
	}
	if ua := m.downloadHeaders.Get("User-Agent"); !strings.HasPrefix(ua, "ttl-cli/") {
		t.Fatalf("User-Agent = %q", ua)
	}
	if m.downloadHeaders.Get("X-API-Key") != key {
		t.Fatal("X-API-Key must be sent on download for private files")
	}
}

func TestGet_BareTokenUsesServerFlag(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	src := tempFile(t, "x.txt", "bare token")
	if err := runSend([]string{"-p", "resume-pass", "-server", m.URL, src}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := runGet([]string{"-p", "resume-pass", "-o", t.TempDir(), "-server", m.URL, "aBcDeFgHiJ"}); err != nil {
		t.Fatalf("get with --server and a bare token: %v", err)
	}
}

func TestContentRangeStart(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"bytes 100-199/200", 100, true},
		{"bytes 0-0/1", 0, true},
		{" bytes 5-9/10 ", 5, true},
		{"bytes */200", 0, false},
		{"100-199/200", 0, false},
		{"bytes -1-5/10", 0, false},
		{"", 0, false},
	}
	for _, tc := range cases {
		got, ok := contentRangeStart(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("contentRangeStart(%q) = (%d, %v), want (%d, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestHandleHTTPError_Messages(t *testing.T) {
	cases := []struct {
		status int
		body   string
		header http.Header
		want   string
	}{
		{404, `{"detail":"File not found. It may have already been downloaded or expired."}`, nil, "Link not found"},
		{401, ``, nil, "API key"},
		{408, ``, nil, "timed out"},
		{429, `{"detail":"Too many concurrent downloads"}`, http.Header{"Retry-After": {"30"}}, "Too many concurrent downloads (retry after 30s)"},
		{502, ``, nil, "Storage temporarily unavailable"},
		{500, `{"detail":"Internal error"}`, nil, "Server error: Internal error"},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for k, v := range tc.header {
				w.Header()[k] = v
			}
			w.WriteHeader(tc.status)
			w.Write([]byte(tc.body))
		}))
		resp, err := http.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		got := handleHTTPError(resp)
		resp.Body.Close()
		srv.Close()
		if got == nil || !strings.Contains(got.Error(), tc.want) {
			t.Fatalf("status %d: got %v, want substring %q", tc.status, got, tc.want)
		}
	}
}
