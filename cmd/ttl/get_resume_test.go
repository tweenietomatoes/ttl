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
