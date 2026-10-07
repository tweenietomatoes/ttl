package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMain shortens the retry pauses, and sends files over 256 KiB in
// parts where the CLI itself starts at 16 MiB: the parts tests use payloads
// of about 300 KiB in the mock's 64 KiB parts. Smaller files take the
// single PUT /v1/files, as they do for real, which is all the small
// stand-in servers of many tests take.
func TestMain(m *testing.M) {
	retryBase = 5 * time.Millisecond
	partMinGap = 0
	singleMaxBytes = 256 << 10
	os.Exit(m.Run())
}

// mockManageKey is a well-formed management key (43 base64url chars).
const mockManageKey = "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm"

// mockUploadServer returns a test server that accepts uploads and returns a
// valid 201 response with a fake link.
func mockUploadServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/limits" {
			writeMockLimits(w)
			return
		}
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"link":       "https://ttl.space/aBcDeFgHiJ",
			"token":      "aBcDeFgHiJ",
			"expires_in": 604800,
			"size_bytes": r.ContentLength,
			"manage_key": mockManageKey,
		})
	}))
}

func writeMockLimits(w http.ResponseWriter) {
	json.NewEncoder(w).Encode(map[string]any{
		"plan": "free", "max_file_bytes": 2147483648, "max_ttl_seconds": 604800,
		"default_ttl_seconds": 604800, "uploads_per_day": 10,
		"allowed_ttl_seconds": []int{300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 259200, 345600, 432000, 518400, 604800},
	})
}

// tempFile creates a file with the given name and content inside a temp
// directory and returns the full path.
func tempFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

// tempFileBytes is tempFile for binary content.
func tempFileBytes(t *testing.T, name string, content []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, content, 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, fn func()) []byte {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()
	fn()
	w.Close()
	os.Stdout = orig
	return <-done
}

// withJSON runs fn in --json mode.
func withJSON(t *testing.T, fn func()) {
	t.Helper()
	old := jsonMode
	jsonMode = true
	defer func() { jsonMode = old }()
	fn()
}

// noKeys makes sure no Orbit key leaks into a test from the environment,
// the home directory or a file next to the test binary.
func noKeys(t *testing.T) {
	t.Helper()
	t.Setenv("TTL_API_KEY", "")
	t.Setenv("HOME", t.TempDir())
	scrubBinaryAdjacentKey(t)
}
