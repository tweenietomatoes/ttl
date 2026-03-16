package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// mockUploadServer returns a test server that accepts uploads and returns a
// valid 201 response with a fake link.
func mockUploadServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/limits" {
			json.NewEncoder(w).Encode(map[string]any{
				"plan":                "free",
				"max_file_bytes":      2147483648,
				"max_ttl_seconds":     604800,
				"default_ttl_seconds": 604800,
				"uploads_per_day":     10,
				"allowed_ttl_seconds": []int{300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 259200, 345600, 432000, 518400, 604800},
				"can_delete":          false,
				"can_list":            false,
			})
			return
		}
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"link": "https://ttl.space/aBcDeFgHiJ",
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
