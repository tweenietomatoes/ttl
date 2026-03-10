package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- URL parsing ---

// TestAttack_ParseURL_Comprehensive tries many invalid URLs and checks that they are all rejected.
func TestAttack_ParseURL_Comprehensive(t *testing.T) {
	invalidURLs := []struct {
		name string
		url  string
	}{
		// Bad schemes
		{"javascript scheme", "javascript:alert(1)"},
		{"data scheme", "data:text/html,<script>"},
		{"file scheme", "file:///etc/passwd"},
		{"ftp scheme", "ftp://evil.com/aBcDeFgHiJ"},
		{"ssh scheme", "ssh://evil.com/aBcDeFgHiJ"},
		{"empty scheme", "://ttl.space/aBcDeFgHiJ"},
		{"no scheme", "ttl.space/aBcDeFgHiJ"},

		// Bad tokens
		{"empty token", "https://ttl.space/"},
		{"short token", "https://ttl.space/short"},
		{"long token", "https://ttl.space/aBcDeFgHiJK"},
		{"special chars", "https://ttl.space/aBcD!@gHiJ"},
		{"unicode token", "https://ttl.space/aBcDéFgHiJ"},
		{"path traversal", "https://ttl.space/../../../etc"},
		// URL-encoded Base62 chars decode to valid tokens, so they are not tested here
		{"null in token", "https://ttl.space/aBcD%00FgHiJ"},
		{"spaces in token", "https://ttl.space/aBcD%20FgHiJ"},

		// No host
		{"no host", "https:///aBcDeFgHiJ"},

		// Multi-segment paths (too many characters after stripping /)
		{"nested path", "https://ttl.space/v1/aBcDeFgHiJ"},
		{"deep path", "https://ttl.space/a/b/c/aBcDeFgHiJ"},
	}

	for _, tc := range invalidURLs {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseURL(tc.url)
			if err == nil {
				t.Fatalf("parseURL(%q) should fail", tc.url)
			}
		})
	}
}

// TestAttack_ParseURL_ValidEdgeCases checks that unusual but valid URLs are accepted.
func TestAttack_ParseURL_ValidEdgeCases(t *testing.T) {
	validURLs := []struct {
		url       string
		wantToken string
		wantBase  string
	}{
		// Normal
		{"https://ttl.space/aBcDeFgHiJ", "aBcDeFgHiJ", "https://ttl.space"},
		{"http://localhost:8080/1234567890", "1234567890", "http://localhost:8080"},
		// All digits
		{"https://ttl.space/0000000000", "0000000000", "https://ttl.space"},
		// All uppercase
		{"https://ttl.space/ABCDEFGHIJ", "ABCDEFGHIJ", "https://ttl.space"},
		// All lowercase
		{"https://ttl.space/abcdefghij", "abcdefghij", "https://ttl.space"},
		// Mixed
		{"https://ttl.space/aB3dEf7hIj", "aB3dEf7hIj", "https://ttl.space"},
		// IP address host
		{"https://192.168.1.1:8080/aBcDeFgHiJ", "aBcDeFgHiJ", "https://192.168.1.1:8080"},
		// HTTP (not HTTPS)
		{"http://ttl.space/aBcDeFgHiJ", "aBcDeFgHiJ", "http://ttl.space"},
	}

	for _, tc := range validURLs {
		t.Run(tc.url, func(t *testing.T) {
			token, base, err := parseURL(tc.url)
			if err != nil {
				t.Fatalf("parseURL(%q) error: %v", tc.url, err)
			}
			if token != tc.wantToken {
				t.Fatalf("token = %q, want %q", token, tc.wantToken)
			}
			if base != tc.wantBase {
				t.Fatalf("base = %q, want %q", base, tc.wantBase)
			}
		})
	}
}

// --- HTTP error handling ---

// TestAttack_HandleHTTPError_MaliciousResponses sends bad responses and checks that errors are clean.
func TestAttack_HandleHTTPError_MaliciousResponses(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		body       string
		expectErr  bool
	}{
		{"404 valid JSON", 404, `{"detail":"Not found"}`, true},
		{"500 valid JSON", 500, `{"detail":"Internal error"}`, true},
		{"500 no detail", 500, `{"error":"something"}`, true},
		{"500 empty body", 500, "", true},
		{"500 garbage", 500, "not json at all", true},
		{"500 huge body", 500, `{"detail":"` + strings.Repeat("A", 10000) + `"}`, true},
		// XSS attempt
		{"500 XSS attempt", 500, `{"detail":"<script>alert(1)</script>"}`, true},
		// Control characters
		{"500 control chars", 500, `{"detail":"evil\nheader: injected\r\nmore: stuff"}`, true},
		// Null bytes
		{"500 null bytes", 500, `{"detail":"evil\u0000null"}`, true},
		// Nested object
		{"500 nested JSON", 500, `{"detail":{"nested":"object"}}`, true},
		// Array instead of string
		{"500 array detail", 500, `{"detail":["a","b"]}`, true},
		// Unusual status code
		{"599 edge status", 599, `{"detail":"edge"}`, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			resp, err := http.Get(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			handlerErr := handleHTTPError(resp)
			if tc.expectErr && handlerErr == nil {
				t.Fatal("expected error")
			}
			if handlerErr != nil {
				errMsg := handlerErr.Error()
				// Check that no control chars leaked into the error message
				for _, r := range errMsg {
					if r < 0x20 && r != 0 {
						t.Fatalf("control char U+%04X in error message: %q", r, errMsg)
					}
				}
			}
		})
	}
}

// TestAttack_HandleHTTPError_LargeBody sends a 1 MB body and checks that the 4 KB limit holds.
func TestAttack_HandleHTTPError_LargeBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		// Send 1 MB of JSON
		w.Write([]byte(`{"detail":"`))
		w.Write(bytes.Repeat([]byte("A"), 1<<20))
		w.Write([]byte(`"}`))
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Must not run out of memory thanks to the 4 KB limit
	handlerErr := handleHTTPError(resp)
	if handlerErr == nil {
		t.Fatal("expected error")
	}
}

// --- Malicious server responses ---

// TestAttack_RunSend_MaliciousServerResponses sends files to servers that return bad responses.
func TestAttack_RunSend_MaliciousServerResponses(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		wantErr bool
	}{
		{
			"server returns 201 with XSS in link",
			func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				w.WriteHeader(201)
				json.NewEncoder(w).Encode(map[string]any{
					"link": "<script>alert(1)</script>",
				})
			},
			false, // link goes to stdout, not rendered as HTML
		},
		{
			"server returns 201 with control chars in link",
			func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				w.WriteHeader(201)
				json.NewEncoder(w).Encode(map[string]any{
					"link": "https://evil.com/\nX-Injected: true",
				})
			},
			false, // control chars are stripped before printing
		},
		{
			"server returns 201 with extremely long link",
			func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				w.WriteHeader(201)
				json.NewEncoder(w).Encode(map[string]any{
					"link": "https://ttl.space/" + strings.Repeat("A", 100000),
				})
			},
			true, // exceeds the 4 KB LimitReader on response parsing
		},
		{
			"server returns 413",
			func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				w.WriteHeader(413)
				json.NewEncoder(w).Encode(map[string]any{
					"detail": "File too large",
				})
			},
			true,
		},
		{
			"server returns 429 rate limit",
			func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				w.WriteHeader(429)
				json.NewEncoder(w).Encode(map[string]any{
					"detail": "Too many requests",
				})
			},
			true,
		},
		{
			"server hangs then closes",
			func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				// Drop the connection
				hj, ok := w.(http.Hijacker)
				if ok {
					conn, _, _ := hj.Hijack()
					conn.Close()
				}
			},
			true,
		},
		{
			"server returns empty 201",
			func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				w.WriteHeader(201)
			},
			true,
		},
		{
			"server returns 201 with null link",
			func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				w.WriteHeader(201)
				w.Write([]byte(`{"link":null}`))
			},
			true,
		},
		{
			"server returns 201 with integer link",
			func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				w.WriteHeader(201)
				w.Write([]byte(`{"link":12345}`))
			},
			true, // integer can't decode into a string field
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			path := filepath.Join(t.TempDir(), "test.txt")
			os.WriteFile(path, []byte("test data here!"), 0o600)

			err := runSend([]string{"-password", "12345678", "-server", srv.URL, path})
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// --- Password handling ---

// TestAttack_Password_EdgeCases tests passwords at and around the minimum length.
func TestAttack_Password_EdgeCases(t *testing.T) {
	cases := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"exactly min length", "12345678", false},
		{"one below min", "1234567", true},
		{"very long", strings.Repeat("A", 10000), false},
		{"unicode", "パスワード1234", false},        // 10 chars (4 kanji + 4 digits)
		{"only spaces", "        ", false},     // 8 spaces
		{"with null", "pass\x00word1", false},  // 9 bytes
		{"with newline", "pass\nword!", false}, // 10 bytes including newline
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				w.WriteHeader(201)
				json.NewEncoder(w).Encode(map[string]any{
					"link": "https://ttl.space/aBcDeFgHiJ",
				})
			}))
			defer srv.Close()

			path := filepath.Join(t.TempDir(), "test.txt")
			os.WriteFile(path, []byte("x"), 0o600)

			err := runSend([]string{"-password", tc.password, "-server", srv.URL, path})
			if tc.wantErr && err == nil {
				t.Fatalf("password %q should be rejected", tc.password)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("password %q should be accepted: %v", tc.password, err)
			}
		})
	}
}

// TestAttack_PasswordFile_Attacks reads passwords from files with tricky contents.
func TestAttack_PasswordFile_Attacks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{
			"link": "https://ttl.space/aBcDeFgHiJ",
		})
	}))
	defer srv.Close()

	cases := []struct {
		name    string
		content string
		wantErr bool
	}{
		{"valid password with newline", "mypassword123\n", false},
		{"valid password with CRLF", "mypassword123\r\n", false},
		{"empty file", "", true},
		{"only newline", "\n", true},
		{"too short", "short\n", true},
		{"very long password", strings.Repeat("X", 10000) + "\n", false},
		{"unicode password", "日本語パスワード!\n", false},
		{"multiple lines", "password1234\nsecond line\nthird line\n", false}, // uses first line only
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			passFile := filepath.Join(dir, "pass.txt")
			os.WriteFile(passFile, []byte(tc.content), 0o600)

			testFile := filepath.Join(dir, "data.txt")
			os.WriteFile(testFile, []byte("test data"), 0o600)

			err := runSend([]string{"-password-file", passFile, "-server", srv.URL, testFile})
			if tc.wantErr && err == nil {
				t.Fatalf("content %q should cause error", tc.content)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("content %q should succeed: %v", tc.content, err)
			}
		})
	}
}

// TestAttack_PasswordConflictingSources checks that using two password sources at once fails.
func TestAttack_PasswordConflictingSources(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{
			"link": "https://ttl.space/aBcDeFgHiJ",
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	passFile := filepath.Join(dir, "pass.txt")
	os.WriteFile(passFile, []byte("password1234\n"), 0o600)
	testFile := filepath.Join(dir, "data.txt")
	os.WriteFile(testFile, []byte("test"), 0o600)

	// -password + --password-file conflict
	err := runSend([]string{
		"-password", "password1234",
		"-password-file", passFile,
		"-server", srv.URL,
		testFile,
	})
	if err == nil {
		t.Fatal("conflicting password sources should be rejected")
	}
}

// --- TTL parsing ---

// TestAttack_TTL_ExhaustiveValid checks every allowed TTL value.
func TestAttack_TTL_ExhaustiveValid(t *testing.T) {
	for label, expected := range labelToSeconds {
		got, err := parseTTL(label)
		if err != nil {
			t.Fatalf("parseTTL(%q) error: %v", label, err)
		}
		if got != expected {
			t.Fatalf("parseTTL(%q) = %d, want %d", label, got, expected)
		}
	}
}

// TestAttack_TTL_ExhaustiveInvalid checks that all unsupported TTL strings are rejected.
func TestAttack_TTL_ExhaustiveInvalid(t *testing.T) {
	invalids := []string{
		"", "0", "1", "1m", "2m", "3m", "4m",
		"7m", "8m", "9m", "11m", "20m", "45m", "60m",
		"0h", "4h", "5h", "7h", "8h", "9h", "10h", "11h",
		"13h", "18h", "36h", "48h", "72h", "168h",
		"1s", "1w", "1y", "8d", "14d", "30d",
		"5M", "1H", "24H", // wrong case
		"-5m", "-1h",
		"5m ", " 5m", " 5m ", // whitespace
		"5min", "1hr", "1hour",
		"0x5m", "5m\x00", "5m\n",
		"300", "3600", "86400", // raw seconds, not labels
		"∞", "forever", "never",
	}

	for _, label := range invalids {
		_, err := parseTTL(label)
		if err == nil {
			t.Fatalf("parseTTL(%q) should fail", label)
		}
	}
}

// --- File size validation ---

// TestAttack_FileSizeEdgeCases checks that empty files are rejected and 1-byte files are accepted.
func TestAttack_FileSizeEdgeCases(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{
			"link": "https://ttl.space/aBcDeFgHiJ",
		})
	}))
	defer srv.Close()

	// Empty file must be rejected
	dir := t.TempDir()
	emptyFile := filepath.Join(dir, "empty.txt")
	os.WriteFile(emptyFile, []byte{}, 0o600)

	err := runSend([]string{"-password", "12345678", "-server", srv.URL, emptyFile})
	if err == nil {
		t.Fatal("empty file should be rejected")
	}
	if !strings.Contains(err.Error(), "file is empty") {
		t.Fatalf("expected 'file is empty' error, got: %v", err)
	}

	// Test with 1-byte file
	oneByteFile := filepath.Join(dir, "one.txt")
	os.WriteFile(oneByteFile, []byte{0x42}, 0o600)

	err = runSend([]string{"-password", "12345678", "-server", srv.URL, oneByteFile})
	if err != nil {
		t.Fatalf("1-byte file should be accepted: %v", err)
	}
}

// TestAttack_NonexistentFile checks that a missing file path returns an error.
func TestAttack_NonexistentFile(t *testing.T) {
	err := runSend([]string{"-password", "12345678", "/tmp/definitely_does_not_exist_12345"})
	if err == nil {
		t.Fatal("nonexistent file should cause error")
	}
}

// TestAttack_SymlinkFile checks that sending a symlink works.
func TestAttack_SymlinkFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{
			"link": "https://ttl.space/aBcDeFgHiJ",
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	realFile := filepath.Join(dir, "real.txt")
	os.WriteFile(realFile, []byte("symlink test data!!"), 0o600)
	linkFile := filepath.Join(dir, "link.txt")
	os.Symlink(realFile, linkFile)

	err := runSend([]string{"-password", "12345678", "-server", srv.URL, linkFile})
	if err != nil {
		t.Fatalf("symlink should work: %v", err)
	}
}

// TestAttack_DirectoryAsSendTarget checks that a directory is rejected.
func TestAttack_DirectoryAsSendTarget(t *testing.T) {
	dir := t.TempDir()
	err := runSend([]string{"-password", "12345678", dir})
	if err == nil {
		t.Fatal("directory as send target should cause error")
	}
}

// --- humanBytes edge cases ---

// TestAttack_HumanBytes_Boundaries checks humanBytes at exact KB/MB/GB boundaries.
func TestAttack_HumanBytes_Boundaries(t *testing.T) {
	cases := []struct {
		input    int64
		expected string
	}{
		{0, "0 B"},
		{1, "1 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1025, "1.0 KB"},
		{1048575, "1024.0 KB"},
		{1048576, "1.0 MB"},
		{1073741823, "1024.0 MB"},
		{1073741824, "1.0 GB"},
		{2147483647, "2.0 GB"},
		{2147483648, "2.0 GB"},
	}

	for _, tc := range cases {
		got := humanBytes(tc.input)
		if got != tc.expected {
			t.Fatalf("humanBytes(%d) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

// --- Password generation ---

// TestAttack_GeneratePassword_Entropy checks that at least 50 of 62 characters appear in a batch of passwords.
func TestAttack_GeneratePassword_Entropy(t *testing.T) {
	// Generate 1000 passwords and check distribution
	const n = 1000
	charCount := make(map[byte]int)

	for i := 0; i < n; i++ {
		p, err := generatePassword(8)
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != 8 {
			t.Fatalf("expected length 8, got %d", len(p))
		}
		for j := 0; j < len(p); j++ {
			charCount[p[j]]++
		}
	}

	// At least 50 of 62 characters should appear in 8000 samples
	if len(charCount) < 50 {
		t.Fatalf("only %d unique chars in %d passwords (expected at least 50)", len(charCount), n)
	}
}

// TestAttack_GeneratePassword_NoDuplicates checks that 10,000 generated passwords are all unique.
func TestAttack_GeneratePassword_NoDuplicates(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 10000; i++ {
		p, err := generatePassword(8)
		if err != nil {
			t.Fatal(err)
		}
		if seen[p] {
			t.Fatalf("duplicate password generated: %s", p)
		}
		seen[p] = true
	}
}

// --- End-to-end upload and download ---

// TestAttack_E2E_UploadDownloadRoundTrip uploads a file and checks the stored data is encrypted.
func TestAttack_E2E_UploadDownloadRoundTrip(t *testing.T) {
	// Create a mock server that stores and returns files
	store := make(map[string][]byte)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT" && r.URL.Path == "/v1/files":
			data, _ := io.ReadAll(r.Body)
			store["test"] = data
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]any{
				"link":       "https://ttl.space/aBcDeFgHiJ",
				"token":      "aBcDeFgHiJ",
				"expires_in": 3600,
				"size_bytes": len(data),
			})
		case r.Method == "GET":
			data, ok := store["test"]
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(data)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	testFile := filepath.Join(dir, "upload_test.txt")
	original := []byte("End-to-end round trip test data! This should survive.")
	os.WriteFile(testFile, original, 0o600)

	// Upload
	err := runSend([]string{"-password", "e2epassword!", "-server", srv.URL, "-t", "1h", testFile})
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}

	// Verify something was stored
	if len(store["test"]) == 0 {
		t.Fatal("nothing stored on server")
	}

	// Verify stored data is encrypted (not plaintext)
	stored := store["test"]
	if strings.Contains(string(stored), "End-to-end round trip") {
		t.Fatal("plaintext found in stored data! Encryption may have failed")
	}

	// Verify it starts with TTL magic
	if len(stored) < 4 || string(stored[:4]) != "TTL\x01" {
		t.Fatal("stored data doesn't start with TTL magic")
	}
}

// --- Random byte generation ---

// TestAttack_RandomBytes_NonDeterministic checks that 1,000 calls never return the same bytes.
func TestAttack_RandomBytes_NonDeterministic(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		b := randomBytes(16)
		key := string(b)
		if seen[key] {
			t.Fatal("randomBytes returned duplicate value!")
		}
		seen[key] = true
	}
}

// TestAttack_RandomBytes_Length checks that the returned slice has the requested length.
func TestAttack_RandomBytes_Length(t *testing.T) {
	for _, length := range []int{1, 8, 16, 24, 32, 64, 256, 1024} {
		b := randomBytes(length)
		if len(b) != length {
			t.Fatalf("randomBytes(%d) returned %d bytes", length, len(b))
		}
	}
}
