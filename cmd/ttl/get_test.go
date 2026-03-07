package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- parseURL ---

func TestParseURL_Valid(t *testing.T) {
	cases := []struct {
		url       string
		wantToken string
		wantBase  string
	}{
		{"https://ttl.space/aBcDeFgHiJ", "aBcDeFgHiJ", "https://ttl.space"},
		{"http://localhost:8080/1234567890", "1234567890", "http://localhost:8080"},
		{"https://example.com/ABCDEFGHIJ", "ABCDEFGHIJ", "https://example.com"},
	}
	for _, tc := range cases {
		token, base, err := parseURL(tc.url)
		if err != nil {
			t.Fatalf("parseURL(%q) error: %v", tc.url, err)
		}
		if token != tc.wantToken {
			t.Fatalf("parseURL(%q) token = %q, want %q", tc.url, token, tc.wantToken)
		}
		if base != tc.wantBase {
			t.Fatalf("parseURL(%q) base = %q, want %q", tc.url, base, tc.wantBase)
		}
	}
}

func TestParseURL_InvalidScheme(t *testing.T) {
	_, _, err := parseURL("ftp://ttl.space/aBcDeFgHiJ")
	if err == nil {
		t.Fatal("expected error for ftp scheme")
	}
}

func TestParseURL_NoScheme(t *testing.T) {
	_, _, err := parseURL("ttl.space/aBcDeFgHiJ")
	if err == nil {
		t.Fatal("expected error for missing scheme")
	}
}

func TestParseURL_BadTokenLength(t *testing.T) {
	_, _, err := parseURL("https://ttl.space/short")
	if err == nil {
		t.Fatal("expected error for short token")
	}
}

func TestParseURL_BadTokenChars(t *testing.T) {
	_, _, err := parseURL("https://ttl.space/aBcD-FgHiJ")
	if err == nil {
		t.Fatal("expected error for invalid chars in token")
	}
}

func TestParseURL_TooLong(t *testing.T) {
	_, _, err := parseURL("https://ttl.space/aBcDeFgHiJK")
	if err == nil {
		t.Fatal("expected error for 11-char token")
	}
}

func TestParseURL_TrailingSlash(t *testing.T) {
	_, _, err := parseURL("https://ttl.space/aBcDeFgHiJ/")
	if err == nil {
		t.Fatal("trailing slash should invalidate the token")
	}
}

func TestParseURL_QueryString(t *testing.T) {
	token, _, err := parseURL("https://ttl.space/aBcDeFgHiJ?foo=bar")
	if err != nil {
		t.Fatal(err)
	}
	if token != "aBcDeFgHiJ" {
		t.Fatalf("expected token aBcDeFgHiJ, got %q", token)
	}
}

func TestParseURL_Fragment(t *testing.T) {
	token, _, err := parseURL("https://ttl.space/aBcDeFgHiJ#section")
	if err != nil {
		t.Fatal(err)
	}
	if token != "aBcDeFgHiJ" {
		t.Fatalf("expected token aBcDeFgHiJ, got %q", token)
	}
}

// --- resolveOutDir ---

func TestResolveOutDir_Empty(t *testing.T) {
	dir, err := resolveOutDir("")
	if err != nil {
		t.Fatal(err)
	}
	if dir != "." {
		t.Fatalf("expected '.', got %q", dir)
	}
}

func TestResolveOutDir_ValidDir(t *testing.T) {
	tmp := t.TempDir()
	dir, err := resolveOutDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if dir == "" {
		t.Fatal("expected non-empty resolved path")
	}
}

func TestResolveOutDir_NotExist(t *testing.T) {
	_, err := resolveOutDir("/nonexistent/path/does/not/exist")
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestResolveOutDir_FileNotDir(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "afile.txt")
	os.WriteFile(f, []byte("x"), 0644)
	_, err := resolveOutDir(f)
	if err == nil {
		t.Fatal("expected error when -o points to a file")
	}
}

func TestResolveOutDir_SymlinkToDir(t *testing.T) {
	tmp := t.TempDir()
	real := filepath.Join(tmp, "real")
	os.Mkdir(real, 0755)
	link := filepath.Join(tmp, "link")
	os.Symlink(real, link)

	dir, err := resolveOutDir(link)
	if err != nil {
		t.Fatalf("symlinked directory should be accepted: %v", err)
	}
	realAbs, _ := filepath.Abs(real)
	if dir != realAbs {
		t.Fatalf("expected resolved real path %q, got %q", realAbs, dir)
	}
}

func TestResolveOutDir_SymlinkToFile(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "afile.txt")
	os.WriteFile(f, []byte("x"), 0644)
	link := filepath.Join(tmp, "link")
	os.Symlink(f, link)

	_, err := resolveOutDir(link)
	if err == nil {
		t.Fatal("expected error when -o is a symlink to a file")
	}
}

func TestResolveOutDir_SymlinkDangling(t *testing.T) {
	tmp := t.TempDir()
	link := filepath.Join(tmp, "broken")
	os.Symlink("/nonexistent/target", link)

	_, err := resolveOutDir(link)
	if err == nil {
		t.Fatal("expected error for dangling symlink")
	}
}

func TestResolveOutDir_ReadOnlyDir(t *testing.T) {
	tmp := t.TempDir()
	ro := filepath.Join(tmp, "readonly")
	os.Mkdir(ro, 0555)
	t.Cleanup(func() { os.Chmod(ro, 0755) })

	_, err := resolveOutDir(ro)
	if err == nil {
		t.Fatal("expected error for read-only directory")
	}
}

// --- isToken ---

func TestIsToken(t *testing.T) {
	good := []string{"aBcDeFgHiJ", "1234567890", "ABCDEFGHIJ", "abcdefghij"}
	for _, s := range good {
		if !isToken(s) {
			t.Fatalf("expected %q to be a valid token", s)
		}
	}
	bad := []string{"", "short", "aBcDeFgHiJK", "aBcD-FgHiJ", "aBcD FgHiJ",
		"https://ttl", "aBcDeFgH\x00J"}
	for _, s := range bad {
		if isToken(s) {
			t.Fatalf("expected %q to NOT be a valid token", s)
		}
	}
}

// --- Argument validation ---

func TestCLI_Get_NoArgs(t *testing.T) {
	err := runGet(nil)
	if err == nil {
		t.Fatal("expected error for no arguments")
	}
}

func TestCLI_Get_NoURL(t *testing.T) {
	err := runGet([]string{"-p", "12345678"})
	if err == nil {
		t.Fatal("expected error when no URL or token is provided")
	}
}

func TestCLI_Get_MultipleURLs(t *testing.T) {
	err := runGet([]string{"-p", "12345678", "aBcDeFgHiJ", "zYxWvUtSrQ"})
	if err == nil {
		t.Fatal("expected error for multiple URL arguments")
	}
}

func TestCLI_Get_UnknownFlag(t *testing.T) {
	err := runGet([]string{"--nonexistent-flag", "aBcDeFgHiJ"})
	if err == nil {
		t.Fatal("unknown flag should cause an error")
	}
}

// --- Flag aliases ---

func TestCLI_Get_PasswordShortFlag(t *testing.T) {
	// Flag parsing should succeed; the error should be about the network, not
	// the password.
	err := runGet([]string{"-p", "12345678", "https://127.0.0.1:1/aBcDeFgHiJ"})
	if err == nil {
		t.Fatal("expected network error, not nil")
	}
	if strings.Contains(err.Error(), "password") {
		t.Fatalf("-p flag should be accepted, but got: %v", err)
	}
}

func TestCLI_Get_PasswordLongFlag(t *testing.T) {
	err := runGet([]string{"-password", "12345678", "https://127.0.0.1:1/aBcDeFgHiJ"})
	if err == nil {
		t.Fatal("expected network error")
	}
	if strings.Contains(err.Error(), "password") {
		t.Fatalf("-password flag should be accepted, but got: %v", err)
	}
}

func TestCLI_Get_OutputShortFlag(t *testing.T) {
	dir := t.TempDir()
	err := runGet([]string{"-p", "12345678", "-o", dir, "https://127.0.0.1:1/aBcDeFgHiJ"})
	if err == nil {
		t.Fatal("expected network error")
	}
	if strings.Contains(err.Error(), "output directory") || strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("-o flag should accept a valid directory, but got: %v", err)
	}
}

func TestCLI_Get_OutputLongFlag(t *testing.T) {
	dir := t.TempDir()
	err := runGet([]string{"-p", "12345678", "-output", dir, "https://127.0.0.1:1/aBcDeFgHiJ"})
	if err == nil {
		t.Fatal("expected network error")
	}
	if strings.Contains(err.Error(), "output directory") || strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("-output flag should accept a valid directory, but got: %v", err)
	}
}

// --- Bare token and URL routing ---

func TestCLI_Get_BareToken(t *testing.T) {
	// A 10-char alphanumeric string should be treated as a bare token and
	// expanded to https://ttl.space/TOKEN — verified without a real network call.
	// The actual network path is tested by TestCLI_Get_FullURL with 127.0.0.1:1.
	if !isToken("aBcDeFgHiJ") {
		t.Fatal("aBcDeFgHiJ should be recognised as a bare token")
	}
	expanded := "https://ttl.space/aBcDeFgHiJ"
	token, base, err := parseURL(expanded)
	if err != nil {
		t.Fatalf("expanded bare token URL should be valid: %v", err)
	}
	if token != "aBcDeFgHiJ" || base != "https://ttl.space" {
		t.Fatalf("unexpected parse result: token=%q base=%q", token, base)
	}
}

func TestCLI_Get_FullURL(t *testing.T) {
	err := runGet([]string{"-p", "12345678", "https://127.0.0.1:1/aBcDeFgHiJ"})
	if err == nil {
		t.Fatal("expected network error")
	}
	if strings.Contains(err.Error(), "invalid") && strings.Contains(err.Error(), "token") {
		t.Fatalf("full URL should be accepted, got: %v", err)
	}
}

func TestCLI_Get_InvalidToken(t *testing.T) {
	err := runGet([]string{"-p", "12345678", "short"})
	if err == nil {
		t.Fatal("short token should be rejected")
	}
}

// --- Server error handling ---

func TestCLI_Get_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]any{"detail": "Not found"})
	}))
	defer srv.Close()

	err := runGet([]string{"-p", "12345678", srv.URL + "/aBcDeFgHiJ"})
	if err == nil {
		t.Fatal("404 should cause an error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected 'not found' error, got: %v", err)
	}
}

func TestCLI_Get_500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]any{"detail": "Internal error"})
	}))
	defer srv.Close()

	err := runGet([]string{"-p", "12345678", srv.URL + "/aBcDeFgHiJ"})
	if err == nil {
		t.Fatal("500 should cause an error")
	}
	if !strings.Contains(err.Error(), "server error") {
		t.Fatalf("expected 'server error', got: %v", err)
	}
}

func TestCLI_Get_CorruptedData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("this is not encrypted data at all"))
	}))
	defer srv.Close()

	err := runGet([]string{"-p", "12345678", srv.URL + "/aBcDeFgHiJ"})
	if err == nil {
		t.Fatal("corrupted data should cause a decryption error")
	}
}

func TestCLI_Get_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	err := runGet([]string{"-p", "12345678", srv.URL + "/aBcDeFgHiJ"})
	if err == nil {
		t.Fatal("empty 200 response should cause an error")
	}
}
