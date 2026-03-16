package main

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Orbit key validation ---

func TestValidateKeyFormat_Valid(t *testing.T) {
	key := keyPrefix + strings.Repeat("a", 48)
	if err := validateKeyFormat(key); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
}

func TestValidateKeyFormat_MixedAlnum(t *testing.T) {
	key := keyPrefix + "aB3kL9mXaB3kL9mXaB3kL9mXaB3kL9mXaB3kL9mXaB3kL9mX"
	if err := validateKeyFormat(key); err != nil {
		t.Fatalf("mixed alnum key rejected: %v", err)
	}
}

func TestValidateKeyFormat_TooShort(t *testing.T) {
	if err := validateKeyFormat(keyPrefix + "short"); err == nil {
		t.Fatal("too short key accepted")
	}
}

func TestValidateKeyFormat_TooLong(t *testing.T) {
	if err := validateKeyFormat(keyPrefix + strings.Repeat("a", 49)); err == nil {
		t.Fatal("too long key accepted")
	}
}

func TestValidateKeyFormat_WrongPrefix(t *testing.T) {
	if err := validateKeyFormat("ttl_free_" + strings.Repeat("a", 48)); err == nil {
		t.Fatal("wrong prefix accepted")
	}
}

func TestValidateKeyFormat_SpecialChars(t *testing.T) {
	if err := validateKeyFormat(keyPrefix + strings.Repeat("a", 47) + "!"); err == nil {
		t.Fatal("special char accepted")
	}
}

func TestValidateKeyFormat_Unicode(t *testing.T) {
	if err := validateKeyFormat(keyPrefix + strings.Repeat("a", 47) + "ü"); err == nil {
		t.Fatal("unicode accepted")
	}
}

func TestValidateKeyFormat_Empty(t *testing.T) {
	if err := validateKeyFormat(""); err == nil {
		t.Fatal("empty accepted")
	}
}

func TestValidateKeyFormat_OnlyPrefix(t *testing.T) {
	if err := validateKeyFormat(keyPrefix); err == nil {
		t.Fatal("prefix-only accepted")
	}
}

func TestValidateKeyFormat_Spaces(t *testing.T) {
	if err := validateKeyFormat(keyPrefix + strings.Repeat(" ", 48)); err == nil {
		t.Fatal("spaces accepted")
	}
}

func TestValidateKeyFormat_Newline(t *testing.T) {
	if err := validateKeyFormat(keyPrefix + strings.Repeat("a", 47) + "\n"); err == nil {
		t.Fatal("newline accepted")
	}
}

// --- Orbit key persistence ---

func TestSaveLoadKey_RoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("TTL_API_KEY", "")

	key := keyPrefix + strings.Repeat("x", 48)
	path, err := saveAPIKey(key)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	t.Cleanup(func() { os.Remove(path) })

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.TrimSpace(string(data)) != key {
		t.Fatalf("got %q", strings.TrimSpace(string(data)))
	}
}

func TestLoadKey_EnvWins(t *testing.T) {
	key := keyPrefix + strings.Repeat("e", 48)
	t.Setenv("TTL_API_KEY", key)

	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".ttl")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "key"), []byte(keyPrefix+strings.Repeat("f", 48)+"\n"), 0600)

	if got := loadAPIKey(); got != key {
		t.Fatalf("env should win, got %q", got)
	}
}

func TestLoadKey_HomeFallback(t *testing.T) {
	t.Setenv("TTL_API_KEY", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".ttl")
	os.MkdirAll(dir, 0700)

	key := keyPrefix + strings.Repeat("h", 48)
	os.WriteFile(filepath.Join(dir, "key"), []byte(key+"\n"), 0600)

	if got := loadAPIKey(); got != key {
		t.Fatalf("got %q", got)
	}
}

func TestLoadKey_EmptyFileSkipped(t *testing.T) {
	t.Setenv("TTL_API_KEY", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".ttl")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "key"), []byte("  \n"), 0600)

	if got := loadAPIKey(); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestLoadKey_WhitespaceTrimmed(t *testing.T) {
	key := keyPrefix + strings.Repeat("w", 48)
	t.Setenv("TTL_API_KEY", "  "+key+"  ")
	if got := loadAPIKey(); got != key {
		t.Fatalf("got %q", got)
	}
}

func TestActivate_NoArgs(t *testing.T) {
	if err := runActivate(nil); err == nil {
		t.Fatal("should fail")
	}
}

func TestActivate_TooManyArgs(t *testing.T) {
	if err := runActivate([]string{"a", "b"}); err == nil {
		t.Fatal("should fail")
	}
}

func TestActivate_InvalidKey(t *testing.T) {
	if err := runActivate([]string{"not-valid"}); err == nil {
		t.Fatal("should fail")
	}
}

func TestDeactivate_WithArgs(t *testing.T) {
	if err := runDeactivate([]string{"extra"}); err == nil {
		t.Fatal("should fail")
	}
}

func TestDeactivate_NoKeyFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := runDeactivate(nil); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

// --- ttl.password auto-detect ---

func TestPasswordPaths_BothLocations(t *testing.T) {
	paths := passwordFilePaths()
	if len(paths) < 2 {
		t.Fatalf("got %d paths", len(paths))
	}
	hasHome := false
	for _, p := range paths {
		if strings.Contains(p, ".ttl") && strings.HasSuffix(p, "password") {
			hasHome = true
		}
	}
	if !hasHome {
		t.Fatal("missing ~/.ttl/password")
	}
}

func TestPasswordFile_FromHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".ttl")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "password"), []byte("myAutoPassword123\n"), 0600)

	found := false
	for _, p := range passwordFilePaths() {
		if raw, err := os.ReadFile(p); err == nil {
			if strings.TrimSpace(string(raw)) == "myAutoPassword123" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("not detected")
	}
}

func TestPasswordFile_TooShortSkipped(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".ttl")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "password"), []byte("short\n"), 0600)

	for _, p := range passwordFilePaths() {
		if raw, err := os.ReadFile(p); err == nil {
			if pass := strings.TrimSpace(string(raw)); pass != "" && len(pass) >= 8 {
				t.Fatal("short password accepted")
			}
		}
	}
}

func TestPasswordFile_EmptySkipped(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".ttl")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "password"), []byte("  \n"), 0600)

	for _, p := range passwordFilePaths() {
		if raw, err := os.ReadFile(p); err == nil {
			if strings.TrimSpace(string(raw)) != "" {
				t.Fatal("empty file not skipped")
			}
		}
	}
}

// --- Token validation ---

func TestIsToken_ValidCases(t *testing.T) {
	for _, s := range []string{"aBcDeFgHiJ", "0123456789", "ABCDEFGHIJ", "abcdefghij"} {
		if !isToken(s) {
			t.Fatalf("%q rejected", s)
		}
	}
}

func TestIsToken_InvalidCases(t *testing.T) {
	for _, s := range []string{
		"", "short", "toolongtoken1",
		"aBcDeFgHi!", "aBcDeFgHi ",
		"aBcDe\nFgHi", "aBcDeFgH\x00J",
		"../../../x",
	} {
		if isToken(s) {
			t.Fatalf("%q accepted", s)
		}
	}
}

func TestTokenExtraction_FromURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://ttl.space/aBcDeFgHiJ", "aBcDeFgHiJ"},
		{"https://ttl.space/v1/files/aBcDeFgHiJ", "aBcDeFgHiJ"},
		{"http://localhost:8080/xK9mQ2vLpA", "xK9mQ2vLpA"},
	}
	for _, tc := range cases {
		token := tc.in
		if len(token) > 10 {
			if u, err := url.Parse(token); err == nil && u.Path != "" {
				parts := strings.Split(strings.Trim(u.Path, "/"), "/")
				if len(parts) > 0 {
					token = parts[len(parts)-1]
				}
			}
		}
		if token != tc.want {
			t.Fatalf("%q: got %q", tc.in, token)
		}
		if !isToken(token) {
			t.Fatalf("%q: invalid token", token)
		}
	}
}

func TestTokenExtraction_EmptyPath(t *testing.T) {
	token := "https://ttl.space/"
	if len(token) > 10 {
		if u, err := url.Parse(token); err == nil && u.Path != "" {
			parts := strings.Split(strings.Trim(u.Path, "/"), "/")
			if len(parts) > 0 {
				token = parts[len(parts)-1]
			}
		}
	}
	if isToken(token) {
		t.Fatal("empty path yielded valid token")
	}
}

func TestTokenExtraction_PathTraversal(t *testing.T) {
	token := "https://ttl.space/../../../etc/passwd"
	if len(token) > 10 {
		if u, err := url.Parse(token); err == nil && u.Path != "" {
			parts := strings.Split(strings.Trim(u.Path, "/"), "/")
			if len(parts) > 0 {
				token = parts[len(parts)-1]
			}
		}
	}
	if isToken(token) {
		t.Fatal("traversal yielded valid token")
	}
}
