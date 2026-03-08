package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- humanBytes ---

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		input    int64
		expected string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1572864, "1.5 MB"},
		{1073741824, "1.0 GB"},
		{2147483648, "2.0 GB"},
	}
	for _, tc := range cases {
		got := humanBytes(tc.input)
		if got != tc.expected {
			t.Fatalf("humanBytes(%d) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

// --- Malformed 201 responses ---

func TestRunSend_RejectsMalformed201_MissingLink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"token":"abc"}`))
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "x.txt")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runSend([]string{"-password", "12345678", "-server", srv.URL, path})
	if err == nil {
		t.Fatal("expected error for 201 response with missing link")
	}
}

func TestRunSend_RejectsMalformed201_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "x.txt")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runSend([]string{"-password", "12345678", "-server", srv.URL, path})
	if err == nil {
		t.Fatal("expected error for 201 response with bad JSON")
	}
}

// --- Argument validation ---

func TestCLI_Send_NoArgs(t *testing.T) {
	err := runSend(nil)
	if err == nil {
		t.Fatal("expected error for no arguments")
	}
}

func TestCLI_Send_NoFile(t *testing.T) {
	err := runSend([]string{"-password", "12345678"})
	if err == nil {
		t.Fatal("expected error when no file is provided")
	}
}

func TestCLI_Send_MultipleFiles(t *testing.T) {
	f1 := tempFile(t, "a.txt", "aaa")
	f2 := tempFile(t, "b.txt", "bbb")
	err := runSend([]string{"-password", "12345678", f1, f2})
	if err == nil {
		t.Fatal("expected error for multiple file arguments")
	}
}

func TestCLI_Send_UnknownFlag(t *testing.T) {
	f := tempFile(t, "x.txt", "data")
	err := runSend([]string{"--nonexistent-flag", f})
	if err == nil {
		t.Fatal("unknown flag should cause an error")
	}
}

// --- Flag aliases ---

func TestCLI_Send_PasswordShortFlag(t *testing.T) {
	srv := mockUploadServer(t)
	defer srv.Close()
	f := tempFile(t, "x.txt", "hello world!")
	if err := runSend([]string{"-p", "12345678", "-server", srv.URL, f}); err != nil {
		t.Fatalf("short -p flag should work: %v", err)
	}
}

func TestCLI_Send_PasswordLongFlag(t *testing.T) {
	srv := mockUploadServer(t)
	defer srv.Close()
	f := tempFile(t, "x.txt", "hello world!")
	if err := runSend([]string{"-password", "12345678", "-server", srv.URL, f}); err != nil {
		t.Fatalf("long -password flag should work: %v", err)
	}
}

func TestCLI_Send_TTL_ShortFlag(t *testing.T) {
	srv := mockUploadServer(t)
	defer srv.Close()
	f := tempFile(t, "x.txt", "data")
	if err := runSend([]string{"-p", "12345678", "-t", "5m", "-server", srv.URL, f}); err != nil {
		t.Fatalf("-t flag should work: %v", err)
	}
}

func TestCLI_Send_TTL_LongFlag(t *testing.T) {
	srv := mockUploadServer(t)
	defer srv.Close()
	f := tempFile(t, "x.txt", "data")
	if err := runSend([]string{"-p", "12345678", "-ttl", "1h", "-server", srv.URL, f}); err != nil {
		t.Fatalf("-ttl flag should work: %v", err)
	}
}

// --- Password file edge cases ---

func TestCLI_Send_PasswordFileNonexistent(t *testing.T) {
	f := tempFile(t, "x.txt", "data")
	err := runSend([]string{"-password-file", "/tmp/no_such_pass_file_999", f})
	if err == nil {
		t.Fatal("nonexistent password file should be rejected")
	}
}

func TestCLI_Send_ConflictPasswordStdinAndFlag(t *testing.T) {
	f := tempFile(t, "x.txt", "data")
	err := runSend([]string{"-p", "mypassword123", "-password-stdin", f})
	if err == nil {
		t.Fatal("conflicting -p and --password-stdin should be rejected")
	}
}

// --- Burn flag ---

func TestCLI_Send_Burn_ShortFlag(t *testing.T) {
	var gotBurn string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBurn = r.Header.Get("X-Burn-After-Reading")
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"link": "https://ttl.space/aBcDeFgHiJ"})
	}))
	defer srv.Close()

	f := tempFile(t, "x.txt", "data")
	if err := runSend([]string{"-p", "12345678", "-b", "-server", srv.URL, f}); err != nil {
		t.Fatalf("-b flag should work: %v", err)
	}
	if gotBurn != "true" {
		t.Fatalf("expected X-Burn-After-Reading=true, got %q", gotBurn)
	}
}

func TestCLI_Send_Burn_LongFlag(t *testing.T) {
	var gotBurn string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBurn = r.Header.Get("X-Burn-After-Reading")
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"link": "https://ttl.space/aBcDeFgHiJ"})
	}))
	defer srv.Close()

	f := tempFile(t, "x.txt", "data")
	if err := runSend([]string{"-p", "12345678", "-burn", "-server", srv.URL, f}); err != nil {
		t.Fatalf("-burn flag should work: %v", err)
	}
	if gotBurn != "true" {
		t.Fatalf("expected X-Burn-After-Reading=true, got %q", gotBurn)
	}
}

func TestCLI_Send_NoBurn_HeaderAbsent(t *testing.T) {
	var gotBurn string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBurn = r.Header.Get("X-Burn-After-Reading")
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"link": "https://ttl.space/aBcDeFgHiJ"})
	}))
	defer srv.Close()

	f := tempFile(t, "x.txt", "data")
	if err := runSend([]string{"-p", "12345678", "-server", srv.URL, f}); err != nil {
		t.Fatal(err)
	}
	if gotBurn != "" {
		t.Fatalf("X-Burn-After-Reading should be absent without -b, got %q", gotBurn)
	}
}

// --- TTL and server headers ---

func TestCLI_Send_TTL_HeaderSent(t *testing.T) {
	var gotTTL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTTL = r.Header.Get("X-TTL")
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"link": "https://ttl.space/aBcDeFgHiJ"})
	}))
	defer srv.Close()

	f := tempFile(t, "x.txt", "data")
	if err := runSend([]string{"-p", "12345678", "-t", "5m", "-server", srv.URL, f}); err != nil {
		t.Fatal(err)
	}
	if gotTTL != "300" {
		t.Fatalf("expected X-TTL=300, got %q", gotTTL)
	}
}

func TestCLI_Send_TTL_DefaultIs7d(t *testing.T) {
	var gotTTL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTTL = r.Header.Get("X-TTL")
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"link": "https://ttl.space/aBcDeFgHiJ"})
	}))
	defer srv.Close()

	f := tempFile(t, "x.txt", "data")
	if err := runSend([]string{"-p", "12345678", "-server", srv.URL, f}); err != nil {
		t.Fatal(err)
	}
	if gotTTL != "604800" {
		t.Fatalf("expected default X-TTL=604800 (7d), got %q", gotTTL)
	}
}

func TestCLI_Send_ContentTypeAndLength(t *testing.T) {
	var gotCT string
	var gotCL int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		gotCL = r.ContentLength
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"link": "https://ttl.space/aBcDeFgHiJ"})
	}))
	defer srv.Close()

	f := tempFile(t, "x.txt", "hello")
	if err := runSend([]string{"-p", "12345678", "-server", srv.URL, f}); err != nil {
		t.Fatal(err)
	}
	if gotCT != "application/octet-stream" {
		t.Fatalf("expected Content-Type application/octet-stream, got %q", gotCT)
	}
	if gotCL <= 0 {
		t.Fatalf("expected positive Content-Length, got %d", gotCL)
	}
}

// --- Server flag and upload path ---

func TestCLI_Send_ServerFlag(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"link": "https://ttl.space/aBcDeFgHiJ"})
	}))
	defer srv.Close()

	f := tempFile(t, "x.txt", "data")
	if err := runSend([]string{"-p", "12345678", "-server", srv.URL, f}); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/files" {
		t.Fatalf("expected PUT to /v1/files, got %q", gotPath)
	}
}

func TestCLI_Send_ServerFlag_InvalidURL(t *testing.T) {
	f := tempFile(t, "x.txt", "data")
	err := runSend([]string{"-p", "12345678", "-server", "not://valid\x00url", f})
	if err == nil {
		t.Fatal("invalid server URL should cause an error")
	}
}

// --- Timeout flag ---

func TestCLI_Send_TimeoutFlag(t *testing.T) {
	srv := mockUploadServer(t)
	defer srv.Close()
	f := tempFile(t, "x.txt", "data")
	if err := runSend([]string{"-p", "12345678", "-timeout", "10m", "-server", srv.URL, f}); err != nil {
		t.Fatalf("--timeout 10m should work: %v", err)
	}
}

// --- Dangling symlink ---

func TestCLI_Send_DanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "broken.txt")
	os.Symlink("/nonexistent/target/file", link)

	err := runSend([]string{"-p", "12345678", link})
	if err == nil {
		t.Fatal("dangling symlink should cause an error")
	}
}

// --- resolveTimeout ---

func TestResolveTimeout_Custom(t *testing.T) {
	if d := resolveTimeout("5m", 1000); d != 5*time.Minute {
		t.Fatalf("expected 5m, got %v", d)
	}
}

func TestResolveTimeout_CustomHour(t *testing.T) {
	if d := resolveTimeout("1h", 1000); d != time.Hour {
		t.Fatalf("expected 1h, got %v", d)
	}
}

func TestResolveTimeout_Auto_Empty(t *testing.T) {
	if d := resolveTimeout("", 0); d < 5*time.Minute {
		t.Fatalf("auto minimum should be 5m, got %v", d)
	}
}

func TestResolveTimeout_Auto_Keyword(t *testing.T) {
	if d := resolveTimeout("auto", 0); d < 5*time.Minute {
		t.Fatalf("auto minimum should be 5m, got %v", d)
	}
}

func TestResolveTimeout_Auto_LargeFile(t *testing.T) {
	// 100 MB at 1 Mbps = ~838 s + 120 s buffer = ~16 min.
	if d := resolveTimeout("", 100*1024*1024); d < 15*time.Minute {
		t.Fatalf("100 MB file should have timeout > 15m, got %v", d)
	}
}

func TestResolveTimeout_Invalid(t *testing.T) {
	if d := resolveTimeout("notaduration", 1000); d < 5*time.Minute {
		t.Fatalf("invalid value should fall back to auto (min 5m), got %v", d)
	}
}

func TestResolveTimeout_Negative(t *testing.T) {
	if d := resolveTimeout("-5m", 1000); d < 5*time.Minute {
		t.Fatalf("negative value should fall back to auto, got %v", d)
	}
}

func TestResolveTimeout_Zero(t *testing.T) {
	if d := resolveTimeout("0s", 1000); d < 5*time.Minute {
		t.Fatalf("zero value should fall back to auto, got %v", d)
	}
}

// --- resolvePassword ---

func TestResolvePassword_FlagOnly(t *testing.T) {
	pass, generated, err := resolvePassword("mypassword123", false, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if pass != "mypassword123" {
		t.Fatalf("expected mypassword123, got %q", pass)
	}
	if generated {
		t.Fatal("should not be marked as generated")
	}
}

func TestResolvePassword_FileOnly(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "pass.txt")
	os.WriteFile(f, []byte("longpassword1\n"), 0600)

	pass, _, err := resolvePassword("", false, f, false)
	if err != nil {
		t.Fatal(err)
	}
	if pass != "longpassword1" {
		t.Fatalf("expected longpassword1, got %q", pass)
	}
}

// Three password sources at once should be rejected.
func TestResolvePassword_ThreeSources(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "pass.txt")
	os.WriteFile(f, []byte("pass12345678\n"), 0600)

	_, _, err := resolvePassword("pass12345678", true, f, false)
	if err == nil {
		t.Fatal("three password sources at once should be rejected")
	}
}

// Seven Unicode runes should be rejected even though the byte length exceeds 8.
func TestResolvePassword_UnicodeUnder8Runes(t *testing.T) {
	pass := "パスワード12" // 5 kanji + 2 digits = 7 runes
	_, _, err := resolvePassword(pass, false, "", false)
	if err == nil {
		t.Fatal("7-rune Unicode password should be rejected")
	}
}

// --- End-to-end round trip ---

func TestCLI_E2E_SendGetRoundTrip(t *testing.T) {
	store := make(map[string][]byte)
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT" && r.URL.Path == "/v1/files":
			data, _ := io.ReadAll(r.Body)
			store["blob"] = data
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]any{"link": srvURL + "/aBcDeFgHiJ"})
		case r.Method == "GET" && r.URL.Path == "/v1/probe/aBcDeFgHiJ":
			data, ok := store["blob"]
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Write(data) // small test files — entire blob is fine for probe
		case r.Method == "GET" && r.URL.Path == "/aBcDeFgHiJ":
			data, ok := store["blob"]
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(data)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	dir := t.TempDir()
	src := filepath.Join(dir, "roundtrip.txt")
	content := "Round-trip test content for brutal testing!"
	os.WriteFile(src, []byte(content), 0644)

	if err := runSend([]string{"-p", "brutaltestpw", "-server", srv.URL, src}); err != nil {
		t.Fatalf("upload failed: %v", err)
	}

	outDir := filepath.Join(dir, "out")
	os.Mkdir(outDir, 0755)

	if err := runGet([]string{"-p", "brutaltestpw", "-o", outDir, srv.URL + "/aBcDeFgHiJ"}); err != nil {
		t.Fatalf("download failed: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(outDir, "roundtrip.txt"))
	if err != nil {
		t.Fatalf("downloaded file not found: %v", err)
	}
	if string(got) != content {
		t.Fatalf("content mismatch:\n  got:  %q\n  want: %q", string(got), content)
	}
}

func TestCLI_E2E_WrongPassword(t *testing.T) {
	store := make(map[string][]byte)
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT":
			data, _ := io.ReadAll(r.Body)
			store["blob"] = data
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]any{"link": srvURL + "/aBcDeFgHiJ"})
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/probe/"):
			w.Write(store["blob"])
		case r.Method == "GET":
			w.Write(store["blob"])
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	dir := t.TempDir()
	src := filepath.Join(dir, "secret.txt")
	os.WriteFile(src, []byte("secret stuff!!"), 0644)

	if err := runSend([]string{"-p", "correctpassword", "-server", srv.URL, src}); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(dir, "out")
	os.Mkdir(outDir, 0755)
	err := runGet([]string{"-p", "wrongpassword!", "-o", outDir, srv.URL + "/aBcDeFgHiJ"})
	if err == nil {
		t.Fatal("wrong password should fail decryption")
	}
	if !strings.Contains(err.Error(), "wrong password") {
		t.Fatalf("expected 'wrong password' error, got: %v", err)
	}
}

func TestCLI_E2E_AutoRename(t *testing.T) {
	store := make(map[string][]byte)
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT":
			data, _ := io.ReadAll(r.Body)
			store["blob"] = data
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]any{"link": srvURL + "/aBcDeFgHiJ"})
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/probe/"):
			w.Write(store["blob"])
		case r.Method == "GET":
			w.Write(store["blob"])
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	dir := t.TempDir()
	src := filepath.Join(dir, "doc.txt")
	os.WriteFile(src, []byte("the real content"), 0644)

	if err := runSend([]string{"-p", "brutaltestpw", "-server", srv.URL, src}); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(dir, "out")
	os.Mkdir(outDir, 0755)

	// Place a conflicting file so auto-rename kicks in.
	os.WriteFile(filepath.Join(outDir, "doc.txt"), []byte("existing"), 0644)

	if err := runGet([]string{"-p", "brutaltestpw", "-o", outDir, srv.URL + "/aBcDeFgHiJ"}); err != nil {
		t.Fatalf("auto-rename download should succeed: %v", err)
	}

	orig, _ := os.ReadFile(filepath.Join(outDir, "doc.txt"))
	if string(orig) != "existing" {
		t.Fatal("original file was overwritten")
	}

	renamed, err := os.ReadFile(filepath.Join(outDir, "doc (1).txt"))
	if err != nil {
		t.Fatal("renamed file not found")
	}
	if string(renamed) != "the real content" {
		t.Fatalf("renamed file has wrong content: %q", string(renamed))
	}
}
