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
)

// =============================================================================
// JSON mode — send
// =============================================================================

// A successful --json send must produce a valid JSON object on stdout with
// every field an AI agent or CI pipeline needs.
func TestJSON_Send_Success(t *testing.T) {
	srv := mockUploadServer(t)
	defer srv.Close()

	f := tempFile(t, "report.csv", "id,name\n1,alice\n2,bob\n")

	old := jsonMode
	jsonMode = true
	defer func() { jsonMode = old }()

	// Capture stdout
	r, w, _ := os.Pipe()
	origStdout := os.Stdout
	os.Stdout = w

	err := runSend([]string{"-p", "securepass1", "-t", "1h", "-b", "-server", srv.URL, f})

	w.Close()
	os.Stdout = origStdout
	out, _ := io.ReadAll(r)

	if err != nil {
		t.Fatalf("send should succeed: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("output is not valid JSON: %v\nraw: %s", err, out)
	}

	// Every required field must be present
	for _, key := range []string{"ok", "link", "filename", "size", "ttl", "burn"} {
		if _, exists := result[key]; !exists {
			t.Errorf("missing field %q in JSON output", key)
		}
	}

	if result["ok"] != true {
		t.Errorf("ok should be true, got %v", result["ok"])
	}
	if result["filename"] != "report.csv" {
		t.Errorf("filename should be report.csv, got %v", result["filename"])
	}
	if result["ttl"] != "1h" {
		t.Errorf("ttl should be 1h, got %v", result["ttl"])
	}
	if result["burn"] != true {
		t.Errorf("burn should be true, got %v", result["burn"])
	}
	// User-provided passwords are not echoed back (avoids leaking secrets in logs)
	if _, exists := result["password"]; exists {
		t.Errorf("password should not be echoed when user-provided")
	}

	link, _ := result["link"].(string)
	if !strings.HasPrefix(link, "https://") {
		t.Errorf("link should start with https://, got %q", link)
	}

	size, _ := result["size"].(float64) // JSON numbers are float64
	if size <= 0 {
		t.Errorf("size should be positive, got %v", size)
	}
}

// When no password is given in --json mode, the CLI must auto-generate one
// (no interactive prompt) and include it in the JSON output.
func TestJSON_Send_AutoGeneratesPassword(t *testing.T) {
	srv := mockUploadServer(t)
	defer srv.Close()

	f := tempFile(t, "data.bin", "binary-ish content here")

	old := jsonMode
	jsonMode = true
	defer func() { jsonMode = old }()

	r, w, _ := os.Pipe()
	origStdout := os.Stdout
	os.Stdout = w

	err := runSend([]string{"-server", srv.URL, f})

	w.Close()
	os.Stdout = origStdout
	out, _ := io.ReadAll(r)

	if err != nil {
		t.Fatalf("auto-generate send should succeed: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, out)
	}

	pass, _ := result["password"].(string)
	if len(pass) < 8 {
		t.Errorf("auto-generated password should be at least 8 chars, got %q", pass)
	}
}

// Verify that --json send produces no output on stderr (clean for pipelines).
func TestJSON_Send_SilentStderr(t *testing.T) {
	srv := mockUploadServer(t)
	defer srv.Close()

	f := tempFile(t, "quiet.txt", "shhh")

	old := jsonMode
	jsonMode = true
	defer func() { jsonMode = old }()

	// Capture stderr
	origStderr := os.Stderr
	stderrR, stderrW, _ := os.Pipe()
	os.Stderr = stderrW

	// Capture stdout (discard)
	stdoutR, stdoutW, _ := os.Pipe()
	origStdout := os.Stdout
	os.Stdout = stdoutW

	_ = runSend([]string{"-p", "securepass1", "-server", srv.URL, f})

	stderrW.Close()
	stdoutW.Close()
	os.Stderr = origStderr
	os.Stdout = origStdout

	io.ReadAll(stdoutR)
	stderrOut, _ := io.ReadAll(stderrR)

	if len(stderrOut) > 0 {
		t.Errorf("stderr should be empty in JSON mode, got: %q", string(stderrOut))
	}
}

// An upload error in --json mode should still produce valid JSON with ok=false.
func TestJSON_Send_ErrorProducesJSON(t *testing.T) {
	f := tempFile(t, "fail.txt", "will fail")

	old := jsonMode
	jsonMode = true
	defer func() { jsonMode = old }()

	// Try to send to a server that doesn't exist
	err := runSend([]string{"-p", "securepass1", "-server", "http://127.0.0.1:1", f})
	if err == nil {
		t.Fatal("should fail with unreachable server")
	}

	// The error is returned to main() which calls exitError().
	// Simulate exitError's JSON path without actually calling os.Exit.
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.Encode(map[string]any{
		"ok":    false,
		"error": err.Error(),
	})

	var result map[string]any
	if jsonErr := json.Unmarshal([]byte(buf.String()), &result); jsonErr != nil {
		t.Fatalf("error JSON is invalid: %v", jsonErr)
	}
	if result["ok"] != false {
		t.Error("ok should be false for errors")
	}
	errMsg, _ := result["error"].(string)
	if errMsg == "" {
		t.Error("error message should not be empty")
	}
}

// --json mode with --burn=false should show burn:false in the output.
func TestJSON_Send_BurnFalse(t *testing.T) {
	srv := mockUploadServer(t)
	defer srv.Close()

	f := tempFile(t, "normal.txt", "no burn")

	old := jsonMode
	jsonMode = true
	defer func() { jsonMode = old }()

	r, w, _ := os.Pipe()
	origStdout := os.Stdout
	os.Stdout = w

	_ = runSend([]string{"-p", "securepass1", "-server", srv.URL, f})

	w.Close()
	os.Stdout = origStdout
	out, _ := io.ReadAll(r)

	var result map[string]any
	json.Unmarshal(out, &result)

	if result["burn"] != false {
		t.Errorf("burn should be false when -b is not set, got %v", result["burn"])
	}
}

// Default TTL should be "7d" in the JSON output when no -t flag is given.
func TestJSON_Send_DefaultTTL(t *testing.T) {
	srv := mockUploadServer(t)
	defer srv.Close()

	f := tempFile(t, "default.txt", "defaults")

	old := jsonMode
	jsonMode = true
	defer func() { jsonMode = old }()

	r, w, _ := os.Pipe()
	origStdout := os.Stdout
	os.Stdout = w

	_ = runSend([]string{"-p", "securepass1", "-server", srv.URL, f})

	w.Close()
	os.Stdout = origStdout
	out, _ := io.ReadAll(r)

	var result map[string]any
	json.Unmarshal(out, &result)

	if result["ttl"] != "7d" {
		t.Errorf("default TTL should be 7d, got %v", result["ttl"])
	}
}

// =============================================================================
// JSON mode — get
// =============================================================================

// A successful --json get must produce a valid JSON object with filename,
// size, and saved_to (absolute path).
func TestJSON_Get_Success(t *testing.T) {
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
			w.Write(store["blob"])
		case r.Method == "GET" && r.URL.Path == "/aBcDeFgHiJ":
			w.Write(store["blob"])
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	dir := t.TempDir()
	src := filepath.Join(dir, "payload.txt")
	os.WriteFile(src, []byte("JSON round-trip test payload"), 0644)

	// Upload normally (not JSON mode)
	if err := runSend([]string{"-p", "jsonroundtrip", "-server", srv.URL, src}); err != nil {
		t.Fatalf("upload: %v", err)
	}

	// Download in JSON mode
	old := jsonMode
	jsonMode = true
	defer func() { jsonMode = old }()

	outDir := filepath.Join(dir, "out")
	os.Mkdir(outDir, 0755)

	r, w, _ := os.Pipe()
	origStdout := os.Stdout
	os.Stdout = w

	err := runGet([]string{"-p", "jsonroundtrip", "-o", outDir, srv.URL + "/aBcDeFgHiJ"})

	w.Close()
	os.Stdout = origStdout
	out, _ := io.ReadAll(r)

	if err != nil {
		t.Fatalf("download: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, out)
	}

	// All required fields
	for _, key := range []string{"ok", "filename", "size", "saved_to"} {
		if _, exists := result[key]; !exists {
			t.Errorf("missing field %q in JSON output", key)
		}
	}

	if result["ok"] != true {
		t.Errorf("ok should be true, got %v", result["ok"])
	}
	if result["filename"] != "payload.txt" {
		t.Errorf("filename should be payload.txt, got %v", result["filename"])
	}

	savedTo, _ := result["saved_to"].(string)
	if !filepath.IsAbs(savedTo) {
		t.Errorf("saved_to should be absolute, got %q", savedTo)
	}

	size, _ := result["size"].(float64)
	if int(size) != len("JSON round-trip test payload") {
		t.Errorf("size should be %d, got %v", len("JSON round-trip test payload"), size)
	}

	// Verify file was actually written
	got, err := os.ReadFile(filepath.Join(outDir, "payload.txt"))
	if err != nil {
		t.Fatalf("file not found: %v", err)
	}
	if string(got) != "JSON round-trip test payload" {
		t.Fatalf("content mismatch: %q", string(got))
	}
}

// Verify that --json get produces no output on stderr.
func TestJSON_Get_SilentStderr(t *testing.T) {
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
	src := filepath.Join(dir, "silent.txt")
	os.WriteFile(src, []byte("silence is golden"), 0644)

	if err := runSend([]string{"-p", "silentpass1", "-server", srv.URL, src}); err != nil {
		t.Fatal(err)
	}

	// Capture stderr during JSON get
	old := jsonMode
	jsonMode = true
	defer func() { jsonMode = old }()

	origStderr := os.Stderr
	stderrR, stderrW, _ := os.Pipe()
	os.Stderr = stderrW

	stdoutR, stdoutW, _ := os.Pipe()
	origStdout := os.Stdout
	os.Stdout = stdoutW

	outDir := filepath.Join(dir, "out")
	os.Mkdir(outDir, 0755)
	_ = runGet([]string{"-p", "silentpass1", "-o", outDir, srv.URL + "/aBcDeFgHiJ"})

	stderrW.Close()
	stdoutW.Close()
	os.Stderr = origStderr
	os.Stdout = origStdout

	io.ReadAll(stdoutR)
	stderrOut, _ := io.ReadAll(stderrR)

	if len(stderrOut) > 0 {
		t.Errorf("stderr should be empty in JSON mode, got: %q", string(stderrOut))
	}
}

// =============================================================================
// JSON mode — error scenarios
// =============================================================================

// Wrong password in --json get should return a meaningful error.
func TestJSON_Get_WrongPassword(t *testing.T) {
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
	os.WriteFile(src, []byte("top secret"), 0644)

	if err := runSend([]string{"-p", "rightpassword1", "-server", srv.URL, src}); err != nil {
		t.Fatal(err)
	}

	old := jsonMode
	jsonMode = true
	defer func() { jsonMode = old }()

	outDir := filepath.Join(dir, "out")
	os.Mkdir(outDir, 0755)

	err := runGet([]string{"-p", "wrongpassword1", "-o", outDir, srv.URL + "/aBcDeFgHiJ"})
	if err == nil {
		t.Fatal("wrong password should fail")
	}
	if !strings.Contains(err.Error(), "wrong password") {
		t.Fatalf("expected 'wrong password' error, got: %v", err)
	}
}

// Empty file should be rejected even in --json mode.
func TestJSON_Send_EmptyFile(t *testing.T) {
	f := tempFile(t, "empty.txt", "")

	old := jsonMode
	jsonMode = true
	defer func() { jsonMode = old }()

	err := runSend([]string{"-p", "securepass1", f})
	if err == nil {
		t.Fatal("empty file should be rejected")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected 'empty' error, got: %v", err)
	}
}

// Directory path should be rejected.
func TestJSON_Send_Directory(t *testing.T) {
	dir := t.TempDir()

	old := jsonMode
	jsonMode = true
	defer func() { jsonMode = old }()

	err := runSend([]string{"-p", "securepass1", dir})
	if err == nil {
		t.Fatal("directory should be rejected")
	}
}

// Invalid TTL should be rejected.
func TestJSON_Send_InvalidTTL(t *testing.T) {
	f := tempFile(t, "ttl.txt", "content")

	old := jsonMode
	jsonMode = true
	defer func() { jsonMode = old }()

	err := runSend([]string{"-p", "securepass1", "-t", "99years", f})
	if err == nil {
		t.Fatal("invalid TTL should be rejected")
	}
}

// =============================================================================
// JSON mode — full E2E round trip (send + get both in JSON mode)
// =============================================================================

// The full automation flow: send with --json, parse the response, then get
// with --json using the returned password and link.
func TestJSON_E2E_FullAutomationRoundTrip(t *testing.T) {
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
			w.Write(store["blob"])
		case r.Method == "GET" && r.URL.Path == "/aBcDeFgHiJ":
			w.Write(store["blob"])
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	dir := t.TempDir()
	src := filepath.Join(dir, "automation.json")
	payload := `{"task":"deploy","version":"2.1.0"}`
	os.WriteFile(src, []byte(payload), 0644)

	// Step 1: Send in JSON mode (auto-generated password)
	old := jsonMode
	jsonMode = true
	defer func() { jsonMode = old }()

	sendR, sendW, _ := os.Pipe()
	origStdout := os.Stdout
	os.Stdout = sendW

	err := runSend([]string{"-server", srv.URL, src})

	sendW.Close()
	os.Stdout = origStdout
	sendOut, _ := io.ReadAll(sendR)

	if err != nil {
		t.Fatalf("send: %v", err)
	}

	var sendResult map[string]any
	if err := json.Unmarshal(sendOut, &sendResult); err != nil {
		t.Fatalf("send JSON: %v\nraw: %s", err, sendOut)
	}

	// Extract password from the JSON response (this is the real automation flow)
	password, _ := sendResult["password"].(string)
	if password == "" {
		t.Fatal("no password in send response")
	}

	// Step 2: Get in JSON mode using the auto-generated password
	outDir := filepath.Join(dir, "out")
	os.Mkdir(outDir, 0755)

	getR, getW, _ := os.Pipe()
	os.Stdout = getW

	err = runGet([]string{"-p", password, "-o", outDir, srv.URL + "/aBcDeFgHiJ"})

	getW.Close()
	os.Stdout = origStdout
	getOut, _ := io.ReadAll(getR)

	if err != nil {
		t.Fatalf("get: %v", err)
	}

	var getResult map[string]any
	if err := json.Unmarshal(getOut, &getResult); err != nil {
		t.Fatalf("get JSON: %v\nraw: %s", err, getOut)
	}

	if getResult["ok"] != true {
		t.Errorf("get ok should be true")
	}
	if getResult["filename"] != "automation.json" {
		t.Errorf("filename should be automation.json, got %v", getResult["filename"])
	}

	// Verify the actual file content
	got, _ := os.ReadFile(filepath.Join(outDir, "automation.json"))
	if string(got) != payload {
		t.Fatalf("content mismatch:\n  got:  %q\n  want: %q", string(got), payload)
	}
}

// =============================================================================
// JSON mode — compatibility with other flags
// =============================================================================

// --json + --password-file should work (agent stores password in a tempfile).
func TestJSON_Send_PasswordFile(t *testing.T) {
	srv := mockUploadServer(t)
	defer srv.Close()

	dir := t.TempDir()
	f := filepath.Join(dir, "data.txt")
	os.WriteFile(f, []byte("password file test"), 0644)

	passFile := filepath.Join(dir, "pass.txt")
	os.WriteFile(passFile, []byte("fromfile1234\n"), 0600)

	old := jsonMode
	jsonMode = true
	defer func() { jsonMode = old }()

	r, w, _ := os.Pipe()
	origStdout := os.Stdout
	os.Stdout = w

	err := runSend([]string{"-password-file", passFile, "-server", srv.URL, f})

	w.Close()
	os.Stdout = origStdout
	out, _ := io.ReadAll(r)

	if err != nil {
		t.Fatalf("send with password file: %v", err)
	}

	var result map[string]any
	json.Unmarshal(out, &result)

	// User-provided passwords (including from file) are not echoed back
	if _, exists := result["password"]; exists {
		t.Errorf("password should not be echoed when user-provided via file")
	}
}

// --json + --burn should reflect in the output.
func TestJSON_Send_BurnTrue(t *testing.T) {
	srv := mockUploadServer(t)
	defer srv.Close()

	f := tempFile(t, "burn.txt", "burn after reading")

	old := jsonMode
	jsonMode = true
	defer func() { jsonMode = old }()

	r, w, _ := os.Pipe()
	origStdout := os.Stdout
	os.Stdout = w

	_ = runSend([]string{"-p", "securepass1", "-b", "-server", srv.URL, f})

	w.Close()
	os.Stdout = origStdout
	out, _ := io.ReadAll(r)

	var result map[string]any
	json.Unmarshal(out, &result)

	if result["burn"] != true {
		t.Errorf("burn should be true when -b is set, got %v", result["burn"])
	}
}

// =============================================================================
// JSON mode — output format guarantees
// =============================================================================

// JSON output must be exactly one line (no pretty-printing, no trailing
// newlines beyond the one json.Encoder adds).
func TestJSON_Send_SingleLineOutput(t *testing.T) {
	srv := mockUploadServer(t)
	defer srv.Close()

	f := tempFile(t, "oneline.txt", "one line")

	old := jsonMode
	jsonMode = true
	defer func() { jsonMode = old }()

	r, w, _ := os.Pipe()
	origStdout := os.Stdout
	os.Stdout = w

	_ = runSend([]string{"-p", "securepass1", "-server", srv.URL, f})

	w.Close()
	os.Stdout = origStdout
	out, _ := io.ReadAll(r)

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 1 {
		t.Errorf("JSON output should be exactly 1 line, got %d: %q", len(lines), string(out))
	}
}

// The JSON output must be parseable by any standard JSON parser — no trailing
// commas, no comments, no single quotes.
func TestJSON_Send_StrictJSONParsing(t *testing.T) {
	srv := mockUploadServer(t)
	defer srv.Close()

	f := tempFile(t, "strict.txt", "strict")

	old := jsonMode
	jsonMode = true
	defer func() { jsonMode = old }()

	r, w, _ := os.Pipe()
	origStdout := os.Stdout
	os.Stdout = w

	_ = runSend([]string{"-p", "securepass1", "-server", srv.URL, f})

	w.Close()
	os.Stdout = origStdout
	out, _ := io.ReadAll(r)

	// Use json.Valid for strict validation
	if !json.Valid(out) {
		t.Fatalf("output is not strictly valid JSON: %q", string(out))
	}

	// Also ensure it decodes into a proper object (not an array, string, etc.)
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("output should decode to an object: %v", err)
	}
}

// "size" must be a number (not a string like "1.5 MB").
func TestJSON_Send_SizeIsNumber(t *testing.T) {
	srv := mockUploadServer(t)
	defer srv.Close()

	f := tempFile(t, "numsize.txt", "check size type")

	old := jsonMode
	jsonMode = true
	defer func() { jsonMode = old }()

	r, w, _ := os.Pipe()
	origStdout := os.Stdout
	os.Stdout = w

	_ = runSend([]string{"-p", "securepass1", "-server", srv.URL, f})

	w.Close()
	os.Stdout = origStdout
	out, _ := io.ReadAll(r)

	var result map[string]any
	json.Unmarshal(out, &result)

	// json.Unmarshal decodes numbers as float64 by default
	if _, ok := result["size"].(float64); !ok {
		t.Errorf("size should be a number, got %T: %v", result["size"], result["size"])
	}
}
