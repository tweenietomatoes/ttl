package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func orbitEnv(t *testing.T) string {
	t.Helper()
	key := keyPrefix + strings.Repeat("o", 48)
	t.Setenv("TTL_API_KEY", key)
	t.Setenv("HOME", t.TempDir())
	return key
}

func mockFiles(n int) []listedFile {
	files := make([]listedFile, n)
	for i := range files {
		tok := fmt.Sprintf("tok%07d", i)
		files[i] = listedFile{
			Token: tok, Link: "https://ttl.space/" + tok, SizeBytes: int64(1000 + i),
			CreatedAt: int64(1_700_000_000 - i), ExpiresAt: int64(1_700_600_000 - i),
			IsNote: i%2 == 1,
		}
	}
	return files
}

func TestList_WalksEveryPage(t *testing.T) {
	orbitEnv(t)
	m := newMockAPI(t)
	m.plan = "orbit"
	m.files = mockFiles(45)

	var out []byte
	var err error
	withJSON(t, func() {
		out = captureStdout(t, func() { err = runList([]string{"-server", m.URL}) })
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var res struct {
		OK      bool         `json:"ok"`
		Files   []listedFile `json:"files"`
		HasMore bool         `json:"has_more"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("invalid JSON %q: %v", out, err)
	}
	if len(res.Files) != 45 || res.HasMore {
		t.Fatalf("files=%d has_more=%v, want 45/false", len(res.Files), res.HasMore)
	}
	if len(m.listCursors) != 3 || m.listCursors[0] != "" || m.listCursors[1] == "" {
		t.Fatalf("cursors seen = %v", m.listCursors)
	}
	if !res.Files[1].IsNote || res.Files[0].IsNote {
		t.Fatal("is_note not carried through")
	}
}

func TestList_LimitStopsEarly(t *testing.T) {
	orbitEnv(t)
	m := newMockAPI(t)
	m.plan = "orbit"
	m.files = mockFiles(45)

	var out []byte
	var err error
	withJSON(t, func() {
		out = captureStdout(t, func() { err = runList([]string{"-n", "5", "-server", m.URL}) })
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var res struct {
		Files   []listedFile `json:"files"`
		HasMore bool         `json:"has_more"`
	}
	json.Unmarshal(out, &res)
	if len(res.Files) != 5 || !res.HasMore {
		t.Fatalf("files=%d has_more=%v, want 5/true", len(res.Files), res.HasMore)
	}
	if len(m.listCursors) != 1 {
		t.Fatalf("-n 5 should need one page, got %d requests", len(m.listCursors))
	}
}

func TestList_EmptyIsAnArray(t *testing.T) {
	orbitEnv(t)
	m := newMockAPI(t)
	m.plan = "orbit"
	var out []byte
	withJSON(t, func() {
		out = captureStdout(t, func() { _ = runList([]string{"-server", m.URL}) })
	})
	if !strings.Contains(string(out), `"files":[]`) {
		t.Fatalf("empty list should be [] not null: %s", out)
	}
}

func TestList_RequiresKey(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	if err := runList([]string{"-server", m.URL}); err == nil || !strings.Contains(err.Error(), "ttl activate") {
		t.Fatalf("expected an activation hint, got %v", err)
	}
}

func TestIsValidCursor(t *testing.T) {
	for _, ok := range []string{"1711800600123456", "1711800600123456.aBcDeFgHiJ"} {
		if !isValidCursor(ok) {
			t.Fatalf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "1711800600123456.aBcD/FgHiJ", strings.Repeat("1", 41), "abc def"} {
		if isValidCursor(bad) {
			t.Fatalf("%q should be invalid", bad)
		}
	}
}

func TestDelete_ManageKey_SendsHeaderWithoutAPIKey(t *testing.T) {
	orbitEnv(t) // an Orbit key is configured, but -k must win and the key stay home
	m := newMockAPI(t)
	if err := runDelete([]string{"-k", mockManageKey, "-server", m.URL, "aBcDeFgHiJ"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if m.deleteHeaders.Get("X-Manage-Key") != mockManageKey {
		t.Fatal("X-Manage-Key not sent")
	}
	if m.deleteHeaders.Get("X-API-Key") != "" {
		t.Fatal("X-API-Key must not be sent alongside a management key")
	}
}

func TestDelete_OrbitKey_SendsAPIKey(t *testing.T) {
	key := orbitEnv(t)
	m := newMockAPI(t)
	if err := runDelete([]string{"-server", m.URL, m.URL + "/aBcDeFgHiJ"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if m.deleteHeaders.Get("X-API-Key") != key || m.deleteHeaders.Get("X-Manage-Key") != "" {
		t.Fatalf("headers = %v", m.deleteHeaders)
	}
}

func TestDelete_ManageKey_Invalid(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	err := runDelete([]string{"-k", "short", "-server", m.URL, "aBcDeFgHiJ"})
	if err == nil || !strings.Contains(err.Error(), "management key") {
		t.Fatalf("expected a key format error, got %v", err)
	}
	if m.deleteHeaders != nil {
		t.Fatal("no request must be sent for a malformed key")
	}
}

func TestDelete_NoKeys_ExplainsBoth(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	err := runDelete([]string{"-server", m.URL, "aBcDeFgHiJ"})
	if err == nil || !strings.Contains(err.Error(), "-k") || !strings.Contains(err.Error(), "ttl activate") {
		t.Fatalf("expected both options in the error, got %v", err)
	}
}

func TestDelete_ManageKey_404Message(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	m.deleteStatus = http.StatusNotFound
	err := runDelete([]string{"-k", mockManageKey, "-server", m.URL, "aBcDeFgHiJ"})
	if err == nil || !strings.Contains(err.Error(), "management key") {
		t.Fatalf("404 with -k should mention the management key, got %v", err)
	}
}

func TestDelete_403MentionsManageKey(t *testing.T) {
	orbitEnv(t)
	m := newMockAPI(t)
	m.deleteStatus = http.StatusForbidden
	err := runDelete([]string{"-server", m.URL, "aBcDeFgHiJ"})
	if err == nil || !strings.Contains(err.Error(), "management key") {
		t.Fatalf("got %v", err)
	}
}

func TestDelete_JSON(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	var out []byte
	withJSON(t, func() {
		out = captureStdout(t, func() {
			if err := runDelete([]string{"-k", mockManageKey, "-server", m.URL, "aBcDeFgHiJ"}); err != nil {
				t.Errorf("delete: %v", err)
			}
		})
	})
	if !strings.Contains(string(out), `"deleted":true`) || !strings.Contains(string(out), `"token":"aBcDeFgHiJ"`) {
		t.Fatalf("unexpected JSON: %s", out)
	}
}

func TestTokenFromArg(t *testing.T) {
	good := map[string]string{
		"aBcDeFgHiJ":                            "aBcDeFgHiJ",
		"https://ttl.space/aBcDeFgHiJ":          "aBcDeFgHiJ",
		"https://ttl.space/v1/files/aBcDeFgHiJ": "aBcDeFgHiJ",
		"http://localhost:8080/xK9mQ2vLpA":      "xK9mQ2vLpA",
		"https://ttl.space/aBcDeFgHiJ/":         "aBcDeFgHiJ",
	}
	for in, want := range good {
		got, err := tokenFromArg(in)
		if err != nil || got != want {
			t.Fatalf("tokenFromArg(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "short", "https://ttl.space/", "https://ttl.space/../../../etc/passwd", "aBcD-FgHiJ"} {
		if _, err := tokenFromArg(bad); err == nil {
			t.Fatalf("tokenFromArg(%q) should fail", bad)
		}
	}
}

func TestStatus_JSON(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	m.statusItems["aBcDeFgHiJ"] = manageStatus{
		State: "active", SizeBytes: 4096, CreatedAt: 1_700_000_000, ExpiresAt: 1_700_600_000,
		Downloads: 2, LastDownloadAt: 1_700_100_000, PartReads: 1, LastPartAt: 1_700_050_000, Burn: true,
	}
	var out []byte
	var err error
	withJSON(t, func() {
		out = captureStdout(t, func() {
			err = runStatus([]string{"-k", mockManageKey, "-server", m.URL, m.URL + "/aBcDeFgHiJ"})
		})
	})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	var res struct {
		OK     bool         `json:"ok"`
		Token  string       `json:"token"`
		Status manageStatus `json:"status"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("invalid JSON %q: %v", out, err)
	}
	if !res.OK || res.Token != "aBcDeFgHiJ" || res.Status.State != "active" || res.Status.Downloads != 2 || !res.Status.Burn {
		t.Fatalf("unexpected JSON: %s", out)
	}
	if !strings.Contains(string(m.statusBody), `"key":"`+mockManageKey+`"`) {
		t.Fatalf("request body = %s", m.statusBody)
	}
}

func TestStatus_NotFound(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	err := runStatus([]string{"-k", mockManageKey, "-server", m.URL, "aBcDeFgHiJ"})
	if err == nil || !strings.Contains(err.Error(), "Not found") {
		t.Fatalf("got %v", err)
	}
}

func TestStatus_RequiresKey(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	if err := runStatus([]string{"-server", m.URL, "aBcDeFgHiJ"}); err == nil || !strings.Contains(err.Error(), "-k") {
		t.Fatalf("got %v", err)
	}
	if err := runStatus([]string{"-k", "nope", "-server", m.URL, "aBcDeFgHiJ"}); err == nil {
		t.Fatal("malformed key accepted")
	}
	if err := runStatus([]string{"-k", mockManageKey, "-server", m.URL}); err == nil {
		t.Fatal("missing token accepted")
	}
}

func TestStatus_TTY_Prints(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	m.statusItems["aBcDeFgHiJ"] = manageStatus{State: "expired", SizeBytes: 10, CreatedAt: 1, ExpiresAt: 2}
	if err := runStatus([]string{"-k", mockManageKey, "-server", m.URL, "aBcDeFgHiJ"}); err != nil {
		t.Fatalf("status: %v", err)
	}
}

func TestActivate_RejectedKeyIsNotSaved(t *testing.T) {
	noKeys(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]any{"detail": "Invalid or expired API key"})
	}))
	defer srv.Close()
	key := keyPrefix + strings.Repeat("z", 48)
	err := runActivate([]string{"--server", srv.URL, key})
	if err == nil || !strings.Contains(err.Error(), "not saved") {
		t.Fatalf("expected a not-saved error, got %v", err)
	}
	if loadAPIKey() != "" {
		t.Fatal("rejected key was saved")
	}
}

func TestActivate_VerifiedKeyIsSaved(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	m.plan = "orbit"
	key := keyPrefix + strings.Repeat("v", 48)
	var out []byte
	var err error
	withJSON(t, func() {
		out = captureStdout(t, func() { err = runActivate([]string{"--server", m.URL, key}) })
	})
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if loadAPIKey() != key {
		t.Fatal("key not saved")
	}
	if !strings.Contains(string(out), `"activated":true`) || !strings.Contains(string(out), `"plan":"orbit"`) {
		t.Fatalf("unexpected JSON: %s", out)
	}
}

func TestActivate_UnreachableServerStillSaves(t *testing.T) {
	noKeys(t)
	key := keyPrefix + strings.Repeat("n", 48)
	if err := runActivate([]string{"--server", "http://127.0.0.1:1", key}); err != nil {
		t.Fatalf("activate without a reachable server should warn and save: %v", err)
	}
	if loadAPIKey() != key {
		t.Fatal("key not saved")
	}
}

func TestDeactivate_JSON(t *testing.T) {
	noKeys(t)
	var out []byte
	withJSON(t, func() {
		out = captureStdout(t, func() {
			if err := runDeactivate(nil); err != nil {
				t.Errorf("deactivate: %v", err)
			}
		})
	})
	if !strings.Contains(string(out), `"deactivated":true`) || !strings.Contains(string(out), `"removed":[]`) {
		t.Fatalf("unexpected JSON: %s", out)
	}
}

func TestPlan_JSON_FreeAndOrbit(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	var out []byte
	withJSON(t, func() {
		out = captureStdout(t, func() {
			if err := runPlan([]string{"-server", m.URL}); err != nil {
				t.Errorf("plan: %v", err)
			}
		})
	})
	if !strings.Contains(string(out), `"daily_bytes_quota":10737418240`) {
		t.Fatalf("free plan JSON should carry the daily quota: %s", out)
	}
	// Terminal output for both plans must not fail either.
	if err := runPlan([]string{"-server", m.URL}); err != nil {
		t.Fatalf("plan (free, tty): %v", err)
	}
	orbitEnv(t)
	m.plan = "orbit"
	if err := runPlan([]string{"-server", m.URL}); err != nil {
		t.Fatalf("plan (orbit, tty): %v", err)
	}
}

func TestFetchLimits_KeyRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]any{"detail": "Invalid or expired API key"})
	}))
	defer srv.Close()
	_, err := fetchLimits(newConn(), srv.URL, keyPrefix+strings.Repeat("x", 48))
	if !isKeyRejected(err) {
		t.Fatalf("expected a key rejection, got %v", err)
	}
	if !strings.Contains(err.Error(), "ttl activate") {
		t.Fatalf("error should tell the user what to do: %v", err)
	}
}

func TestValidateManageKey(t *testing.T) {
	if err := validateManageKey(mockManageKey); err != nil {
		t.Fatal(err)
	}
	if err := validateManageKey(strings.Repeat("a", 21) + "-_" + strings.Repeat("Z", 20)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "short", mockManageKey + "x", strings.Repeat("a", 42) + "+", strings.Repeat("a", 42) + "="} {
		if err := validateManageKey(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

// Flags may follow the positional argument, as the README and the send
// hint show them ("ttl delete TOKEN -k KEY").
func TestParseArgs_FlagsAfterPositionals(t *testing.T) {
	noKeys(t)
	m := newMockAPI(t)
	if err := runDelete([]string{"aBcDeFgHiJ", "-k", mockManageKey, "-server", m.URL}); err != nil {
		t.Fatalf("delete with trailing flags: %v", err)
	}
	if m.deleteHeaders.Get("X-Manage-Key") != mockManageKey {
		t.Fatal("trailing -k was not parsed")
	}
	m.statusItems["aBcDeFgHiJ"] = manageStatus{State: "active"}
	if err := runStatus([]string{"aBcDeFgHiJ", "-k", mockManageKey, "-server", m.URL}); err != nil {
		t.Fatalf("status with trailing flags: %v", err)
	}
	// send: "-b" after the file.
	src := tempFile(t, "x.txt", "trailing burn flag")
	if err := runSend([]string{"-p", "12345678", "-server", m.URL, src, "-b"}); err != nil {
		t.Fatalf("send with trailing -b: %v", err)
	}
	if m.lastUploadHeaders.Get("X-Burn-After-Reading") != "true" {
		t.Fatal("trailing -b was not parsed")
	}
	// "--" ends flag parsing: what follows is positional even if it looks like a flag.
	if err := runDelete([]string{"-k", mockManageKey, "-server", m.URL, "--", "-not-a-token"}); err == nil || !strings.Contains(err.Error(), "Invalid token") {
		t.Fatalf("expected an invalid-token error for the positional after --, got %v", err)
	}
	// Two positionals are still refused.
	if err := runDelete([]string{"aBcDeFgHiJ", "zYxWvUtSrQ", "-k", mockManageKey, "-server", m.URL}); err == nil {
		t.Fatal("two tokens accepted")
	}
}
