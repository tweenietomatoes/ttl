package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tweenietomatoes/ttl/internal/crypto"
)

const (
	fpToken     = "aBcDeFgHiJ"
	fpManageKey = "k7Qm2vXpL9aR4tB8cD1eF6gH3jK5mN0oP2qS4uV7wYz"
)

// fpServer keeps one upload and its manifest as the server does: the
// manifest with the management key, handed back after the header and the
// metadata to a probe that asks for it.
type fpServer struct {
	mu       sync.Mutex
	blob     []byte
	manifest []byte
	puts     int
	fail     int // the first manifest puts answered 503
	srv      *httptest.Server
}

func newFPServer(t *testing.T) *fpServer {
	t.Helper()
	s := &fpServer{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case r.URL.Path == "/v1/limits":
			writeMockLimits(w)
		case r.Method == http.MethodPut && r.URL.Path == "/v1/files":
			s.blob, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"link": s.srv.URL + "/" + fpToken, "token": fpToken, "manage_key": fpManageKey})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/files/"+fpToken+"/manifest":
			s.puts++
			body, _ := io.ReadAll(r.Body)
			switch {
			case r.Header.Get("X-Manage-Key") != fpManageKey:
				w.WriteHeader(http.StatusNotFound)
			case s.puts <= s.fail:
				w.WriteHeader(http.StatusServiceUnavailable)
			default:
				s.manifest = body
				w.WriteHeader(http.StatusNoContent)
			}
		case r.Method == http.MethodGet && r.URL.Path == "/v1/probe/"+fpToken:
			meta := int(binary.BigEndian.Uint16(s.blob[crypto.MetaLenOffset:crypto.HeaderSize]))
			_, _ = w.Write(s.blob[:crypto.HeaderSize+meta])
			if r.URL.Query().Get("manifest") == "1" {
				_, _ = w.Write(s.manifest)
			}
		case r.Method == http.MethodGet && r.URL.Path == "/"+fpToken:
			_, _ = w.Write(s.blob)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *fpServer) setManifest(b []byte) {
	s.mu.Lock()
	s.manifest = b
	s.mu.Unlock()
}

func fastManifest(t *testing.T) {
	t.Helper()
	old := manifestPause
	manifestPause = time.Millisecond
	t.Cleanup(func() { manifestPause = old })
}

func getJSON(t *testing.T, s *fpServer, pass string) map[string]any {
	t.Helper()
	out := t.TempDir()
	var err error
	raw := captureStdout(t, func() {
		withJSON(t, func() { err = runGet([]string{"-p", pass, "-o", out, s.srv.URL + "/" + fpToken}) })
	})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var res map[string]any
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("get JSON: %v\n%s", err, raw)
	}
	return res
}

// The sender's fingerprint goes up sealed with the upload; the recipient
// holds its own to it: same, not the same (said, the file saved all the
// same), or nothing to hold it to (said nowhere).
func TestFingerprint_SendGet(t *testing.T) {
	noKeys(t)
	fastManifest(t)
	s := newFPServer(t)
	s.fail = 1 // the first try finds the server restarting
	payload := "the report, version 2\n"
	src := tempFile(t, "report.txt", payload)
	want := sha256.Sum256([]byte(payload))
	wantHex := hex.EncodeToString(want[:])

	var err error
	raw := captureStdout(t, func() {
		withJSON(t, func() { err = runSend([]string{"-server", s.srv.URL, src}) })
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	var sent map[string]any
	if err := json.Unmarshal(raw, &sent); err != nil {
		t.Fatalf("send JSON: %v\n%s", err, raw)
	}
	pass, _ := sent["password"].(string)
	if sent["sha256"] != wantHex || pass == "" {
		t.Fatalf("send: sha256 %v, password %q", sent["sha256"], pass)
	}
	if s.puts != 2 || len(s.manifest) != crypto.ManifestMin {
		t.Fatalf("manifest: %d puts, %d bytes", s.puts, len(s.manifest))
	}

	got := getJSON(t, s, pass)
	if got["sha256"] != wantHex || got["same_as_sender"] != true || got["files"] != nil {
		t.Errorf("same: %v", got)
	}

	// Another digest, sealed with this file's key: not the same.
	key := crypto.DeriveEncKey(pass, s.blob[crypto.SaltOffset:crypto.NonceOffset])
	other := sha256.Sum256([]byte("something else"))
	nonce := bytes.Repeat([]byte{1}, 24)
	bad, err := crypto.SealManifest(key, fpToken, nonce, crypto.ManifestRecord{Type: crypto.ManifestSHA256, Value: other[:]})
	if err != nil {
		t.Fatal(err)
	}
	s.setManifest(bad)
	got = getJSON(t, s, pass)
	if got["ok"] != true || got["sha256"] != wantHex || got["same_as_sender"] != false {
		t.Errorf("differs: %v", got)
	}

	// Two digests for one file, a manifest of another link, none at all:
	// nothing to hold it to.
	two, _ := crypto.SealManifest(key, fpToken, nonce, crypto.ManifestRecord{Type: crypto.ManifestSHA256, Value: append(want[:], want[:]...)})
	elsewhere, _ := crypto.SealManifest(key, "zZzZzZzZzZ", nonce, crypto.ManifestRecord{Type: crypto.ManifestSHA256, Value: want[:]})
	for name, m := range map[string][]byte{"two": two, "another link's": elsewhere, "none": nil, "garbage": bytes.Repeat([]byte{'T'}, crypto.ManifestMin)} {
		s.setManifest(m)
		got = getJSON(t, s, pass)
		if _, said := got["same_as_sender"]; said || got["sha256"] != wantHex {
			t.Errorf("%s: %v", name, got)
		}
	}

	// Without --json: the line, and whether it is the sender's.
	s.setManifest(nil)
	s.puts, s.fail = 0, 0
	captureStdout(t, func() {
		if err := runSend([]string{"-server", s.srv.URL, "-p", "a long enough password", src}); err != nil {
			t.Error(err)
		}
	})
	stderr := captureStderr(t, func() {
		if err := runGet([]string{"-p", "a long enough password", "-o", t.TempDir(), s.srv.URL + "/" + fpToken}); err != nil {
			t.Error(err)
		}
	})
	if !strings.Contains(stderr, "SHA-256: "+wantHex) || !strings.Contains(stderr, "Same as the sender's fingerprint") {
		t.Errorf("stderr:\n%s", stderr)
	}
}

// The manifest is sent again only while the answer is a 429, a 5xx or
// none, at most manifestTries times; Ctrl-C (the context) ends it.
func TestSendManifest_Tries(t *testing.T) {
	fastManifest(t)
	for _, c := range []struct {
		answers []int
		tries   int
	}{
		{[]int{204}, 1},
		{[]int{503, 502, 204}, 3},
		{[]int{429, 204}, 2},
		{[]int{404}, 1},
		{[]int{409}, 1},
		{[]int{410}, 1},
		{[]int{500, 500, 500, 500, 500}, manifestTries},
	} {
		var n int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if r.Method != http.MethodPut || r.URL.Path != "/v1/files/"+fpToken+"/manifest" ||
				r.Header.Get("X-Manage-Key") != fpManageKey || len(body) != crypto.ManifestMin || !bytes.HasPrefix(body, []byte(crypto.ManifestMagic)) {
				t.Errorf("request %s %s, %d bytes", r.Method, r.URL.Path, len(body))
			}
			w.WriteHeader(c.answers[min(n, len(c.answers)-1)])
			n++
		}))
		sum := sha256.Sum256(nil)
		out := captureStderr(t, func() {
			sendManifest(context.Background(), newConn(), srv.URL, fpToken, fpManageKey, make([]byte, 32), sum[:])
		})
		srv.Close()
		if n != c.tries {
			t.Errorf("%v: %d tries, want %d", c.answers, n, c.tries)
		}
		// A manifest given up on is said once, after the last try.
		if failed := c.answers[len(c.answers)-1] != 204; failed != strings.Contains(out, "Fingerprint not stored (") {
			t.Errorf("%v: said %q", c.answers, out)
		}
	}

	// Not sent at all: no token, no management key.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("sent: %s", r.URL.Path)
	}))
	defer srv.Close()
	sum := sha256.Sum256(nil)
	sendManifest(context.Background(), newConn(), srv.URL, "", fpManageKey, make([]byte, 32), sum[:])
	sendManifest(context.Background(), newConn(), srv.URL, fpToken, "", make([]byte, 32), sum[:])
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sendManifest(ctx, newConn(), srv.URL, fpToken, fpManageKey, make([]byte, 32), sum[:])
}

// A package the sender's page made is fingerprinted file by file only when
// it is a .zip and the manifest has a digest for each of two files or more.
func TestNewDownloadFingerprint(t *testing.T) {
	d := make([]byte, 32)
	for _, c := range []struct {
		name   string
		theirs int
		pack   bool
	}{
		{"photos.zip", 3, true},
		{"PHOTOS.ZIP", 2, true},
		{"photos.zip", 1, false},
		{"photos.zip", 0, false},
		{"photos.tar", 3, false},
		{"zip", 3, false},
	} {
		theirs := make([][]byte, c.theirs)
		for i := range theirs {
			theirs[i] = d
		}
		// A package's fingerprint takes nothing but a package; a file's
		// takes anything.
		fp := newDownloadFingerprint(c.name, theirs)
		_, _ = fp.Write([]byte("not a zip"))
		if _, _, ok := fp.Sums(); ok == c.pack {
			t.Errorf("%s with %d digests: package %v", c.name, c.theirs, !ok)
		}
	}
}

// captureStderr runs fn with os.Stderr redirected and returns what it wrote.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()
	fn()
	w.Close()
	os.Stderr = orig
	return string(<-done)
}
