package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/tweenietomatoes/ttl/internal/crypto"
)

// A file's fingerprint is its SHA-256, as sha256sum and Get-FileHash show
// it. The sender's client takes it as it encrypts and sends it to the
// server sealed in the upload's manifest (internal/crypto/manifest.go),
// which only the password opens; the recipient's client takes its own of
// what it saves and holds it to the sender's. It is advisory: AEAD already
// keeps every byte as it was sent, so a manifest that is missing or cannot
// be read leaves nothing to compare with and is said nowhere, one that
// does not match is said, and the download is never stopped for it (nor
// does the exit code change).

// manifestTries: the manifest is sent up to this many times, 4, 8 and 16
// seconds apart (manifestPause doubled), while the answer is a 429, a 5xx
// or none, as the page does; each try within manifestTimeout. The server
// keeps it once (the same bytes again find it kept) and only in the 20
// minutes after the upload.
const (
	manifestTries   = 4
	manifestTimeout = 15 * time.Second
)

// manifestPause: a variable for tests.
var manifestPause = 2 * time.Second

// sendManifest seals the upload's manifest (the file's SHA-256, sum) with
// the file key and sends it with the management key. Nothing it meets is
// an error of the upload's.
func sendManifest(ctx context.Context, hc *httpConn, server, token, manageKey string, fileKey, sum []byte) {
	if !isToken(token) || validateManageKey(manageKey) != nil || len(sum) != sha256.Size {
		return
	}
	nonce, err := randomBytes(24)
	if err != nil {
		return
	}
	sealed, err := crypto.SealManifest(fileKey, token, nonce, crypto.ManifestRecord{Type: crypto.ManifestSHA256, Value: sum})
	if err != nil {
		return
	}
	putURL, err := url.JoinPath(server, "v1", "files", token, "manifest")
	if err != nil {
		return
	}
	for i := range manifestTries {
		if i > 0 && sleepCtx(ctx, manifestPause<<i) != nil {
			return
		}
		tctx, cancel := context.WithTimeout(ctx, manifestTimeout)
		req, err := newRequest(tctx, http.MethodPut, putURL, bytes.NewReader(sealed))
		if err != nil {
			cancel()
			return
		}
		req.Header.Set("X-Manage-Key", manageKey)
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err := hc.do(req)
		status, detail := 0, ""
		if err == nil {
			status, detail = resp.StatusCode, readDetail(resp)
			_ = resp.Body.Close()
		}
		cancel()
		if status >= 200 && status < 300 || ctx.Err() != nil {
			return
		}
		last := i+1 == manifestTries || status != 0 && status < 500 && status != http.StatusTooManyRequests
		if !jsonMode {
			if last {
				fmt.Fprintf(os.Stderr, "%sFingerprint not stored (%s); the recipient's download will not be checked against it%s\n",
					c(cAmber), errorCause(err, status, detail), c(cReset))
			} else {
				fmt.Fprintf(os.Stderr, "%sFingerprint not stored yet (%s), retrying in %s; Ctrl-C skips it%s\n",
					c(cGray), errorCause(err, status, detail), manifestPause<<(i+1), c(cReset))
			}
		}
		if last {
			return
		}
	}
}

// senderSums are the sender's fingerprints, from the manifest that came
// with the probe (tail): the file's, or each packaged file's in ZIP order.
// None when there is no manifest or it does not open.
func senderSums(fileKey []byte, token string, tail []byte) [][]byte {
	if len(tail) == 0 {
		return nil
	}
	m, err := crypto.OpenManifest(fileKey, token, tail)
	if err != nil {
		return nil
	}
	return m.SHA256
}

// newDownloadFingerprint is what takes the download's fingerprints: file
// by file for a package the sender's page made (a .zip whose manifest has
// a SHA-256 for each of its two files or more: the page packs two or
// more), else of the one file it is.
func newDownloadFingerprint(name string, theirs [][]byte) crypto.Fingerprint {
	if len(theirs) > 1 && len(name) >= 4 && strings.EqualFold(name[len(name)-4:], ".zip") {
		return crypto.NewPackageFingerprint(len(theirs))
	}
	return crypto.NewFileFingerprint()
}

// downloadPrint is what a download says of its fingerprints: the SHA-256s
// in lower-case hex, a package's with the names its files have in it, and
// for each whether it is the sender's (same nil: nothing to hold them to).
type downloadPrint struct {
	sha256 []string
	names  []string
	same   []bool
}

func fingerprintOf(fp crypto.Fingerprint, theirs [][]byte) *downloadPrint {
	sums, names, ok := fp.Sums()
	if !ok || len(sums) == 0 {
		return nil
	}
	p := &downloadPrint{names: names}
	for _, s := range sums {
		p.sha256 = append(p.sha256, hex.EncodeToString(s))
	}
	if len(theirs) == len(sums) {
		for i, s := range sums {
			p.same = append(p.same, bytes.Equal(s, theirs[i]))
		}
	}
	return p
}

func (p *downloadPrint) allSame() bool {
	for _, ok := range p.same {
		if !ok {
			return false
		}
	}
	return true
}

// fingerprintJSON is the download's fingerprints in --json: sha256 for a
// file; files for a package, each with its name; same_as_sender when there
// is something to hold them to.
type fingerprintJSON struct {
	SHA256       string            `json:"sha256,omitempty"`
	Files        []fingerprintFile `json:"files,omitempty"`
	SameAsSender *bool             `json:"same_as_sender,omitempty"`
}

type fingerprintFile struct {
	Name         string `json:"name"`
	SHA256       string `json:"sha256"`
	SameAsSender *bool  `json:"same_as_sender,omitempty"`
}

func (p *downloadPrint) json() fingerprintJSON {
	var out fingerprintJSON
	if p == nil {
		return out
	}
	if p.same != nil {
		ok := p.allSame()
		out.SameAsSender = &ok
	}
	if p.names == nil {
		out.SHA256 = p.sha256[0]
		return out
	}
	for i, h := range p.sha256 {
		f := fingerprintFile{Name: p.names[i], SHA256: h}
		if p.same != nil {
			ok := p.same[i]
			f.SameAsSender = &ok
		}
		out.Files = append(out.Files, f)
	}
	return out
}

// print writes the fingerprints to stderr: "SHA-256: <hex>" for a file; for
// a package a line a file as sha256sum writes it, with "⚠ " before the
// name of one that is not the sender's (names are the sender's: stripped
// of what a terminal would act on); then whether they are the sender's.
func (p *downloadPrint) print() {
	if p == nil {
		return
	}
	differs := func(i int) bool { return p.same != nil && !p.same[i] }
	if p.names == nil {
		hc := cWhite
		if differs(0) {
			hc = cAmber
		}
		fmt.Fprintf(os.Stderr, "%sSHA-256:%s %s%s%s\n", c(cGray), c(cReset), c(hc), p.sha256[0], c(cReset))
	} else {
		fmt.Fprintf(os.Stderr, "%sSHA-256:%s\n", c(cGray), c(cReset))
		for i, h := range p.sha256 {
			mark, hc := "", cWhite
			if differs(i) {
				mark, hc = "⚠ ", cAmber
			}
			fmt.Fprintf(os.Stderr, "%s%s%s  %s%s\n", c(hc), h, c(cReset), mark, stripControl(p.names[i]))
		}
	}
	switch {
	case p.same == nil:
	case p.allSame():
		fmt.Fprintf(os.Stderr, "%s✓ Same as the sender's fingerprint%s\n", c(cGreen), c(cReset))
	default:
		fmt.Fprintf(os.Stderr, "%s⚠ Not the same as the sender's fingerprint; ask the sender.%s\n", c(cAmber), c(cReset))
	}
}
