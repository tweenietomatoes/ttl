package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockAPI is an in-memory ttl.space for tests: limits, PUT /v1/files,
// resumable upload sessions, probe, download with byte ranges, list,
// delete and status. Fields set before the first request shape its
// behaviour; counters and captured headers are read afterwards.
type mockAPI struct {
	t   *testing.T
	URL string

	mu sync.Mutex

	plan string // "free" (default) or "orbit"

	// Uploads
	blob              []byte // ciphertext of the last completed upload
	partSize          int64  // default 64 KiB
	noSessions        bool   // POST /v1/uploads answers 501
	sessions          map[string]*mockSession
	putCalls          int
	sessionCalls      int
	completeCalls     int
	abortCalls        int
	partAttempts      map[int]int
	partDigests       map[int]string
	lastUploadHeaders http.Header // PUT /v1/files or POST /v1/uploads
	// fileHook answers the attempt-th PUT /v1/files with status (and
	// detail) instead of storing it; 0 stores it. attempt starts at 1.
	fileHook func(attempt int) (status int, detail string)
	// partHook answers a part request with status (and detail) instead of
	// storing it; 0 stores it. attempt starts at 1.
	partHook func(n, attempt int) (status int, detail string)
	// bodyRate (bytes/s, 0 = unlimited) reads every part body through one
	// shared bucket: a slow uplink that concurrent parts share.
	bodyRate int64
	rateMu   sync.Mutex
	rateNext time.Time
	// stallPart: the first attempt of this part stops being read halfway
	// (a connection that died silently) until the client gives up on it.
	stallPart int
	// completeHook answers a complete request with status and body
	// instead of assembling; 0 assembles.
	completeHook func(attempt int) (status int, body string)
	// cutCompletes: the first this many answers to complete break off
	// after a few bytes; the upload is done all the same.
	cutCompletes int

	// Downloads
	dropAfter   int64 // first full download: close the connection after this many bytes
	dropped     bool
	ignoreRange bool   // answer a Range request with the whole file (200)
	burn        bool   // refuse ranges (400) like the server does for one-time files
	ticket      string // with burn: the first answer's X-Resume-Ticket; a range bringing it is served
	// rangeHook answers the attempt-th range request with this status
	// instead of serving it (0 serves). attempt starts at 1.
	rangeHook func(attempt int) int
	// dropRanges: range answers are also cut after dropAfter bytes, this many times.
	dropRanges int
	// dropAtStart: the first full download sends its headers, then hangs up.
	dropAtStart bool
	// newTicket: a full download after the first answers with this ticket.
	newTicket string
	// silentAfter: the first full download sends this many bytes, then
	// nothing, with the connection kept open (a path that died silently).
	silentAfter int64
	// fullHook answers the attempt-th full (not ranged) download with this
	// status instead of serving it (0 serves). attempt starts at 1.
	fullHook  func(attempt int) int
	fullCalls int
	// cutAfterLast: the first full download sends every byte, chunked, then
	// hangs up before the end of the stream.
	cutAfterLast    bool
	rangeRequests   []string
	downloadHeaders http.Header

	// Orbit management
	files         []listedFile
	listCursors   []string
	listHeaders   http.Header
	deleteHeaders http.Header
	deleteStatus  int // default 204
	statusItems   map[string]manageStatus
	statusBody    []byte
}

type mockSession struct {
	id       string
	size     int64
	parts    int
	stored   map[int][]byte
	done     bool
	response []byte
}

func newMockAPI(t *testing.T) *mockAPI {
	t.Helper()
	m := &mockAPI{
		t:            t,
		plan:         "free",
		partSize:     64 << 10,
		sessions:     map[string]*mockSession{},
		partAttempts: map[int]int{},
		partDigests:  map[int]string{},
		deleteStatus: http.StatusNoContent,
		statusItems:  map[string]manageStatus{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/limits", m.limits)
	mux.HandleFunc("PUT /v1/files", m.putFile)
	mux.HandleFunc("POST /v1/uploads", m.createSession)
	mux.HandleFunc("PUT /v1/uploads/{id}/parts/{n}", m.putPart)
	mux.HandleFunc("POST /v1/uploads/{id}/complete", m.complete)
	mux.HandleFunc("DELETE /v1/uploads/{id}", m.abort)
	mux.HandleFunc("GET /v1/probe/{token}", m.probe)
	mux.HandleFunc("GET /v1/files", m.list)
	mux.HandleFunc("DELETE /v1/files/{token}", m.deleteFile)
	mux.HandleFunc("POST /v1/status", m.status)
	mux.HandleFunc("GET /{token}", m.download)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	m.URL = srv.URL
	return m
}

func (m *mockAPI) problem(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"status": status, "detail": detail})
}

func (m *mockAPI) limits(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	plan := m.plan
	m.mu.Unlock()
	if plan == "orbit" {
		if !strings.HasPrefix(r.Header.Get("X-API-Key"), keyPrefix) {
			m.problem(w, 401, "Invalid API key format")
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"plan": "orbit", "max_file_bytes": 10737418240, "max_ttl_seconds": 2592000,
			"default_ttl_seconds": 86400, "uploads_per_day": 1000000,
			"allowed_ttl_seconds": []int{300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 259200, 345600, 432000, 518400, 604800, 1209600, 1296000, 2419200, 2592000},
			"can_delete":          true, "can_list": true,
			"storage_quota_bytes": 536870912000, "storage_addons": 0,
			"usage":               map[string]any{"uploads_today": 3, "active_storage_bytes": 4294967296},
			"cancel_scheduled_at": 0, "perm_grace_until": 0,
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"plan": "free", "max_file_bytes": 2147483648, "max_ttl_seconds": 604800,
		"default_ttl_seconds": 86400, "uploads_per_day": 10,
		"allowed_ttl_seconds": []int{300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 259200, 345600, 432000, 518400, 604800},
		"can_delete":          false, "can_list": false,
		"daily_bytes_quota": 10737418240,
		"usage":             map[string]any{"uploads_today": 1, "daily_bytes_used": 1048576, "daily_bytes_remaining": 10736369664},
	})
}

func (m *mockAPI) uploadResponse(size int64, burn bool) []byte {
	resp := map[string]any{
		"link":       m.URL + "/aBcDeFgHiJ",
		"token":      "aBcDeFgHiJ",
		"expires_in": 604800,
		"size_bytes": size,
		"manage_key": mockManageKey,
	}
	if burn {
		resp["burn_after_reading"] = true
	}
	b, _ := json.Marshal(resp)
	return append(b, '\n')
}

func (m *mockAPI) putFile(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(r.Body)
	m.mu.Lock()
	m.putCalls++
	attempt := m.putCalls
	m.lastUploadHeaders = r.Header.Clone()
	hook := m.fileHook
	m.mu.Unlock()
	if err != nil {
		return
	}
	if hook != nil {
		if status, detail := hook(attempt); status != 0 {
			m.problem(w, status, detail)
			return
		}
	}
	// Like the server: the whole file's SHA-256 is required and checked.
	sum := sha256Sum(data)
	if r.Header.Get("Content-Digest") != "sha-256=:"+base64.StdEncoding.EncodeToString(sum)+":" {
		m.problem(w, 422, "Content-Digest mismatch")
		return
	}
	if xs := r.Header.Get("X-File-Size"); xs != "" {
		if declared, _ := strconv.ParseInt(xs, 10, 64); declared != int64(len(data)) {
			m.problem(w, 400, fmt.Sprintf("Upload incomplete: received %d of %d bytes", len(data), declared))
			return
		}
	}
	m.mu.Lock()
	m.blob = data
	m.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(m.uploadResponse(int64(len(data)), r.Header.Get("X-Burn-After-Reading") == "true"))
}

func (m *mockAPI) createSession(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessionCalls++
	m.lastUploadHeaders = r.Header.Clone()
	if m.noSessions {
		m.problem(w, 501, "Resumable uploads are not available")
		return
	}
	size, err := strconv.ParseInt(r.Header.Get("X-File-Size"), 10, 64)
	if err != nil || size <= 0 {
		m.problem(w, 400, "Missing or invalid X-File-Size header")
		return
	}
	if r.Header.Get("X-Token-Hash") == "" {
		m.problem(w, 400, "Missing or invalid X-Token-Hash header (expected 64 hex chars)")
		return
	}
	var raw [32]byte
	rand.Read(raw[:])
	id := base64.RawURLEncoding.EncodeToString(raw[:])
	parts := int((size + m.partSize - 1) / m.partSize)
	m.sessions[id] = &mockSession{id: id, size: size, parts: parts, stored: map[int][]byte{}}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"id": id, "part_size": m.partSize, "parts": parts})
}

func (m *mockAPI) putPart(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	sess := m.sessions[r.PathValue("id")]
	m.mu.Unlock()
	if sess == nil {
		m.problem(w, 404, "Upload session not found")
		return
	}
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil || n < 1 || n > sess.parts {
		m.problem(w, 400, "Invalid part number")
		return
	}
	want := m.partSize
	if n == sess.parts {
		want = sess.size - int64(sess.parts-1)*m.partSize
	}
	if r.ContentLength != want {
		m.problem(w, 400, fmt.Sprintf("Part %d must be exactly %d bytes", n, want))
		return
	}
	m.mu.Lock()
	m.partAttempts[n]++
	attempt := m.partAttempts[n]
	m.mu.Unlock()
	data, err := m.readPart(r, n, attempt, want)
	if err == errSilent {
		m.problem(w, http.StatusRequestTimeout, "No data received; send it again")
		return
	}
	if err != nil || int64(len(data)) != want {
		m.problem(w, 400, "Incomplete part")
		return
	}
	m.mu.Lock()
	m.partDigests[n] = r.Header.Get("Content-Digest")
	hook := m.partHook
	m.mu.Unlock()
	if hook != nil {
		if status, detail := hook(n, attempt); status != 0 {
			m.problem(w, status, detail)
			return
		}
	}
	if cd := r.Header.Get("Content-Digest"); cd != "" {
		sum := sha256Sum(data)
		if cd != "sha-256=:"+base64.StdEncoding.EncodeToString(sum)+":" {
			m.problem(w, 422, "Part digest mismatch")
			return
		}
	}
	m.mu.Lock()
	sess.stored[n] = data
	m.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (m *mockAPI) complete(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	sess := m.sessions[r.PathValue("id")]
	m.completeCalls++
	attempt := m.completeCalls
	hook := m.completeHook
	m.mu.Unlock()
	if sess == nil {
		m.problem(w, 404, "Upload session not found")
		return
	}
	if hook != nil {
		if status, body := hook(attempt); status != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			w.Write([]byte(body))
			return
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if sess.done {
		m.answerComplete(w, attempt, sess.response)
		return
	}
	var missing []int
	var buf bytes.Buffer
	for i := 1; i <= sess.parts; i++ {
		p, ok := sess.stored[i]
		if !ok {
			missing = append(missing, i)
			continue
		}
		buf.Write(p)
	}
	if len(missing) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{"detail": "Parts missing", "missing": missing})
		return
	}
	m.blob = buf.Bytes()
	sess.done = true
	sess.response = m.uploadResponse(sess.size, r.Header.Get("X-Burn-After-Reading") == "true")
	m.answerComplete(w, attempt, sess.response)
}

// answerComplete writes a complete's 201, broken off after its first bytes
// for the first cutCompletes attempts. The caller holds m.mu.
func (m *mockAPI) answerComplete(w http.ResponseWriter, attempt int, resp []byte) {
	w.Header().Set("Content-Type", "application/json")
	if attempt > m.cutCompletes {
		w.WriteHeader(http.StatusCreated)
		w.Write(resp)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(resp)))
	w.WriteHeader(http.StatusCreated)
	w.Write(resp[:10])
	w.(http.Flusher).Flush()
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			conn.Close()
		}
	}
}

func (m *mockAPI) abort(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.abortCalls++
	if _, ok := m.sessions[r.PathValue("id")]; !ok {
		m.problem(w, 404, "Upload session not found")
		return
	}
	delete(m.sessions, r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

func (m *mockAPI) probe(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	blob := m.blob
	m.mu.Unlock()
	if blob == nil {
		m.problem(w, 404, "File not found. It may have already been downloaded or expired.")
		return
	}
	n := min(len(blob), 314)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(blob[:n])
}

func (m *mockAPI) download(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	blob := m.blob
	m.downloadHeaders = r.Header.Clone()
	m.mu.Unlock()
	if blob == nil {
		m.problem(w, 404, "File not found. It may have already been downloaded or expired.")
		return
	}
	if r.Header.Get("X-Download-Token") == "" {
		m.problem(w, 403, "Missing X-Download-Token header. Open the link in a browser or run: ttl get LINK")
		return
	}
	total := int64(len(blob))
	if rh := r.Header.Get("Range"); rh != "" {
		m.mu.Lock()
		m.rangeRequests = append(m.rangeRequests, rh)
		burn, ignore, ticket := m.burn, m.ignoreRange, m.ticket
		hook, attempt := m.rangeHook, len(m.rangeRequests)
		m.mu.Unlock()
		if hook != nil {
			if st := hook(attempt); st != 0 {
				m.problem(w, st, "busy")
				return
			}
		}
		if burn && (ticket == "" || r.Header.Get("X-Resume-Ticket") != ticket) {
			m.problem(w, 400, "Byte ranges are not available for one-time files")
			return
		}
		if !ignore {
			spec := strings.TrimSuffix(strings.TrimPrefix(rh, "bytes="), "-")
			start, err := strconv.ParseInt(spec, 10, 64)
			if err != nil || start < 0 || start >= total {
				w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", total))
				m.problem(w, 416, "Invalid or unsatisfiable range")
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, total-1, total))
			w.Header().Set("Content-Length", strconv.FormatInt(total-start, 10))
			w.WriteHeader(http.StatusPartialContent)
			m.mu.Lock()
			cut := m.dropRanges > 0 && start+m.dropAfter < total
			if cut {
				m.dropRanges--
			}
			m.mu.Unlock()
			if cut {
				w.Write(blob[start : start+m.dropAfter])
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				if hj, ok := w.(http.Hijacker); ok {
					if conn, _, err := hj.Hijack(); err == nil {
						conn.Close()
						return
					}
				}
				return
			}
			w.Write(blob[start:])
			return
		}
	}
	m.mu.Lock()
	m.fullCalls++
	fullHook, fullAttempt := m.fullHook, m.fullCalls
	m.mu.Unlock()
	if fullHook != nil {
		if st := fullHook(fullAttempt); st != 0 {
			m.problem(w, st, "storage")
			return
		}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	m.mu.Lock()
	if m.cutAfterLast && !m.dropped {
		m.dropped = true
		m.mu.Unlock()
		w.WriteHeader(http.StatusOK) // no Content-Length: chunked
		w.Write(blob)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				conn.Close() // before the last, empty chunk
			}
		}
		return
	}
	m.mu.Unlock()
	w.Header().Set("Content-Length", strconv.FormatInt(total, 10))
	m.mu.Lock()
	if m.burn && m.ticket != "" {
		t := m.ticket
		if m.dropped && m.newTicket != "" {
			t = m.newTicket
		}
		w.Header().Set("X-Resume-Ticket", t)
	}
	if m.silentAfter > 0 && !m.dropped && m.silentAfter < total {
		m.dropped = true
		n := m.silentAfter
		m.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		w.Write(blob[:n])
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done() // until the client gives up on it
		return
	}
	if m.dropAtStart && !m.dropped {
		m.dropped = true
		m.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				conn.Close()
			}
		}
		return
	}
	drop := m.dropAfter > 0 && !m.dropped && m.dropAfter < total
	if drop {
		m.dropped = true
	}
	dropAfter := m.dropAfter
	m.mu.Unlock()
	if drop {
		w.WriteHeader(http.StatusOK)
		w.Write(blob[:dropAfter])
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				conn.Close()
				return
			}
		}
		m.t.Error("mock server cannot hijack the connection")
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(blob)
}

func (m *mockAPI) list(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listHeaders = r.Header.Clone()
	if r.Header.Get("X-API-Key") == "" {
		m.problem(w, 403, "File listing requires an Orbit plan API key")
		return
	}
	const pageSize = 20
	cursor := r.URL.Query().Get("cursor")
	m.listCursors = append(m.listCursors, cursor)
	start := 0
	if cursor != "" {
		// cursor = "<createdMicro>.<token>" of the last file of the previous page
		for i, f := range m.files {
			if strconv.FormatInt(f.CreatedAt*1_000_000, 10)+"."+f.Token == cursor {
				start = i + 1
				break
			}
		}
	}
	end := min(start+pageSize, len(m.files))
	page := m.files[start:end]
	resp := map[string]any{"files": page, "has_more": end < len(m.files)}
	if end < len(m.files) && len(page) > 0 {
		last := page[len(page)-1]
		resp["next_cursor"] = strconv.FormatInt(last.CreatedAt*1_000_000, 10) + "." + last.Token
	}
	json.NewEncoder(w).Encode(resp)
}

func (m *mockAPI) deleteFile(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteHeaders = r.Header.Clone()
	switch m.deleteStatus {
	case http.StatusNoContent:
		w.WriteHeader(http.StatusNoContent)
	case http.StatusNotFound:
		m.problem(w, 404, "Not found")
	case http.StatusForbidden:
		m.problem(w, 403, "File deletion requires an Orbit plan API key or the upload's management key")
	default:
		m.problem(w, m.deleteStatus, "as configured")
	}
}

func (m *mockAPI) status(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	var req struct {
		Items []struct {
			Token string `json:"token"`
			Key   string `json:"key"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		m.problem(w, 400, "Invalid request body")
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statusBody = body
	type item struct {
		Token string `json:"token"`
		Found bool   `json:"found"`
		*manageStatus
	}
	out := make([]item, 0, len(req.Items))
	for _, it := range req.Items {
		res := item{Token: it.Token}
		if st, ok := m.statusItems[it.Token]; ok && it.Key == mockManageKey {
			res.Found = true
			res.manageStatus = &st
		}
		out = append(out, res)
	}
	json.NewEncoder(w).Encode(map[string]any{"items": out})
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

var errSilent = errors.New("part sender went silent")

// readPart reads a part body, slowly when bodyRate is set, and stalls the
// first attempt of stallPart halfway until the client's request ends.
func (m *mockAPI) readPart(r *http.Request, n, attempt int, want int64) ([]byte, error) {
	if m.bodyRate == 0 && m.stallPart == 0 {
		return io.ReadAll(r.Body)
	}
	buf := make([]byte, 0, want)
	chunk := make([]byte, 4096)
	for {
		if n == m.stallPart && attempt == 1 && int64(len(buf)) >= want/2 {
			// Silent for a while, then dropped as the server drops a
			// silent part (90 s there): 408, "send it again".
			time.Sleep(500 * time.Millisecond)
			return buf, errSilent
		}
		k, err := r.Body.Read(chunk)
		buf = append(buf, chunk[:k]...)
		if m.bodyRate > 0 && k > 0 {
			m.rateMu.Lock()
			now := time.Now()
			if m.rateNext.Before(now) {
				m.rateNext = now
			}
			m.rateNext = m.rateNext.Add(time.Duration(int64(k) * int64(time.Second) / m.bodyRate))
			wait := time.Until(m.rateNext)
			m.rateMu.Unlock()
			time.Sleep(wait)
		}
		if err == io.EOF {
			return buf, nil
		}
		if err != nil {
			return buf, err
		}
	}
}
