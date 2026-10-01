package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const apiTimeout = 30 * time.Second

func runPlan(args []string) error {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	var serverVal string
	fs.StringVar(&serverVal, "server", "https://ttl.space", "server URL")
	fs.Usage = func() {
		if !jsonMode {
			fmt.Fprintln(os.Stderr, "Usage: ttl plan [--server URL]")
		}
	}
	if jsonMode {
		fs.SetOutput(io.Discard)
	}
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return fmt.Errorf("Usage: ttl plan [--server URL]")
	}

	if err := validateServerURL(serverVal); err != nil {
		return err
	}
	apiKey := loadAPIKey()
	limits, err := fetchLimits(newConn(), serverVal, apiKey)
	if err != nil {
		return err
	}

	if jsonMode {
		writeJSON(struct {
			OK     bool           `json:"ok"`
			Limits map[string]any `json:"limits"`
		}{true, limits})
		return nil
	}

	plan, _ := limits["plan"].(string)
	planColor := c(cWhite, cBold)
	if plan == "orbit" {
		planColor = c(cBlue, cBold)
	}
	// Server-controlled string; strip ANSI/format chars before printing.
	fmt.Fprintf(os.Stderr, "%sPlan:%s %s%s%s\n", c(cGray), c(cReset), planColor, stripControl(plan), c(cReset))
	fmt.Fprintf(os.Stderr, "%sMax file size:%s %s\n", c(cGray), c(cReset), humanBytes(jsonInt64(limits["max_file_bytes"])))
	maxTTL := humanDuration(jsonInt64(limits["max_ttl_seconds"]))
	if plan == "orbit" {
		maxTTL += " (or permanent)"
	}
	fmt.Fprintf(os.Stderr, "%sMax TTL:%s %s\n", c(cGray), c(cReset), maxTTL)
	fmt.Fprintf(os.Stderr, "%sUploads per day:%s %d\n", c(cGray), c(cReset), int(jsonInt64(limits["uploads_per_day"])))
	dailyQuota := jsonInt64(limits["daily_bytes_quota"])
	if dailyQuota > 0 {
		fmt.Fprintf(os.Stderr, "%sUpload volume per day:%s %s\n", c(cGray), c(cReset), humanBytes(dailyQuota))
	}
	storageQuota := jsonInt64(limits["storage_quota_bytes"])
	if storageQuota > 0 {
		fmt.Fprintf(os.Stderr, "%sStorage quota:%s %s", c(cGray), c(cReset), humanBytes(storageQuota))
		if addons := jsonInt64(limits["storage_addons"]); addons > 0 {
			fmt.Fprintf(os.Stderr, " %s(%d add-on)%s", c(cGray), addons, c(cReset))
		}
		fmt.Fprintln(os.Stderr)
	}

	if usage, ok := limits["usage"].(map[string]any); ok {
		fmt.Fprintf(os.Stderr, "\n%sUsage:%s\n", c(cBold), c(cReset))
		fmt.Fprintf(os.Stderr, "  %sUploads today:%s %d\n", c(cGray), c(cReset), int(jsonInt64(usage["uploads_today"])))
		if storageQuota > 0 {
			fmt.Fprintf(os.Stderr, "  %sActive storage:%s %s / %s\n",
				c(cGray), c(cReset),
				humanBytes(jsonInt64(usage["active_storage_bytes"])),
				humanBytes(storageQuota))
		}
		if _, has := usage["daily_bytes_used"]; has && dailyQuota > 0 {
			fmt.Fprintf(os.Stderr, "  %sUpload volume today:%s %s / %s %s(%s remaining)%s\n",
				c(cGray), c(cReset),
				humanBytes(jsonInt64(usage["daily_bytes_used"])), humanBytes(dailyQuota),
				c(cGray), humanBytes(jsonInt64(usage["daily_bytes_remaining"])), c(cReset))
		}
	}

	// A cancellation on its way: access lasts until the paid period ends.
	if at := jsonInt64(limits["cancel_scheduled_at"]); at > 0 {
		fmt.Fprintf(os.Stderr, "\n%s%sCancellation scheduled.%s", c(cAmber), c(cBold), c(cReset))
		if until := jsonInt64(limits["access_until"]); until > 0 {
			fmt.Fprintf(os.Stderr, " Orbit stays active until %s%s%s.",
				c(cBold), time.UnixMicro(until).Format("2006-01-02 15:04 MST"), c(cReset))
		}
		fmt.Fprintln(os.Stderr)
	}

	// Red banner when subscription ended; permanent files are queued for
	// hard delete at perm_grace_until.
	if grace := jsonInt64(limits["perm_grace_until"]); grace > 0 {
		deadline := time.Unix(grace, 0)
		remaining := grace - time.Now().Unix()
		fmt.Fprintf(os.Stderr, "\n%s%sPermanent files at risk:%s your subscription has ended.\n",
			c(cRed), c(cBold), c(cReset))
		if remaining <= 0 {
			fmt.Fprintf(os.Stderr, "  %sHard delete window:%s %s%s%s (deadline passed — purge in progress)\n",
				c(cGray), c(cReset),
				c(cRed, cBold), deadline.Format("2006-01-02 15:04 MST"), c(cReset))
		} else {
			fmt.Fprintf(os.Stderr, "  %sHard delete on:%s %s%s%s (%s remaining)\n",
				c(cGray), c(cReset),
				c(cRed, cBold), deadline.Format("2006-01-02 15:04 MST"), c(cReset),
				humanDuration(remaining))
		}
		fmt.Fprintf(os.Stderr, "  %sRenew at:%s https://ttl.space/orbit\n", c(cGray), c(cReset))
	}
	return nil
}

// listedFile is one entry of GET /v1/files.
type listedFile struct {
	Token          string `json:"token"`
	Link           string `json:"link"`
	SizeBytes      int64  `json:"size_bytes"`
	CreatedAt      int64  `json:"created_at"`
	ExpiresAt      int64  `json:"expires_at"`
	Burn           bool   `json:"burn"`
	Expired        bool   `json:"expired"`
	UploaderOnly   bool   `json:"uploader_only"`
	IsPermanent    bool   `json:"is_permanent"`
	IsNote         bool   `json:"is_note"`
	PermGraceUntil int64  `json:"perm_grace_until"`
}

// maxListPages bounds the walk over next_cursor (20 files per page).
const maxListPages = 250

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	var serverVal string
	fs.StringVar(&serverVal, "server", "https://ttl.space", "server URL")
	var limitVal int
	fs.IntVar(&limitVal, "n", 0, "stop after N files (0 = all)")
	fs.IntVar(&limitVal, "limit", 0, "stop after N files (0 = all)")
	fs.Usage = func() {
		if !jsonMode {
			fmt.Fprintln(os.Stderr, "Usage: ttl list [-n N] [--server URL]")
		}
	}
	if jsonMode {
		fs.SetOutput(io.Discard)
	}
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return fmt.Errorf("Usage: ttl list [-n N] [--server URL]")
	}
	if limitVal < 0 {
		return fmt.Errorf("Invalid -n: %d", limitVal)
	}

	if err := validateServerURL(serverVal); err != nil {
		return err
	}
	apiKey := loadAPIKey()
	if apiKey == "" {
		return fmt.Errorf("No API key configured. Run: ttl activate <key>")
	}

	listURL, err := url.JoinPath(serverVal, "/v1/files")
	if err != nil {
		return fmt.Errorf("Invalid server URL: %w", err)
	}

	// The server answers 20 files per page, newest first, with next_cursor
	// while has_more: walk the pages until the end or -n.
	hc := newConn()
	var files []listedFile
	hasMore := false
	cursor := ""
	for page := 0; ; page++ {
		if page >= maxListPages {
			hasMore = true
			break
		}
		pageURL := listURL
		if cursor != "" {
			pageURL += "?cursor=" + url.QueryEscape(cursor)
		}
		var result struct {
			Files      []listedFile `json:"files"`
			HasMore    bool         `json:"has_more"`
			NextCursor string       `json:"next_cursor"`
		}
		if err := apiGetJSON(hc, pageURL, apiKey, &result); err != nil {
			return err
		}
		files = append(files, result.Files...)
		if limitVal > 0 && len(files) >= limitVal {
			hasMore = result.HasMore || len(files) > limitVal
			files = files[:limitVal]
			break
		}
		if !result.HasMore || result.NextCursor == "" || !isValidCursor(result.NextCursor) {
			break
		}
		cursor = result.NextCursor
	}

	if jsonMode {
		if files == nil {
			files = []listedFile{}
		}
		writeJSON(struct {
			OK      bool         `json:"ok"`
			Files   []listedFile `json:"files"`
			HasMore bool         `json:"has_more"`
		}{true, files, hasMore})
		return nil
	}

	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "%sNo files found.%s\n", c(cGray), c(cReset))
		return nil
	}

	for _, f := range files {
		status := "active"
		statusColor := c(cGreen)
		if f.Expired {
			status = "expired"
			statusColor = c(cGray)
		}
		if f.Burn {
			status += " (burn)"
			if !f.Expired {
				statusColor = c(cAmber)
			}
		}
		// perm_grace_until > 0 means "subscription ended, hard delete at this time".
		if f.IsPermanent && !f.Expired && f.PermGraceUntil > 0 {
			status = "grace (until " + time.Unix(f.PermGraceUntil, 0).Format("2006-01-02 15:04") + ")"
			statusColor = c(cRed)
		}
		created := time.Unix(f.CreatedAt, 0).Format("2006-01-02 15:04")
		// Pad to timestamp width so "permanent" rows line up.
		var expiresCol string
		if f.IsPermanent {
			expiresCol = "permanent"
		} else {
			expiresCol = time.Unix(f.ExpiresAt, 0).Format("2006-01-02 15:04")
		}
		// Server-controlled; reject anything outside the 10 base62 schema
		// so a malformed entry can't smuggle ANSI through the bold wrapper.
		if !isToken(f.Token) {
			fmt.Fprintf(os.Stderr, "  %s[skipped: invalid token]%s\n", c(cAmber), c(cReset))
			continue
		}
		fmt.Fprintf(os.Stderr, "  %s%s%s  %8s  %s%s → %-16s%s  %s[%s]%s",
			c(cBold), f.Token, c(cReset),
			humanBytes(f.SizeBytes),
			c(cGray), created, expiresCol, c(cReset),
			statusColor, status, c(cReset))
		if f.UploaderOnly {
			fmt.Fprintf(os.Stderr, " %s[private]%s", c(cBlue), c(cReset))
		}
		if f.IsNote {
			fmt.Fprintf(os.Stderr, " %s[note]%s", c(cGray), c(cReset))
		}
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "  %s%s%s\n", c(cLightBlue), stripControl(f.Link), c(cReset))
	}
	if hasMore {
		fmt.Fprintf(os.Stderr, "  %s… more files not shown%s\n", c(cGray), c(cReset))
	}
	return nil
}

// isValidCursor accepts the server's cursor shapes: "<unix µs>" or
// "<unix µs>.<token>".
func isValidCursor(s string) bool {
	if s == "" || len(s) > 40 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && r != '.' {
			return false
		}
	}
	return true
}

func runDelete(args []string) error {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	var serverVal string
	fs.StringVar(&serverVal, "server", "https://ttl.space", "server URL")
	var manageKey string
	fs.StringVar(&manageKey, "k", "", "management key printed by ttl send")
	fs.StringVar(&manageKey, "manage-key", "", "management key printed by ttl send")
	fs.Usage = func() {
		if !jsonMode {
			fmt.Fprintln(os.Stderr, "Usage: ttl delete [-k MANAGE_KEY] [--server URL] <token or link>")
		}
	}
	if jsonMode {
		fs.SetOutput(io.Discard)
	}
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("Usage: ttl delete [-k MANAGE_KEY] <token or link>")
	}

	if err := validateServerURL(serverVal); err != nil {
		return err
	}

	token, err := tokenFromArg(pos[0])
	if err != nil {
		return err
	}

	// The upload's management key (any plan) or the Orbit key (owner).
	var apiKey string
	if manageKey != "" {
		if err := validateManageKey(manageKey); err != nil {
			return err
		}
	} else {
		apiKey = loadAPIKey()
		if apiKey == "" {
			return fmt.Errorf("No Orbit key configured and no management key given\nRun: ttl activate <key>, or pass -k <manage key> (printed by ttl send)")
		}
	}

	deleteURL, err := url.JoinPath(serverVal, "/v1/files/"+token)
	if err != nil {
		return fmt.Errorf("Invalid server URL: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()
	req, err := newRequest(ctx, http.MethodDelete, deleteURL, nil)
	if err != nil {
		return err
	}
	if manageKey != "" {
		req.Header.Set("X-Manage-Key", manageKey)
	} else {
		setAPIKeyHeader(req.Header, apiKey)
	}

	resp, err := newConn().do(req)
	if err != nil {
		return fmt.Errorf("Request failed: %w", err)
	}
	defer resp.Body.Close()
	detail := readDetail(resp)

	switch resp.StatusCode {
	case http.StatusNoContent:
		if jsonMode {
			writeJSON(struct {
				OK      bool   `json:"ok"`
				Token   string `json:"token"`
				Deleted bool   `json:"deleted"`
			}{true, token, true})
		} else {
			fmt.Fprintf(os.Stderr, "%sDeleted:%s %s%s%s\n", c(cGreen), c(cReset), c(cBold), token, c(cReset))
		}
		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("Invalid or expired API key\nRun: ttl activate <key> with a valid key, or ttl deactivate to use the free plan")
	case http.StatusForbidden:
		return fmt.Errorf("File deletion requires an Orbit plan key, or the upload's management key (-k)")
	case http.StatusNotFound:
		if manageKey != "" {
			return fmt.Errorf("File not found: wrong management key, or the file is already gone")
		}
		return fmt.Errorf("File not found or not owned by this key")
	case http.StatusBadGateway, http.StatusServiceUnavailable:
		return fmt.Errorf("Storage temporarily unavailable, try again later")
	default:
		if detail != "" {
			return fmt.Errorf("Server returned %d: %s", resp.StatusCode, detail)
		}
		return fmt.Errorf("Server returned %d", resp.StatusCode)
	}
}

// tokenFromArg accepts a bare token or a link and returns the token.
func tokenFromArg(s string) (string, error) {
	if isToken(s) {
		return s, nil
	}
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if t := parts[len(parts)-1]; isToken(t) {
			return t, nil
		}
	}
	return "", fmt.Errorf("Invalid token: %s (expected a 10-character token or a ttl.space link)", stripControl(s))
}

// serverError is a non-2xx answer from the API.
type serverError struct {
	status int
	detail string
}

func (e *serverError) Error() string {
	switch e.status {
	case http.StatusUnauthorized:
		return "Invalid or expired API key\nRun: ttl activate <key> with a valid key, or ttl deactivate to use the free plan"
	case http.StatusBadGateway, http.StatusServiceUnavailable:
		return "Storage temporarily unavailable, try again later"
	}
	if e.detail != "" {
		return fmt.Sprintf("Server returned %d: %s", e.status, e.detail)
	}
	return fmt.Sprintf("Server returned %d", e.status)
}

// apiGetJSON fetches an API document with the Orbit key, at most 1 MiB.
func apiGetJSON(hc *httpConn, rawURL, apiKey string, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()
	req, err := newRequest(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	setAPIKeyHeader(req.Header, apiKey)
	resp, err := hc.do(req)
	if err != nil {
		return fmt.Errorf("Cannot reach server: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("File listing requires an Orbit plan")
	}
	if resp.StatusCode != http.StatusOK {
		return &serverError{status: resp.StatusCode, detail: readDetail(resp)}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
		return fmt.Errorf("Invalid server response: %w", err)
	}
	return nil
}

// fetchLimits reads GET /v1/limits for the key's plan. A rejected key is
// a *serverError with status 401; an unreachable server wraps the
// transport error.
func fetchLimits(hc *httpConn, serverURL, apiKey string) (map[string]any, error) {
	limitsURL, err := url.JoinPath(serverURL, "/v1/limits")
	if err != nil {
		return nil, fmt.Errorf("Invalid server URL: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := newRequest(ctx, http.MethodGet, limitsURL, nil)
	if err != nil {
		return nil, err
	}
	setAPIKeyHeader(req.Header, apiKey)

	resp, err := hc.do(req)
	if err != nil {
		return nil, fmt.Errorf("Cannot reach server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &serverError{status: resp.StatusCode, detail: readDetail(resp)}
	}

	var limits map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&limits); err != nil {
		return nil, fmt.Errorf("Invalid server response: %w", err)
	}
	if limits == nil {
		return nil, fmt.Errorf("Invalid server response: empty limits")
	}
	return limits, nil
}

// isKeyRejected reports whether err is the server refusing the API key.
func isKeyRejected(err error) bool {
	var se *serverError
	return errors.As(err, &se) && se.status == http.StatusUnauthorized
}

func jsonInt64(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	default:
		return 0
	}
}

func humanDuration(seconds int64) string {
	switch {
	case seconds >= 86400:
		return fmt.Sprintf("%d days", seconds/86400)
	case seconds >= 3600:
		return fmt.Sprintf("%d hours", seconds/3600)
	case seconds >= 60:
		return fmt.Sprintf("%d minutes", seconds/60)
	default:
		return fmt.Sprintf("%d seconds", seconds)
	}
}
