package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

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
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := validateServerURL(serverVal); err != nil {
		return err
	}
	apiKey := loadAPIKey()
	limits, err := fetchLimits(serverVal, apiKey)
	if err != nil {
		return err
	}

	if jsonMode {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "limits": limits})
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

	if usage, ok := limits["usage"].(map[string]any); ok {
		fmt.Fprintf(os.Stderr, "\n%sUsage:%s\n", c(cBold), c(cReset))
		fmt.Fprintf(os.Stderr, "  %sUploads today:%s %d\n", c(cGray), c(cReset), int(jsonInt64(usage["uploads_today"])))
		fmt.Fprintf(os.Stderr, "  %sActive storage:%s %s / %s\n",
			c(cGray), c(cReset),
			humanBytes(jsonInt64(usage["active_storage_bytes"])),
			humanBytes(jsonInt64(limits["storage_quota_bytes"])))
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

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	var serverVal string
	fs.StringVar(&serverVal, "server", "https://ttl.space", "server URL")
	fs.Usage = func() {
		if !jsonMode {
			fmt.Fprintln(os.Stderr, "Usage: ttl list [--server URL]")
		}
	}
	if jsonMode {
		fs.SetOutput(io.Discard)
	}
	if err := fs.Parse(args); err != nil {
		return err
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

	client := newTCPClient(30 * time.Second)
	req, err := http.NewRequest("GET", listURL, nil)
	if err != nil {
		return err
	}
	setAPIKeyHeader(req.Header, apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return fmt.Errorf("Invalid or expired API key")
	}
	if resp.StatusCode == 403 {
		return fmt.Errorf("File listing requires an Orbit plan")
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("Server returned %d", resp.StatusCode)
	}

	var result struct {
		Files []struct {
			Token          string `json:"token"`
			Link           string `json:"link"`
			SizeBytes      int64  `json:"size_bytes"`
			CreatedAt      int64  `json:"created_at"`
			ExpiresAt      int64  `json:"expires_at"`
			Burn           bool   `json:"burn"`
			Expired        bool   `json:"expired"`
			UploaderOnly   bool   `json:"uploader_only"`
			IsPermanent    bool   `json:"is_permanent"`
			PermGraceUntil int64  `json:"perm_grace_until"`
		} `json:"files"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return fmt.Errorf("Invalid server response: %w", err)
	}

	if jsonMode {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "files": result.Files})
		return nil
	}

	if len(result.Files) == 0 {
		fmt.Fprintf(os.Stderr, "%sNo files found.%s\n", c(cGray), c(cReset))
		return nil
	}

	for _, f := range result.Files {
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
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "  %s%s%s\n", c(cLightBlue), stripControl(f.Link), c(cReset))
	}
	return nil
}

func runDelete(args []string) error {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	var serverVal string
	fs.StringVar(&serverVal, "server", "https://ttl.space", "server URL")
	fs.Usage = func() {
		if !jsonMode {
			fmt.Fprintln(os.Stderr, "Usage: ttl delete [--server URL] <token>")
		}
	}
	if jsonMode {
		fs.SetOutput(io.Discard)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() != 1 {
		return fmt.Errorf("Usage: ttl delete <token>")
	}

	if err := validateServerURL(serverVal); err != nil {
		return err
	}

	token := fs.Arg(0)
	// Accept full URL or bare token
	if len(token) > 10 {
		if u, err := url.Parse(token); err == nil && u.Path != "" {
			parts := strings.Split(strings.Trim(u.Path, "/"), "/")
			if len(parts) > 0 {
				token = parts[len(parts)-1]
			}
		}
	}
	if !isToken(token) {
		return fmt.Errorf("Invalid token: %s (expected 10 alphanumeric characters)", token)
	}

	apiKey := loadAPIKey()
	if apiKey == "" {
		return fmt.Errorf("No API key configured. Run: ttl activate <key>")
	}

	deleteURL, err := url.JoinPath(serverVal, "/v1/files/"+token)
	if err != nil {
		return fmt.Errorf("Invalid server URL: %w", err)
	}

	client := newTCPClient(30 * time.Second)
	req, err := http.NewRequest("DELETE", deleteURL, nil)
	if err != nil {
		return err
	}
	setAPIKeyHeader(req.Header, apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Request failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case 204:
		if jsonMode {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "token": token, "deleted": true})
		} else {
			fmt.Fprintf(os.Stderr, "%sDeleted:%s %s%s%s\n", c(cGreen), c(cReset), c(cBold), token, c(cReset))
		}
		return nil
	case 401:
		return fmt.Errorf("Invalid or expired API key")
	case 403:
		return fmt.Errorf("File deletion requires an Orbit plan")
	case 404:
		return fmt.Errorf("File not found or not owned by this key")
	default:
		return fmt.Errorf("Server returned %d", resp.StatusCode)
	}
}

func fetchLimits(serverURL, apiKey string) (map[string]any, error) {
	limitsURL, err := url.JoinPath(serverURL, "/v1/limits")
	if err != nil {
		return nil, fmt.Errorf("Invalid server URL: %w", err)
	}

	client := newTCPClient(10 * time.Second)
	req, err := http.NewRequest("GET", limitsURL, nil)
	if err != nil {
		return nil, err
	}
	setAPIKeyHeader(req.Header, apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Cannot reach server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("Invalid or expired API key")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Server returned %d", resp.StatusCode)
	}

	var limits map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&limits); err != nil {
		return nil, fmt.Errorf("Invalid server response: %w", err)
	}
	return limits, nil
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
