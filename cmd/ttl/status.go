package main

import (
	"bytes"
	"context"
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

// manageStatus is what POST /v1/status tells the uploader about their own
// upload: counts and times only, nothing about who downloaded it.
type manageStatus struct {
	State          string `json:"state"` // active | expired | burned | deleted
	SizeBytes      int64  `json:"size_bytes"`
	CreatedAt      int64  `json:"created_at"` // unix seconds
	ExpiresAt      int64  `json:"expires_at"` // unix seconds; 0 = permanent
	Permanent      bool   `json:"permanent"`
	Burn           bool   `json:"burn"`
	Note           bool   `json:"note"`
	UploaderOnly   bool   `json:"uploader_only"`
	Downloads      int    `json:"downloads"`
	LastDownloadAt int64  `json:"last_download_at"` // unix seconds; 0 = never
	PartReads      int    `json:"part_reads"`       // opened on the recipient page
	LastPartAt     int64  `json:"last_part_at"`
}

// runStatus asks the server about one upload with its management key
// (printed by ttl send): whether it is still there, how often it was
// downloaded, when it expires.
func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	var serverVal string
	fs.StringVar(&serverVal, "server", "https://ttl.space", "server URL")
	var manageKey string
	fs.StringVar(&manageKey, "k", "", "management key printed by ttl send")
	fs.StringVar(&manageKey, "manage-key", "", "management key printed by ttl send")
	fs.Usage = func() {
		if !jsonMode {
			fmt.Fprintln(os.Stderr, "Usage: ttl status -k MANAGE_KEY [--server URL] <token or link>")
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
		return fmt.Errorf("Usage: ttl status -k MANAGE_KEY <token or link>")
	}
	if err := validateServerURL(serverVal); err != nil {
		return err
	}
	token, err := tokenFromArg(pos[0])
	if err != nil {
		return err
	}
	if manageKey == "" {
		return fmt.Errorf("Management key required: ttl status -k <manage key> %s (printed by ttl send)", token)
	}
	if err := validateManageKey(manageKey); err != nil {
		return err
	}

	statusURL, err := url.JoinPath(serverVal, "/v1/status")
	if err != nil {
		return fmt.Errorf("Invalid server URL: %w", err)
	}
	body, err := json.Marshal(map[string]any{
		"items": []map[string]string{{"token": token, "key": manageKey}},
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()
	req, err := newRequest(ctx, http.MethodPost, statusURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := newConn().do(req)
	if err != nil {
		return fmt.Errorf("Request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &serverError{status: resp.StatusCode, detail: readDetail(resp)}
	}
	var result struct {
		Items []struct {
			Token string `json:"token"`
			Found bool   `json:"found"`
			manageStatus
		} `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&result); err != nil {
		return fmt.Errorf("Invalid server response: %w", err)
	}
	if len(result.Items) != 1 {
		return fmt.Errorf("Invalid server response: expected one item, got %d", len(result.Items))
	}
	item := result.Items[0]
	if !item.Found {
		return fmt.Errorf("Not found: wrong management key, or the file has expired and been removed")
	}
	st := item.manageStatus
	st.State = stripControl(st.State)

	if jsonMode {
		writeJSON(struct {
			OK     bool         `json:"ok"`
			Token  string       `json:"token"`
			Status manageStatus `json:"status"`
		}{true, token, st})
		return nil
	}

	stateColor := c(cGreen)
	switch st.State {
	case "active":
	case "expired", "deleted":
		stateColor = c(cGray)
	case "burned":
		stateColor = c(cAmber)
	default:
		stateColor = c(cWhite)
	}
	var flags []string
	if st.Burn {
		flags = append(flags, "burn after reading")
	}
	if st.Note {
		flags = append(flags, "note")
	}
	if st.UploaderOnly {
		flags = append(flags, "private")
	}
	fmt.Fprintf(os.Stderr, "%sToken:%s      %s%s%s\n", c(cGray), c(cReset), c(cBold), token, c(cReset))
	fmt.Fprintf(os.Stderr, "%sState:%s      %s%s%s\n", c(cGray), c(cReset), stateColor, st.State, c(cReset))
	fmt.Fprintf(os.Stderr, "%sSize:%s       %s\n", c(cGray), c(cReset), humanBytes(st.SizeBytes))
	fmt.Fprintf(os.Stderr, "%sCreated:%s    %s\n", c(cGray), c(cReset), localTime(st.CreatedAt))
	if st.Permanent {
		fmt.Fprintf(os.Stderr, "%sExpires:%s    %spermanent%s\n", c(cGray), c(cReset), c(cBlue), c(cReset))
	} else {
		fmt.Fprintf(os.Stderr, "%sExpires:%s    %s\n", c(cGray), c(cReset), localTime(st.ExpiresAt))
	}
	fmt.Fprintf(os.Stderr, "%sDownloads:%s  %d", c(cGray), c(cReset), st.Downloads)
	if st.LastDownloadAt > 0 {
		fmt.Fprintf(os.Stderr, " %s(last %s)%s", c(cGray), localTime(st.LastDownloadAt), c(cReset))
	}
	fmt.Fprintln(os.Stderr)
	if st.PartReads > 0 {
		fmt.Fprintf(os.Stderr, "%sOpened on page:%s %d %s(last %s)%s\n", c(cGray), c(cReset), st.PartReads, c(cGray), localTime(st.LastPartAt), c(cReset))
	}
	if len(flags) > 0 {
		fmt.Fprintf(os.Stderr, "%sFlags:%s      %s\n", c(cGray), c(cReset), strings.Join(flags, ", "))
	}
	return nil
}

func localTime(unix int64) string {
	if unix <= 0 {
		return "-"
	}
	return time.Unix(unix, 0).Format("2006-01-02 15:04")
}
