package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"
)

const keyPrefix = "ttl_orbit_"
const keyFileName = "ttl.key"

// manageKeyLen is a management key's length: 32 random bytes, base64url
// without padding (newManageKey on the server).
const manageKeyLen = 43

// loadAPIKey returns the API key from (in priority order):
//  1. TTL_API_KEY environment variable
//  2. ttl.key file next to the binary
//  3. ~/.ttl/key file
func loadAPIKey() string {
	// 1. Environment variable
	if k := os.Getenv("TTL_API_KEY"); k != "" {
		return strings.TrimSpace(k)
	}

	// 2. File next to the binary
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), keyFileName)
		if k, err := os.ReadFile(p); err == nil { //nolint:gosec // user-config path resolved relative to the user's own binary
			if s := strings.TrimSpace(string(k)); s != "" {
				return s
			}
		}
	}

	// 3. ~/.ttl/key
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".ttl", "key")
		if k, err := os.ReadFile(p); err == nil { //nolint:gosec // user-config path under $HOME
			if s := strings.TrimSpace(string(k)); s != "" {
				return s
			}
		}
	}

	return ""
}

func saveAPIKey(key string) (string, error) {
	// Try binary-adjacent first
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), keyFileName)
		if err := writeKeyAtomic(p, key); err == nil {
			return p, nil
		}
	}
	// Fallback to ~/.ttl/key
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("Cannot determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".ttl")
	if err := os.MkdirAll(dir, 0700); err != nil { //nolint:gosec // 0700 is the right perm for a key dir
		return "", fmt.Errorf("Cannot create key directory: %w", err)
	}
	// Tighten existing dir perms (some dotfile managers create at 0755).
	_ = os.Chmod(dir, 0700) //nolint:gosec // 0700 is the right perm for a key dir
	p := filepath.Join(dir, "key")
	if err := writeKeyAtomic(p, key); err != nil {
		return "", err
	}
	return p, nil
}

// writeKeyAtomic writes key to dst via tempfile + rename. Refuses to
// follow symlinks (multi-user box pre-planted symlink attack) and avoids
// torn writes that would otherwise leave dst empty on Ctrl-C.
func writeKeyAtomic(dst, key string) error {
	if fi, err := os.Lstat(dst); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("Refusing to write key: %s is a symlink", dst)
		}
	}
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".ttl-key-*")
	if err != nil {
		return fmt.Errorf("Cannot create temp key file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("Cannot set key file perms: %w", err)
	}
	if _, err := tmp.WriteString(key + "\n"); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("Cannot write key file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("Cannot fsync key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("Cannot close key file: %w", err)
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		cleanup()
		return fmt.Errorf("Cannot install key file: %w", err)
	}
	return nil
}

func validateKeyFormat(key string) error {
	if len(key) != len(keyPrefix)+48 {
		return fmt.Errorf("Invalid key format (expected %d characters, got %d)", len(keyPrefix)+48, len(key))
	}
	if !strings.HasPrefix(key, keyPrefix) {
		return fmt.Errorf("Invalid key format (must start with %s)", keyPrefix)
	}
	body := key[len(keyPrefix):]
	for _, c := range body {
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return fmt.Errorf("Invalid key format (non-alphanumeric character in key body)")
		}
	}
	return nil
}

// validateManageKey checks the shape of a management key (43 base64url
// characters), the same test the server applies.
func validateManageKey(key string) error {
	if len(key) != manageKeyLen {
		return fmt.Errorf("Invalid management key (expected %d characters, got %d)", manageKeyLen, len(key))
	}
	for _, c := range key {
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '-' && c != '_' {
			return fmt.Errorf("Invalid management key (unexpected character)")
		}
	}
	return nil
}

func setAPIKeyHeader(r interface{ Set(string, string) }, key string) {
	if key != "" {
		r.Set("X-API-Key", key)
	}
}

func runActivate(args []string) error {
	fs := flag.NewFlagSet("activate", flag.ContinueOnError)
	var keyStdin bool
	fs.BoolVar(&keyStdin, "key-stdin", false, "read the API key from stdin")
	var keyFile string
	fs.StringVar(&keyFile, "key-file", "", "read the API key from a file")
	var serverVal string
	fs.StringVar(&serverVal, "server", "https://ttl.space", "server URL")
	fs.Usage = func() {
		if !jsonMode {
			fmt.Fprintln(os.Stderr, "Usage: ttl activate [--key-stdin | --key-file F | <key>] [--server URL]")
		}
	}
	if jsonMode {
		fs.SetOutput(io.Discard)
	}
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := validateServerURL(serverVal); err != nil {
		return err
	}

	// stdin > file > positional. Positional kept for backward compat but
	// leaks the key to /proc and shell history.
	sources := 0
	if keyStdin {
		sources++
	}
	if keyFile != "" {
		sources++
	}
	if len(pos) > 0 {
		sources++
	}
	if sources == 0 {
		// Interactive prompt; also keeps the key out of argv/history.
		if !term.IsTerminal(int(os.Stdin.Fd())) { //nolint:gosec // stdin fd is 0..2, fits int
			return fmt.Errorf("No key provided; use --key-stdin or --key-file")
		}
		fmt.Fprintf(os.Stderr, "%sEnter Orbit API key:%s ", c(cGray), c(cReset))
		raw, err := term.ReadPassword(int(os.Stdin.Fd())) //nolint:gosec // stdin fd is 0..2, fits int
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return fmt.Errorf("Failed to read key")
		}
		return activateWithKey(strings.TrimSpace(string(raw)), serverVal)
	}
	if sources > 1 {
		return fmt.Errorf("Use only one of: --key-stdin, --key-file, or positional <key>")
	}

	switch {
	case keyStdin:
		// First line only; keys are 58 chars.
		br := bufio.NewReader(os.Stdin)
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return fmt.Errorf("Failed to read key from stdin: %w", err)
		}
		return activateWithKey(strings.TrimSpace(line), serverVal)
	case keyFile != "":
		// 4 KiB cap; misconfigured --key-file (/dev/zero, log) shouldn't OOM.
		f, err := os.Open(keyFile) //nolint:gosec // user-supplied --key-file
		if err != nil {
			return fmt.Errorf("Cannot read key file: %w", err)
		}
		defer f.Close()
		raw, err := io.ReadAll(io.LimitReader(f, 4096))
		if err != nil {
			return fmt.Errorf("Cannot read key file: %w", err)
		}
		if i := strings.IndexAny(string(raw), "\r\n"); i >= 0 {
			raw = raw[:i]
		}
		return activateWithKey(strings.TrimSpace(string(raw)), serverVal)
	default:
		if len(pos) != 1 {
			return fmt.Errorf("Usage: ttl activate [--key-stdin | --key-file F | <key>]")
		}
		// Positional still works but warn once (silent in JSON mode).
		if !jsonMode {
			fmt.Fprintf(os.Stderr, "%sNote:%s passing the key on the command line exposes it via /proc and shell history.\n      Prefer %s--key-stdin%s or %s--key-file%s.\n",
				c(cAmber, cBold), c(cReset),
				c(cBold), c(cReset),
				c(cBold), c(cReset))
		}
		return activateWithKey(strings.TrimSpace(pos[0]), serverVal)
	}
}

// activateWithKey checks the key's shape, asks the server whether it is
// live (a revoked or mistyped key is refused here instead of at the next
// upload), and stores it. A server that cannot be reached does not block
// the activation; the key is stored with a warning.
func activateWithKey(key, server string) error {
	if err := validateKeyFormat(key); err != nil {
		return err
	}
	plan := ""
	limits, err := fetchLimits(newConn(), server, key)
	switch {
	case err == nil:
		plan, _ = limits["plan"].(string)
		plan = stripControl(plan)
	case isKeyRejected(err):
		return fmt.Errorf("%w\nThe key was not saved", err)
	default:
		if !jsonMode {
			fmt.Fprintf(os.Stderr, "%sWarning:%s could not verify the key with the server (%v); saving it anyway.\n", c(cAmber, cBold), c(cReset), err)
		}
	}
	path, err := saveAPIKey(key)
	if err != nil {
		return err
	}
	if jsonMode {
		writeJSON(struct {
			OK        bool   `json:"ok"`
			Activated bool   `json:"activated"`
			Path      string `json:"path"`
			Plan      string `json:"plan,omitempty"`
		}{true, true, path, plan})
		return nil
	}
	fmt.Fprintf(os.Stderr, "%sOrbit plan activated.%s Key saved to %s%s%s\n", c(cGreen), c(cReset), c(cGray), path, c(cReset))
	if plan != "" && plan != "orbit" {
		fmt.Fprintf(os.Stderr, "%sNote:%s the server reports plan %q for this key.\n", c(cAmber, cBold), c(cReset), plan)
	}
	return nil
}

func runDeactivate(args []string) error {
	fs := flag.NewFlagSet("deactivate", flag.ContinueOnError)
	fs.Usage = func() {
		if !jsonMode {
			fmt.Fprintln(os.Stderr, "Usage: ttl deactivate (no arguments)")
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
		return fmt.Errorf("Usage: ttl deactivate (no arguments)")
	}

	var removed, failed []string

	// Try to remove the key file next to the binary
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), keyFileName)
		if _, statErr := os.Stat(p); statErr == nil {
			if err := os.Remove(p); err == nil {
				removed = append(removed, p)
			} else {
				failed = append(failed, p)
			}
		}
	}

	// Also try ~/.ttl/key
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".ttl", "key")
		if _, statErr := os.Stat(p); statErr == nil {
			if err := os.Remove(p); err == nil {
				removed = append(removed, p)
			} else {
				failed = append(failed, p)
			}
		}
	}

	if len(failed) > 0 {
		return fmt.Errorf("Cannot remove key file: %s (check permissions)", failed[0])
	}

	if jsonMode {
		if removed == nil {
			removed = []string{}
		}
		writeJSON(struct {
			OK          bool     `json:"ok"`
			Deactivated bool     `json:"deactivated"`
			Removed     []string `json:"removed"`
		}{true, true, removed})
		return nil
	}
	for _, p := range removed {
		fmt.Fprintf(os.Stderr, "Key file removed: %s%s%s\n", c(cGray), p, c(cReset))
	}
	if len(removed) == 0 {
		fmt.Fprintf(os.Stderr, "%sNo key file found.%s\n", c(cGray), c(cReset))
	}
	if os.Getenv("TTL_API_KEY") != "" && !jsonMode {
		fmt.Fprintf(os.Stderr, "%sNote:%s TTL_API_KEY is set in the environment and still applies.\n", c(cAmber, cBold), c(cReset))
	}
	return nil
}
