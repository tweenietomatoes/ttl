package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const keyPrefix = "ttl_orbit_"
const keyFileName = "ttl.key"

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
		if k, err := os.ReadFile(p); err == nil {
			if s := strings.TrimSpace(string(k)); s != "" {
				return s
			}
		}
	}

	// 3. ~/.ttl/key
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".ttl", "key")
		if k, err := os.ReadFile(p); err == nil {
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
		if err := os.WriteFile(p, []byte(key+"\n"), 0600); err == nil {
			return p, nil
		}
	}
	// Fallback to ~/.ttl/key
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("Cannot determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".ttl")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("Cannot create key directory: %w", err)
	}
	p := filepath.Join(dir, "key")
	if err := os.WriteFile(p, []byte(key+"\n"), 0600); err != nil {
		return "", fmt.Errorf("Cannot write key file: %w", err)
	}
	return p, nil
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
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return fmt.Errorf("Invalid key format (non-alphanumeric character in key body)")
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
	if len(args) != 1 {
		return fmt.Errorf("Usage: ttl activate <api-key>")
	}

	key := strings.TrimSpace(args[0])
	if err := validateKeyFormat(key); err != nil {
		return err
	}

	path, err := saveAPIKey(key)
	if err != nil {
		return err
	}

	if jsonMode {
		return nil // JSON output handled in main
	}
	fmt.Fprintf(os.Stderr, "%sOrbit plan activated.%s Key saved to %s%s%s\n", c(cGreen), c(cReset), c(cGray), path, c(cReset))
	return nil
}

func runDeactivate(args []string) error {
	if len(args) != 0 {
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
		return nil
	}
	for _, p := range removed {
		fmt.Fprintf(os.Stderr, "Key file removed: %s%s%s\n", c(cGray), p, c(cReset))
	}
	if len(removed) == 0 {
		fmt.Fprintf(os.Stderr, "%sNo key file found.%s\n", c(cGray), c(cReset))
	}
	return nil
}
