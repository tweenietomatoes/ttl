package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
)

// version is set at build time by goreleaser via ldflags.
var version = "dev"

var jsonMode bool // set by the --json flag

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Strip global flags before routing to subcommands
	var args []string
	for _, a := range os.Args[1:] {
		if a == "-h3" || a == "--h3" || a == "-http3" || a == "--http3" {
			forceH3 = true
		} else if a == "--json" {
			jsonMode = true
		} else {
			args = append(args, a)
		}
	}
	if len(args) == 0 {
		if jsonMode {
			exitError(fmt.Errorf("No command specified"))
		}
		printUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "send":
		if err := runSend(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				os.Exit(0)
			}
			exitError(err)
		}
	case "get":
		if err := runGet(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				os.Exit(0)
			}
			exitError(err)
		}
	case "version":
		if jsonMode {
			json.NewEncoder(os.Stdout).Encode(map[string]any{
				"ok":      true,
				"version": version,
			})
		} else {
			fmt.Printf("ttl %s\n", version)
		}
	default:
		if jsonMode {
			exitError(fmt.Errorf("Unknown command: %s", stripControl(args[0])))
		}
		printUsage()
		os.Exit(1)
	}
}

func exitError(err error) {
	if jsonMode {
		json.NewEncoder(os.Stdout).Encode(map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
	} else {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
	os.Exit(1)
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `ttl.space — End-to-end encrypted ephemeral storage

Files are encrypted on your device before upload.
The server never sees your data or password.
Passwords are auto-generated during send if not provided.
Default time to live is 7 days.

Usage:
  ttl send [-p P | --password P | --password-stdin | --password-file F] [-t DUR] [-b] [--json] [--timeout D] FILE
  ttl get  [-p P | --password P | --password-stdin | --password-file F] [--json] [--timeout D] [-o DIR] URL or TOKEN
  ttl version

Options:
  -p, --password P       Encryption/decryption password
  -t, --ttl DUR          Time to live: 5m,10m,15m,30m,1h,2h,3h,6h,12h,24h,1d,2d,3d,4d,5d,6d,7d (default: 7d)
  -b, --burn             Burn after reading (file is deleted after first download)
  -o, --output DIR       Output directory for downloaded file (default: current directory)
  --json                 Output JSON to stdout (for scripts and AI agents)
  --timeout D            Transfer timeout (e.g. 5m, 1h). Default: auto (assumes 1 Mbps)
  --password-stdin       Read password from stdin (for scripts)
  --password-file F      Read password from file (for scripts)
  -h3, --http3           Try HTTP/3 (QUIC) first, fall back to TCP if unavailable

Password: Auto-generated if not provided during send.
  -p / --password is visible in ps output and shell history.
  Prefer --password-stdin or --password-file in scripts.
  --json auto-generates a password if none is provided.

Download: You can pass a full URL or just the 10-character token.
  ttl get aBcDeFgHiJ  is the same as  ttl get https://ttl.space/aBcDeFgHiJ`)
}
