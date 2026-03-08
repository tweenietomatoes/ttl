package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

// version is set at build time by goreleaser via ldflags.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Remove the -h3 flag from args before passing them to subcommands
	var args []string
	for _, a := range os.Args[1:] {
		if a == "-h3" || a == "--h3" || a == "-http3" || a == "--http3" {
			forceH3 = true
		} else {
			args = append(args, a)
		}
	}
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "send":
		if err := runSend(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				os.Exit(0)
			}
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "get":
		if err := runGet(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				os.Exit(0)
			}
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "version":
		fmt.Printf("ttl %s\n", version)
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `ttl — end-to-end encrypted ephemeral storage

files are encrypted on your device before upload.
the server never sees your data or password.
passwords are auto-generated during send if not provided.
default time to live is 7 days. progress is shown during transfer.

usage:
  ttl send [-p P | --password P | --password-stdin | --password-file F] [-t DUR] [-b] [--timeout D] FILE
  ttl get  [-p P | --password P | --password-stdin | --password-file F] [--timeout D] [-o DIR] URL or TOKEN
  ttl version

options:
  -p, --password P       encryption/decryption password
  -t, --ttl DUR          time to live: 5m,10m,15m,30m,1h,2h,3h,6h,12h,24h,1d,2d,3d,4d,5d,6d,7d (default: 7d)
  -b, --burn             burn after reading (file is deleted after first download)
  -o, --output DIR       output directory for downloaded file (default: current directory)
  --timeout D            transfer timeout (e.g. 5m, 1h). default: auto (assumes 1 Mbps)
  --server URL           server endpoint (default: https://ttl.space)
  --password-stdin       read password from stdin (for scripts)
  --password-file F      read password from file (for scripts)
  -h3, --http3           try HTTP/3 (QUIC) first, fall back to TCP if unavailable

password: auto-generated if not provided during send.
  -p / --password is visible in ps output and shell history.
  prefer --password-stdin or --password-file in scripts.

download: you can pass a full URL or just the 10-character token.
  ttl get aBcDeFgHiJ  is the same as  ttl get https://ttl.space/aBcDeFgHiJ`)
}
