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

	// Strip global flags before subcommand dispatch. "--" stops scanning
	// so a positional like a file literally named "--json" gets through.
	var args []string
	passthrough := false
	for _, a := range os.Args[1:] {
		if passthrough {
			args = append(args, a)
			continue
		}
		if a == "--" {
			passthrough = true
			args = append(args, a)
			continue
		}
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
				exitHelp()
			}
			exitError(err)
		}
	case "get":
		if err := runGet(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				exitHelp()
			}
			exitError(err)
		}
	case "activate":
		if err := runActivate(args[1:]); err != nil {
			exitError(err)
		}
		if jsonMode {
			json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "activated": true})
		}
	case "deactivate":
		if err := runDeactivate(args[1:]); err != nil {
			exitError(err)
		}
		if jsonMode {
			json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "deactivated": true})
		}
	case "plan":
		if err := runPlan(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				exitHelp()
			}
			exitError(err)
		}
	case "list":
		if err := runList(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				exitHelp()
			}
			exitError(err)
		}
	case "delete":
		if err := runDelete(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				exitHelp()
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

func exitHelp() {
	if jsonMode {
		json.NewEncoder(os.Stdout).Encode(map[string]any{
			"ok":    false,
			"error": "Use --help without --json for usage information",
		})
		os.Exit(0)
	}
	os.Exit(0)
}

func exitError(err error) {
	if jsonMode {
		json.NewEncoder(os.Stdout).Encode(map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
	} else {
		fmt.Fprintf(os.Stderr, "%sError:%s %v\n", c(cRed, cBold), c(cReset), err)
	}
	os.Exit(1)
}

func printUsage() {
	B := c(cBold)          // bold
	R := c(cReset)         // reset
	T := c(cBlue, cBold)   // title
	F := c(cAmber)         // flags
	D := c(cGray)          // dim/description
	U := c(cLightBlue)     // url
	Cm := c(cTeal)         // command

	fmt.Fprintf(os.Stderr, `%sttl.space%s %s— Encrypted file transfer. Ephemeral by design, permanent with Orbit.%s

%sFiles are encrypted on your device before upload.%s
%sThe server never sees your data or password.%s
%sPasswords are auto-generated during send if not provided.%s
%sDefault time to live is 7 days.%s

%sUsage:%s
  %sttl send%s %s[-p P | --password P | --password-stdin | --password-file F] [-t DUR] [-b] [-u] [--json] [--timeout D]%s %sFILE%s
  %sttl get%s  %s[-p P | --password P | --password-stdin | --password-file F] [--json] [--timeout D] [-o DIR]%s %sURL or TOKEN%s
  %sttl activate%s %s<key>%s           %sActivate Orbit plan%s
  %sttl deactivate%s               %sRemove stored Orbit key%s
  %sttl plan%s                     %sShow current plan and usage%s
  %sttl list%s                     %sList recent uploads (Orbit)%s
  %sttl delete%s %s<token>%s           %sDelete a file early (Orbit)%s
  %sttl version%s

%sOptions:%s
  %s-p, --password P%s       %sEncryption/decryption password%s
  %s-t, --ttl DUR%s          %sTime to live: 5m,10m,15m,30m,1h,2h,3h,6h,12h,24h,1d-7d (default: 7d, Orbit: up to 30d or permanent)%s
  %s-b, --burn%s             %sBurn after reading (file is deleted after first download)%s
  %s-u, --uploader-only%s    %sPrivate file (Orbit): only the uploader's API key can download it%s
  %s-o, --output DIR%s       %sOutput directory for downloaded file (default: current directory)%s
  %s--json%s                 %sOutput JSON to stdout (for scripts and AI agents)%s
  %s--timeout D%s            %sTransfer timeout (e.g. 5m, 1h). Default: auto (assumes 1 Mbps)%s
  %s--password-stdin%s       %sRead password from stdin (for scripts)%s
  %s--password-file F%s      %sRead password from file (for scripts)%s
  %s-h3, --http3%s           %sTry HTTP/3 (QUIC) first, fall back to TCP if unavailable%s

%sPassword:%s Auto-generated if not provided during send.
  %sAuto-detected from ttl.password next to binary or ~/.ttl/password.%s
  %s-p / --password is visible in ps output and shell history.%s
  %sPrefer --password-stdin or --password-file in scripts.%s
  %s--json auto-generates a password if none is provided.%s

%sOrbit key:%s %sAuto-detected from TTL_API_KEY env, ttl.key next to binary, or ~/.ttl/key.%s
  %sPassed automatically on get/probe so private (uploader-only) files open transparently.%s

%sDownload:%s You can pass a full URL or just the 10-character token.
  %sttl get aBcDeFgHiJ%s  is the same as  %sttl get%s %s%s%s
`,
		T, R, D, R,
		D, R,
		D, R,
		D, R,
		D, R,
		B, R,
		Cm, R, F, R, B, R,
		Cm, R, F, R, B, R,
		Cm, R, B, R, D, R,
		Cm, R, D, R,
		Cm, R, D, R,
		Cm, R, D, R,
		Cm, R, B, R, D, R,
		Cm, R,
		B, R,
		F, R, D, R,
		F, R, D, R,
		F, R, D, R,
		F, R, D, R,
		F, R, D, R,
		F, R, D, R,
		F, R, D, R,
		F, R, D, R,
		F, R, D, R,
		F, R, D, R,
		B, R,
		D, R,
		D, R,
		D, R,
		D, R,
		B, R, D, R,
		D, R,
		B, R,
		Cm, R, Cm, R, U, "https://ttl.space/aBcDeFgHiJ", R,
	)
}
