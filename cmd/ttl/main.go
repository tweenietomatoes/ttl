// Package main is the ttl CLI: send / get / status / list / delete files on
// ttl.space with end-to-end encryption.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

// version is set at build time by goreleaser via ldflags.
var version = "dev"

var jsonMode bool // set by the --json flag

// commands maps a subcommand to its runner. Each runner parses its own
// flags and answers flag.ErrHelp for -h.
var commands = map[string]func([]string) error{
	"send":       runSend,
	"get":        runGet,
	"status":     runStatus,
	"activate":   runActivate,
	"deactivate": runDeactivate,
	"plan":       runPlan,
	"list":       runList,
	"delete":     runDelete,
}

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
		switch a {
		case "-h3", "--h3", "-http3", "--http3":
			forceH3 = true
		case "--json":
			jsonMode = true
		default:
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
	case "version", "--version", "-v":
		if jsonMode {
			writeJSON(struct {
				OK      bool   `json:"ok"`
				Version string `json:"version"`
			}{true, version})
		} else {
			fmt.Printf("ttl %s\n", version)
		}
		return
	case "help", "-h", "--help":
		if !jsonMode {
			printUsage()
		}
		exitHelp()
	}

	run, ok := commands[args[0]]
	if !ok {
		if jsonMode {
			exitError(fmt.Errorf("Unknown command: %s", stripControl(args[0])))
		}
		fmt.Fprintf(os.Stderr, "%sError:%s Unknown command: %s\n\n", c(cRed, cBold), c(cReset), stripControl(args[0]))
		printUsage()
		os.Exit(1)
	}
	if err := run(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			exitHelp()
		}
		exitError(err)
	}
}

// exitHelp ends a -h run. The flag package has printed the usage text by
// then; in --json mode a note goes out instead.
func exitHelp() {
	if jsonMode {
		writeJSON(jsonError{Error: "Use --help without --json for usage information"})
	}
	os.Exit(0)
}

func exitError(err error) {
	if jsonMode {
		writeJSON(jsonError{Error: err.Error()})
	} else {
		fmt.Fprintf(os.Stderr, "%sError:%s %v\n", c(cRed, cBold), c(cReset), err)
	}
	os.Exit(1)
}

// jsonError is the --json shape of a failure: {"ok":false,"error":"…"}.
type jsonError struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

// writeJSON prints one JSON document on stdout, the whole output of a
// --json run.
func writeJSON(v any) {
	_ = json.NewEncoder(os.Stdout).Encode(v)
}

// usageText is the help page. Markers in braces are colour codes,
// replaced in printUsage: {T} title, {B} bold, {C} command, {F} flag,
// {D} dim, {U} url, {R} reset.
const usageText = `{T}ttl.space{R} {D}— Encrypted file transfer. Ephemeral by design, permanent with Orbit.{R}

{D}Files are encrypted on your device before upload.{R}
{D}The server never sees your data or password.{R}
{D}Passwords are auto-generated during send if not provided.{R}
{D}Default time to live is 7 days.{R}

{B}Usage:{R}
  {C}ttl send{R} {F}[-p P | --password-stdin | --password-file F] [-t DUR] [-b] [-u] [--timeout D]{R} {B}FILE{R}
  {C}ttl get{R}  {F}[-p P | --password-stdin | --password-file F] [-o DIR] [--timeout D]{R} {B}URL or TOKEN{R}
  {C}ttl status{R} {B}<token>{R} {F}-k KEY{R}        {D}Status of an upload (management key from send){R}
  {C}ttl delete{R} {B}<token>{R} {F}[-k KEY]{R}      {D}Delete a file early (Orbit key, or the management key){R}
  {C}ttl activate{R} {F}[--key-stdin | --key-file F | <key>]{R}   {D}Activate Orbit plan{R}
  {C}ttl deactivate{R}                  {D}Remove stored Orbit key{R}
  {C}ttl plan{R}                        {D}Show current plan and usage{R}
  {C}ttl list{R} {F}[-n N]{R}                 {D}List uploads (Orbit){R}
  {C}ttl version{R}

{B}Options:{R}
  {F}-p, --password P{R}       {D}Encryption/decryption password{R}
  {F}-t, --ttl DUR{R}          {D}Time to live: 5m,10m,15m,30m,1h,2h,3h,6h,12h,24h,1d-7d (default: 7d, Orbit: 14d,15d,28d,30d,permanent){R}
  {F}-b, --burn{R}             {D}Burn after reading (file is deleted after first download){R}
  {F}-u, --uploader-only{R}    {D}Private file (Orbit): only the uploader's API key can download it{R}
  {F}-o, --output DIR{R}       {D}Output directory for downloaded file (default: current directory){R}
  {F}-k, --manage-key KEY{R}   {D}Management key printed by ttl send (status / early delete on any plan){R}
  {F}-n, --limit N{R}          {D}List at most N files (default: all){R}
  {F}--server URL{R}           {D}Server to talk to (default: https://ttl.space){R}
  {F}--json{R}                 {D}Output JSON to stdout (for scripts and AI agents){R}
  {F}--timeout D{R}            {D}Transfer timeout (e.g. 5m, 1h). Default: auto (assumes 1 Mbps){R}
  {F}--password-stdin{R}       {D}Read password from stdin (for scripts){R}
  {F}--password-file F{R}      {D}Read password from file (for scripts){R}
  {F}-h3, --http3{R}           {D}Try HTTP/3 (QUIC) first, fall back to TCP if unavailable{R}

{B}Password:{R} Auto-generated if not provided during send.
  {D}Auto-detected from ttl.password next to binary or ~/.ttl/password.{R}
  {D}-p / --password is visible in ps output and shell history.{R}
  {D}Prefer --password-stdin or --password-file in scripts.{R}
  {D}--json auto-generates a password if none is provided.{R}

{B}Manage key:{R} {D}Printed once by ttl send (manage_key in --json). It lets you check the{R}
  {D}upload's status or delete it early on any plan: ttl status|delete TOKEN -k KEY.{R}

{B}Orbit key:{R} {D}Auto-detected from TTL_API_KEY env, ttl.key next to binary, or ~/.ttl/key.{R}
  {D}Passed automatically on get/probe so private (uploader-only) files open transparently.{R}

{B}Transfers:{R} {D}Large uploads go in resumable parts and interrupted downloads resume,{R}
  {D}so a dropped connection continues where it stopped. Ctrl-C cancels cleanly.{R}

{B}Download:{R} You can pass a full URL or just the 10-character token.
  {C}ttl get aBcDeFgHiJ{R}  is the same as  {C}ttl get{R} {U}https://ttl.space/aBcDeFgHiJ{R}
`

func printUsage() {
	r := strings.NewReplacer(
		"{T}", c(cBlue, cBold),
		"{B}", c(cBold),
		"{C}", c(cTeal),
		"{F}", c(cAmber),
		"{D}", c(cGray),
		"{U}", c(cLightBlue),
		"{R}", c(cReset),
	)
	fmt.Fprint(os.Stderr, r.Replace(usageText))
}
