package main

import (
	"os"

	"golang.org/x/term"
)

// Disable colour when piped or when NO_COLOR is set (https://no-color.org/).
var colorEnabled = func() bool {
	_, noColor := os.LookupEnv("NO_COLOR")
	return !noColor && term.IsTerminal(int(os.Stderr.Fd()))
}()

// Colours lifted from the ttl.space CSS palette.
const (
	cReset = "\033[0m"
	cBold  = "\033[1m"

	cBlue      = "\033[38;2;37;99;235m"   // #2563eb — primary brand
	cLightBlue = "\033[38;2;147;197;253m"  // #93c5fd — URLs/links
	cTeal      = "\033[38;2;94;234;212m"   // #5eead4 — success/accent
	cAmber     = "\033[38;2;251;191;36m"   // #fbbf24 — warnings
	cRed       = "\033[38;2;239;68;68m"    //nolint:gosec // ANSI escape, not a credential
	cGreen     = "\033[38;2;52;211;153m"   // #34d399 — emerald success
	cGold      = "\033[38;2;212;160;86m"   // #d4a056 — glyphs
	cGray      = "\033[38;2;107;122;153m"  // #6b7a99 — secondary
	cWhite     = "\033[38;2;208;223;240m"  // #d0dff0 — bright text
)

// c joins ANSI codes; returns "" when colour is off.
func c(codes ...string) string {
	if !colorEnabled {
		return ""
	}
	s := ""
	for _, code := range codes {
		s += code
	}
	return s
}
