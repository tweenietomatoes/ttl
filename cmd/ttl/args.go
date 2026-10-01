package main

import "flag"

// parseArgs parses a subcommand's flags wherever they appear — before or
// after the positional arguments ("ttl delete TOKEN -k KEY" as well as
// "ttl delete -k KEY TOKEN") — and returns the positionals in order. A
// "--" ends flag parsing; everything after it is positional.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		consumed := len(args) - len(rest)
		if consumed > 0 && args[consumed-1] == "--" {
			return append(positional, rest...), nil
		}
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}
