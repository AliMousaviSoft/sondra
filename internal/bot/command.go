package bot

import (
	"fmt"
	"strings"
	"time"
)

// Command is a parsed chat command with full scan/monitor flag parity.
type Command struct {
	Name     string // scan | monitor | diff | status | list | stop | report | help
	Domain   string
	Preset   string
	Modules  []string
	Exclude  []string
	Interval time.Duration
	OnMode   string
	Arg      string // positional argument for stop/report (a job id)
}

// parseCommand parses a Telegram message body like:
//
//	/scan example.com quick --modules subfinder,httpx --exclude foo.example.com
//	/monitor example.com --interval 6h --on findings
//	/stop 3
//
// It tolerates the "--flag value" and "--flag=value" forms and strips a
// "@botname" suffix from the command token (Telegram adds it in groups).
func parseCommand(text string) (Command, error) {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return Command{}, fmt.Errorf("empty command")
	}

	name := strings.TrimPrefix(fields[0], "/")
	if i := strings.IndexByte(name, '@'); i >= 0 {
		name = name[:i]
	}
	c := Command{Name: strings.ToLower(name), Preset: "quick", OnMode: "all"}

	args := fields[1:]
	var positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		key, inline, hasInline := strings.Cut(a, "=")

		next := func() (string, bool) {
			if hasInline {
				return inline, true
			}
			if i+1 < len(args) {
				i++
				return args[i], true
			}
			return "", false
		}

		switch key {
		case "--modules", "-m":
			if v, ok := next(); ok {
				c.Modules = append(c.Modules, splitCSV(v)...)
			}
		case "--exclude", "-e":
			if v, ok := next(); ok {
				c.Exclude = append(c.Exclude, splitCSV(v)...)
			}
		case "--on":
			if v, ok := next(); ok {
				c.OnMode = strings.ToLower(strings.TrimSpace(v))
			}
		case "--interval", "-i":
			v, ok := next()
			if !ok {
				return c, fmt.Errorf("--interval needs a value (e.g. 6h)")
			}
			d, err := time.ParseDuration(v)
			if err != nil {
				return c, fmt.Errorf("bad interval %q (try 30m, 6h)", v)
			}
			c.Interval = d
		case "--preset", "-p":
			if v, ok := next(); ok {
				c.Preset = strings.ToLower(strings.TrimSpace(v))
			}
		default:
			if strings.HasPrefix(a, "-") {
				return c, fmt.Errorf("unknown flag %q", a)
			}
			positional = append(positional, a)
		}
	}

	if len(positional) > 0 {
		c.Domain = strings.ToLower(strings.TrimSpace(positional[0]))
		c.Arg = positional[0]
	}
	// Second positional is the preset for scan/monitor (e.g. "/scan x.com full").
	if len(positional) > 1 && isPreset(positional[1]) {
		c.Preset = strings.ToLower(positional[1])
	}
	return c, nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isPreset(s string) bool {
	switch strings.ToLower(s) {
	case "full", "quick", "passive", "enum", "vuln":
		return true
	}
	return false
}
