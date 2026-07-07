// Package doctor implements `sondra doctor`: a preflight check of the external
// tools, nuclei templates, and config that sondra needs before a scan, so a
// missing dependency is reported up front instead of failing mid-run.
package doctor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/AliMousaviSoft/sondra/internal/config"
)

// Kind classifies how a tool is provided.
type Kind int

const (
	Builtin Kind = iota // compiled in (Go lib) or plain HTTP — always available
	Binary              // external executable that must be on PATH
)

// Tool describes one dependency sondra relies on.
type Tool struct {
	Name        string
	Kind        Kind
	Bin         string   // executable name (Binary only)
	Install     string   // install hint (Binary only)
	VersionArgs []string // best-effort version probe
	Uses        string   // step(s) that need it (for display)
}

// Tools is the single source of truth for sondra's dependencies.
var Tools = []Tool{
	{Name: "subfinder", Kind: Builtin, Uses: "subfinder"},
	{Name: "crt.sh", Kind: Builtin, Uses: "crtsh"},
	{Name: "jsanalysis", Kind: Builtin, Uses: "jsanalysis"},
	{Name: "dnsx", Kind: Binary, Bin: "dnsx", VersionArgs: []string{"-version"}, Install: "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest", Uses: "resolve"},
	{Name: "httpx", Kind: Binary, Bin: "httpx", VersionArgs: []string{"-version"}, Install: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", Uses: "httpx probe"},
	{Name: "naabu", Kind: Binary, Bin: "naabu", VersionArgs: []string{"-version"}, Install: "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", Uses: "port scan"},
	{Name: "nuclei", Kind: Binary, Bin: "nuclei", VersionArgs: []string{"-version"}, Install: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", Uses: "nuclei, takeover"},
	{Name: "assetfinder", Kind: Binary, Bin: "assetfinder", Install: "go install github.com/tomnomnom/assetfinder@latest", Uses: "assetfinder"},
	{Name: "alterx", Kind: Binary, Bin: "alterx", VersionArgs: []string{"-version"}, Install: "go install github.com/projectdiscovery/alterx/cmd/alterx@latest", Uses: "active brute"},
	{Name: "massdns", Kind: Binary, Bin: "massdns", Install: "https://github.com/blechschmidt/massdns", Uses: "active brute"},
	{Name: "gau", Kind: Binary, Bin: "gau", VersionArgs: []string{"--version"}, Install: "go install github.com/lc/gau/v2/cmd/gau@latest", Uses: "url collection"},
	{Name: "gowaybackgo", Kind: Binary, Bin: "gowaybackgo", Install: "go install -v github.com/OoS-MaMaD/gowaybackgo@latest", Uses: "url collection"},
	{Name: "katana", Kind: Binary, Bin: "katana", VersionArgs: []string{"-version"}, Install: "go install github.com/projectdiscovery/katana/cmd/katana@latest", Uses: "url collection"},
	{Name: "gowitness", Kind: Binary, Bin: "gowitness", VersionArgs: []string{"version"}, Install: "go install github.com/sensepost/gowitness@latest", Uses: "screenshots"},
}

// Result is a probed tool.
type Result struct {
	Tool
	Found   bool
	Version string
}

var verRe = regexp.MustCompile(`v?\d+\.\d+(?:\.\d+)?`)

// Check probes every tool for presence and a best-effort version.
func Check() []Result {
	out := make([]Result, 0, len(Tools))
	for _, t := range Tools {
		r := Result{Tool: t}
		if t.Kind == Builtin {
			r.Found = true
		} else if _, err := exec.LookPath(t.Bin); err == nil {
			r.Found = true
			r.Version = probeVersion(t.Bin, t.VersionArgs)
		}
		out = append(out, r)
	}
	return out
}

func probeVersion(bin string, args []string) string {
	if len(args) == 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	if m := verRe.Find(out); m != nil {
		return strings.TrimPrefix(string(m), "v") // normalize v1.2.3 → 1.2.3
	}
	return ""
}

// humanAge renders a template-directory age compactly (e.g. "6h", "3d").
func humanAge(d time.Duration) string {
	if h := int(d.Hours()); h < 48 {
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dd", int(d.Hours())/24)
}

func foundSet(results []Result) map[string]bool {
	s := map[string]bool{}
	for _, r := range results {
		if r.Found && r.Kind == Binary {
			s[r.Bin] = true
		}
	}
	return s
}

// requiredBinaries returns the external binaries a module set needs to run.
func requiredBinaries(m config.ModuleFlags) []string {
	seen := map[string]bool{}
	var bins []string
	add := func(on bool, bin string) {
		if on && bin != "" && !seen[bin] {
			seen[bin] = true
			bins = append(bins, bin)
		}
	}
	add(m.Assetfinder, "assetfinder")
	add(m.Alterx, "alterx")
	add(m.Massdns, "massdns")
	// resolve (dnsx) runs whenever hosts must be resolved for httpx/naabu.
	if m.Httpx || m.Naabu {
		add(true, "dnsx")
	}
	add(m.Httpx, "httpx")
	add(m.Naabu, "naabu")
	add(m.Gau, "gau")
	add(m.Gowayback, "gowaybackgo")
	add(m.Katana, "katana")
	add(m.Gowitness, "gowitness")
	add(m.NucleiHigh || m.NucleiMedium || m.Takeover, "nuclei")
	return bins
}

// Run prints the full report and returns a process exit code (0 = all external
// tools present, 1 = at least one missing).
func Run(cfgFile string) int {
	results := Check()

	fmt.Println("sondra doctor — environment check")
	fmt.Println()

	fmt.Println("Recon tools")
	missing := 0
	for _, r := range results {
		switch {
		case r.Kind == Builtin:
			fmt.Printf("  ✓ %-13s built-in\n", r.Name)
		case r.Found:
			ver := r.Version
			if ver == "" {
				ver = "present"
			}
			fmt.Printf("  ✓ %-13s %s\n", r.Name, ver)
		default:
			missing++
			fmt.Printf("  ✗ %-13s NOT FOUND → %s\n", r.Name, r.Install)
		}
	}
	fmt.Println()

	found := foundSet(results)
	fmt.Println("Presets")
	for _, p := range []string{"quick", "passive", "enum", "full", "vuln"} {
		var miss []string
		for _, bin := range requiredBinaries(config.PresetModules(p)) {
			if !found[bin] {
				miss = append(miss, bin)
			}
		}
		if len(miss) == 0 {
			fmt.Printf("  ✓ %-8s ready\n", p)
		} else {
			fmt.Printf("  ✗ %-8s needs %s\n", p, strings.Join(miss, ", "))
		}
	}
	fmt.Println()

	fmt.Println("Config")
	if cfg, err := config.Load(cfgFile, "doctor.local", nil, "quick", true, false); err != nil {
		fmt.Printf("  ⚠ config load failed: %v\n", err)
	} else {
		if cfg.NucleiTemplates != "" {
			if fi, err := os.Stat(expandHome(cfg.NucleiTemplates)); err == nil && fi.IsDir() {
				fmt.Printf("  ✓ nuclei templates: %s (updated ~%s ago)\n",
					cfg.NucleiTemplates, humanAge(time.Since(fi.ModTime())))
			} else {
				fmt.Printf("  ✗ nuclei templates: %s not found → nuclei -update-templates\n", cfg.NucleiTemplates)
			}
		}
		if cfg.ResolversFile != "" {
			if _, err := os.Stat(cfg.ResolversFile); err == nil {
				fmt.Printf("  ✓ resolvers_file: %s\n", cfg.ResolversFile)
			} else {
				fmt.Printf("  ✗ resolvers_file: %s not found\n", cfg.ResolversFile)
			}
		}
		if ch := notifyChannels(cfg.Notify); ch != "" {
			fmt.Printf("  ✓ notifications: %s\n", ch)
		} else {
			fmt.Println("  – notifications: none configured")
		}
		var bot []string
		if cfg.Bot.TelegramEnabled() {
			bot = append(bot, "telegram")
		}
		if cfg.Bot.DiscordEnabled() {
			bot = append(bot, "discord")
		}
		if len(bot) > 0 {
			fmt.Printf("  ✓ control bot: %s\n", strings.Join(bot, "+"))
		} else {
			fmt.Println("  – control bot: not configured")
		}
	}
	fmt.Println()

	if missing == 0 {
		fmt.Println("All external tools present. ✓")
		return 0
	}
	fmt.Printf("%d tool(s) missing — install with the commands above. Built-in modules still work.\n", missing)
	return 1
}

func notifyChannels(n config.NotifyConfig) string {
	var on []string
	if n.Discord != "" {
		on = append(on, "discord")
	}
	if n.Telegram.Token != "" {
		on = append(on, "telegram")
	}
	if n.Webhook != "" {
		on = append(on, "webhook")
	}
	return strings.Join(on, ", ")
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}
