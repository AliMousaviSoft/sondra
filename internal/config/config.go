package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config is the single source of truth passed to every module and the TUI.
type Config struct {
	Domain          string
	OutputDir       string
	Excluded        []string
	Concurrency     int
	RateLimit       int
	Timeout         time.Duration
	CacheAge        time.Duration
	ResolversFile   string
	NucleiTemplates string
	Modules         ModuleFlags
	Version         string
	// SkipSelector is true when -y/--yes is passed: bypass the interactive TUI module selector.
	SkipSelector bool
	// Preset is the module preset applied when SkipSelector is true or used as default selection.
	Preset string
	// Notify holds outbound notification settings (Discord/Telegram/webhook).
	Notify NotifyConfig
}

// NotifyConfig configures where scan lifecycle events are delivered.
type NotifyConfig struct {
	Discord       string         // Discord incoming-webhook URL
	Telegram      TelegramConfig // Telegram bot token + chat id
	Webhook       string         // generic JSON webhook URL
	MinSeverity   string         // lowest nuclei severity to list in summaries (critical|high|medium|low)
	NotifyOnStart bool           // also send a message when a scan starts (default off)
	OnlyNotable   bool           // only send the finish message when there's signal (findings/new subs/takeovers) or an error
}

// TelegramConfig holds Telegram Bot API credentials.
type TelegramConfig struct {
	Token  string
	ChatID string
}

// Active reports whether at least one notification channel is configured.
func (n NotifyConfig) Active() bool {
	return n.Discord != "" || n.Webhook != "" || (n.Telegram.Token != "" && n.Telegram.ChatID != "")
}

// ModuleFlags controls which recon steps are active.
type ModuleFlags struct {
	Subfinder    bool
	Assetfinder  bool
	Crtsh        bool
	Alterx       bool
	Massdns      bool
	Httpx        bool
	Takeover     bool
	Naabu        bool
	Gowitness    bool
	Gau          bool
	Gowayback    bool
	Katana       bool
	NucleiHigh   bool
	NucleiMedium bool
}

// Load builds a Config by merging, in ascending priority order:
//  1. Hard-coded defaults
//  2. ~/.sondra.yaml
//  3. .sondra.yaml in the current directory
//  4. Environment variables (SONDRA_ prefix)
//  5. CLI flags passed in (domain, excluded, preset)
func Load(cfgFile, domain string, excluded []string, preset string, skipSelector bool) (*Config, error) {
	v := viper.New()

	// ── defaults ──────────────────────────────────────────────────────────
	v.SetDefault("concurrency", 50)
	v.SetDefault("rate_limit", 150)
	v.SetDefault("timeout", "10s")
	v.SetDefault("cache_age", "24h")
	v.SetDefault("resolvers_file", "")
	v.SetDefault("nuclei_templates", nucleiDefaultTemplates())
	v.SetDefault("output_base", ".")
	v.SetDefault("notify.min_severity", "high")
	v.SetDefault("notify.on_start", false)
	v.SetDefault("notify.only_notable", false)

	// ── config files ──────────────────────────────────────────────────────
	v.SetConfigType("yaml")
	v.SetConfigName(".sondra")

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		// Let viper search in order: current dir first, then home.
		// First match wins.
		v.AddConfigPath(".")
		if home, err := os.UserHomeDir(); err == nil {
			v.AddConfigPath(home)
		}
	}

	// Ignore "not found" — defaults cover missing config.
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("config file error: %w", err)
		}
	}
	// fmt.Fprintf(os.Stderr, "DEBUG config=%s resolvers=%s\n", v.ConfigFileUsed(), v.GetString("resolvers_file"))

	// ── env vars ──────────────────────────────────────────────────────────
	v.SetEnvPrefix("SONDRA")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	// ── parse durations ───────────────────────────────────────────────────
	timeout, err := time.ParseDuration(v.GetString("timeout"))
	if err != nil {
		return nil, fmt.Errorf("invalid timeout %q: %w", v.GetString("timeout"), err)
	}
	cacheAge, err := time.ParseDuration(v.GetString("cache_age"))
	if err != nil {
		return nil, fmt.Errorf("invalid cache_age %q: %w", v.GetString("cache_age"), err)
	}

	// ── build output dir ──────────────────────────────────────────────────
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	outputDir := buildOutputDir(v.GetString("output_base"), domain)

	// fmt.Println("Config file used:", v.ConfigFileUsed())
	// fmt.Printf("DEBUG resolvers_file raw: '%s'\n", v.GetString("resolvers_file"))
	// fmt.Printf("DEBUG all keys: %+v\n", v.AllKeys())
	// ── assemble config ───────────────────────────────────────────────────
	cfg := &Config{
		Domain:          domain,
		OutputDir:       outputDir,
		Excluded:        excluded,
		Concurrency:     v.GetInt("concurrency"),
		RateLimit:       v.GetInt("rate_limit"),
		Timeout:         timeout,
		CacheAge:        cacheAge,
		ResolversFile:   v.GetString("resolvers_file"),
		NucleiTemplates: v.GetString("nuclei_templates"),
		SkipSelector:    skipSelector,
		Preset:          preset,
		Notify: NotifyConfig{
			Discord: v.GetString("notify.discord"),
			Telegram: TelegramConfig{
				Token:  v.GetString("notify.telegram.token"),
				ChatID: v.GetString("notify.telegram.chat_id"),
			},
			Webhook:       v.GetString("notify.webhook"),
			MinSeverity:   v.GetString("notify.min_severity"),
			NotifyOnStart: v.GetBool("notify.on_start"),
			OnlyNotable:   v.GetBool("notify.only_notable"),
		},
	}

	// Apply preset to ModuleFlags when skipping the selector.
	if skipSelector {
		cfg.Modules = PresetModules(preset)
	}

	return cfg, nil
}

// ParseModules turns an explicit module list (e.g. []string{"subfinder","httpx"})
// into ModuleFlags, overriding presets for fine-grained control. Unknown names
// return an error. Note the modules form a pipeline: downstream modules (httpx,
// naabu, nuclei) need an upstream enum source (subfinder/assetfinder/crtsh) to
// have anything to work on.
func ParseModules(names []string) (ModuleFlags, error) {
	var m ModuleFlags
	var unknown []string
	for _, raw := range names {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "":
			continue
		case "subfinder":
			m.Subfinder = true
		case "assetfinder":
			m.Assetfinder = true
		case "crtsh", "crt.sh":
			m.Crtsh = true
		case "alterx":
			m.Alterx = true
		case "massdns":
			m.Massdns = true
		case "httpx", "probe":
			m.Httpx = true
		case "takeover", "takeovers":
			m.Takeover = true
		case "naabu", "ports":
			m.Naabu = true
		case "gowitness", "screenshots":
			m.Gowitness = true
		case "gau":
			m.Gau = true
		case "gowayback", "gowaybackgo", "wayback":
			m.Gowayback = true
		case "katana":
			m.Katana = true
		case "nuclei":
			m.NucleiHigh, m.NucleiMedium = true, true
		case "nuclei-high", "nucleihigh":
			m.NucleiHigh = true
		case "nuclei-medium", "nucleimedium":
			m.NucleiMedium = true
		default:
			unknown = append(unknown, raw)
		}
	}
	if len(unknown) > 0 {
		return m, fmt.Errorf("unknown module(s): %s (valid: subfinder, assetfinder, crtsh, alterx, massdns, httpx, takeover, naabu, gowitness, gau, gowayback, katana, nuclei, nuclei-high, nuclei-medium)", strings.Join(unknown, ", "))
	}
	return m, nil
}

// PresetModules returns ModuleFlags for a named preset.
func PresetModules(preset string) ModuleFlags {
	switch strings.ToLower(preset) {
	case "quick":
		return ModuleFlags{
			Subfinder: true, Crtsh: true,
			Httpx: true, NucleiHigh: true,
		}
	case "passive":
		return ModuleFlags{
			Subfinder: true, Assetfinder: true, Crtsh: true,
		}
	case "enum":
		return ModuleFlags{
			Subfinder: true, Assetfinder: true, Crtsh: true,
			Alterx: true, Massdns: true,
			Httpx: true, Naabu: true,
		}
	case "vuln":
		return ModuleFlags{
			NucleiHigh: true, NucleiMedium: true,
		}
	default: // "full"
		return ModuleFlags{
			Subfinder: true, Assetfinder: true, Crtsh: true,
			Alterx: true, Massdns: true,
			Httpx: true, Takeover: true, Naabu: true,
			Gowitness: true, Gau: true, Gowayback: true, Katana: true,
			NucleiHigh: true, NucleiMedium: true,
		}
	}
}

// buildOutputDir constructs a timestamped output directory path.
// Format: <base>/<domain>/recon-<YYYY-MM-DD_HH-MM>
func buildOutputDir(base, domain string) string {
	ts := time.Now().Format("2006-01-02_15-04")
	dir := filepath.Join(base, domain, "recon-"+ts)
	return dir
}

// nucleiDefaultTemplates returns the default nuclei templates path.
func nucleiDefaultTemplates() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "nuclei-templates")
}
