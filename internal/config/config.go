package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// firstNonEmpty returns the first non-blank string.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// parseStringList parses a comma-separated list into trimmed, non-empty items.
func parseStringList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseUserIDs parses a comma-separated list of Telegram user IDs.
func parseUserIDs(s string) []int64 {
	var ids []int64
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if id, err := strconv.ParseInt(part, 10, 64); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// Config is the single source of truth passed to every module and the TUI.
type Config struct {
	Domain          string
	OutputDir       string
	Excluded        []string
	Concurrency     int
	RateLimit       int
	WaybackRate     int // gowaybackgo CDX requests/sec (Wayback 429s easily)
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
	// Bot holds the Telegram control-bot settings.
	Bot BotConfig
}

// BotConfig configures the `sondra bot` control daemon (Telegram + Discord).
type BotConfig struct {
	Token        string   // Telegram bot token (falls back to notify.telegram.token)
	AllowedUsers []int64  // Telegram user IDs permitted to command the bot
	DiscordToken string   // Discord bot token (enables Discord slash commands)
	DiscordUsers []string // Discord user IDs permitted to command the bot
	DiscordGuild string   // optional: register slash commands to this guild (instant); else global
	StateDB      string   // SQLite path for persisting monitor jobs across restarts ("off" disables)
}

// Enabled reports whether at least one transport is fully configured. The
// allow-list is mandatory on each — the bot refuses to run open to everyone.
func (b BotConfig) Enabled() bool { return b.TelegramEnabled() || b.DiscordEnabled() }

// TelegramEnabled reports whether the Telegram transport is configured.
func (b BotConfig) TelegramEnabled() bool {
	return b.Token != "" && len(b.AllowedUsers) > 0
}

// DiscordEnabled reports whether the Discord transport is configured.
func (b BotConfig) DiscordEnabled() bool {
	return b.DiscordToken != "" && len(b.DiscordUsers) > 0
}

// Allowed reports whether a Telegram user id may command the bot.
func (b BotConfig) Allowed(userID int64) bool {
	for _, id := range b.AllowedUsers {
		if id == userID {
			return true
		}
	}
	return false
}

// DiscordAllowed reports whether a Discord user id may command the bot.
func (b BotConfig) DiscordAllowed(id string) bool {
	for _, u := range b.DiscordUsers {
		if u == id {
			return true
		}
	}
	return false
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
	JSAnalysis   bool
	NucleiHigh   bool
	NucleiMedium bool
}

// Load builds a Config by merging, in ascending priority order:
//  1. Hard-coded defaults
//  2. ~/.sondra.yaml
//  3. .sondra.yaml in the current directory
//  4. Environment variables (SONDRA_ prefix)
//  5. CLI flags passed in (domain, excluded, preset)
func Load(cfgFile, domain string, excluded []string, preset string, skipSelector, resume bool) (*Config, error) {
	v := viper.New()

	// ── defaults ──────────────────────────────────────────────────────────
	v.SetDefault("concurrency", 50)
	v.SetDefault("rate_limit", 150)
	v.SetDefault("wayback_rate", 2) // web.archive.org 429s hard on big domains; go low
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
	// --resume continues the most recent run dir so per-step caches (CacheValid
	// / cache_age) can skip already-completed work; otherwise start a fresh dir.
	outputDir := ""
	if resume {
		outputDir = latestRunDir(v.GetString("output_base"), domain)
	}
	if outputDir == "" {
		outputDir = buildOutputDir(v.GetString("output_base"), domain)
	}

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
		WaybackRate:     v.GetInt("wayback_rate"),
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
		Bot: BotConfig{
			Token:        firstNonEmpty(v.GetString("bot.token"), v.GetString("notify.telegram.token")),
			AllowedUsers: parseUserIDs(v.GetString("bot.allowed_users")),
			DiscordToken: v.GetString("bot.discord_token"),
			DiscordUsers: parseStringList(v.GetString("bot.discord_users")),
			DiscordGuild: v.GetString("bot.discord_guild"),
			StateDB:      firstNonEmpty(v.GetString("bot.state_db"), "sondra-bot.db"),
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
		case "js", "jsanalysis", "js-analysis", "secrets":
			m.JSAnalysis = true
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
		return m, fmt.Errorf("unknown module(s): %s (valid: subfinder, assetfinder, crtsh, alterx, massdns, httpx, takeover, naabu, gowitness, gau, gowayback, katana, jsanalysis, nuclei, nuclei-high, nuclei-medium)", strings.Join(unknown, ", "))
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
			JSAnalysis: true,
			NucleiHigh: true, NucleiMedium: true,
		}
	}
}

// latestRunDir returns the most recent recon-* directory for a domain (run dirs
// sort chronologically by their timestamp name), or "" if none exists. Used by
// --resume to continue a prior run instead of starting a fresh one.
func latestRunDir(base, domain string) string {
	entries, err := os.ReadDir(filepath.Join(base, domain))
	if err != nil {
		return ""
	}
	var latest string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "recon-") && e.Name() > latest {
			latest = e.Name()
		}
	}
	if latest == "" {
		return ""
	}
	return filepath.Join(base, domain, latest)
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
