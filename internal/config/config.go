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
}

// ModuleFlags controls which recon steps are active.
type ModuleFlags struct {
	Subfinder   bool
	Assetfinder bool
	Crtsh       bool
	Alterx      bool
	Massdns     bool
	Httpx       bool
	Takeover    bool
	Naabu       bool
	Gowitness   bool
	Gau         bool
	Katana      bool
	NucleiHigh  bool
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

	// ── config files ──────────────────────────────────────────────────────
	v.SetConfigType("yaml")

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		// Project-local first, then user home — viper reads the first found.
		v.AddConfigPath(".")
		v.SetConfigName(".sondra")
		if err := v.ReadInConfig(); err == nil {
			// local config loaded
		}

		// Home config (may override local defaults if keys differ).
		home, err := os.UserHomeDir()
		if err == nil {
			v2 := viper.New()
			v2.SetConfigType("yaml")
			v2.SetConfigFile(filepath.Join(home, ".sondra.yaml"))
			if err := v2.ReadInConfig(); err == nil {
				for _, k := range v2.AllKeys() {
					if !v.IsSet(k) {
						v.Set(k, v2.Get(k))
					}
				}
			}
		}
	}

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
	}

	// Apply preset to ModuleFlags when skipping the selector.
	if skipSelector {
		cfg.Modules = PresetModules(preset)
	}

	return cfg, nil
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
			Gowitness: true, Gau: true, Katana: true,
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
