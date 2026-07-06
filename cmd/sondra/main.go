package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AliMousaviSoft/sondra/internal/bot"
	"github.com/AliMousaviSoft/sondra/internal/config"
	"github.com/AliMousaviSoft/sondra/internal/notify"
	"github.com/AliMousaviSoft/sondra/internal/report"
	"github.com/AliMousaviSoft/sondra/internal/runner"
	"github.com/AliMousaviSoft/sondra/internal/tui"
	"github.com/AliMousaviSoft/sondra/internal/updater"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	root := buildRoot()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func buildRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "sondra",
		Short:         "sondra — automated bug bounty recon pipeline",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(buildScan(), buildMonitor(), buildBot(), buildReport(), buildDiff(), buildVersion(), buildUpdate())
	return root
}

func buildScan() *cobra.Command {
	var (
		domain     string
		preset     string
		excluded   []string
		yes        bool
		cfgFile    string
		headless   bool
		jsonLogs   bool
		moduleList []string
		resume     bool
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run recon pipeline against a domain",
		Example: `  sondra scan -d target.com
  sondra scan -d target.com -p quick
  sondra scan -d target.com -y
  sondra scan -d target.com -p quick --headless   # no TUI, for VPS/cron
  sondra scan -d target.com -p quick --json        # NDJSON logs to stdout`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile, domain, excluded, preset, yes, resume)
			if err != nil {
				return fmt.Errorf("config: %w", err)
			}
			cfg.Version = version

			// Resolve modules: an explicit --modules list overrides the preset
			// and bypasses the interactive selector.
			mods := config.PresetModules(cfg.Preset)
			explicitMods := len(moduleList) > 0
			if explicitMods {
				if mods, err = config.ParseModules(moduleList); err != nil {
					return err
				}
			}

			// Build the notifier once; shared by both TUI and headless paths.
			var notifier notify.Notifier
			if nm := notify.FromConfig(cfg.Notify); nm.Active() {
				notifier = nm
			}

			// Headless when asked, when emitting JSON, or when stdout isn't a
			// terminal (piped/redirected/cron) — bubbletea can't run there.
			if headless || jsonLogs || !isTTY() {
				return runHeadless(cfg, notifier, jsonLogs, mods)
			}

			// Interactive TUI path.
			latest := updater.LatestVersion(context.Background())
			fmt.Println(tui.RenderBanner(version, latest))

			m := tui.NewModel(cfg)
			r := runner.New(cfg, m.LogCh(), m.ProgressCh())
			if notifier != nil {
				r.SetNotifier(notifier)
			}
			m.SetRunner(r)

			if cfg.SkipSelector || explicitMods {
				r.Build(mods)
				m.StartImmediate()
			}

			p := tea.NewProgram(m, tea.WithAltScreen())
			if _, err := p.Run(); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&domain, "domain", "d", "", "Target domain (required)")
	cmd.Flags().StringVarP(&preset, "preset", "p", "full", "Preset: full|quick|passive|enum|vuln")
	cmd.Flags().StringArrayVarP(&excluded, "exclude", "e", nil, "Subdomains to exclude")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip interactive module selector")
	cmd.Flags().StringSliceVar(&moduleList, "modules", nil, "Explicit module list, overrides preset (e.g. subfinder,crtsh,httpx). Skips the selector.")
	cmd.Flags().BoolVar(&resume, "resume", false, "Reuse the latest run dir for this domain, skipping already-completed steps")
	cmd.Flags().BoolVar(&headless, "headless", false, "Run without the interactive TUI (structured stdout; for VPS/cron)")
	cmd.Flags().BoolVar(&jsonLogs, "json", false, "Emit newline-delimited JSON logs (implies --headless)")
	cmd.Flags().StringVar(&cfgFile, "config", "", "Config file (default: ~/.sondra.yaml)")
	_ = cmd.MarkFlagRequired("domain")

	viper.BindPFlag("domain", cmd.Flags().Lookup("domain"))    //nolint:errcheck
	viper.BindPFlag("preset", cmd.Flags().Lookup("preset"))    //nolint:errcheck
	viper.BindPFlag("excluded", cmd.Flags().Lookup("exclude")) //nolint:errcheck

	return cmd
}

// execPipeline builds and runs the recon pipeline against ctx, draining the
// runner's log/progress channels to stdout. Shared by headless scan and
// monitor. Returns the run error (nil on success).
func execPipeline(ctx context.Context, cfg *config.Config, notifier notify.Notifier, jsonLogs bool, mods config.ModuleFlags) error {
	logCh := make(chan tui.LogEntry, 512)
	progressCh := make(chan tui.StepUpdate, 64)

	r := runner.New(cfg, logCh, progressCh)
	if notifier != nil {
		r.SetNotifier(notifier)
	}
	r.Build(mods)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for e := range logCh {
			printLog(e, jsonLogs)
		}
	}()
	go func() {
		defer wg.Done()
		for p := range progressCh {
			printProgress(p, jsonLogs)
		}
	}()

	err := r.RunSync(ctx)
	close(logCh)
	close(progressCh)
	wg.Wait()
	return err
}

// runHeadless executes the pipeline without bubbletea, threading a
// signal-cancellable context so SIGINT/SIGTERM aborts cleanly — the mode for
// VPS and cron use.
func runHeadless(cfg *config.Config, notifier notify.Notifier, jsonLogs bool, mods config.ModuleFlags) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if !jsonLogs {
		fmt.Println(tui.RenderBanner(version, ""))
	}

	if err := execPipeline(ctx, cfg, notifier, jsonLogs, mods); err != nil {
		return err
	}
	if !jsonLogs {
		fmt.Print(tui.RenderResultsBox(cfg))
	}
	return nil
}

// isTTY reports whether stdout is an interactive terminal.
func isTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func printLog(e tui.LogEntry, asJSON bool) {
	if asJSON {
		b, _ := json.Marshal(struct {
			Time    string `json:"time"`
			Level   string `json:"level"`
			Step    string `json:"step"`
			Message string `json:"message"`
		}{e.Time.Format(time.RFC3339), e.Level.String(), e.Step, e.Message})
		fmt.Println(string(b))
		return
	}
	// Shared renderer with the TUI — colored on a terminal, plain when piped.
	fmt.Println(tui.RenderLogLine(e))
}

func printProgress(p tui.StepUpdate, asJSON bool) {
	if asJSON {
		b, _ := json.Marshal(struct {
			Type    string `json:"type"`
			Step    string `json:"step"`
			Current int    `json:"current"`
			Total   int    `json:"total"`
		}{"progress", p.Label, p.Current, p.Total})
		fmt.Println(string(b))
		return
	}
	fmt.Printf("─── [%d/%d] %s\n", p.Current, p.Total, p.Label)
}

func buildMonitor() *cobra.Command {
	var (
		domain     string
		preset     string
		excluded   []string
		cfgFile    string
		interval   time.Duration
		once       bool
		onMode     string
		jsonLogs   bool
		moduleList []string
	)

	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Continuously scan a domain and alert only on changes vs the last run",
		Example: `  sondra monitor -d target.com --interval 6h    # rescan every 6h, alert on changes
  sondra monitor -d target.com --once           # single pass (for cron/systemd)
  sondra monitor -d target.com --on findings    # only alert on new vulns`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			mode := normalizeOnMode(onMode)
			if !jsonLogs {
				fmt.Println(tui.RenderBanner(version, ""))
				fmt.Printf("monitor: %s · every %s · alert on: %s\n\n", domain, interval, mode)
			}

			for {
				if err := monitorPass(ctx, cfgFile, domain, excluded, preset, jsonLogs, mode, moduleList); err != nil && ctx.Err() == nil {
					fmt.Fprintf(os.Stderr, "monitor: pass error: %v\n", err)
				}
				if once || ctx.Err() != nil {
					return nil
				}
				fmt.Printf("\nmonitor: next scan in %s (Ctrl-C to stop)\n", interval)
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(interval):
				}
			}
		},
	}

	cmd.Flags().StringVarP(&domain, "domain", "d", "", "Target domain (required)")
	cmd.Flags().StringVarP(&preset, "preset", "p", "quick", "Preset: full|quick|passive|enum|vuln")
	cmd.Flags().StringArrayVarP(&excluded, "exclude", "e", nil, "Subdomains to exclude")
	cmd.Flags().DurationVar(&interval, "interval", 6*time.Hour, "Time between scans (e.g. 30m, 6h) — keep ≥ a few minutes")
	cmd.Flags().BoolVar(&once, "once", false, "Run a single pass then exit (for cron/systemd)")
	cmd.Flags().StringVar(&onMode, "on", "all", "Alert trigger: all | assets | findings")
	cmd.Flags().StringSliceVar(&moduleList, "modules", nil, "Explicit module list, overrides preset (e.g. subfinder,crtsh,httpx)")
	cmd.Flags().BoolVar(&jsonLogs, "json", false, "Emit newline-delimited JSON logs")
	cmd.Flags().StringVar(&cfgFile, "config", "", "Config file (default: ~/.sondra.yaml)")
	_ = cmd.MarkFlagRequired("domain")
	return cmd
}

// monitorPass runs one scan then alerts on the delta vs the previous run. The
// runner runs WITHOUT a notifier: monitor sends a single delta alert instead of
// the per-scan summaries, so persistent findings don't re-alert every interval.
func monitorPass(ctx context.Context, cfgFile, domain string, excluded []string, preset string, jsonLogs bool, mode string, moduleList []string) error {
	cfg, err := config.Load(cfgFile, domain, excluded, preset, true, false)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	cfg.Version = version

	mods := config.PresetModules(cfg.Preset)
	if len(moduleList) > 0 {
		if mods, err = config.ParseModules(moduleList); err != nil {
			return err
		}
	}

	if err := execPipeline(ctx, cfg, nil, jsonLogs, mods); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return nil
	}

	delta, err := report.DiffRunsDetailed(domain)
	if err != nil {
		return fmt.Errorf("diff: %w", err)
	}

	if !deltaNotable(delta, mode) {
		fmt.Printf("monitor: no new %s for %s\n", mode, domain)
		return nil
	}

	fmt.Printf("monitor: CHANGES for %s — +%d subs · +%d live · +%d findings · +%d takeovers · +%d ports\n",
		domain, len(delta.NewSubdomains), len(delta.NewLiveHosts),
		len(delta.NewFindings), len(delta.NewTakeovers), len(delta.NewPorts))

	if nm := notify.FromConfig(cfg.Notify); nm.Active() {
		msg := runner.DeltaMessage(domain, cfg.Preset, delta, cfg.OutputDir+"/master_report.html")
		if err := nm.Send(ctx, msg); err != nil {
			fmt.Fprintf(os.Stderr, "monitor: notify: %v\n", err)
		}
	}
	return nil
}

// deltaNotable reports whether the delta should trigger an alert under mode.
func deltaNotable(d *report.Delta, mode string) bool {
	return d.Notable(mode)
}

func normalizeOnMode(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "findings", "finding", "vuln", "vulns":
		return "findings"
	case "assets", "asset", "surface":
		return "assets"
	default:
		return "all"
	}
}

func buildBot() *cobra.Command {
	var cfgFile string

	cmd := &cobra.Command{
		Use:   "bot",
		Short: "Run the control bot (drive scans/monitors from Telegram/Discord)",
		Long: `Run a control bot that lets allow-listed users start scans and monitors,
run diffs, and check status from chat. Enable Telegram, Discord, or both.

Config (.sondra.yaml or env):
  bot:
    # Telegram (text commands)
    token: "123456:ABC..."             # falls back to notify.telegram.token
    allowed_users: "111111,222222"     # Telegram user ids
    # Discord (slash commands)
    discord_token: "..."               # Discord bot token
    discord_users: "333333,444444"     # Discord user ids
    discord_guild: "5555"              # optional: instant per-guild registration

  SONDRA_BOT_TOKEN, SONDRA_BOT_ALLOWED_USERS, SONDRA_BOT_DISCORD_TOKEN,
  SONDRA_BOT_DISCORD_USERS also work.`,
		Example: `  sondra bot                    # start the control bot
  # then: /scan example.com quick  (Telegram text or Discord slash)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// A domain isn't needed to start the bot; pass a placeholder so
			// config.Load doesn't reject it (jobs reload config per target).
			cfg, err := config.Load(cfgFile, "bot.local", nil, "quick", true, false)
			if err != nil {
				return fmt.Errorf("config: %w", err)
			}
			if !cfg.Bot.Enabled() {
				return fmt.Errorf("bot not configured: enable Telegram (bot.token + bot.allowed_users) and/or Discord (bot.discord_token + bot.discord_users)")
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			fmt.Println(tui.RenderBanner(version, ""))
			return bot.New(cfg, cfgFile, version).Run(ctx)
		},
	}

	cmd.Flags().StringVar(&cfgFile, "config", "", "Config file (default: ~/.sondra.yaml)")
	return cmd
}

func buildReport() *cobra.Command {
	var (
		domain string
		dir    string
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Regenerate HTML report for a completed scan",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load("", domain, nil, "", true, false)
			if err != nil {
				return err
			}
			if dir != "" {
				cfg.OutputDir = dir
			}
			return report.Generate(cfg)
		},
	}

	cmd.Flags().StringVarP(&domain, "domain", "d", "", "Target domain (required)")
	cmd.Flags().StringVar(&dir, "dir", "", "Specific run directory to use")
	_ = cmd.MarkFlagRequired("domain")
	return cmd
}

func buildDiff() *cobra.Command {
	var domain string

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Show new subdomains between the last two runs",
		RunE: func(cmd *cobra.Command, args []string) error {
			newSubs, err := report.DiffRuns(domain)
			if err != nil {
				return err
			}
			if len(newSubs) == 0 {
				fmt.Println("No new subdomains found (or only one run exists).")
				return nil
			}
			fmt.Printf("New subdomains since last run (%d):\n", len(newSubs))
			for _, s := range newSubs {
				fmt.Println(" +", s)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&domain, "domain", "d", "", "Target domain (required)")
	_ = cmd.MarkFlagRequired("domain")
	return cmd
}

func buildVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			latest := updater.LatestVersion(context.Background())
			fmt.Println(tui.RenderBanner(version, latest))
			fmt.Printf("version : %s\n", version)
			fmt.Printf("commit  : %s\n", commit)
			fmt.Printf("built   : %s\n", date)
		},
	}
}

func buildUpdate() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update sondra to the latest version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Checking for updates...")
			latest := updater.LatestVersion(context.Background())
			if latest == "" {
				fmt.Println("Could not reach GitHub — check your connection.")
				return
			}
			if version == latest {
				fmt.Printf("Already on latest version: v%s\n", version)
				return
			}
			updater.DoUpdate(latest)
		},
	}
}
