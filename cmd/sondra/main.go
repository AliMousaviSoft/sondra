package main

import (
	"context"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/AliMousaviSoft/sondra/internal/config"
	"github.com/AliMousaviSoft/sondra/internal/report"
	"github.com/AliMousaviSoft/sondra/internal/runner"
	"github.com/AliMousaviSoft/sondra/internal/tui"
	"github.com/AliMousaviSoft/sondra/internal/updater"
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
	root.AddCommand(buildScan(), buildReport(), buildDiff(), buildVersion(), buildUpdate())
	return root
}

func buildScan() *cobra.Command {
	var (
		domain   string
		preset   string
		excluded []string
		yes      bool
		cfgFile  string
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run recon pipeline against a domain",
		Example: `  sondra scan -d target.com
  sondra scan -d target.com -p quick
  sondra scan -d target.com -y`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Show banner with async version check.
			latest := updater.LatestVersion(context.Background())
			fmt.Println(tui.RenderBanner(version, latest))

			cfg, err := config.Load(cfgFile, domain, excluded, preset, yes)
			if err != nil {
				return fmt.Errorf("config: %w", err)
			}
			cfg.Version = version

			m := tui.NewModel(cfg)
			r := runner.New(cfg, m.LogCh(), m.ProgressCh())
			m.SetRunner(r)

			if cfg.SkipSelector {
				r.Build(cfg.Modules)
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
	cmd.Flags().StringVar(&cfgFile, "config", "", "Config file (default: ~/.sondra.yaml)")
	_ = cmd.MarkFlagRequired("domain")

	viper.BindPFlag("domain", cmd.Flags().Lookup("domain"))    //nolint:errcheck
	viper.BindPFlag("preset", cmd.Flags().Lookup("preset"))    //nolint:errcheck
	viper.BindPFlag("excluded", cmd.Flags().Lookup("exclude")) //nolint:errcheck

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
			cfg, err := config.Load("", domain, nil, "", true)
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