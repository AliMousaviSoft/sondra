package runner

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/AliMousaviSoft/sondra/internal/config"
	"github.com/AliMousaviSoft/sondra/internal/modules"
	"github.com/AliMousaviSoft/sondra/internal/report"
	"github.com/AliMousaviSoft/sondra/internal/tui"
)

type StepDef struct {
	Name string
	Run  func(ctx context.Context) error
}

type Runner struct {
	cfg        *config.Config
	logCh      chan<- tui.LogEntry
	progressCh chan<- tui.StepUpdate
	steps      []StepDef
	bgWg       sync.WaitGroup
}

func New(cfg *config.Config, logCh chan<- tui.LogEntry, progressCh chan<- tui.StepUpdate) *Runner {
	return &Runner{
		cfg:        cfg,
		logCh:      logCh,
		progressCh: progressCh,
	}
}

func (r *Runner) Build(mods config.ModuleFlags) {
	r.cfg.Modules = mods
	r.steps = nil

	add := func(name string, fn func(ctx context.Context) error) {
		r.steps = append(r.steps, StepDef{name, fn})
	}

	add("setup", r.runSetup)

	if mods.Subfinder || mods.Assetfinder || mods.Crtsh {
		add("passive enum", r.runPassiveEnum)
	}
	if mods.Alterx || mods.Massdns {
		add("active brute", r.runActiveBrute)
	}
	add("resolve", r.runResolve)
	if mods.Httpx {
		add("httpx probe", r.runProbe)
	}
	if mods.Naabu {
		add("port scan", r.runPorts)
	}
	if mods.Gowitness {
		add("screenshots", r.runScreenshots)
	}
	if mods.Gau || mods.Katana {
		add("url collection", r.runURLCollection)
	}
	if mods.NucleiHigh || mods.NucleiMedium {
		add("nuclei", r.runNuclei)
	}
	add("report", r.runReport)
}

func (r *Runner) StepTotal() int { return len(r.steps) }

// RunSync runs the full pipeline synchronously.
// Called inside a tea.Cmd goroutine in model.go — the return value
// becomes a doneMsg in the bubbletea event loop.
func (r *Runner) RunSync() error {
	ctx := context.Background()
	total := len(r.steps)

	for i, step := range r.steps {
		r.progressCh <- tui.StepUpdate{
			Label:   step.Name,
			Current: i + 1,
			Total:   total,
		}

		r.log(tui.LogInfo, step.Name, "starting")
		start := time.Now()

		if err := step.Run(ctx); err != nil {
			r.log(tui.LogError, step.Name, fmt.Sprintf("failed: %v", err))
			return fmt.Errorf("step %q: %w", step.Name, err)
		}

		r.log(tui.LogSuccess, step.Name,
			fmt.Sprintf("done in %s", time.Since(start).Round(time.Millisecond)))
	}

	r.log(tui.LogInfo, "runner", "waiting for background jobs…")
	r.bgWg.Wait()
	return nil
}

func (r *Runner) log(level tui.LogLevel, step, msg string) {
	entry := tui.NewLog(level, step, msg)
	select {
	case r.logCh <- entry:
	default:
	}
}

// ──────────────────────────────────────────────
// Step implementations
// ──────────────────────────────────────────────

func (r *Runner) runSetup(ctx context.Context) error {
	dirs := []string{
		r.cfg.OutputDir,
		r.cfg.OutputDir + "/naabu-output",
		r.cfg.OutputDir + "/wayback-data",
		r.cfg.OutputDir + "/gowitness-output/screenshots",
		r.cfg.OutputDir + "/nuclei-results",
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	r.log(tui.LogInfo, "setup", fmt.Sprintf("output: %s", r.cfg.OutputDir))
	return nil
}

func (r *Runner) runPassiveEnum(ctx context.Context) error {
	result := modules.RunPassiveEnum(ctx, r.cfg, r.logCh)
	if result.Error != nil {
		return result.Error
	}
	r.log(tui.LogSuccess, "passive enum", fmt.Sprintf("found %d unique subdomains", result.Count))
	return nil
}

func (r *Runner) runActiveBrute(ctx context.Context) error {
	result := modules.RunActiveBrute(ctx, r.cfg, r.logCh)
	if result.Error != nil {
		r.log(tui.LogWarn, "active brute", result.Error.Error())
	}
	return nil
}

func (r *Runner) runResolve(ctx context.Context) error {
	result := modules.RunResolve(ctx, r.cfg, r.logCh)
	if result.Error != nil {
		return result.Error
	}
	if result.Count == 0 {
		return fmt.Errorf("zero subdomains resolved — aborting")
	}
	r.log(tui.LogSuccess, "resolve", fmt.Sprintf("%d live DNS records", result.Count))
	return nil
}

func (r *Runner) runProbe(ctx context.Context) error {
	result := modules.RunProbe(ctx, r.cfg, r.logCh)
	if result.Error != nil {
		return result.Error
	}
	if result.Count == 0 {
		return fmt.Errorf("httpx produced no live hosts — aborting")
	}
	r.log(tui.LogSuccess, "httpx", fmt.Sprintf("%d live HTTP(S) endpoints", result.Count))
	return nil
}

func (r *Runner) runPorts(ctx context.Context) error {
	result := modules.RunPorts(ctx, r.cfg, r.logCh)
	if result.Error != nil {
		r.log(tui.LogWarn, "naabu", result.Error.Error())
	}
	return nil
}

func (r *Runner) runScreenshots(ctx context.Context) error {
	result := modules.RunScreenshots(ctx, r.cfg, r.logCh)
	if result.Error != nil {
		r.log(tui.LogWarn, "gowitness", result.Error.Error())
	}
	return nil
}

func (r *Runner) runURLCollection(ctx context.Context) error {
	result := modules.RunURLCollection(ctx, r.cfg, r.logCh)
	if result.Error != nil {
		r.log(tui.LogWarn, "url collection", result.Error.Error())
	}
	return nil
}

func (r *Runner) runNuclei(ctx context.Context) error {
	return modules.RunNuclei(ctx, r.cfg, r.logCh, &r.bgWg)
}

func (r *Runner) runReport(ctx context.Context) error {
	r.log(tui.LogInfo, "report", "generating master_report.html")
	if err := report.Generate(r.cfg); err != nil {
		return err
	}
	r.log(tui.LogSuccess, "report", r.cfg.OutputDir+"/master_report.html")
	return nil
}