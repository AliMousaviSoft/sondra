package runner

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/AliMousaviSoft/sondra/internal/config"
	"github.com/AliMousaviSoft/sondra/internal/modules"
	"github.com/AliMousaviSoft/sondra/internal/notify"
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
	steps      []StepDef // recon phase — fast, gates the initial report + alert
	vulnSteps  []StepDef // vuln phase — slow (nuclei), runs after recon is delivered
	bgWg       sync.WaitGroup
	notifyWg   sync.WaitGroup // tracks in-flight async notifications
	notifier   notify.Notifier
}

// SetNotifier attaches an outbound notifier. Safe to leave nil (no-op).
// Leave nil to suppress all notifications (e.g. monitor mode sends its own
// delta alert instead of the per-scan summaries).
func (r *Runner) SetNotifier(n notify.Notifier) { r.notifier = n }

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
	r.vulnSteps = nil

	add := func(name string, fn func(ctx context.Context) error) {
		r.steps = append(r.steps, StepDef{name, fn})
	}
	addVuln := func(name string, fn func(ctx context.Context) error) {
		r.vulnSteps = append(r.vulnSteps, StepDef{name, fn})
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
	if mods.Gau || mods.Gowayback || mods.Katana {
		add("url collection", r.runURLCollection)
	}
	// Nuclei is the slow phase — it runs AFTER recon results are reported so the
	// pipeline delivers value in minutes instead of blocking for ~15-20m. The
	// report is generated inline by RunSync (initial + regenerated post-nuclei).
	if mods.NucleiHigh || mods.NucleiMedium || mods.Takeover {
		addVuln("nuclei", r.runNuclei)
	}
}

func (r *Runner) StepTotal() int { return len(r.steps) + len(r.vulnSteps) }

// RunSync runs the pipeline in two phases against ctx.
//
// Phase 1 (recon) is fast: on completion it generates the report and — if a
// vuln phase follows — fires an initial "recon done" notification so results
// land in minutes. Phase 2 (nuclei) is slow and non-fatal: recon has already
// been delivered, so a nuclei error doesn't fail the run. When it finishes the
// report is regenerated with findings and the final notification is sent.
//
// Called inside a tea.Cmd goroutine in model.go (TUI) or directly in headless
// mode. Cancelling ctx (e.g. SIGINT) aborts between steps and propagates into
// each module's exec calls.
func (r *Runner) RunSync(parent context.Context) error {
	// Child context so an error or cancellation can tear down background jobs
	// (e.g. the medium-nuclei goroutine) instead of blocking on them or leaving
	// them to send on a closed channel after this returns.
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	// Block on in-flight async notifications before returning, so a headless
	// process doesn't exit mid-send. (Notifications use a background context,
	// so it doesn't matter that this runs before the deferred cancel.)
	defer r.notifyWg.Wait()

	total := len(r.steps) + len(r.vulnSteps)
	runStart := time.Now()
	r.notifyStart(ctx)

	// ── Phase 1: recon ──
	for i, step := range r.steps {
		if err := ctx.Err(); err != nil {
			r.log(tui.LogWarn, "runner", "cancelled")
			cancel()
			r.bgWg.Wait()
			r.notifyFinish(err, time.Since(runStart))
			return err
		}
		if err := r.runStep(ctx, step, i+1, total); err != nil {
			r.log(tui.LogError, step.Name, fmt.Sprintf("failed: %v", err))
			cancel() // stop any background jobs before we return
			r.bgWg.Wait()
			r.notifyFinish(err, time.Since(runStart))
			return fmt.Errorf("step %q: %w", step.Name, err)
		}
	}

	// Initial report from recon output.
	if err := r.runReport(ctx); err != nil {
		r.log(tui.LogWarn, "report", err.Error())
	}

	// No vuln phase → single finish notification, done.
	if len(r.vulnSteps) == 0 {
		r.notifyFinish(nil, time.Since(runStart))
		return nil
	}

	// Recon delivered — notify now, before the slow vuln scan.
	r.notifyReconDone(time.Since(runStart))
	r.log(tui.LogInfo, "nuclei", "recon results reported — running vuln scan (this can take a while)…")

	// ── Phase 2: nuclei (slow, non-fatal). ──
	base := len(r.steps)
	for i, step := range r.vulnSteps {
		if err := ctx.Err(); err != nil {
			r.log(tui.LogWarn, "runner", "cancelled during vuln scan — recon results already delivered")
			cancel()
			r.bgWg.Wait()
			return nil
		}
		if err := r.runStep(ctx, step, base+i+1, total); err != nil {
			r.log(tui.LogWarn, step.Name, err.Error())
		}
	}
	r.bgWg.Wait() // wait for the background medium-nuclei job

	// Regenerate the report with vuln findings, then send the final alert.
	if err := r.runReport(ctx); err != nil {
		r.log(tui.LogWarn, "report", err.Error())
	}
	r.notifyFinish(nil, time.Since(runStart))
	return nil
}

// runStep emits progress + start/done logs around one step's execution.
func (r *Runner) runStep(ctx context.Context, step StepDef, num, total int) error {
	r.progressCh <- tui.StepUpdate{Label: step.Name, Current: num, Total: total}
	r.log(tui.LogInfo, step.Name, "starting")
	start := time.Now()
	if err := step.Run(ctx); err != nil {
		return err
	}
	r.log(tui.LogSuccess, step.Name,
		fmt.Sprintf("done in %s", time.Since(start).Round(time.Millisecond)))
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
	return modules.RunNuclei(ctx, r.cfg, r.logCh, &r.bgWg, r.notifyFinding)
}

func (r *Runner) runReport(ctx context.Context) error {
	r.log(tui.LogInfo, "report", "generating master_report.html")
	if err := report.Generate(r.cfg); err != nil {
		return err
	}
	r.log(tui.LogSuccess, "report", r.cfg.OutputDir+"/master_report.html")
	return nil
}
