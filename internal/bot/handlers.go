package bot

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/AliMousaviSoft/sondra/internal/config"
	"github.com/AliMousaviSoft/sondra/internal/notify"
	"github.com/AliMousaviSoft/sondra/internal/report"
	"github.com/AliMousaviSoft/sondra/internal/runner"
)

// dispatch routes a parsed command to its handler using the given responder,
// so Telegram and Discord share one implementation.
func (b *Bot) dispatch(r responder, cmd Command) {
	f := r.fmtr()
	switch cmd.Name {
	case "scan":
		b.doScan(r, cmd)
	case "monitor":
		b.doMonitor(r, cmd)
	case "diff":
		b.doDiff(r, cmd)
	case "status", "list", "jobs":
		r.reply(b.jobs.render(f))
	case "stop":
		b.doStop(r, cmd)
	case "stopall":
		b.doStopAll(r)
	case "report":
		b.doReport(r, cmd)
	case "presets":
		r.reply(presetsText(f))
	case "modules":
		r.reply(modulesText(f))
	case "version":
		r.reply("sondra " + f.bold(f.esc(b.version)))
	case "help", "start":
		r.reply(helpText(f))
	default:
		r.reply("Unknown command. Try /help")
	}
}

// resolveModules turns a command's preset/--modules into ModuleFlags.
func (b *Bot) resolveModules(cmd Command) (config.ModuleFlags, error) {
	if len(cmd.Modules) > 0 {
		return config.ParseModules(cmd.Modules)
	}
	return config.PresetModules(cmd.Preset), nil
}

// chatNotifier delivers scan alerts to the requesting Telegram chat AND to the
// operator's configured Discord/webhook, so bot-initiated scans notify
// everywhere. (Configured Telegram is skipped to avoid a duplicate chat message.)
func (b *Bot) chatNotifier(chatID int64) notify.Notifier {
	ns := notify.Multi{notify.NewTelegram(b.cfg.Bot.Token, strconv.FormatInt(chatID, 10))}
	if b.cfg.Notify.Discord != "" {
		ns = append(ns, notify.NewDiscord(b.cfg.Notify.Discord))
	}
	if b.cfg.Notify.Webhook != "" {
		ns = append(ns, notify.NewWebhook(b.cfg.Notify.Webhook))
	}
	return ns
}

func (b *Bot) doScan(r responder, cmd Command) {
	f := r.fmtr()
	if !validDomain(cmd.Domain) {
		r.reply("❌ invalid or missing domain. Usage: " + f.code("/scan example.com"))
		return
	}
	if !validExcludes(cmd.Exclude) {
		r.reply("❌ invalid exclude value (must be a domain)")
		return
	}
	mods, err := b.resolveModules(cmd)
	if err != nil {
		r.reply("❌ " + f.esc(err.Error()))
		return
	}

	job, jobCtx := b.jobs.add(b.rootCtx, "scan", cmd.Domain, cmd.Preset)
	label := f.bold(fmt.Sprintf("Scan #%d", job.ID))
	r.reply("🚀 " + label + " started: " + f.code(cmd.Domain) + " (" + f.esc(describeModules(cmd)) + ")\nResults will stream here.")

	notifier := r.notifier()
	go func() {
		defer b.jobs.finish(job.ID)
		cfg, err := config.Load(b.cfgFile, cmd.Domain, cmd.Exclude, cmd.Preset, true)
		if err != nil {
			r.reply("❌ " + label + " config: " + f.esc(err.Error()))
			return
		}
		cfg.Version = b.version
		if err := runner.Run(jobCtx, cfg, mods, notifier); err != nil {
			if jobCtx.Err() != nil {
				r.reply("🛑 " + label + " stopped.")
				return
			}
			r.reply("❌ " + label + " failed: " + f.esc(err.Error()))
		}
	}()
}

func (b *Bot) doMonitor(r responder, cmd Command) {
	f := r.fmtr()
	if !validDomain(cmd.Domain) {
		r.reply("❌ invalid or missing domain. Usage: " + f.code("/monitor example.com --interval 6h"))
		return
	}
	if !validExcludes(cmd.Exclude) {
		r.reply("❌ invalid exclude value (must be a domain)")
		return
	}
	mods, err := b.resolveModules(cmd)
	if err != nil {
		r.reply("❌ " + f.esc(err.Error()))
		return
	}
	interval := cmd.Interval
	if interval == 0 {
		interval = 6 * time.Hour
	}
	if interval < time.Minute {
		r.reply("❌ interval too short (minimum 1m)")
		return
	}
	onMode := normalizeOn(cmd.OnMode)

	job, jobCtx := b.jobs.add(b.rootCtx, "monitor", cmd.Domain, cmd.Preset)
	label := f.bold(fmt.Sprintf("Monitor #%d", job.ID))
	r.reply("🔭 " + label + " started: " + f.code(cmd.Domain) +
		fmt.Sprintf(" every %s (on=%s)\nAlerts only on changes. ", interval, onMode) +
		f.code(fmt.Sprintf("/stop %d", job.ID)) + " to cancel.")

	notifier := r.notifier()
	go func() {
		defer b.jobs.finish(job.ID)
		for {
			if jobCtx.Err() != nil {
				r.reply("🛑 " + label + " stopped.")
				return
			}
			cfg, err := config.Load(b.cfgFile, cmd.Domain, cmd.Exclude, cmd.Preset, true)
			if err != nil {
				r.reply("❌ " + label + " config: " + f.esc(err.Error()))
				return
			}
			cfg.Version = b.version

			if err := runner.Run(jobCtx, cfg, mods, nil); err != nil {
				if jobCtx.Err() != nil {
					r.reply("🛑 " + label + " stopped.")
					return
				}
				r.reply("⚠️ " + label + " pass error: " + f.esc(err.Error()))
			} else if delta, derr := report.DiffRunsDetailed(cmd.Domain); derr == nil && delta.Notable(onMode) {
				msg := runner.DeltaMessage(cmd.Domain, cmd.Preset, delta, cfg.OutputDir+"/master_report.html")
				sctx, sc := context.WithTimeout(context.Background(), 30*time.Second)
				_ = notifier.Send(sctx, msg)
				sc()
			}

			select {
			case <-jobCtx.Done():
				r.reply("🛑 " + label + " stopped.")
				return
			case <-time.After(interval):
			}
		}
	}()
}

func (b *Bot) doDiff(r responder, cmd Command) {
	f := r.fmtr()
	if !validDomain(cmd.Domain) {
		r.reply("❌ invalid or missing domain. Usage: " + f.code("/diff example.com"))
		return
	}
	delta, err := report.DiffRunsDetailed(cmd.Domain)
	if err != nil {
		r.reply("❌ " + f.esc(err.Error()))
		return
	}
	if delta.Empty() {
		r.reply("No changes vs the previous run (or only one run exists).")
		return
	}
	r.reply(deltaText(f, cmd.Domain, delta))
}

func (b *Bot) doStop(r responder, cmd Command) {
	f := r.fmtr()
	id, err := strconv.Atoi(cmd.Arg)
	if err != nil {
		r.reply("Usage: " + f.code("/stop <job id>") + "  (see /status)")
		return
	}
	if b.jobs.stop(id) {
		r.reply(fmt.Sprintf("🛑 Stopping job %s…", f.bold(fmt.Sprintf("#%d", id))))
	} else {
		r.reply(fmt.Sprintf("No active job #%d. /status", id))
	}
}

func (b *Bot) doStopAll(r responder) {
	n := b.jobs.stopAll()
	if n == 0 {
		r.reply("No active jobs.")
		return
	}
	r.reply(fmt.Sprintf("🛑 Stopping %s job(s)…", r.fmtr().bold(strconv.Itoa(n))))
}

func (b *Bot) doReport(r responder, cmd Command) {
	f := r.fmtr()
	if !validDomain(cmd.Domain) {
		r.reply("Usage: " + f.code("/report <domain>"))
		return
	}
	dir, err := report.LatestRunDir(cmd.Domain)
	if err != nil {
		r.reply("❌ " + f.esc(err.Error()))
		return
	}
	r.reply("📄 Latest report:\n" + f.code(dir+"/master_report.html"))
}

// ── helpers ──

func normalizeOn(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "findings", "finding", "vuln", "vulns":
		return "findings"
	case "assets", "asset", "surface":
		return "assets"
	default:
		return "all"
	}
}

func describeModules(cmd Command) string {
	if len(cmd.Modules) > 0 {
		return strings.Join(cmd.Modules, ",")
	}
	return cmd.Preset
}

// deltaText renders a diff delta as a chat reply in the transport's markup.
func deltaText(f formatter, domain string, d *report.Delta) string {
	var b strings.Builder
	b.WriteString(f.bold("Changes for "+f.esc(domain)) + "\n")
	fmt.Fprintf(&b, "+%d subs · +%d live · +%d findings · +%d takeovers · +%d ports\n",
		len(d.NewSubdomains), len(d.NewLiveHosts), len(d.NewFindings), len(d.NewTakeovers), len(d.NewPorts))

	const cap = 15
	if len(d.NewFindings) > 0 {
		var body strings.Builder
		for i, fnd := range d.NewFindings {
			if i >= cap {
				body.WriteString("…and more\n")
				break
			}
			where := fnd.URL
			if where == "" {
				where = fnd.Host
			}
			fmt.Fprintf(&body, "[%s] %s — %s\n", fnd.Severity, fnd.Name, where)
		}
		b.WriteString("\n" + f.bold("New findings") + "\n" + f.block(strings.TrimRight(body.String(), "\n")))
	}
	if len(d.NewSubdomains) > 0 {
		var body strings.Builder
		for i, s := range d.NewSubdomains {
			if i >= cap {
				body.WriteString("…and more\n")
				break
			}
			body.WriteString("+ " + s + "\n")
		}
		b.WriteString("\n" + f.bold("New subdomains") + "\n" + f.block(strings.TrimRight(body.String(), "\n")))
	}
	return b.String()
}
