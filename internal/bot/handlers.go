package bot

import (
	"context"
	"fmt"
	"os"
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
		cfg, err := config.Load(b.cfgFile, cmd.Domain, cmd.Exclude, cmd.Preset, true, false)
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
	if _, err := b.resolveModules(cmd); err != nil {
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

	spec := monitorSpec{
		Domain:   cmd.Domain,
		Preset:   cmd.Preset,
		Modules:  cmd.Modules,
		Exclude:  cmd.Exclude,
		Interval: interval,
		OnMode:   normalizeOn(cmd.OnMode),
	}

	job, jobCtx := b.jobs.add(b.rootCtx, "monitor", spec.Domain, spec.Preset)
	if b.store != nil {
		rec := jobRecord{ID: job.ID, Kind: "monitor", Spec: spec, Transport: r.transport(), Dest: r.dest()}
		if err := b.store.save(rec); err != nil {
			fmt.Fprintf(os.Stderr, "bot: state save #%d: %v\n", job.ID, err)
		}
	}

	label := f.bold(fmt.Sprintf("Monitor #%d", job.ID))
	r.reply("🔭 " + label + " started: " + f.code(spec.Domain) +
		fmt.Sprintf(" every %s (on=%s)\nAlerts only on changes. ", interval, spec.OnMode) +
		f.code(fmt.Sprintf("/stop %d", job.ID)) + " to cancel.")

	go b.runMonitor(r, spec, job, jobCtx)
}

// runMonitor drives a monitor loop until its context is cancelled. It is shared
// by freshly-started monitors and ones resumed from the store after a restart.
func (b *Bot) runMonitor(r responder, spec monitorSpec, job *Job, jobCtx context.Context) {
	f := r.fmtr()
	label := f.bold(fmt.Sprintf("Monitor #%d", job.ID))

	defer func() {
		b.jobs.finish(job.ID)
		// Forget the job only if it ended while the daemon is still up — a user
		// /stop or a fatal error. On a daemon shutdown (rootCtx cancelled) leave
		// the row so the monitor resumes on the next start.
		if b.store != nil && b.rootCtx.Err() == nil {
			if err := b.store.delete(job.ID); err != nil {
				fmt.Fprintf(os.Stderr, "bot: state delete #%d: %v\n", job.ID, err)
			}
		}
	}()

	mods, err := modulesFromSpec(spec)
	if err != nil {
		r.reply("❌ " + label + " bad modules: " + f.esc(err.Error()))
		return
	}
	notifier := r.notifier()

	for {
		if jobCtx.Err() != nil {
			r.reply("🛑 " + label + " stopped.")
			return
		}
		cfg, err := config.Load(b.cfgFile, spec.Domain, spec.Exclude, spec.Preset, true, false)
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
		} else if delta, derr := report.DiffRunsDetailed(spec.Domain); derr == nil && delta.Notable(spec.OnMode) {
			msg := runner.DeltaMessage(spec.Domain, spec.Preset, delta, cfg.OutputDir+"/master_report.html")
			sctx, sc := context.WithTimeout(context.Background(), 30*time.Second)
			_ = notifier.Send(sctx, msg)
			sc()
		}

		select {
		case <-jobCtx.Done():
			r.reply("🛑 " + label + " stopped.")
			return
		case <-time.After(spec.Interval):
		}
	}
}

// resumeJobs re-spawns monitors persisted before the last shutdown, rebuilding
// a responder for the stored transport so alerts and status resume in place.
func (b *Bot) resumeJobs() {
	if b.store == nil {
		return
	}
	recs, err := b.store.loadAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "bot: load persisted jobs: %v\n", err)
		return
	}
	for _, rec := range recs {
		if rec.Kind != "monitor" {
			continue
		}
		// Re-validate: the store is an input that feeds domains into exec.
		if !validDomain(rec.Spec.Domain) || !validExcludes(rec.Spec.Exclude) {
			fmt.Fprintf(os.Stderr, "bot: dropping persisted job #%d: invalid domain/exclude\n", rec.ID)
			_ = b.store.delete(rec.ID)
			continue
		}
		r, err := b.responderForRecord(rec)
		if err != nil {
			// Keep the row — its transport may be enabled on a later start.
			fmt.Fprintf(os.Stderr, "bot: cannot resume job #%d: %v\n", rec.ID, err)
			continue
		}
		job, jobCtx := b.jobs.addWithID(b.rootCtx, rec.ID, "monitor", rec.Spec.Domain, rec.Spec.Preset)
		r.reply(fmt.Sprintf("♻️ Resumed monitor #%d for %s — every %s (on=%s)",
			rec.ID, rec.Spec.Domain, rec.Spec.Interval, rec.Spec.OnMode))
		go b.runMonitor(r, rec.Spec, job, jobCtx)
	}
}

// responderForRecord rebuilds a detached responder for a persisted job's
// transport, so a resumed monitor delivers to the original chat/channel.
func (b *Bot) responderForRecord(rec jobRecord) (responder, error) {
	switch rec.Transport {
	case "telegram":
		if b.cfg.Bot.Token == "" {
			return nil, fmt.Errorf("telegram not configured")
		}
		id, err := strconv.ParseInt(rec.Dest, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bad telegram dest %q", rec.Dest)
		}
		return &tgResponder{bot: b, chatID: id}, nil
	case "discord":
		if b.discord == nil {
			return nil, fmt.Errorf("discord not enabled")
		}
		return &discordChannelResponder{session: b.discord.session, channelID: rec.Dest}, nil
	}
	return nil, fmt.Errorf("unknown transport %q", rec.Transport)
}

// modulesFromSpec resolves a monitor spec's --modules/preset into ModuleFlags.
func modulesFromSpec(spec monitorSpec) (config.ModuleFlags, error) {
	if len(spec.Modules) > 0 {
		return config.ParseModules(spec.Modules)
	}
	return config.PresetModules(spec.Preset), nil
}

func (b *Bot) doDiff(r responder, cmd Command) {
	f := r.fmtr()
	domain, ok := b.resolveDomain(r, cmd)
	if !ok {
		return
	}
	delta, err := report.DiffRunsDetailed(domain)
	if err != nil {
		r.reply("❌ " + f.esc(err.Error()))
		return
	}
	if delta.Empty() {
		r.reply("No changes vs the previous run (or only one run exists).")
		return
	}
	r.reply(deltaText(f, domain, delta))
}

// resolveDomain returns the command's domain, defaulting to the most recently
// scanned domain when it's omitted — so bare /report and /diff "just work".
func (b *Bot) resolveDomain(r responder, cmd Command) (string, bool) {
	if validDomain(cmd.Domain) {
		return cmd.Domain, true
	}
	f := r.fmtr()
	if cmd.Domain != "" {
		r.reply("❌ invalid domain " + f.code(cmd.Domain))
		return "", false
	}
	domain, err := report.LatestDomain()
	if err != nil {
		r.reply("❌ " + f.esc(err.Error()))
		return "", false
	}
	return domain, true
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
	domain, ok := b.resolveDomain(r, cmd)
	if !ok {
		return
	}
	path, err := report.LatestReport(domain)
	if err != nil {
		r.reply("❌ " + f.esc(err.Error()))
		return
	}
	r.reply("📄 Latest report for " + f.code(domain) + ":")
	if err := r.sendFile(path, "master_report.html"); err != nil {
		fmt.Fprintf(os.Stderr, "bot: sendFile %s: %v\n", path, err)
		r.reply("⚠️ couldn't upload it (" + f.esc(err.Error()) + ")\nHost path: " + f.code(path))
	}
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
