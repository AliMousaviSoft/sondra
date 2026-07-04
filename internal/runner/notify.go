package runner

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/AliMousaviSoft/sondra/internal/config"
	"github.com/AliMousaviSoft/sondra/internal/notify"
	"github.com/AliMousaviSoft/sondra/internal/report"
	"github.com/AliMousaviSoft/sondra/internal/tui"
)

// notifyStart announces the beginning of a run.
func (r *Runner) notifyStart(ctx context.Context) {
	if r.notifier == nil || !r.cfg.Notify.NotifyOnStart {
		return
	}
	mods := activeModuleNames(r.cfg.Modules)
	r.dispatch(notify.Message{
		Title: "🚀 Recon started: " + r.cfg.Domain,
		Level: notify.LevelInfo,
		Fields: []notify.Field{
			{Name: "Preset", Value: presetLabel(r.cfg.Preset), Inline: true},
			{Name: "Modules", Value: strconv.Itoa(len(mods)), Inline: true},
			{Name: "Steps", Value: strconv.Itoa(len(r.steps)), Inline: true},
		},
		Text:   "Modules: " + strings.Join(mods, ", "),
		Footer: r.footer(),
	})
}

// notifyFinish sends the end-of-run summary, built from the scan's output
// files so the counts and findings are accurate (nuclei background jobs have
// already joined by the time this is called). When notify.only_notable is set,
// a clean run (no findings ≥ min_severity, no new subs/takeovers, no error) is
// skipped entirely so the channel isn't flooded with empty results.
func (r *Runner) notifyFinish(runErr error, elapsed time.Duration) {
	if r.notifier == nil {
		return
	}

	data, _ := report.Collect(r.cfg)
	crit, high, med, low := 0, 0, 0, 0
	notable := runErr != nil
	if data != nil {
		crit, high, med, low = severityCounts(data.Findings)
		floor := severityRank(r.cfg.Notify.MinSeverity)
		notable = notable ||
			countAtOrAbove(data.Findings, floor) > 0 ||
			len(data.NewSubdomains) > 0 ||
			data.TakeoverCount > 0
	}

	if r.cfg.Notify.OnlyNotable && !notable {
		return
	}

	// Colour and title track the worst thing found, so a glance at the embed
	// tells you whether it needs attention.
	level := notify.LevelSuccess
	title := "✅ Scan complete: " + r.cfg.Domain
	switch {
	case runErr != nil:
		level, title = notify.LevelError, "❌ Recon failed: "+r.cfg.Domain
	case crit > 0:
		level, title = notify.LevelError, fmt.Sprintf("🚨 %d critical finding(s): %s", crit, r.cfg.Domain)
	case high > 0:
		level, title = notify.LevelWarn, fmt.Sprintf("⚠️ %d high finding(s): %s", high, r.cfg.Domain)
	}

	msg := notify.Message{
		Title:    title,
		Level:    level,
		Duration: elapsed,
		Footer:   r.footer(),
	}

	if data != nil {
		msg.Fields = []notify.Field{
			{Name: "Subdomains", Value: strconv.Itoa(data.SubdomainCount), Inline: true},
			{Name: "Live hosts", Value: strconv.Itoa(data.LiveCount), Inline: true},
			{Name: "New subs", Value: strconv.Itoa(len(data.NewSubdomains)), Inline: true},
			{Name: "Findings", Value: fmt.Sprintf("%d  🔴%d 🟠%d 🟡%d ⚪%d", data.NucleiHits, crit, high, med, low), Inline: false},
			{Name: "Takeovers", Value: strconv.Itoa(data.TakeoverCount), Inline: true},
			{Name: "Open ports", Value: strconv.Itoa(data.PortCount), Inline: true},
			{Name: "URLs", Value: strconv.Itoa(data.URLCount), Inline: true},
		}
		if s := statusCodeBreakdown(data.StatusCodes); s != "" {
			msg.Fields = append(msg.Fields, notify.Field{Name: "Status codes", Value: s, Inline: false})
		}
		if s := techBreakdown(data.LiveHosts); s != "" {
			msg.Fields = append(msg.Fields, notify.Field{Name: "Tech", Value: s, Inline: false})
		}
		msg.Text = summaryText(data, r.cfg.Notify.MinSeverity)
		msg.Fields = append(msg.Fields, notify.Field{
			Name:  "Report",
			Value: r.cfg.OutputDir + "/master_report.html",
		})
		msg.Data = r.resultPayload(data, "scan_complete", elapsed)
	}

	if runErr != nil {
		msg.Text = strings.TrimSpace("Error: " + runErr.Error() + "\n\n" + msg.Text)
	}

	r.dispatch(msg)
}

// notifyFinding pushes a single finding the moment nuclei discovers it, gated to
// severities at or above notify.min_severity so the channel isn't spammed with
// low/medium noise. Called from the nuclei module's live tailer.
func (r *Runner) notifyFinding(name, severity, where string) {
	if r.notifier == nil {
		return
	}
	if severityRank(severity) < severityRank(r.cfg.Notify.MinSeverity) {
		return
	}
	level := notify.LevelWarn
	if strings.EqualFold(severity, "critical") {
		level = notify.LevelError
	}
	r.dispatch(notify.Message{
		Title: fmt.Sprintf("%s %s finding: %s", severityEmoji(severity), strings.ToUpper(severity), r.cfg.Domain),
		Level: level,
		Text:  name + "\n" + where,
		Fields: []notify.Field{
			{Name: "Severity", Value: strings.ToUpper(severity), Inline: true},
			{Name: "Host", Value: where, Inline: false},
		},
		Footer: r.footer(),
		Data: &notify.ResultPayload{
			Domain: r.cfg.Domain,
			Event:  "finding",
			Findings: []notify.FindingPayload{
				{Name: name, Severity: strings.ToLower(severity), Host: where, URL: where},
			},
		},
	})
}

// notifyReconDone fires the interim alert after the recon phase, before the
// slow nuclei phase — this is what delivers results in minutes. Under
// only_notable it's suppressed unless recon surfaced something worth seeing
// (new subdomains, high-value hosts, or takeovers).
func (r *Runner) notifyReconDone(elapsed time.Duration) {
	if r.notifier == nil {
		return
	}
	data, _ := report.Collect(r.cfg)

	if r.cfg.Notify.OnlyNotable {
		if data == nil || (len(data.NewSubdomains) == 0 && len(data.HighValue) == 0 && data.TakeoverCount == 0) {
			return
		}
	}

	msg := notify.Message{
		Title:    "✅ Recon done: " + r.cfg.Domain + " — 🔍 scanning vulns…",
		Level:    notify.LevelInfo,
		Duration: elapsed,
		Footer:   r.footer(),
	}
	if data != nil {
		msg.Fields = []notify.Field{
			{Name: "Subdomains", Value: strconv.Itoa(data.SubdomainCount), Inline: true},
			{Name: "Live hosts", Value: strconv.Itoa(data.LiveCount), Inline: true},
			{Name: "New subs", Value: strconv.Itoa(len(data.NewSubdomains)), Inline: true},
			{Name: "High-value", Value: strconv.Itoa(len(data.HighValue)), Inline: true},
			{Name: "Open ports", Value: strconv.Itoa(data.PortCount), Inline: true},
			{Name: "URLs", Value: strconv.Itoa(data.URLCount), Inline: true},
		}
		msg.Text = reconText(data)
	}
	r.dispatch(msg)
}

// dispatch sends a message best-effort. It intentionally uses a fresh
// background context (not the run's ctx) so a cancelled/failed run can still
// deliver its final notification, and never fails the scan on a delivery error.
func (r *Runner) dispatch(msg notify.Message) {
	if r.notifier == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := r.notifier.Send(ctx, msg); err != nil {
		r.log(tui.LogWarn, "notify", err.Error())
	}
}

func (r *Runner) footer() string {
	v := r.cfg.Version
	if v == "" {
		v = "dev"
	}
	return "sondra " + v
}

// summaryText builds the notification body: findings at or above the severity
// floor, high-value hosts, and newly discovered subdomains — each section
// capped so the message stays inside Discord/Telegram size limits.
func summaryText(d *report.ReportData, minSeverity string) string {
	const cap = 15
	var b strings.Builder

	floor := severityRank(minSeverity)
	var listed int
	for _, f := range d.Findings {
		if severityRank(f.Severity) < floor {
			continue
		}
		if listed == 0 {
			b.WriteString("Findings (≥ " + strings.ToLower(defaultSeverity(minSeverity)) + "):\n")
		}
		if listed >= cap {
			b.WriteString(fmt.Sprintf("…and %d more\n", countAtOrAbove(d.Findings, floor)-cap))
			break
		}
		where := f.URL
		if where == "" {
			where = f.Host
		}
		b.WriteString(fmt.Sprintf("%s %s — %s\n", severityEmoji(f.Severity), f.Name, where))
		listed++
	}

	if len(d.HighValue) > 0 {
		section(&b, fmt.Sprintf("⭐ High-value hosts (%d):", len(d.HighValue)), d.HighValue, cap, "")
	}
	if len(d.NewSubdomains) > 0 {
		section(&b, fmt.Sprintf("🆕 New subdomains (%d):", len(d.NewSubdomains)), d.NewSubdomains, cap, "+ ")
	}

	return strings.TrimSpace(b.String())
}

// reconText builds the interim-alert body: high-value hosts and new subdomains
// (nuclei findings aren't available yet at this phase).
func reconText(d *report.ReportData) string {
	const cap = 15
	var b strings.Builder
	if len(d.HighValue) > 0 {
		section(&b, fmt.Sprintf("⭐ High-value hosts (%d):", len(d.HighValue)), d.HighValue, cap, "")
	}
	if len(d.NewSubdomains) > 0 {
		section(&b, fmt.Sprintf("🆕 New subdomains (%d):", len(d.NewSubdomains)), d.NewSubdomains, cap, "+ ")
	}
	return strings.TrimSpace(b.String())
}

// section appends a titled, capped list of items to b.
func section(b *strings.Builder, title string, items []string, cap int, prefix string) {
	if b.Len() > 0 {
		b.WriteString("\n")
	}
	b.WriteString(title + "\n")
	for i, s := range items {
		if i >= cap {
			b.WriteString(fmt.Sprintf("…and %d more\n", len(items)-cap))
			break
		}
		b.WriteString(prefix + s + "\n")
	}
}

func severityEmoji(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "⚪"
	default:
		return "▫️"
	}
}

func countAtOrAbove(findings []report.NucleiFinding, floor int) int {
	n := 0
	for _, f := range findings {
		if severityRank(f.Severity) >= floor {
			n++
		}
	}
	return n
}

func severityCounts(findings []report.NucleiFinding) (crit, high, med, low int) {
	for _, f := range findings {
		switch strings.ToLower(f.Severity) {
		case "critical":
			crit++
		case "high":
			high++
		case "medium":
			med++
		case "low":
			low++
		}
	}
	return
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func defaultSeverity(s string) string {
	if strings.TrimSpace(s) == "" {
		return "high"
	}
	return s
}

func presetLabel(p string) string {
	if strings.TrimSpace(p) == "" {
		return "custom"
	}
	return p
}

// DeltaMessage builds a monitoring alert describing what changed since the last
// run. Exported so the monitor command can send it directly.
func DeltaMessage(domain, preset string, d *report.Delta, reportPath string) notify.Message {
	crit, high, med, low := severityCounts(d.NewFindings)

	level := notify.LevelInfo
	title := "🔔 New activity: " + domain
	switch {
	case crit > 0:
		level, title = notify.LevelError, fmt.Sprintf("🚨 %d new critical: %s", crit, domain)
	case high > 0 || len(d.NewTakeovers) > 0:
		level, title = notify.LevelWarn, fmt.Sprintf("⚠️ %d new high / %d takeover(s): %s", high, len(d.NewTakeovers), domain)
	}

	fields := []notify.Field{
		{Name: "New subdomains", Value: strconv.Itoa(len(d.NewSubdomains)), Inline: true},
		{Name: "New live hosts", Value: strconv.Itoa(len(d.NewLiveHosts)), Inline: true},
		{Name: "New open ports", Value: strconv.Itoa(len(d.NewPorts)), Inline: true},
		{Name: "New findings", Value: fmt.Sprintf("%d  🔴%d 🟠%d 🟡%d ⚪%d", len(d.NewFindings), crit, high, med, low), Inline: false},
		{Name: "New takeovers", Value: strconv.Itoa(len(d.NewTakeovers)), Inline: true},
	}

	const cap = 12
	var b strings.Builder
	for i, f := range d.NewFindings {
		if i == 0 {
			b.WriteString("New findings:\n")
		}
		if i >= cap {
			b.WriteString(fmt.Sprintf("…and %d more\n", len(d.NewFindings)-cap))
			break
		}
		where := f.URL
		if where == "" {
			where = f.Host
		}
		b.WriteString(fmt.Sprintf("%s [%s] %s — %s\n", severityEmoji(f.Severity), f.Severity, f.Name, where))
	}
	if len(d.NewLiveHosts) > 0 {
		section(&b, fmt.Sprintf("🆕 New live hosts (%d):", len(d.NewLiveHosts)), d.NewLiveHosts, cap, "+ ")
	}
	if len(d.NewSubdomains) > 0 {
		section(&b, fmt.Sprintf("🆕 New subdomains (%d):", len(d.NewSubdomains)), d.NewSubdomains, cap, "+ ")
	}

	payload := &notify.ResultPayload{
		Domain:        domain,
		Event:         "monitor_delta",
		Preset:        preset,
		NewSubdomains: d.NewSubdomains,
		NewLiveHosts:  d.NewLiveHosts,
		ReportPath:    reportPath,
		Stats: map[string]int{
			"new_subdomains": len(d.NewSubdomains),
			"new_live_hosts": len(d.NewLiveHosts),
			"new_findings":   len(d.NewFindings),
			"new_takeovers":  len(d.NewTakeovers),
			"new_open_ports": len(d.NewPorts),
		},
	}
	for _, f := range d.NewFindings {
		payload.Findings = append(payload.Findings, findingPayload(f))
	}

	return notify.Message{
		Title:  title,
		Level:  level,
		Fields: fields,
		Text:   strings.TrimSpace(b.String()),
		Footer: "sondra monitor",
		Data:   payload,
	}
}

// resultPayload builds the machine-readable payload for generic webhooks.
func (r *Runner) resultPayload(d *report.ReportData, event string, elapsed time.Duration) *notify.ResultPayload {
	if d == nil {
		return nil
	}
	p := &notify.ResultPayload{
		Domain:        r.cfg.Domain,
		Event:         event,
		Preset:        r.cfg.Preset,
		DurationSec:   int(elapsed.Seconds()),
		NewSubdomains: d.NewSubdomains,
		HighValue:     d.HighValue,
		ReportPath:    r.cfg.OutputDir + "/master_report.html",
		Stats: map[string]int{
			"subdomains": d.SubdomainCount,
			"live_hosts": d.LiveCount,
			"findings":   d.NucleiHits,
			"takeovers":  d.TakeoverCount,
			"open_ports": d.PortCount,
			"urls":       d.URLCount,
		},
	}
	for _, f := range d.Findings {
		p.Findings = append(p.Findings, findingPayload(f))
	}
	return p
}

func findingPayload(f report.NucleiFinding) notify.FindingPayload {
	return notify.FindingPayload{
		TemplateID: f.TemplateID,
		Name:       f.Name,
		Severity:   strings.ToLower(f.Severity),
		Host:       f.Host,
		URL:        f.URL,
	}
}

// statusCodeBreakdown renders "200×6 403×3 301×1" sorted by frequency.
func statusCodeBreakdown(codes map[int]int) string {
	if len(codes) == 0 {
		return ""
	}
	type kv struct {
		code, n int
	}
	var items []kv
	for c, n := range codes {
		items = append(items, kv{c, n})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].n != items[j].n {
			return items[i].n > items[j].n
		}
		return items[i].code < items[j].code
	})
	var parts []string
	for i, it := range items {
		if i >= 8 {
			break
		}
		parts = append(parts, fmt.Sprintf("%d×%d", it.code, it.n))
	}
	return strings.Join(parts, "  ")
}

// techBreakdown renders the most common technologies across live hosts.
func techBreakdown(hosts []report.HostEntry) string {
	counts := make(map[string]int)
	for _, h := range hosts {
		for _, t := range h.Technologies {
			if t = strings.TrimSpace(t); t != "" {
				counts[t]++
			}
		}
	}
	if len(counts) == 0 {
		return ""
	}
	type kv struct {
		name string
		n    int
	}
	var items []kv
	for name, n := range counts {
		items = append(items, kv{name, n})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].n != items[j].n {
			return items[i].n > items[j].n
		}
		return items[i].name < items[j].name
	})
	var parts []string
	for i, it := range items {
		if i >= 8 {
			break
		}
		parts = append(parts, it.name)
	}
	return strings.Join(parts, ", ")
}

// activeModuleNames lists the enabled modules for the start notification.
func activeModuleNames(m config.ModuleFlags) []string {
	var names []string
	add := func(on bool, name string) {
		if on {
			names = append(names, name)
		}
	}
	add(m.Subfinder, "subfinder")
	add(m.Assetfinder, "assetfinder")
	add(m.Crtsh, "crtsh")
	add(m.Alterx, "alterx")
	add(m.Massdns, "massdns")
	add(m.Httpx, "httpx")
	add(m.Takeover, "takeover")
	add(m.Naabu, "naabu")
	add(m.Gowitness, "gowitness")
	add(m.Gau, "gau")
	add(m.Katana, "katana")
	add(m.NucleiHigh, "nuclei-high")
	add(m.NucleiMedium, "nuclei-medium")
	return names
}
