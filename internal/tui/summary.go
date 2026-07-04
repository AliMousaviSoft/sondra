package tui

import (
	"fmt"
	"strings"

	"github.com/AliMousaviSoft/sondra/internal/config"
	"github.com/AliMousaviSoft/sondra/internal/report"
	"github.com/charmbracelet/lipgloss"
)

var (
	summaryTitle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#E84855"))
	summaryDim   = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888"))
)

// RenderResultsBox collects a completed scan's output and renders the summary
// box for headless stdout. Empty string if the scan produced no data.
func RenderResultsBox(cfg *config.Config) string {
	data, err := report.Collect(cfg)
	if err != nil || data == nil {
		return ""
	}
	return RenderSummary(76, data, cfg.OutputDir+"/master_report.html")
}

// RenderSummary renders a results box at the given width. Shared by headless
// output and the TUI's done state so both look identical.
func RenderSummary(width int, d *report.ReportData, reportPath string) string {
	if width < 44 {
		width = 44
	}
	if width > 100 {
		width = 100
	}

	crit, high, med, low := severityBreakdown(d.Findings)

	var b strings.Builder
	b.WriteString(summaryTitle.Render("RESULTS · "+d.Domain) + "\n")
	b.WriteString(fmt.Sprintf("%d subdomains · %d live · %d high-value\n",
		d.SubdomainCount, d.LiveCount, len(d.HighValue)))
	b.WriteString(fmt.Sprintf("findings  🔴 %d  🟠 %d  🟡 %d  ⚪ %d\n", crit, high, med, low))
	b.WriteString(fmt.Sprintf("takeovers %d · open ports %d · urls %d\n",
		d.TakeoverCount, d.PortCount, d.URLCount))
	b.WriteString(summaryDim.Render("report → " + reportPath))

	return "\n" + lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#E84855")).
		Padding(0, 2).
		Width(width-2).
		Render(strings.TrimRight(b.String(), "\n")) + "\n"
}

func severityBreakdown(findings []report.NucleiFinding) (crit, high, med, low int) {
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
