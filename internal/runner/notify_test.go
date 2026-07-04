package runner

import (
	"strings"
	"testing"

	"github.com/AliMousaviSoft/sondra/internal/config"
	"github.com/AliMousaviSoft/sondra/internal/report"
)

func TestSeverityCounts(t *testing.T) {
	findings := []report.NucleiFinding{
		{Severity: "critical"}, {Severity: "high"}, {Severity: "HIGH"},
		{Severity: "medium"}, {Severity: "low"}, {Severity: "info"},
	}
	crit, high, med, low := severityCounts(findings)
	if crit != 1 || high != 2 || med != 1 || low != 1 {
		t.Fatalf("got c=%d h=%d m=%d l=%d", crit, high, med, low)
	}
}

func TestSeverityRankOrdering(t *testing.T) {
	if !(severityRank("critical") > severityRank("high") &&
		severityRank("high") > severityRank("medium") &&
		severityRank("medium") > severityRank("low") &&
		severityRank("low") > severityRank("unknown")) {
		t.Fatal("severity ranks are not strictly ordered")
	}
}

func TestSummaryTextFiltersByFloor(t *testing.T) {
	d := &report.ReportData{
		Findings: []report.NucleiFinding{
			{Name: "crit-bug", Severity: "critical", URL: "https://a"},
			{Name: "low-noise", Severity: "low", URL: "https://b"},
		},
		HighValue:     []string{"https://admin.example.com"},
		NewSubdomains: []string{"new.example.com"},
	}
	out := summaryText(d, "high")
	if !strings.Contains(out, "crit-bug") {
		t.Fatalf("critical finding should be listed: %q", out)
	}
	if strings.Contains(out, "low-noise") {
		t.Fatalf("low finding below floor should be excluded: %q", out)
	}
	if !strings.Contains(out, "admin.example.com") {
		t.Fatalf("high-value hosts should be listed: %q", out)
	}
	if !strings.Contains(out, "new.example.com") {
		t.Fatalf("new subdomains should be listed: %q", out)
	}
}

func TestCountAtOrAbove(t *testing.T) {
	findings := []report.NucleiFinding{
		{Severity: "critical"}, {Severity: "high"}, {Severity: "medium"}, {Severity: "low"},
	}
	if got := countAtOrAbove(findings, severityRank("high")); got != 2 {
		t.Fatalf("expected 2 findings ≥ high, got %d", got)
	}
	if got := countAtOrAbove(findings, severityRank("low")); got != 4 {
		t.Fatalf("expected 4 findings ≥ low, got %d", got)
	}
}

func TestDeltaMessage(t *testing.T) {
	d := &report.Delta{
		Domain:        "example.com",
		NewSubdomains: []string{"new.example.com"},
		NewLiveHosts:  []string{"https://new.example.com"},
		NewFindings: []report.NucleiFinding{
			{Name: "New Crit", Severity: "critical", URL: "https://new.example.com/x"},
		},
	}
	msg := DeltaMessage("example.com", "quick", d, "/tmp/report.html")

	if !strings.Contains(msg.Title, "critical") {
		t.Fatalf("title should flag the critical: %q", msg.Title)
	}
	if !strings.Contains(msg.Text, "New Crit") || !strings.Contains(msg.Text, "new.example.com") {
		t.Fatalf("text missing finding/subdomain: %q", msg.Text)
	}
	if msg.Data == nil || msg.Data.Event != "monitor_delta" {
		t.Fatalf("structured payload missing/wrong: %+v", msg.Data)
	}
	if len(msg.Data.Findings) != 1 {
		t.Fatalf("payload should carry the new finding: %+v", msg.Data)
	}
}

func TestStatusCodeBreakdown(t *testing.T) {
	got := statusCodeBreakdown(map[int]int{200: 6, 403: 3, 301: 1})
	if !strings.HasPrefix(got, "200×6") {
		t.Fatalf("expected most-frequent first, got %q", got)
	}
}

func TestActiveModuleNames(t *testing.T) {
	mods := config.ModuleFlags{Subfinder: true, Httpx: true, NucleiHigh: true}
	names := activeModuleNames(mods)
	if len(names) != 3 {
		t.Fatalf("expected 3 active modules, got %d: %v", len(names), names)
	}
	joined := strings.Join(names, ",")
	for _, want := range []string{"subfinder", "httpx", "nuclei-high"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in %v", want, names)
		}
	}
}
