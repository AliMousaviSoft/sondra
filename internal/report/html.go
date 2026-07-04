package report

import (
	"bufio"
	"encoding/json"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/AliMousaviSoft/sondra/internal/config"
)

// ──────────────────────────────────────────────
// Data types
// ──────────────────────────────────────────────

// ReportData is the template input struct.
type ReportData struct {
	Domain         string
	Date           time.Time
	ModulesRan     []string
	SubdomainCount int
	LiveCount      int
	NucleiHits     int
	TakeoverCount  int
	URLCount       int
	JSCount        int
	PortCount      int
	StatusCodes    map[int]int
	LiveHosts      []HostEntry
	Findings       []NucleiFinding
	Takeovers      []string
	NewSubdomains  []string
	OpenPorts      []string
	HighValue      []string
}

// HostEntry is one live HTTP host for the report table.
type HostEntry struct {
	URL          string
	StatusCode   int
	Title        string
	Technologies []string
	WebServer    string
	HighValue    bool
}

// NucleiFinding represents a nuclei JSONL result line.
type NucleiFinding struct {
	TemplateID string `json:"template-id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	Host       string `json:"host"`
	URL        string `json:"matched-at"`
	Timestamp  string `json:"timestamp"`
}

// ──────────────────────────────────────────────
// Generate
// ──────────────────────────────────────────────

// Generate produces master_report.html in cfg.OutputDir.
func Generate(cfg *config.Config) error {
	data, err := collectData(cfg)
	if err != nil {
		return err
	}

	tmplStr := reportTemplate()
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"join":  strings.Join,
		"lower": strings.ToLower,
		"severityClass": func(s string) string {
			switch strings.ToLower(s) {
			case "critical":
				return "sev-critical"
			case "high":
				return "sev-high"
			case "medium":
				return "sev-medium"
			default:
				return "sev-low"
			}
		},
	}).Parse(tmplStr)
	if err != nil {
		return err
	}

	outPath := filepath.Join(cfg.OutputDir, "master_report.html")
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

// ──────────────────────────────────────────────
// Data collection
// ──────────────────────────────────────────────

// Collect gathers a completed scan's output into a ReportData summary.
// Exported for consumers (e.g. notifications) that need scan stats without
// rendering the full HTML report.
func Collect(cfg *config.Config) (*ReportData, error) {
	return collectData(cfg)
}

func collectData(cfg *config.Config) (*ReportData, error) {
	d := &ReportData{
		Domain:      cfg.Domain,
		Date:        time.Now(),
		StatusCodes: make(map[int]int),
	}

	// Subdomains
	if lines, err := readLines(filepath.Join(cfg.OutputDir, "alldomains.txt")); err == nil {
		d.SubdomainCount = len(lines)
	}

	// Live hosts
	if lines, err := readLines(filepath.Join(cfg.OutputDir, "live.txt")); err == nil {
		d.LiveCount = len(lines)
	}

	// High-value
	d.HighValue, _ = readLines(filepath.Join(cfg.OutputDir, "high_value.txt"))

	// Build high-value set for marking.
	hvSet := make(map[string]struct{})
	for _, h := range d.HighValue {
		hvSet[h] = struct{}{}
	}

	// httpx JSON enrichment.
	d.LiveHosts = parseHTTPXJSON(filepath.Join(cfg.OutputDir, "httpx_full.json"), hvSet)
	for _, h := range d.LiveHosts {
		d.StatusCodes[h.StatusCode]++
	}

	// Nuclei findings.
	d.Findings = append(d.Findings, parseNucleiJSONL(filepath.Join(cfg.OutputDir, "nuclei-results", "crit_high.jsonl"))...)
	d.Findings = append(d.Findings, parseNucleiJSONL(filepath.Join(cfg.OutputDir, "nuclei-results", "medium.jsonl"))...)
	d.NucleiHits = len(d.Findings)

	// Sort findings: critical → high → medium → low.
	sort.Slice(d.Findings, func(i, j int) bool {
		return severityRank(d.Findings[i].Severity) > severityRank(d.Findings[j].Severity)
	})

	// Takeovers.
	d.Takeovers, _ = readLines(filepath.Join(cfg.OutputDir, "nuclei-results", "takeovers.txt"))
	d.TakeoverCount = len(d.Takeovers)

	// Open ports.
	d.OpenPorts, _ = readLines(filepath.Join(cfg.OutputDir, "naabu-output", "open_ports.txt"))
	d.PortCount = len(d.OpenPorts)

	// URLs.
	if lines, err := readLines(filepath.Join(cfg.OutputDir, "wayback-data", "all_urls.txt")); err == nil {
		d.URLCount = len(lines)
	}
	if lines, err := readLines(filepath.Join(cfg.OutputDir, "wayback-data", "js_urls.txt")); err == nil {
		d.JSCount = len(lines)
	}

	// New subdomains (diff from previous run).
	d.NewSubdomains, _ = readLines(filepath.Join(cfg.OutputDir, "new_subdomains.txt"))

	return d, nil
}

// ──────────────────────────────────────────────
// Parsers
// ──────────────────────────────────────────────

func parseHTTPXJSON(path string, hvSet map[string]struct{}) []HostEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	type httpxLine struct {
		URL          string   `json:"url"`
		StatusCode   int      `json:"status_code"`
		Title        string   `json:"title"`
		Technologies []string `json:"technologies"`
		WebServer    string   `json:"webserver"`
	}

	dec := json.NewDecoder(f)
	var hosts []HostEntry
	for dec.More() {
		var h httpxLine
		if err := dec.Decode(&h); err == nil {
			_, hv := hvSet[h.URL]
			hosts = append(hosts, HostEntry{
				URL:          h.URL,
				StatusCode:   h.StatusCode,
				Title:        h.Title,
				Technologies: h.Technologies,
				WebServer:    h.WebServer,
				HighValue:    hv,
			})
		}
	}
	return hosts
}

func parseNucleiJSONL(path string) []NucleiFinding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// nuclei result lines (with request/response) can exceed the default 64KB
	// token size — raise it so long findings aren't silently dropped.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var findings []NucleiFinding
	for sc.Scan() {
		// nuclei v3 nests name/severity under "info"; older/flat output has them
		// top-level. Parse both and prefer whichever is populated.
		var raw struct {
			NucleiFinding
			Info struct {
				Name     string `json:"name"`
				Severity string `json:"severity"`
			} `json:"info"`
		}
		if err := json.Unmarshal(sc.Bytes(), &raw); err != nil {
			continue
		}
		nf := raw.NucleiFinding
		if nf.Name == "" {
			nf.Name = raw.Info.Name
		}
		if nf.Severity == "" {
			nf.Severity = raw.Info.Severity
		}
		findings = append(findings, nf)
	}
	return findings
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

// ──────────────────────────────────────────────
// File helpers (local to report package)
// ──────────────────────────────────────────────

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, sc.Err()
}
