package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DiffRuns compares alldomains.txt from the last two scan runs for a domain.
// Returns a slice of subdomains present in the latest run but not the previous one.
func DiffRuns(domain string) ([]string, error) {
	runs, err := listRuns(domain)
	if err != nil {
		return nil, err
	}
	if len(runs) < 2 {
		return nil, nil // only one run exists — nothing to diff
	}

	prev := filepath.Join(runs[len(runs)-2], "alldomains.txt")
	curr := filepath.Join(runs[len(runs)-1], "alldomains.txt")

	newSubs, err := diffFiles(prev, curr)
	if err != nil {
		return nil, fmt.Errorf("diff: %w", err)
	}

	// Write new_subdomains.txt into the latest run directory.
	if len(newSubs) > 0 {
		outFile := filepath.Join(runs[len(runs)-1], "new_subdomains.txt")
		f, err := os.Create(outFile)
		if err == nil {
			defer f.Close()
			for _, s := range newSubs {
				fmt.Fprintln(f, s)
			}
		}
	}

	return newSubs, nil
}

// Delta captures everything new in the latest run vs the previous one — the
// unit continuous monitoring alerts on.
type Delta struct {
	Domain        string
	NewSubdomains []string
	NewLiveHosts  []string
	NewPorts      []string
	NewTakeovers  []string
	NewFindings   []NucleiFinding
}

// Empty reports whether nothing changed between the two runs.
func (d *Delta) Empty() bool {
	return d == nil || (len(d.NewSubdomains) == 0 && len(d.NewLiveHosts) == 0 &&
		len(d.NewPorts) == 0 && len(d.NewTakeovers) == 0 && len(d.NewFindings) == 0)
}

// AssetsChanged reports new attack surface (subdomains / live hosts / ports).
func (d *Delta) AssetsChanged() bool {
	return d != nil && (len(d.NewSubdomains) > 0 || len(d.NewLiveHosts) > 0 || len(d.NewPorts) > 0)
}

// FindingsChanged reports new vulns (nuclei findings / takeovers).
func (d *Delta) FindingsChanged() bool {
	return d != nil && (len(d.NewFindings) > 0 || len(d.NewTakeovers) > 0)
}

// Notable reports whether the delta should trigger an alert under the given
// monitor mode: "findings", "assets", or anything else ("all").
func (d *Delta) Notable(mode string) bool {
	switch mode {
	case "findings":
		return d.FindingsChanged()
	case "assets":
		return d.AssetsChanged()
	default:
		return !d.Empty()
	}
}

// DiffRunsDetailed diffs the two most recent runs across every result type.
// With fewer than two runs it returns a non-nil empty Delta (baseline only).
func DiffRunsDetailed(domain string) (*Delta, error) {
	runs, err := listRuns(domain)
	if err != nil {
		return nil, err
	}
	d := &Delta{Domain: domain}
	if len(runs) < 2 {
		return d, nil // first run — establishes the baseline, nothing to diff
	}
	prev, curr := runs[len(runs)-2], runs[len(runs)-1]

	// diffFiles errors only when the current file is missing (module didn't run);
	// treat that as "no change" for that category.
	d.NewSubdomains, _ = diffFiles(filepath.Join(prev, "alldomains.txt"), filepath.Join(curr, "alldomains.txt"))
	d.NewLiveHosts, _ = diffFiles(filepath.Join(prev, "live.txt"), filepath.Join(curr, "live.txt"))
	d.NewPorts, _ = diffFiles(filepath.Join(prev, "naabu-output", "open_ports.txt"), filepath.Join(curr, "naabu-output", "open_ports.txt"))
	d.NewTakeovers, _ = diffFiles(filepath.Join(prev, "nuclei-results", "takeovers.txt"), filepath.Join(curr, "nuclei-results", "takeovers.txt"))
	d.NewFindings = diffFindings(prev, curr)
	return d, nil
}

// diffFindings returns nuclei findings present in curr but not in prev, keyed by
// template + host + matched-at so re-detections of the same issue don't re-alert.
func diffFindings(prevDir, currDir string) []NucleiFinding {
	load := func(dir string) []NucleiFinding {
		var fs []NucleiFinding
		fs = append(fs, parseNucleiJSONL(filepath.Join(dir, "nuclei-results", "crit_high.jsonl"))...)
		fs = append(fs, parseNucleiJSONL(filepath.Join(dir, "nuclei-results", "medium.jsonl"))...)
		return fs
	}
	key := func(f NucleiFinding) string { return f.TemplateID + "|" + f.Host + "|" + f.URL }

	prevSet := make(map[string]bool)
	for _, f := range load(prevDir) {
		prevSet[key(f)] = true
	}
	var out []NucleiFinding
	for _, f := range load(currDir) {
		if !prevSet[key(f)] {
			out = append(out, f)
		}
	}
	return out
}

// LatestDomain returns the domain whose most recent run is newest, for commands
// that omit an explicit domain. Run dirs are recon-<timestamp>, so the domain
// owning the lexicographically-greatest run name is the most recently scanned.
func LatestDomain() (string, error) {
	entries, err := os.ReadDir(".")
	if err != nil {
		return "", err
	}
	var bestDomain, bestRun string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		runs, err := listRuns(e.Name())
		if err != nil || len(runs) == 0 {
			continue
		}
		if latest := filepath.Base(runs[len(runs)-1]); latest > bestRun {
			bestRun, bestDomain = latest, e.Name()
		}
	}
	if bestDomain == "" {
		return "", fmt.Errorf("no reports yet — run a scan first")
	}
	return bestDomain, nil
}

// LatestReport returns the path to the most recent run's master_report.html
// that actually exists, skipping in-progress runs whose report hasn't been
// written yet (e.g. a monitor pass that just started on restart).
func LatestReport(domain string) (string, error) {
	runs, err := listRuns(domain)
	if err != nil {
		return "", err
	}
	if len(runs) == 0 {
		return "", fmt.Errorf("no runs found for %s", domain)
	}
	for i := len(runs) - 1; i >= 0; i-- {
		p := filepath.Join(runs[i], "master_report.html")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no finished report yet for %s (scan still running?)", domain)
}

// listRuns returns all recon-* subdirectories for a domain, sorted chronologically.
func listRuns(domain string) ([]string, error) {
	base := domain // looks in ./<domain>/
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil, fmt.Errorf("listRuns: can't read %s: %w", base, err)
	}

	var runs []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "recon-") {
			runs = append(runs, filepath.Join(base, e.Name()))
		}
	}

	sort.Strings(runs) // timestamp prefix makes lexicographic = chronological
	return runs, nil
}

// diffFiles returns lines present in b but not in a.
func diffFiles(a, b string) ([]string, error) {
	prevSet, err := readLineSet(a)
	if err != nil {
		return nil, fmt.Errorf("read prev run: %w", err)
	}

	currLines, err := readLines(b)
	if err != nil {
		return nil, fmt.Errorf("read curr run: %w", err)
	}

	var newOnes []string
	for _, line := range currLines {
		if !prevSet[line] {
			newOnes = append(newOnes, line)
		}
	}
	return newOnes, nil
}

// readLineSet reads a file and returns a set (map) of its non-empty lines.
func readLineSet(path string) (map[string]bool, error) {
	lines, err := readLines(path)
	if err != nil {
		// If the file doesn't exist (first run), return empty set — not an error.
		if os.IsNotExist(err) {
			return make(map[string]bool), nil
		}
		return nil, err
	}
	set := make(map[string]bool, len(lines))
	for _, l := range lines {
		set[l] = true
	}
	return set, nil
}
