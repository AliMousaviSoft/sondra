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
