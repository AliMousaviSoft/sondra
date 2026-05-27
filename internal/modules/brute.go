package modules

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/AliMousaviSoft/sondra/internal/config"
	"github.com/AliMousaviSoft/sondra/internal/tui"
)

// RunActiveBrute runs alterx → massdns permutation-based subdomain discovery.
// Non-fatal: if either binary is missing, logs a warning and returns.
func RunActiveBrute(ctx context.Context, cfg *config.Config, log chan<- tui.LogEntry) Result {
	start := time.Now()
	outFile := filepath.Join(cfg.OutputDir, "all_raw.txt")

	if CacheValid(outFile, cfg.CacheAge) {
		count := countLines(outFile)
		sendLog(log, tui.LogInfo, "active brute", fmt.Sprintf("cache hit — %d entries", count))
		return Result{Name: "active brute", Count: count, Output: outFile}
	}

	// ── alterx: generate permutations ─────────────────────────────────────
	var permFile string
	if cfg.Modules.Alterx {
		pf, err := runAlterx(ctx, cfg, log)
		if err != nil {
			sendLog(log, tui.LogWarn, "alterx", err.Error())
		} else {
			permFile = pf
		}
	}

	// ── massdns: resolve permutations ─────────────────────────────────────
	if cfg.Modules.Massdns && permFile != "" {
		if err := runMassdns(ctx, cfg, permFile, outFile, log); err != nil {
			sendLog(log, tui.LogWarn, "massdns", err.Error())
			return Result{Name: "active brute", Error: err}
		}
	}

	// Merge all_raw.txt into alldomains.txt.
	if lines, err := readLines(outFile); err == nil && len(lines) > 0 {
		if err := appendLines(filepath.Join(cfg.OutputDir, "alldomains.txt"), lines); err != nil {
			sendLog(log, tui.LogWarn, "active brute", fmt.Sprintf("merge alldomains: %v", err))
		}
	}

	count := countLines(outFile)
	return Result{
		Name:    "active brute",
		Count:   count,
		Output:  outFile,
		Elapsed: time.Since(start),
	}
}

// runAlterx generates permutations from the passive subdomain list.
func runAlterx(ctx context.Context, cfg *config.Config, log chan<- tui.LogEntry) (string, error) {
	passiveFile := filepath.Join(cfg.OutputDir, "passive_subs.txt")
	permFile := filepath.Join(cfg.OutputDir, "alterx_perms.txt")

	if CacheValid(permFile, cfg.CacheAge) {
		return permFile, nil
	}

	if _, err := exec.LookPath("alterx"); err != nil {
		return "", fmt.Errorf("alterx not in PATH")
	}

	// alterx -l passive_subs.txt -o alterx_perms.txt
	cmd := exec.CommandContext(ctx, "alterx",
		"-l", passiveFile,
		"-o", permFile,
		"-silent",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("alterx: %w — %s", err, stderr.String())
	}

	count := countLines(permFile)
	sendLog(log, tui.LogSuccess, "alterx", fmt.Sprintf("generated %d permutations", count))
	return permFile, nil
}

// runMassdns resolves a wordlist using massdns.
func runMassdns(ctx context.Context, cfg *config.Config, wordlist, outFile string, log chan<- tui.LogEntry) error {
	if _, err := exec.LookPath("massdns"); err != nil {
		return fmt.Errorf("massdns not in PATH")
	}

	resolvers := cfg.ResolversFile
	if resolvers == "" {
		// Try common default locations.
		for _, p := range []string{
			"/usr/share/seclists/Miscellaneous/dns-resolvers.txt",
			"/opt/resolvers.txt",
		} {
			if _, err := os.Stat(p); err == nil {
				resolvers = p
				break
			}
		}
	}
	if resolvers == "" {
		return fmt.Errorf("no resolvers file found — set resolvers_file in config or SONDRA_RESOLVERS_FILE env")
	}

	rawOut := filepath.Join(filepath.Dir(outFile), "massdns_raw.txt")

	cmd := exec.CommandContext(ctx, "massdns",
		"-r", resolvers,
		"-t", "A",
		"-o", "S",
		"-w", rawOut,
		wordlist,
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("massdns: %w — %s", err, stderr.String())
	}

	// Parse massdns simple output → extract resolved hostnames.
	f, err := os.Open(rawOut)
	if err != nil {
		return err
	}
	defer f.Close()

	seen := make(map[string]struct{})
	var resolved []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		// Simple format: <name>. A <ip>
		parts := strings.Fields(line)
		if len(parts) >= 3 && parts[1] == "A" {
			name := strings.TrimSuffix(parts[0], ".")
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				resolved = append(resolved, name)
			}
		}
	}

	if err := writeLines(outFile, resolved); err != nil {
		return err
	}

	sendLog(log, tui.LogSuccess, "massdns",
		fmt.Sprintf("resolved %d subdomains from %d permutations", len(resolved), countLines(wordlist)))
	return nil
}
