package modules

import (
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

func RunResolve(ctx context.Context, cfg *config.Config, log chan<- tui.LogEntry) Result {
	start := time.Now()
	inFile := filepath.Join(cfg.OutputDir, "alldomains.txt")
	outFile := filepath.Join(cfg.OutputDir, "resolved.txt")

	if CacheValid(outFile, cfg.CacheAge) {
		count := countLines(outFile)
		sendLog(log, tui.LogInfo, "resolve", fmt.Sprintf("cache hit — %d resolved", count))
		return Result{Name: "resolve", Count: count, Output: outFile}
	}

	lines, err := readLines(inFile)
	if err != nil {
		return Result{Name: "resolve", Error: fmt.Errorf("read alldomains.txt: %w", err)}
	}
	if len(lines) == 0 {
		return Result{Name: "resolve", Error: fmt.Errorf("alldomains.txt is empty")}
	}

	// Dedup before resolving.
	seen := make(map[string]struct{}, len(lines))
	var unique []string
	for _, l := range lines {
		if _, ok := seen[l]; !ok {
			seen[l] = struct{}{}
			unique = append(unique, l)
		}
	}

	sendLog(log, tui.LogInfo, "resolve",
		fmt.Sprintf("resolving %d unique subdomains via dnsx…", len(unique)))

	if _, err := exec.LookPath("dnsx"); err != nil {
		return Result{Name: "resolve", Error: fmt.Errorf("dnsx not in PATH — install: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest")}
	}

	tmpFile := inFile + ".tmp"
	if err := writeLines(tmpFile, unique); err != nil {
		return Result{Name: "resolve", Error: err}
	}
	defer os.Remove(tmpFile)

	resolvedFile := inFile + ".resolved"
	args := []string{
		"-l", tmpFile,
		"-o", resolvedFile,
		"-silent",
		"-no-color",
		"-t", fmt.Sprintf("%d", cfg.Concurrency),
		"-rl", fmt.Sprintf("%d", cfg.RateLimit),
		"-resp",
	}

	if cfg.ResolversFile != "" {
		if _, err := os.Stat(cfg.ResolversFile); err == nil {
			args = append(args, "-r", cfg.ResolversFile)
		}
	}

	cmd := exec.CommandContext(ctx, "dnsx", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return Result{Name: "resolve", Error: fmt.Errorf("dnsx: %w — %s", err, stderr.String())}
	}

	rawLines, err := readLines(resolvedFile)
	if err != nil {
		return Result{Name: "resolve", Error: fmt.Errorf("read dnsx output: %w", err)}
	}
	defer os.Remove(resolvedFile)

	// dnsx -resp outputs: "sub.example.com [1.2.3.4]" — strip the IP part.
	var resolved []string
	for _, l := range rawLines {
		parts := strings.Fields(l)
		if len(parts) > 0 {
			resolved = append(resolved, parts[0])
		}
	}

	if len(resolved) == 0 {
		return Result{Name: "resolve", Error: fmt.Errorf("zero subdomains resolved — check network/resolvers")}
	}

	if err := writeLines(outFile, resolved); err != nil {
		return Result{Name: "resolve", Error: err}
	}

	sendLog(log, tui.LogSuccess, "resolve",
		fmt.Sprintf("%d/%d subdomains resolved", len(resolved), len(unique)))

	return Result{
		Name:    "resolve",
		Count:   len(resolved),
		Output:  outFile,
		Elapsed: time.Since(start),
	}
}