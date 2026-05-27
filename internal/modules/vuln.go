package modules

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AliMousaviSoft/sondra/internal/config"
	"github.com/AliMousaviSoft/sondra/internal/tui"
)

// ──────────────────────────────────────────────
// Port scan (naabu)
// ──────────────────────────────────────────────

func RunPorts(ctx context.Context, cfg *config.Config, log chan<- tui.LogEntry) Result {
	start := time.Now()
	outFile := filepath.Join(cfg.OutputDir, "naabu-output", "open_ports.txt")

	if CacheValid(outFile, cfg.CacheAge) {
		count := countLines(outFile)
		sendLog(log, tui.LogInfo, "naabu", fmt.Sprintf("cache hit — %d open ports", count))
		return Result{Name: "port scan", Count: count, Output: outFile}
	}

	liveFile := filepath.Join(cfg.OutputDir, "live.txt")
	hostsFile := filepath.Join(cfg.OutputDir, "naabu-output", "hosts.txt")

	if err := stripURLsToHosts(liveFile, hostsFile); err != nil {
		return Result{Name: "port scan", Error: fmt.Errorf("prepare hosts: %w", err)}
	}

	if _, err := exec.LookPath("naabu"); err != nil {
		return Result{Name: "port scan", Error: fmt.Errorf("naabu not in PATH")}
	}

	ports := "8080,8443,8888,9090,9200,9300,6379,5432,3306,27017,11211,2181,7001,7002,4848,8161,61616,9001"

	cmd := exec.CommandContext(ctx, "naabu",
		"-list", hostsFile,
		"-p", ports,
		"-rate", fmt.Sprintf("%d", cfg.RateLimit),
		"-c", fmt.Sprintf("%d", cfg.Concurrency),
		"-o", outFile,
		"-silent",
		"-no-color",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return Result{Name: "port scan", Error: fmt.Errorf("naabu: %w — %s", err, stderr.String())}
	}

	count := countLines(outFile)
	if count > 0 {
		sendLog(log, tui.LogSuccess, "naabu", fmt.Sprintf("%d open non-standard ports", count))
	}

	return Result{
		Name:    "port scan",
		Count:   count,
		Output:  outFile,
		Elapsed: time.Since(start),
	}
}

// stripURLsToHosts extracts bare hostnames from a URL list.
// "https://api.hackerone.com" → "api.hackerone.com"
func stripURLsToHosts(inFile, outFile string) error {
	lines, err := readLines(inFile)
	if err != nil {
		return err
	}

	seen := make(map[string]struct{})
	var hosts []string
	for _, l := range lines {
		if idx := strings.LastIndex(l, " ["); idx != -1 {
			l = strings.TrimSpace(l[:idx])
		}
		l = strings.TrimPrefix(l, "https://")
		l = strings.TrimPrefix(l, "http://")
		if idx := strings.Index(l, "/"); idx != -1 {
			l = l[:idx]
		}
		if idx := strings.LastIndex(l, ":"); idx != -1 {
			l = l[:idx]
		}
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if _, ok := seen[l]; !ok {
			seen[l] = struct{}{}
			hosts = append(hosts, l)
		}
	}
	return writeLines(outFile, hosts)
}

// ──────────────────────────────────────────────
// Screenshots (gowitness)
// ──────────────────────────────────────────────

func RunScreenshots(ctx context.Context, cfg *config.Config, log chan<- tui.LogEntry) Result {
	start := time.Now()
	screenshotDir := filepath.Join(cfg.OutputDir, "gowitness-output", "screenshots")
	liveFile := filepath.Join(cfg.OutputDir, "live.txt")

	if _, err := exec.LookPath("gowitness"); err != nil {
		return Result{Name: "screenshots", Error: fmt.Errorf("gowitness not in PATH")}
	}

	sendLog(log, tui.LogInfo, "gowitness", "capturing screenshots…")

	cmd := exec.CommandContext(ctx, "gowitness",
		"scan", "file",
		"-f", liveFile,
		"--screenshot-path", screenshotDir,
		"--write-none",
		"--threads", "4",
		"--timeout", fmt.Sprintf("%d", int(cfg.Timeout.Seconds())),
		"--screenshot-format", "png",
		"-q",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return Result{
			Name:  "screenshots",
			Error: fmt.Errorf("gowitness: %w — %s", err, stderr.String()),
		}
	}

	count := countFiles(screenshotDir, ".png")
	sendLog(log, tui.LogSuccess, "gowitness",
		fmt.Sprintf("%d screenshots captured", count))

	return Result{
		Name:    "screenshots",
		Count:   count,
		Output:  screenshotDir,
		Elapsed: time.Since(start),
	}
}

// ──────────────────────────────────────────────
// URL collection (gau + katana)
// ──────────────────────────────────────────────

func RunURLCollection(ctx context.Context, cfg *config.Config, log chan<- tui.LogEntry) Result {
	start := time.Now()
	allURLs := filepath.Join(cfg.OutputDir, "wayback-data", "all_urls.txt")

	if CacheValid(allURLs, cfg.CacheAge) {
		count := countLines(allURLs)
		sendLog(log, tui.LogInfo, "url collection", fmt.Sprintf("cache hit — %d URLs", count))
		return Result{Name: "url collection", Count: count, Output: allURLs}
	}

	liveFile := filepath.Join(cfg.OutputDir, "live.txt")
	hosts, err := readLines(liveFile)
	if err != nil || len(hosts) == 0 {
		return Result{Name: "url collection", Error: fmt.Errorf("no live hosts for URL collection")}
	}

	var allLines []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	if cfg.Modules.Gau {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lines, err := runGau(ctx, cfg, log)
			if err != nil {
				sendLog(log, tui.LogWarn, "gau", err.Error())
				return
			}
			mu.Lock()
			allLines = append(allLines, lines...)
			mu.Unlock()
		}()
	}

	if cfg.Modules.Katana {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lines, err := runKatana(ctx, cfg, liveFile, log)
			if err != nil {
				sendLog(log, tui.LogWarn, "katana", err.Error())
				return
			}
			mu.Lock()
			allLines = append(allLines, lines...)
			mu.Unlock()
		}()
	}

	wg.Wait()

	if err := deduplicateAndClassify(cfg, allLines, allURLs); err != nil {
		return Result{Name: "url collection", Error: err}
	}

	count := countLines(allURLs)
	sendLog(log, tui.LogSuccess, "url collection",
		fmt.Sprintf("%d unique URLs collected", count))

	return Result{
		Name:    "url collection",
		Count:   count,
		Output:  allURLs,
		Elapsed: time.Since(start),
	}
}

func runGau(ctx context.Context, cfg *config.Config, log chan<- tui.LogEntry) ([]string, error) {
	// Resolve binary directly — avoids shell alias conflicts (e.g. gau aliased to git add --update).
	gauBin := ""
	for _, candidate := range []string{
		filepath.Join(os.Getenv("HOME"), "go/bin/gau"),
		"/usr/local/bin/gau",
		"/usr/bin/gau",
	} {
		if _, err := os.Stat(candidate); err == nil {
			gauBin = candidate
			break
		}
	}
	if gauBin == "" {
		return nil, fmt.Errorf("gau binary not found — install: go install github.com/lc/gau/v2/cmd/gau@latest")
	}

	gauFile := filepath.Join(cfg.OutputDir, "wayback-data", "gau.txt")
	cmd := exec.CommandContext(ctx, gauBin,
		"--threads", "5",
		"--timeout", fmt.Sprintf("%d", int(cfg.Timeout.Seconds())),
		"--o", gauFile,
		cfg.Domain,
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gau: %w — %s", err, stderr.String())
	}

	lines, err := readLines(gauFile)
	if err != nil {
		return nil, err
	}
	sendLog(log, tui.LogSuccess, "gau", fmt.Sprintf("%d URLs from Wayback/CommonCrawl", len(lines)))
	return lines, nil
}

func runKatana(ctx context.Context, cfg *config.Config, liveFile string, log chan<- tui.LogEntry) ([]string, error) {
	if _, err := exec.LookPath("katana"); err != nil {
		return nil, fmt.Errorf("katana not in PATH")
	}

	katanaFile := filepath.Join(cfg.OutputDir, "wayback-data", "katana.txt")
	cmd := exec.CommandContext(ctx, "katana",
		"-list", liveFile,
		"-depth", "2",          // was 3
		"-jc",
		"-kf", "all",
		"-c", fmt.Sprintf("%d", cfg.Concurrency/2),
		"-timeout", fmt.Sprintf("%d", int(cfg.Timeout.Seconds())),
		"-o", katanaFile,
		"-silent",
		"-no-color",
		"-fs", "fqdn",          // scope: stay on same FQDN only
		"-duc",                 // disable update check
		"-rl", "50",            // rate limit: 50 req/sec max
		"-ct", "30",            // crawl duration timeout: 30 seconds per host
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("katana: %w — %s", err, stderr.String())
	}

	lines, err := readLines(katanaFile)
	if err != nil {
		return nil, err
	}
	sendLog(log, tui.LogSuccess, "katana", fmt.Sprintf("%d endpoints crawled", len(lines)))
	return lines, nil
}

func deduplicateAndClassify(cfg *config.Config, urls []string, allURLsFile string) error {
	seen := make(map[string]struct{}, len(urls))
	var unique []string
	for _, u := range urls {
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			unique = append(unique, u)
		}
	}

	if err := writeLines(allURLsFile, unique); err != nil {
		return err
	}

	dir := filepath.Join(cfg.OutputDir, "wayback-data")
	classify := map[string]func(string) bool{
		"js_urls.txt":   func(u string) bool { return matchExt(u, ".js") },
		"php_urls.txt":  func(u string) bool { return matchExt(u, ".php") },
		"aspx_urls.txt": func(u string) bool { return matchExt(u, ".aspx", ".asp") },
		"endpoints.txt": func(u string) bool { return hasParam(u) },
	}

	for file, filterFn := range classify {
		var matched []string
		for _, u := range unique {
			if filterFn(u) {
				matched = append(matched, u)
			}
		}
		_ = writeLines(filepath.Join(dir, file), matched)
	}

	return nil
}

// ──────────────────────────────────────────────
// Nuclei
// ──────────────────────────────────────────────

func RunNuclei(ctx context.Context, cfg *config.Config, log chan<- tui.LogEntry, bgWg *sync.WaitGroup) error {
	if _, err := exec.LookPath("nuclei"); err != nil {
		sendLog(log, tui.LogWarn, "nuclei", "nuclei not in PATH — skipping")
		return nil
	}

	liveFile := filepath.Join(cfg.OutputDir, "live.txt")
	templates := buildTemplateDirs(cfg.NucleiTemplates)

	if cfg.Modules.NucleiHigh {
		sendLog(log, tui.LogInfo, "nuclei", "running crit/high templates (blocking)…")
		outFile := filepath.Join(cfg.OutputDir, "nuclei-results", "crit_high.jsonl")
		if err := runNucleiExec(ctx, cfg, templates, "critical,high", liveFile, outFile, log); err != nil {
			sendLog(log, tui.LogWarn, "nuclei", fmt.Sprintf("crit/high: %v", err))
		}
	}

	if cfg.Modules.Takeover {
		sendLog(log, tui.LogInfo, "nuclei", "running takeover templates…")
		takeoverFile := filepath.Join(cfg.OutputDir, "nuclei-results", "takeovers.txt")
		allDomains := filepath.Join(cfg.OutputDir, "alldomains.txt")
		_ = runNucleiExec(ctx, cfg, []string{"dns/takeovers"}, "info,low,medium,high,critical",
			allDomains, takeoverFile, log)
	}

	if cfg.Modules.NucleiMedium {
		bgWg.Add(1)
		go func() {
			defer bgWg.Done()
			sendLog(log, tui.LogInfo, "nuclei", "running medium templates (background)…")
			outFile := filepath.Join(cfg.OutputDir, "nuclei-results", "medium.jsonl")
			if err := runNucleiExec(context.Background(), cfg, templates, "medium",
				liveFile, outFile, log); err != nil {
				sendLog(log, tui.LogWarn, "nuclei medium", err.Error())
				return
			}
			count := countLines(outFile)
			sendLog(log, tui.LogSuccess, "nuclei medium",
				fmt.Sprintf("%d medium findings", count))
		}()
		sendLog(log, tui.LogInfo, "nuclei", "medium scan running in background…")
	}

	return nil
}

func runNucleiExec(ctx context.Context, cfg *config.Config,
	templates []string, severity, inFile, outFile string,
	log chan<- tui.LogEntry) error {

	args := []string{
		"-l", inFile,
		"-severity", severity,
		"-o", outFile,
		"-jsonl",
		"-silent",
		"-no-color",
		"-rate-limit", fmt.Sprintf("%d", cfg.RateLimit/3),
		"-c", fmt.Sprintf("%d", cfg.Concurrency/4),
		"-timeout", fmt.Sprintf("%d", int(cfg.Timeout.Seconds())),
	}

	for _, t := range templates {
		args = append(args, "-t", t)
	}

	cmd := exec.CommandContext(ctx, "nuclei", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return fmt.Errorf("nuclei (%s): %w — %s", severity, err, stderr.String())
		}
	}

	count := countLines(outFile)
	if count > 0 {
		sendLog(log, tui.LogSuccess, "nuclei",
			fmt.Sprintf("[%s] %d findings", severity, count))
	}

	return nil
}

func buildTemplateDirs(base string) []string {
	preferred := []string{
		"http/cves",
		"http/misconfiguration",
		"http/exposures",
		"http/default-logins",
		"http/takeovers",
		"http/technologies",
	}

	var found []string
	for _, d := range preferred {
		full := filepath.Join(base, d)
		if isDir(full) {
			found = append(found, full)
		}
	}

	if len(found) == 0 {
		return []string{base}
	}
	return found
}