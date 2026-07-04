package modules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

	if cfg.Modules.Gowayback {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lines, err := runGoWayback(ctx, cfg, log)
			if err != nil {
				sendLog(log, tui.LogWarn, "gowaybackgo", err.Error())
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

// runGoWayback collects Wayback Machine CDX URLs via gowaybackgo, excluding
// common static assets. Preferred over gau/waybackurls for wayback coverage.
func runGoWayback(ctx context.Context, cfg *config.Config, log chan<- tui.LogEntry) ([]string, error) {
	if _, err := exec.LookPath("gowaybackgo"); err != nil {
		return nil, fmt.Errorf("gowaybackgo not in PATH — install: go install -v github.com/OoS-MaMaD/gowaybackgo@latest")
	}

	outFile := filepath.Join(cfg.OutputDir, "wayback-data", "gowaybackgo.txt")
	cmd := exec.CommandContext(ctx, "gowaybackgo",
		"-u", cfg.Domain,
		"--exclude-defaults",
		"-o", outFile,
		"--rate", "10",
		"--timeout", fmt.Sprintf("%d", int(cfg.Timeout.Seconds())),
	)

	var stderr bytes.Buffer
	cmd.Stdout = io.Discard // it also prints URLs to stdout; we read the file
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("gowaybackgo: %w — %s", err, strings.TrimSpace(stderr.String()))
	}

	lines, err := readLines(outFile)
	if err != nil {
		return nil, err
	}
	sendLog(log, tui.LogSuccess, "gowaybackgo", fmt.Sprintf("%d URLs from Wayback CDX", len(lines)))
	return lines, nil
}

func runKatana(ctx context.Context, cfg *config.Config, liveFile string, log chan<- tui.LogEntry) ([]string, error) {
	if _, err := exec.LookPath("katana"); err != nil {
		return nil, fmt.Errorf("katana not in PATH")
	}

	katanaFile := filepath.Join(cfg.OutputDir, "wayback-data", "katana.txt")
	cmd := exec.CommandContext(ctx, "katana",
		"-list", liveFile,
		"-depth", "2", // was 3
		"-jc",
		"-kf", "all",
		"-c", fmt.Sprintf("%d", cfg.Concurrency/2),
		"-timeout", fmt.Sprintf("%d", int(cfg.Timeout.Seconds())),
		"-o", katanaFile,
		"-silent",
		"-no-color",
		"-fs", "fqdn", // scope: stay on same FQDN only
		"-duc",      // disable update check
		"-rl", "50", // rate limit: 50 req/sec max
		"-ct", "30", // crawl duration timeout: 30 seconds per host
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

// FindingFunc is called once per newly discovered nuclei finding, enabling
// real-time per-finding notifications. May be nil.
type FindingFunc func(name, severity, where string)

func RunNuclei(ctx context.Context, cfg *config.Config, log chan<- tui.LogEntry, bgWg *sync.WaitGroup, onFinding FindingFunc) error {
	if _, err := exec.LookPath("nuclei"); err != nil {
		sendLog(log, tui.LogWarn, "nuclei", "nuclei not in PATH — skipping")
		return nil
	}

	liveFile := filepath.Join(cfg.OutputDir, "live.txt")
	templates := buildTemplateDirs(cfg.NucleiTemplates)

	if cfg.Modules.NucleiHigh {
		sendLog(log, tui.LogInfo, "nuclei", "running crit/high templates (blocking)…")
		outFile := filepath.Join(cfg.OutputDir, "nuclei-results", "crit_high.jsonl")
		if err := runNucleiExec(ctx, cfg, templates, "critical,high", liveFile, outFile, log, onFinding); err != nil {
			sendLog(log, tui.LogWarn, "nuclei", fmt.Sprintf("crit/high: %v", err))
		}
	}

	if cfg.Modules.Takeover {
		sendLog(log, tui.LogInfo, "nuclei", "running takeover templates…")
		takeoverFile := filepath.Join(cfg.OutputDir, "nuclei-results", "takeovers.txt")
		allDomains := filepath.Join(cfg.OutputDir, "alldomains.txt")
		_ = runNucleiExec(ctx, cfg, []string{"dns/takeovers"}, "info,low,medium,high,critical",
			allDomains, takeoverFile, log, onFinding)
	}

	if cfg.Modules.NucleiMedium {
		bgWg.Add(1)
		go func() {
			defer bgWg.Done()
			sendLog(log, tui.LogInfo, "nuclei", "running medium templates (background)…")
			outFile := filepath.Join(cfg.OutputDir, "nuclei-results", "medium.jsonl")
			// Bound to the run ctx so SIGINT / a failed later step tears this
			// down instead of leaving nuclei running after the scan returns.
			if err := runNucleiExec(ctx, cfg, templates, "medium",
				liveFile, outFile, log, onFinding); err != nil {
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
	log chan<- tui.LogEntry, onFinding FindingFunc) error {

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
	// nuclei's own -stats display only renders to a TTY; piped it shows nothing,
	// so we tail the -o JSONL file instead. Keep nuclei's stdout off ours and
	// capture stderr only for error diagnostics.
	var stderr bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("nuclei (%s): start: %w", severity, err)
	}

	// Tail the results file: stream each finding live and beat a heartbeat while
	// nuclei is quiet, so the run is observable regardless of TTY/-silent.
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tailNucleiFindings(done, outFile, severity, log, onFinding)
	}()

	err := cmd.Wait()
	close(done)
	wg.Wait()

	if err != nil {
		// A cancelled context is expected on SIGINT — don't treat it as failure.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if s := strings.TrimSpace(stderr.String()); s != "" {
			return fmt.Errorf("nuclei (%s): %w — %s", severity, err, s)
		}
	}

	count := countLines(outFile)
	if count > 0 {
		sendLog(log, tui.LogSuccess, "nuclei",
			fmt.Sprintf("[%s] %d findings total", severity, count))
	}

	return nil
}

// nucleiHit is the minimal shape we pull from a nuclei JSONL result line.
type nucleiHit struct {
	name     string
	severity string
	where    string
}

// parseNucleiLine extracts a finding from one JSONL line, tolerating both the
// nested (info.name/info.severity) and flat schemas across nuclei versions.
func parseNucleiLine(b []byte) (nucleiHit, bool) {
	var o struct {
		TemplateID string `json:"template-id"`
		Host       string `json:"host"`
		MatchedAt  string `json:"matched-at"`
		Name       string `json:"name"`
		Severity   string `json:"severity"`
		Info       struct {
			Name     string `json:"name"`
			Severity string `json:"severity"`
		} `json:"info"`
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return nucleiHit{}, false
	}
	name := firstNonEmpty(o.Info.Name, o.Name, o.TemplateID)
	if name == "" {
		return nucleiHit{}, false
	}
	return nucleiHit{
		name:     name,
		severity: firstNonEmpty(o.Info.Severity, o.Severity, "unknown"),
		where:    firstNonEmpty(o.MatchedAt, o.Host),
	}, true
}

func sevEmoji(s string) string {
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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// tailNucleiFindings polls the JSONL results file until done, logging each new
// finding live and emitting a heartbeat when nuclei has been quiet for a while.
func tailNucleiFindings(done <-chan struct{}, outFile, severity string, log chan<- tui.LogEntry, onFinding FindingFunc) {
	start := time.Now()
	lastBeat := time.Now()
	seen := 0

	drain := func() {
		lines, err := readLines(outFile)
		if err != nil {
			return
		}
		var hits []nucleiHit
		for _, l := range lines {
			if h, ok := parseNucleiLine([]byte(l)); ok {
				hits = append(hits, h)
			}
		}
		// Log only findings we haven't reported yet. Partial trailing lines fail
		// to parse and simply reappear (complete) on the next poll.
		for _, h := range hits[min(seen, len(hits)):] {
			sendLog(log, tui.LogSuccess, "nuclei",
				fmt.Sprintf("%s [%s] %s — %s", sevEmoji(h.severity), h.severity, h.name, h.where))
			if onFinding != nil {
				onFinding(h.name, h.severity, h.where)
			}
		}
		if len(hits) > seen {
			seen = len(hits)
			lastBeat = time.Now() // a finding is itself a sign of life
		}
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			drain() // final flush
			return
		case <-ticker.C:
			drain()
			if time.Since(lastBeat) >= 30*time.Second {
				sendLog(log, tui.LogInfo, "nuclei", fmt.Sprintf(
					"[%s] scanning… %s elapsed, %d findings so far",
					severity, time.Since(start).Round(time.Second), seen))
				lastBeat = time.Now()
			}
		}
	}
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
