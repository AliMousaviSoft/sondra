package modules

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AliMousaviSoft/sondra/internal/config"
	"github.com/AliMousaviSoft/sondra/internal/tui"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// RunPassiveEnum runs subfinder, assetfinder, and crt.sh in parallel.
// It merges and deduplicates results into passive_subs.txt and alldomains.txt.
func RunPassiveEnum(ctx context.Context, cfg *config.Config, log chan<- tui.LogEntry) Result {
	start := time.Now()

	// Skip if cache is still fresh.
	passiveOut := filepath.Join(cfg.OutputDir, "passive_subs.txt")
	if CacheValid(passiveOut, cfg.CacheAge) {
		count := countLines(passiveOut)
		sendLog(log, tui.LogInfo, "passive enum", fmt.Sprintf("cache hit — %d subdomains", count))
		return Result{Name: "passive enum", Count: count, Output: passiveOut}
	}

	results := make(chan []string, 3)
	errs := make(chan error, 3)
	var wg sync.WaitGroup

	// ── subfinder (Go lib) ────────────────────────────────────────────────
	if cfg.Modules.Subfinder {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subs, err := runSubfinder(ctx, cfg)
			if err != nil {
				errs <- fmt.Errorf("subfinder: %w", err)
				sendLog(log, tui.LogWarn, "subfinder", err.Error())
				results <- nil
				return
			}
			sendLog(log, tui.LogSuccess, "subfinder", fmt.Sprintf("%d subdomains", len(subs)))
			results <- subs
		}()
	}

	// ── assetfinder (exec) ────────────────────────────────────────────────
	if cfg.Modules.Assetfinder {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subs, err := execAssetfinder(ctx, cfg.Domain)
			if err != nil {
				errs <- fmt.Errorf("assetfinder: %w", err)
				sendLog(log, tui.LogWarn, "assetfinder", err.Error())
				results <- nil
				return
			}
			sendLog(log, tui.LogSuccess, "assetfinder", fmt.Sprintf("%d subdomains", len(subs)))
			results <- subs
		}()
	}

	// ── crt.sh (HTTP) ─────────────────────────────────────────────────────
	if cfg.Modules.Crtsh {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subs, err := queryCrtsh(ctx, cfg.Domain)
			if err != nil {
				errs <- fmt.Errorf("crtsh: %w", err)
				sendLog(log, tui.LogWarn, "crt.sh", err.Error())
				results <- nil
				return
			}
			sendLog(log, tui.LogSuccess, "crt.sh", fmt.Sprintf("%d subdomains", len(subs)))
			results <- subs
		}()
	}

	// Close channels once all goroutines finish.
	go func() {
		wg.Wait()
		close(results)
		close(errs)
	}()

	// Merge + dedup.
	seen := make(map[string]struct{})
	var all []string
	for batch := range results {
		for _, s := range batch {
			s = strings.ToLower(strings.TrimSpace(s))
			if s == "" {
				continue
			}
			// Basic validation: must be a subdomain of the target.
			if s == "" || (!strings.HasSuffix(s, "."+cfg.Domain) && s != cfg.Domain) {
				continue
			}
			// Exclusion list.
			if isExcluded(s, cfg.Excluded) {
				continue
			}
			if _, ok := seen[s]; !ok {
				seen[s] = struct{}{}
				all = append(all, s)
			}
		}
	}

	var sourceErrs []string
	for err := range errs {
		sourceErrs = append(sourceErrs, err.Error())
	}

	if len(all) == 0 {
		errDetail := strings.Join(sourceErrs, "; ")
		return Result{Name: "passive enum", Error: fmt.Errorf("no subdomains found — sources: %s", errDetail)}
	}

	// Write passive_subs.txt.
	if err := writeLines(passiveOut, all); err != nil {
		return Result{Name: "passive enum", Error: err}
	}

	// Append to alldomains.txt (for resolver input).
	allDomainsOut := filepath.Join(cfg.OutputDir, "alldomains.txt")
	if err := appendLines(allDomainsOut, all); err != nil {
		return Result{Name: "passive enum", Error: err}
	}

	sendLog(log, tui.LogSuccess, "passive enum",
		fmt.Sprintf("%d unique subdomains → passive_subs.txt", len(all)))

	return Result{
		Name:    "passive enum",
		Count:   len(all),
		Output:  passiveOut,
		Elapsed: time.Since(start),
	}
}

// ──────────────────────────────────────────────
// subfinder
// ──────────────────────────────────────────────

func runSubfinder(ctx context.Context, cfg *config.Config) ([]string, error) {
	outFile := filepath.Join(cfg.OutputDir, "subfinder.txt")
	if CacheValid(outFile, cfg.CacheAge) {
		return readLines(outFile)
	}

	// Create the output file first so subfinder has a valid writer.
	f, err := os.Create(outFile)
	if err != nil {
		return nil, fmt.Errorf("subfinder output file: %w", err)
	}
	defer f.Close()

	options := &runner.Options{
		Threads:            cfg.Concurrency,
		Timeout:            int(cfg.Timeout.Seconds()),
		MaxEnumerationTime: 10,
		Domain:             []string{cfg.Domain},
		Output:             f, // io.Writer, not OutputFile string
		Silent:             true,
	}

	r, err := runner.NewRunner(options)
	if err != nil {
		return nil, fmt.Errorf("subfinder init: %w", err)
	}

	if err := r.RunEnumeration(); err != nil {
		return nil, fmt.Errorf("subfinder run: %w", err)
	}

	return readLines(outFile)
}

// ──────────────────────────────────────────────
// assetfinder
// ──────────────────────────────────────────────

func execAssetfinder(ctx context.Context, domain string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "assetfinder", "--subs-only", domain)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("assetfinder exec: %w", err)
	}
	return splitLines(string(out)), nil
}

// ──────────────────────────────────────────────
// crt.sh
// ──────────────────────────────────────────────

type crtshEntry struct {
	NameValue string `json:"name_value"`
}

func queryCrtsh(ctx context.Context, domain string) ([]string, error) {
	apiURL := "https://crt.sh/?q=%25." + url.QueryEscape(domain) + "&output=json"

	client := &http.Client{Timeout: 45 * time.Second}

	var body []byte
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*3) * time.Second)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; sondra-recon/1.0)")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("crt.sh request: %w", err)
			continue
		}

		ct := resp.Header.Get("Content-Type")
		body, err = io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("crt.sh read: %w", err)
			continue
		}

		// If we got HTML back (rate limit / challenge page), retry.
		if strings.Contains(ct, "text/html") || (len(body) > 0 && body[0] == '<') {
			lastErr = fmt.Errorf("crt.sh returned HTML (rate limited), attempt %d/3", attempt+1)
			continue
		}

		// Got JSON.
		lastErr = nil
		break
	}

	if lastErr != nil {
		return nil, lastErr
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("crt.sh returned empty response")
	}

	var entries []crtshEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crt.sh parse: %w", err)
	}

	seen := make(map[string]struct{})
	var subs []string
	for _, e := range entries {
		for _, line := range strings.Split(e.NameValue, "\n") {
			s := strings.TrimSpace(strings.TrimPrefix(line, "*."))
			if s != "" {
				if _, ok := seen[s]; !ok {
					seen[s] = struct{}{}
					subs = append(subs, s)
				}
			}
		}
	}
	return subs, nil
}

// ──────────────────────────────────────────────
// Helpers shared within the modules package
// ──────────────────────────────────────────────

// CacheValid returns true if path exists, is non-empty, and was modified
// within maxAge.  Used by every module before running.
func CacheValid(path string, maxAge time.Duration) bool {
	info, err := os.Stat(path)
	if err != nil || info.Size() == 0 {
		return false
	}
	return time.Since(info.ModTime()) < maxAge
}

// Result is the standard return type for every module function.
type Result struct {
	Name    string
	Count   int
	Output  string // path to primary output file
	Error   error
	Elapsed time.Duration
}

func sendLog(ch chan<- tui.LogEntry, level tui.LogLevel, step, msg string) {
	entry := tui.NewLog(level, step, msg)
	select {
	case ch <- entry:
	default:
	}
}

func isExcluded(s string, excluded []string) bool {
	for _, ex := range excluded {
		if s == ex || strings.HasSuffix(s, "."+ex) {
			return true
		}
	}
	return false
}

func writeLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	return w.Flush()
}

func appendLines(path string, lines []string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	return w.Flush()
}

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

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func countLines(path string) int {
	lines, _ := readLines(path)
	return len(lines)
}
