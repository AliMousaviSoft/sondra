package modules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/AliMousaviSoft/sondra/internal/config"
	"github.com/AliMousaviSoft/sondra/internal/tui"
)

type HostResult struct {
	URL           string   `json:"url"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title"`
	Technologies  []string `json:"technologies"`
	ContentLength int64    `json:"content_length"`
	WebServer     string   `json:"webserver"`
}

var highValuePattern = regexp.MustCompile(
	`(?i)admin|dev|staging|api|internal|corp|vpn|jenkins|jira|` +
		`gitlab|grafana|kibana|elastic|consul|vault|k8s|dashboard|` +
		`manage|portal|auth|sso|login|test|uat|preprod|beta|` +
		`monitor|metrics|status|debug|trace|swagger|openapi|graphql`,
)

func RunProbe(ctx context.Context, cfg *config.Config, log chan<- tui.LogEntry) Result {
	start := time.Now()
	liveFile := filepath.Join(cfg.OutputDir, "live.txt")
	jsonFile := filepath.Join(cfg.OutputDir, "httpx_full.json")
	hvFile := filepath.Join(cfg.OutputDir, "high_value.txt")

	if CacheValid(liveFile, cfg.CacheAge) {
		count := countLines(liveFile)
		sendLog(log, tui.LogInfo, "httpx", fmt.Sprintf("cache hit — %d live hosts", count))
		return Result{Name: "httpx probe", Count: count, Output: liveFile}
	}

	if _, err := exec.LookPath("httpx"); err != nil {
		return Result{Name: "httpx probe", Error: fmt.Errorf("httpx not in PATH — install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")}
	}

	inFile := filepath.Join(cfg.OutputDir, "resolved.txt")

	// ── Phase 1: fast alive check ─────────────────────────────────────────
	sendLog(log, tui.LogInfo, "httpx", "phase 1: alive check…")

	phase1Args := []string{
		"-l", inFile,
		"-o", liveFile,
		"-silent",
		"-no-color",
		"-threads", fmt.Sprintf("%d", cfg.Concurrency*2),
		"-timeout", fmt.Sprintf("%d", int(cfg.Timeout.Seconds())),
		"-follow-redirects",
		"-max-redirects", "5",
		"-status-code",
	}

	if err := runHTTPX(ctx, phase1Args); err != nil {
		return Result{Name: "httpx probe", Error: fmt.Errorf("phase1: %w", err)}
	}

	// Strip status codes from live.txt in-place.
	// live.txt is used by gowitness, naabu, katana — all need clean URLs.
	if err := stripStatusCodes(liveFile, liveFile); err != nil {
		return Result{Name: "httpx probe", Error: err}
	}

	liveCount := countLines(liveFile)
	if liveCount == 0 {
		return Result{Name: "httpx probe", Error: fmt.Errorf("no live hosts found")}
	}
	sendLog(log, tui.LogSuccess, "httpx", fmt.Sprintf("phase 1: %d alive hosts", liveCount))

	// ── Phase 2: enrichment on live hosts ─────────────────────────────────
	sendLog(log, tui.LogInfo, "httpx", "phase 2: enrichment (title, tech, status)…")

	phase2Args := []string{
		"-l", liveFile,
		"-o", jsonFile,
		"-json",
		"-silent",
		"-no-color",
		"-threads", fmt.Sprintf("%d", cfg.Concurrency),
		"-timeout", fmt.Sprintf("%d", int(cfg.Timeout.Seconds())),
		"-follow-redirects",
		"-status-code",
		"-title",
		"-web-server",
		"-tech-detect",
		"-content-length",
	}

	if err := runHTTPX(ctx, phase2Args); err != nil {
		sendLog(log, tui.LogWarn, "httpx", fmt.Sprintf("enrichment failed: %v", err))
	}

	// ── Prioritize ────────────────────────────────────────────────────────
	hosts := parseHTTPXJSONL(jsonFile)
	hv := Prioritize(hosts)
	if len(hv) > 0 {
		_ = writeLines(hvFile, hv)
		sendLog(log, tui.LogSuccess, "httpx",
			fmt.Sprintf("%d high-value targets → high_value.txt", len(hv)))
	}

	return Result{
		Name:    "httpx probe",
		Count:   liveCount,
		Output:  liveFile,
		Elapsed: time.Since(start),
	}
}

func runHTTPX(ctx context.Context, args []string) error {
	cmd := exec.CommandContext(ctx, "httpx", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if se := strings.TrimSpace(stderr.String()); se != "" {
			return fmt.Errorf("%w — %s", err, se)
		}
		return err
	}
	return nil
}

// stripStatusCodes strips httpx status code suffixes from URLs.
// Handles in-place rewrite safely via temp file + rename.
// "https://foo.com [200]" → "https://foo.com"
func stripStatusCodes(inFile, outFile string) error {
	lines, err := readLines(inFile)
	if err != nil {
		return err
	}
	var urls []string
	for _, l := range lines {
		if idx := strings.LastIndex(l, " ["); idx != -1 {
			l = strings.TrimSpace(l[:idx])
		}
		if l != "" {
			urls = append(urls, l)
		}
	}
	tmp := outFile + ".tmp"
	if err := writeLines(tmp, urls); err != nil {
		return err
	}
	return os.Rename(tmp, outFile)
}

func parseHTTPXJSONL(path string) []HostResult {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	var hosts []HostResult
	for dec.More() {
		var h HostResult
		if err := dec.Decode(&h); err == nil {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

func Prioritize(hosts []HostResult) []string {
	var hv []string
	for _, h := range hosts {
		if highValuePattern.MatchString(h.URL) {
			hv = append(hv, h.URL)
		}
	}
	return hv
}
