package modules

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/AliMousaviSoft/sondra/internal/config"
	"github.com/AliMousaviSoft/sondra/internal/tui"
)

// maxJSFiles caps how many .js files we fetch, and maxJSBody caps each body, so
// analysis stays bounded on large targets.
const (
	maxJSFiles = 500
	maxJSBody  = 5 << 20 // 5 MB
)

// Secret is a credential-like match found in a JS file.
type Secret struct {
	Type      string
	Value     string
	SourceURL string
}

// RunJSAnalysis fetches the .js URLs collected by the URL modules and extracts
// endpoints and secrets from their bodies. It writes js-analysis/endpoints.txt
// and js-analysis/secrets.txt under the run directory.
func RunJSAnalysis(ctx context.Context, cfg *config.Config, log chan<- tui.LogEntry) Result {
	jsURLsFile := filepath.Join(cfg.OutputDir, "wayback-data", "js_urls.txt")
	urls, err := readLines(jsURLsFile)
	if err != nil || len(urls) == 0 {
		sendLog(log, tui.LogInfo, "js analysis", "no .js URLs collected — run gau/gowayback/katana first")
		return Result{Name: "js analysis"}
	}
	urls = dedupStrings(urls)
	if len(urls) > maxJSFiles {
		sendLog(log, tui.LogInfo, "js analysis", fmt.Sprintf("capping %d .js URLs to %d", len(urls), maxJSFiles))
		urls = urls[:maxJSFiles]
	}

	outDir := filepath.Join(cfg.OutputDir, "js-analysis")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return Result{Name: "js analysis", Error: err}
	}

	client := &http.Client{Timeout: cfg.Timeout}
	sem := make(chan struct{}, max(1, cfg.Concurrency))
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		endpoint = map[string]struct{}{}
		secret   = map[string]Secret{} // dedup key = type|value|source
		fetched  int
	)

	for _, u := range urls {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			body, err := fetchJS(ctx, client, u)
			if err != nil {
				return
			}
			eps := ExtractEndpoints(body)
			secs := ExtractSecrets(body)
			mu.Lock()
			fetched++
			for _, e := range eps {
				endpoint[e] = struct{}{}
			}
			for _, s := range secs {
				s.SourceURL = u
				secret[s.Type+"|"+s.Value+"|"+u] = s
			}
			mu.Unlock()
		}(u)
	}
	wg.Wait()

	endpoints := sortedSet(endpoint)
	epFile := filepath.Join(outDir, "endpoints.txt")
	if err := writeLines(epFile, endpoints); err != nil {
		return Result{Name: "js analysis", Error: err}
	}

	secrets := make([]Secret, 0, len(secret))
	for _, s := range secret {
		secrets = append(secrets, s)
	}
	sort.Slice(secrets, func(i, j int) bool {
		if secrets[i].Type != secrets[j].Type {
			return secrets[i].Type < secrets[j].Type
		}
		return secrets[i].Value < secrets[j].Value
	})
	secLines := make([]string, 0, len(secrets))
	for _, s := range secrets {
		secLines = append(secLines, fmt.Sprintf("[%s] %s\t%s", s.Type, s.Value, s.SourceURL))
	}
	_ = writeLines(filepath.Join(outDir, "secrets.txt"), secLines)

	level := tui.LogSuccess
	if len(secrets) > 0 {
		level = tui.LogWarn // leaked secrets are noteworthy
	}
	sendLog(log, level, "js analysis",
		fmt.Sprintf("%d endpoints, %d secrets from %d/%d JS files", len(endpoints), len(secrets), fetched, len(urls)))
	return Result{Name: "js analysis", Count: len(endpoints), Output: epFile}
}

// ── extraction (pure, unit-tested) ──

const jsQuote = "[\"'`]" // the three JS string delimiters

var (
	// Absolute URLs, stopping at a quote/whitespace/bracket delimiter.
	reAbsURL = regexp.MustCompile(`https?://[^\s"'` + "`" + `<>()\[\]{}\\]{4,}`)
	// Rooted relative paths inside a JS string: "/api/v2/users?x=1".
	reQuotedPath = regexp.MustCompile(jsQuote + `(/[A-Za-z0-9_./\-]{2,}(?:\?[^"'` + "`" + `]*)?)` + jsQuote)
	// Static assets we don't treat as interesting endpoints.
	staticExts = []string{".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico", ".map"}
)

// ExtractEndpoints pulls candidate URLs and API paths out of JS source.
func ExtractEndpoints(js string) []string {
	set := map[string]struct{}{}
	for _, m := range reAbsURL.FindAllString(js, -1) {
		set[strings.TrimRight(m, `\`)] = struct{}{}
	}
	for _, m := range reQuotedPath.FindAllStringSubmatch(js, -1) {
		p := m[1]
		if p == "//" || matchExt(p, staticExts...) {
			continue
		}
		set[p] = struct{}{}
	}
	return sortedSet(set)
}

// secretPattern matches one class of credential; group is the submatch index
// holding the value (0 = whole match).
type secretPattern struct {
	name  string
	re    *regexp.Regexp
	group int
}

var secretPatterns = []secretPattern{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), 0},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), 0},
	{"Google OAuth Token", regexp.MustCompile(`ya29\.[0-9A-Za-z\-_]{20,}`), 0},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z\-]{10,48}`), 0},
	{"Slack Webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}`), 0},
	{"GitHub Token", regexp.MustCompile(`gh[porsu]_[0-9A-Za-z]{36}`), 0},
	{"Stripe Secret Key", regexp.MustCompile(`sk_live_[0-9A-Za-z]{24}`), 0},
	{"JWT", regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`), 0},
	{"Private Key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`), 0},
	{"Generic API Key", regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*["']([0-9A-Za-z\-_.]{16,64})["']`), 1},
}

// ExtractSecrets scans JS source for credential-like tokens.
func ExtractSecrets(js string) []Secret {
	var out []Secret
	seen := map[string]struct{}{}
	for _, p := range secretPatterns {
		for _, m := range p.re.FindAllStringSubmatch(js, -1) {
			val := m[p.group]
			if val == "" {
				continue
			}
			key := p.name + "|" + val
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, Secret{Type: p.name, Value: val})
		}
	}
	return out
}

// ── helpers ──

func fetchJS(ctx context.Context, client *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "sondra-js-analysis")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxJSBody))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func dedupStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func sortedSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
