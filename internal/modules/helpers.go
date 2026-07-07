package modules

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// retry runs fn up to attempts times with ctx-aware exponential backoff
// (base, 2×base, 4×base, …). It returns nil on the first success, the last
// error after exhausting attempts, or ctx.Err() if the context is cancelled —
// so a SIGINT never blocks inside a backoff sleep.
func retry(ctx context.Context, attempts int, base time.Duration, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(base << (i - 1)): // base, 2×base, 4×base…
			}
		}
		if err = fn(); err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return err
}

// isDir returns true if path is an existing directory.
func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// countFiles counts files with a given extension in a directory.
func countFiles(dir, ext string) int {
	var count int
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(path, ext) {
			count++
		}
		return nil
	})
	return count
}

// matchExt returns true if the URL path ends with any of the given extensions.
func matchExt(rawURL string, exts ...string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	for _, ext := range exts {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

// hasParam returns true if the URL has at least one query parameter.
func hasParam(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return len(u.Query()) > 0
}

// extractParam returns true and extracts parameter names as a side-effect.
// When used in the classify loop it writes the param name (not the URL).
func extractParam(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return len(u.Query()) > 0
}
