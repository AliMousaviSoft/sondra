package modules

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

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
