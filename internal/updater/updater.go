package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const releaseAPI = "https://api.github.com/repos/AliMousaviSoft/sondra/releases/latest"

type release struct {
	TagName string `json:"tag_name"`
}

// LatestVersion fetches the latest release tag from GitHub.
// Returns empty string on any error — callers treat that as "unknown".
func LatestVersion(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releaseAPI, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "sondra-updater/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var r release
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return ""
	}

	return strings.TrimPrefix(r.TagName, "v")
}

// DoUpdate prints install instructions — actual binary replacement
// is done via go install since CGO_ENABLED=0 makes self-update complex.
func DoUpdate(latest string) {
	fmt.Printf("\nUpdating to v%s...\n\n", latest)
	fmt.Println("Run:")
	fmt.Println("  go install github.com/AliMousaviSoft/sondra/cmd/sondra@latest")
	fmt.Println()
}
