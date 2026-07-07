package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AliMousaviSoft/sondra/internal/config"
)

func TestCollectDataJSFindings(t *testing.T) {
	dir := t.TempDir()
	jsdir := filepath.Join(dir, "js-analysis")
	if err := os.MkdirAll(jsdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jsdir, "endpoints.txt"),
		[]byte("/api/v1/users\nhttps://x.com/graphql\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jsdir, "secrets.txt"),
		[]byte("[AWS Access Key] AKIAIOSFODNN7EXAMPLE\thttps://x.com/app.js\n[JWT] eyJabc.eyJdef.sig\thttps://x.com/a.js\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	d, err := collectData(&config.Config{Domain: "x.com", OutputDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if d.JSEndpointCount != 2 || len(d.JSEndpoints) != 2 {
		t.Errorf("endpoints: got %d %v", d.JSEndpointCount, d.JSEndpoints)
	}
	if d.JSSecretCount != 2 {
		t.Fatalf("secrets count: got %d", d.JSSecretCount)
	}
	s := d.JSSecrets[0]
	if s.Type != "AWS Access Key" || s.Value != "AKIAIOSFODNN7EXAMPLE" || s.Source != "https://x.com/app.js" {
		t.Errorf("parsed secret wrong: %+v", s)
	}
}

func TestParseJSSecretsMalformed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secrets.txt")
	// A line without the tab/brackets shouldn't panic — value falls through.
	if err := os.WriteFile(p, []byte("plainstring\n[Type only]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := parseJSSecrets(p)
	if len(got) != 2 {
		t.Fatalf("want 2 rows, got %d: %+v", len(got), got)
	}
	if got[0].Value != "plainstring" {
		t.Errorf("row0: %+v", got[0])
	}
}

func TestReportRendersJSSection(t *testing.T) {
	dir := t.TempDir()
	jsdir := filepath.Join(dir, "js-analysis")
	_ = os.MkdirAll(jsdir, 0o755)
	_ = os.WriteFile(filepath.Join(jsdir, "secrets.txt"),
		[]byte("[Google API Key] AIzaSyTESTKEY\thttps://x.com/main.js\n"), 0o644)

	if err := Generate(&config.Config{Domain: "x.com", OutputDir: dir}); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(filepath.Join(dir, "master_report.html"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"JS Analysis", "Google API Key", "AIzaSyTESTKEY", "js secrets"} {
		if !strings.Contains(string(html), want) {
			t.Errorf("report HTML missing %q", want)
		}
	}
}
