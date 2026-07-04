package report

import (
	"os"
	"path/filepath"
	"testing"
)

// chdirTemp switches into a fresh temp dir for the test and restores cwd after.
func chdirTemp(t *testing.T) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
}

func writeRunFile(t *testing.T, runDir, name, content string) {
	t.Helper()
	p := filepath.Join(runDir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiffRunsDetailed(t *testing.T) {
	chdirTemp(t)
	domain := "example.com"
	run1 := filepath.Join(domain, "recon-2026-01-01_00-00")
	run2 := filepath.Join(domain, "recon-2026-01-02_00-00")
	if err := os.MkdirAll(run1, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(run2, 0o755); err != nil {
		t.Fatal(err)
	}

	writeRunFile(t, run1, "alldomains.txt", "a.example.com\nb.example.com\n")
	writeRunFile(t, run2, "alldomains.txt", "a.example.com\nb.example.com\nc.example.com\n")
	writeRunFile(t, run1, "live.txt", "https://a.example.com\n")
	writeRunFile(t, run2, "live.txt", "https://a.example.com\nhttps://c.example.com\n")
	writeRunFile(t, run1, "nuclei-results/crit_high.jsonl",
		`{"template-id":"t1","info":{"name":"Old","severity":"high"},"host":"a","matched-at":"https://a"}`+"\n")
	writeRunFile(t, run2, "nuclei-results/crit_high.jsonl",
		`{"template-id":"t1","info":{"name":"Old","severity":"high"},"host":"a","matched-at":"https://a"}`+"\n"+
			`{"template-id":"t2","info":{"name":"New RCE","severity":"critical"},"host":"c","matched-at":"https://c"}`+"\n")

	d, err := DiffRunsDetailed(domain)
	if err != nil {
		t.Fatalf("DiffRunsDetailed: %v", err)
	}
	if len(d.NewSubdomains) != 1 || d.NewSubdomains[0] != "c.example.com" {
		t.Fatalf("new subdomains: %v", d.NewSubdomains)
	}
	if len(d.NewLiveHosts) != 1 || d.NewLiveHosts[0] != "https://c.example.com" {
		t.Fatalf("new live hosts: %v", d.NewLiveHosts)
	}
	if len(d.NewFindings) != 1 || d.NewFindings[0].Name != "New RCE" {
		t.Fatalf("new findings: %+v", d.NewFindings)
	}
	if d.Empty() || !d.AssetsChanged() || !d.FindingsChanged() {
		t.Fatal("delta flags wrong for a run with new assets AND findings")
	}
}

func TestDiffRunsDetailedBaseline(t *testing.T) {
	chdirTemp(t)
	if err := os.MkdirAll("example.com/recon-2026-01-01_00-00", 0o755); err != nil {
		t.Fatal(err)
	}
	d, err := DiffRunsDetailed("example.com")
	if err != nil {
		t.Fatalf("DiffRunsDetailed: %v", err)
	}
	if !d.Empty() {
		t.Fatal("a single run should produce an empty baseline delta")
	}
}
