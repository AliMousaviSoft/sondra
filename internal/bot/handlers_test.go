package bot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AliMousaviSoft/sondra/internal/notify"
)

// fakeResponder records what a handler tried to send, so command handlers can be
// tested without a live transport.
type fakeResponder struct {
	replies []string
	files   []string
	fileErr error
}

func (f *fakeResponder) reply(text string) { f.replies = append(f.replies, text) }
func (f *fakeResponder) sendFile(path, _ string) error {
	f.files = append(f.files, path)
	return f.fileErr
}
func (f *fakeResponder) notifier() notify.Notifier { return notify.Multi{} }
func (f *fakeResponder) fmtr() formatter           { return htmlFmt{} }
func (f *fakeResponder) transport() string         { return "test" }
func (f *fakeResponder) dest() string              { return "0" }

func TestDoReportSendsFile(t *testing.T) {
	// LatestReport looks under ./<domain>/recon-*, so run from a temp cwd.
	cwd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join("example.com", "recon-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join("example.com", "recon-1", "master_report.html")
	if err := os.WriteFile(report, []byte("<html></html>"), 0o644); err != nil {
		t.Fatal(err)
	}

	fake := &fakeResponder{}
	(&Bot{}).doReport(fake, Command{Name: "report", Domain: "example.com"})

	if len(fake.files) != 1 || !strings.HasSuffix(fake.files[0], filepath.Join("recon-1", "master_report.html")) {
		t.Fatalf("expected sendFile with the report path, got files=%v replies=%v", fake.files, fake.replies)
	}
}

func TestDoReportSkipsInProgressRun(t *testing.T) {
	cwd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	// An older finished run (has a report) and a newer in-progress run (none yet,
	// e.g. a monitor pass that just started on restart).
	done := filepath.Join("example.com", "recon-2026-01-01_00-00")
	inProgress := filepath.Join("example.com", "recon-2026-06-01_00-00")
	if err := os.MkdirAll(done, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(done, "master_report.html"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(inProgress, 0o755); err != nil { // no master_report.html
		t.Fatal(err)
	}

	fake := &fakeResponder{}
	(&Bot{}).doReport(fake, Command{Name: "report", Domain: "example.com"})

	if len(fake.files) != 1 || !strings.Contains(fake.files[0], "2026-01-01") {
		t.Fatalf("should fall back to the last finished report, got files=%v replies=%v", fake.files, fake.replies)
	}
}

func TestDoReportDefaultsToLatestDomain(t *testing.T) {
	cwd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join("example.com", "recon-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("example.com", "recon-1", "master_report.html"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	fake := &fakeResponder{}
	// No domain given → should resolve to the only scanned domain.
	(&Bot{}).doReport(fake, Command{Name: "report"})

	if len(fake.files) != 1 || !strings.Contains(fake.files[0], "example.com") {
		t.Fatalf("bare /report should default to latest domain, got files=%v replies=%v", fake.files, fake.replies)
	}
}

func TestDoReportInvalidDomain(t *testing.T) {
	fake := &fakeResponder{}
	(&Bot{}).doReport(fake, Command{Name: "report", Domain: "bad_domain"})
	if len(fake.files) != 0 {
		t.Fatalf("should not send a file for an invalid domain: %v", fake.files)
	}
	if len(fake.replies) == 0 || !strings.Contains(fake.replies[0], "invalid domain") {
		t.Fatalf("expected an invalid-domain reply, got %v", fake.replies)
	}
}
