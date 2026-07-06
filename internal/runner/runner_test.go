package runner

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/AliMousaviSoft/sondra/internal/config"
	"github.com/AliMousaviSoft/sondra/internal/notify"
	"github.com/AliMousaviSoft/sondra/internal/tui"
)

// recordNotifier captures the title of every message it's asked to send.
type recordNotifier struct {
	mu     sync.Mutex
	titles []string
}

func (n *recordNotifier) Name() string { return "record" }

func (n *recordNotifier) Send(_ context.Context, m notify.Message) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.titles = append(n.titles, m.Title)
	return nil
}

func newTestRunner(t *testing.T, rec notify.Notifier) *Runner {
	t.Helper()
	cfg := &config.Config{Domain: "example.com", OutputDir: t.TempDir(), Version: "test"}
	r := New(cfg, make(chan tui.LogEntry, 256), make(chan tui.StepUpdate, 256))
	r.SetNotifier(rec)
	return r
}

func noopStep(context.Context) error { return nil }

func stepNames(r *Runner) string {
	var names []string
	for _, s := range r.steps {
		names = append(names, s.Name)
	}
	return strings.Join(names, ",")
}

// A passive URL/JS run has no enum source, so resolve (which needs enum output)
// must be skipped — otherwise it hard-fails on a missing alldomains.txt.
func TestBuildSkipsResolveWithoutEnum(t *testing.T) {
	r := newTestRunner(t, nil)
	r.Build(config.ModuleFlags{Gowayback: true, JSAnalysis: true})
	names := stepNames(r)
	if strings.Contains(names, "resolve") {
		t.Errorf("resolve should be skipped without an enum source; steps=%s", names)
	}
	for _, want := range []string{"url collection", "js analysis"} {
		if !strings.Contains(names, want) {
			t.Errorf("missing step %q; steps=%s", want, names)
		}
	}
}

func TestBuildKeepsResolveWithEnum(t *testing.T) {
	r := newTestRunner(t, nil)
	r.Build(config.ModuleFlags{Subfinder: true, Httpx: true})
	if names := stepNames(r); !strings.Contains(names, "resolve") {
		t.Errorf("resolve should run when an enum source is present; steps=%s", names)
	}
}

// A run with a vuln phase must emit two notifications in order:
// recon-done first, then the final scan-complete summary.
func TestRunSyncTwoPhaseNotifications(t *testing.T) {
	rec := &recordNotifier{}
	r := newTestRunner(t, rec)
	r.steps = []StepDef{{Name: "recon", Run: noopStep}}
	r.vulnSteps = []StepDef{{Name: "nuclei", Run: noopStep}}

	if err := r.RunSync(context.Background()); err != nil {
		t.Fatalf("RunSync: %v", err)
	}
	if len(rec.titles) != 2 {
		t.Fatalf("expected 2 notifications, got %d: %v", len(rec.titles), rec.titles)
	}
	if !strings.Contains(rec.titles[0], "Recon done") {
		t.Fatalf("first notification should be recon-done, got %q", rec.titles[0])
	}
	if !strings.Contains(rec.titles[1], "complete") {
		t.Fatalf("second notification should be the finish summary, got %q", rec.titles[1])
	}
}

// A run with no vuln phase emits exactly one (finish) notification.
func TestRunSyncSingleNotificationWithoutVuln(t *testing.T) {
	rec := &recordNotifier{}
	r := newTestRunner(t, rec)
	r.steps = []StepDef{{Name: "recon", Run: noopStep}}

	if err := r.RunSync(context.Background()); err != nil {
		t.Fatalf("RunSync: %v", err)
	}
	if len(rec.titles) != 1 {
		t.Fatalf("expected 1 notification, got %d: %v", len(rec.titles), rec.titles)
	}
}

// A recon-phase failure aborts before the vuln phase and reports one failure.
func TestRunSyncReconFailureStopsBeforeVuln(t *testing.T) {
	rec := &recordNotifier{}
	r := newTestRunner(t, rec)
	failing := func(context.Context) error { return context.DeadlineExceeded }
	r.steps = []StepDef{{Name: "recon", Run: failing}}
	r.vulnSteps = []StepDef{{Name: "nuclei", Run: noopStep}}

	if err := r.RunSync(context.Background()); err == nil {
		t.Fatal("expected error from failing recon step")
	}
	if len(rec.titles) != 1 || !strings.Contains(rec.titles[0], "failed") {
		t.Fatalf("expected a single failure notification, got %v", rec.titles)
	}
}
