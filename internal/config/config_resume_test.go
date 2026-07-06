package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadResumeReusesLatestRun(t *testing.T) {
	cwd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	older := filepath.Join("example.com", "recon-2026-01-01_00-00")
	newer := filepath.Join("example.com", "recon-2026-06-01_00-00")
	for _, d := range []string{older, newer} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// --resume reuses the newest existing run dir.
	cfg, err := Load("", "example.com", nil, "quick", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OutputDir != newer {
		t.Errorf("resume should reuse newest run dir %q, got %q", newer, cfg.OutputDir)
	}

	// Without --resume a fresh dir is created (not either existing one).
	fresh, err := Load("", "example.com", nil, "quick", true, false)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.OutputDir == older || fresh.OutputDir == newer {
		t.Errorf("without resume expected a fresh dir, got existing %q", fresh.OutputDir)
	}
}

func TestLoadResumeNoPriorRun(t *testing.T) {
	cwd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	// resume with nothing to resume falls back to a fresh dir.
	cfg, err := Load("", "example.com", nil, "quick", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OutputDir == "" {
		t.Error("expected a fresh output dir when no prior run exists")
	}
}
