package runner

import (
	"context"
	"sync"

	"github.com/AliMousaviSoft/sondra/internal/config"
	"github.com/AliMousaviSoft/sondra/internal/notify"
	"github.com/AliMousaviSoft/sondra/internal/tui"
)

// Run executes a full scan pipeline against ctx with the given modules and
// notifier, discarding log/progress output. It's the non-TUI, non-stdout entry
// point used by the control bot (which delivers results through the notifier).
func Run(ctx context.Context, cfg *config.Config, mods config.ModuleFlags, notifier notify.Notifier) error {
	logCh := make(chan tui.LogEntry, 512)
	progressCh := make(chan tui.StepUpdate, 64)

	r := New(cfg, logCh, progressCh)
	if notifier != nil {
		r.SetNotifier(notifier)
	}
	r.Build(mods)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range logCh {
		}
	}()
	go func() {
		defer wg.Done()
		for range progressCh {
		}
	}()

	err := r.RunSync(ctx)
	close(logCh)
	close(progressCh)
	wg.Wait()
	return err
}
