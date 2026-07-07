package modules

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetrySucceedsAfterFailures(t *testing.T) {
	calls := 0
	err := retry(context.Background(), 3, time.Millisecond, func() error {
		calls++
		if calls < 3 {
			return errors.New("transient")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestRetryExhausts(t *testing.T) {
	calls := 0
	want := errors.New("boom")
	err := retry(context.Background(), 3, time.Millisecond, func() error {
		calls++
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("want last error %v, got %v", want, err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 attempts, got %d", calls)
	}
}

func TestRetryStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	calls := 0
	start := time.Now()
	// A long base would block for seconds without ctx-awareness; it must return
	// immediately instead.
	err := retry(ctx, 5, 10*time.Second, func() error {
		calls++
		return errors.New("fail")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("should stop after the first attempt, got %d calls", calls)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("cancelled retry should not block in backoff")
	}
}
