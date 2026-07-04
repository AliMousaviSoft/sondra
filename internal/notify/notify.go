// Package notify delivers scan lifecycle events to external channels
// (Discord, Telegram, generic webhooks). It is provider-agnostic: callers
// build a Message and every configured Notifier renders it in its own format.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/AliMousaviSoft/sondra/internal/config"
)

// Level classifies a message so drivers can colour/emoji it.
type Level int

const (
	LevelInfo Level = iota
	LevelSuccess
	LevelWarn
	LevelError
)

// Field is a key/value row in a message summary.
type Field struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

// Message is a provider-agnostic notification payload.
type Message struct {
	Title    string        `json:"title"`
	Text     string        `json:"text"`
	Level    Level         `json:"-"`
	Fields   []Field       `json:"fields,omitempty"`
	Duration time.Duration `json:"-"`
	Footer   string        `json:"footer,omitempty"`
	// Data, when set, carries the full structured result. The generic Webhook
	// driver POSTs it verbatim for machine/bot consumption; chat drivers
	// (Discord/Telegram) ignore it and render the human fields above.
	Data *ResultPayload `json:"-"`
}

// ResultPayload is the machine-readable scan result delivered to generic
// webhooks. Stable shape intended for a bot/automation backend (roadmap #4).
type ResultPayload struct {
	Domain        string           `json:"domain"`
	Event         string           `json:"event"` // scan_complete | recon_done | finding | monitor_delta
	Preset        string           `json:"preset,omitempty"`
	DurationSec   int              `json:"duration_seconds,omitempty"`
	Stats         map[string]int   `json:"stats,omitempty"`
	Findings      []FindingPayload `json:"findings,omitempty"`
	NewSubdomains []string         `json:"new_subdomains,omitempty"`
	NewLiveHosts  []string         `json:"new_live_hosts,omitempty"`
	HighValue     []string         `json:"high_value,omitempty"`
	ReportPath    string           `json:"report_path,omitempty"`
}

// FindingPayload is one nuclei finding in structured form.
type FindingPayload struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	Host       string `json:"host"`
	URL        string `json:"url,omitempty"`
}

// Notifier delivers a Message to a single destination.
type Notifier interface {
	Name() string
	Send(ctx context.Context, msg Message) error
}

// Multi fans a message out to several notifiers, best-effort:
// one failing channel never stops the others.
type Multi []Notifier

func (m Multi) Name() string { return "multi" }

// Active reports whether any notifier is configured.
func (m Multi) Active() bool { return len(m) > 0 }

func (m Multi) Send(ctx context.Context, msg Message) error {
	var errs []string
	for _, n := range m {
		if n == nil {
			continue
		}
		if err := n.Send(ctx, msg); err != nil {
			errs = append(errs, n.Name()+": "+err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// FromConfig builds a Multi from the user's notification settings.
// A driver is only added when its credentials are present.
func FromConfig(c config.NotifyConfig) Multi {
	var ns Multi
	if c.Discord != "" {
		ns = append(ns, NewDiscord(c.Discord))
	}
	if c.Telegram.Token != "" && c.Telegram.ChatID != "" {
		ns = append(ns, NewTelegram(c.Telegram.Token, c.Telegram.ChatID))
	}
	if c.Webhook != "" {
		ns = append(ns, NewWebhook(c.Webhook))
	}
	return ns
}

// ──────────────────────────────────────────────
// Shared helpers
// ──────────────────────────────────────────────

var httpClient = &http.Client{Timeout: 15 * time.Second}

// postJSON marshals payload and POSTs it, returning an error on any non-2xx.
func postJSON(ctx context.Context, url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

// truncate caps s to n bytes, appending an ellipsis when it cuts.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// dash returns "—" for empty values so drivers that reject blank fields are safe.
func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func discordColor(l Level) int {
	switch l {
	case LevelSuccess:
		return 0x2ECC71
	case LevelWarn:
		return 0xF1C40F
	case LevelError:
		return 0xE74C3C
	default:
		return 0x3498DB
	}
}

func levelString(l Level) string {
	switch l {
	case LevelSuccess:
		return "success"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "info"
	}
}
