package notify

import "context"

// Webhook POSTs the raw Message as JSON to an arbitrary URL — a catch-all for
// Slack (via a compatible endpoint), ntfy, or a custom automation/bot backend.
type Webhook struct {
	url string
}

func NewWebhook(url string) *Webhook { return &Webhook{url: url} }

func (w *Webhook) Name() string { return "webhook" }

func (w *Webhook) Send(ctx context.Context, m Message) error {
	payload := map[string]any{
		"title":            m.Title,
		"text":             m.Text,
		"level":            levelString(m.Level),
		"fields":           m.Fields,
		"footer":           m.Footer,
		"duration_seconds": int(m.Duration.Seconds()),
	}
	// When structured result data is present, include it so a bot/automation
	// backend gets findings/hosts/subdomains arrays, not just display text.
	if m.Data != nil {
		payload["result"] = m.Data
	}
	return postJSON(ctx, w.url, payload)
}
