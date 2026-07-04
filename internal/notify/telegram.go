package notify

import (
	"context"
	"strings"
	"time"
)

// Telegram sends messages through the Bot API. It renders the Message as a
// plain-text block (no parse_mode) so unescaped URLs or titles never trigger
// a 400 from Telegram's Markdown parser.
type Telegram struct {
	token  string
	chatID string
}

func NewTelegram(token, chatID string) *Telegram {
	return &Telegram{token: token, chatID: chatID}
}

func (t *Telegram) Name() string { return "telegram" }

func (t *Telegram) Send(ctx context.Context, m Message) error {
	var b strings.Builder
	if m.Title != "" {
		b.WriteString(m.Title)
		b.WriteString("\n")
	}
	for _, f := range m.Fields {
		b.WriteString("• " + f.Name + ": " + dash(f.Value) + "\n")
	}
	if m.Text != "" {
		b.WriteString("\n" + m.Text + "\n")
	}
	if m.Duration > 0 {
		b.WriteString("\n⏱ " + m.Duration.Round(time.Second).String())
	}
	if m.Footer != "" {
		b.WriteString("\n" + m.Footer)
	}

	payload := map[string]any{
		"chat_id":                  t.chatID,
		"text":                     truncate(b.String(), 4000),
		"disable_web_page_preview": true,
	}
	url := "https://api.telegram.org/bot" + t.token + "/sendMessage"
	return postJSON(ctx, url, payload)
}
