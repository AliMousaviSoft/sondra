package notify

import (
	"context"
	"strings"
	"time"
)

// Discord posts messages to a Discord channel via an incoming webhook URL,
// rendered as a coloured embed.
type Discord struct {
	webhook string
}

func NewDiscord(webhook string) *Discord { return &Discord{webhook: webhook} }

func (d *Discord) Name() string { return "discord" }

func (d *Discord) Send(ctx context.Context, m Message) error {
	type embedField struct {
		Name   string `json:"name"`
		Value  string `json:"value"`
		Inline bool   `json:"inline"`
	}
	type embedFooter struct {
		Text string `json:"text"`
	}
	type embed struct {
		Title       string       `json:"title,omitempty"`
		Description string       `json:"description,omitempty"`
		Color       int          `json:"color"`
		Fields      []embedField `json:"fields,omitempty"`
		Footer      *embedFooter `json:"footer,omitempty"`
		Timestamp   string       `json:"timestamp,omitempty"`
	}

	e := embed{
		Title:       truncate(m.Title, 256),
		Description: truncate(m.Text, 4000),
		Color:       discordColor(m.Level),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}
	for _, f := range m.Fields {
		e.Fields = append(e.Fields, embedField{
			Name:   truncate(f.Name, 256),
			Value:  truncate(dash(f.Value), 1024),
			Inline: f.Inline,
		})
	}

	footerText := m.Footer
	if m.Duration > 0 {
		footerText = strings.TrimSpace(footerText + "  •  took " + m.Duration.Round(time.Second).String())
	}
	if footerText != "" {
		e.Footer = &embedFooter{Text: truncate(footerText, 2048)}
	}

	payload := map[string]any{"embeds": []embed{e}}
	return postJSON(ctx, d.webhook, payload)
}
