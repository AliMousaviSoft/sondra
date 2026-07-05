package bot

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/AliMousaviSoft/sondra/internal/notify"
)

// responder abstracts replying and scan-result delivery across transports
// (Telegram, Discord), so command handlers are written once.
type responder interface {
	reply(text string)                   // send a message back to the invoker
	sendFile(path, caption string) error // upload a file (e.g. the HTML report)
	notifier() notify.Notifier           // where scan alerts stream
	fmtr() formatter                     // transport-specific text styling
	transport() string                   // "telegram" | "discord" (for persistence)
	dest() string                        // chat/channel id to resume delivery to
}

// formatter renders inline styling for a transport: Telegram HTML vs Discord
// markdown. Handlers build replies through it so one string works on both.
type formatter interface {
	bold(string) string
	code(string) string
	block(string) string // fenced/monospace block
	esc(string) string   // escape dynamic content
}

// htmlFmt renders Telegram HTML parse-mode markup.
type htmlFmt struct{}

func (htmlFmt) bold(s string) string  { return "<b>" + s + "</b>" }
func (htmlFmt) code(s string) string  { return "<code>" + s + "</code>" }
func (htmlFmt) block(s string) string { return "<pre>" + s + "</pre>" }
func (htmlFmt) esc(s string) string   { return esc(s) }

// mdFmt renders Discord markdown.
type mdFmt struct{}

func (mdFmt) bold(s string) string  { return "**" + s + "**" }
func (mdFmt) code(s string) string  { return "`" + s + "`" }
func (mdFmt) block(s string) string { return "```\n" + s + "\n```" }
func (mdFmt) esc(s string) string   { return escapeMarkdown(s) }

func escapeMarkdown(s string) string {
	r := strings.NewReplacer(
		`\`, `\\`, "`", "\\`", "*", "\\*", "_", "\\_", "~", "\\~", "|", "\\|",
	)
	return r.Replace(s)
}

// ── Telegram responder ──

type tgResponder struct {
	bot    *Bot
	chatID int64
}

func (t *tgResponder) reply(text string) { t.bot.reply(t.chatID, text) }
func (t *tgResponder) sendFile(path, caption string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return t.bot.tg.sendDocument(ctx, t.chatID, path, caption)
}
func (t *tgResponder) notifier() notify.Notifier { return t.bot.chatNotifier(t.chatID) }
func (t *tgResponder) fmtr() formatter           { return htmlFmt{} }
func (t *tgResponder) transport() string         { return "telegram" }
func (t *tgResponder) dest() string              { return strconv.FormatInt(t.chatID, 10) }
