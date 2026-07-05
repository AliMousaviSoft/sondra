package bot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// telegram is a minimal Bot API client: long-poll getUpdates + sendMessage.
type telegram struct {
	token  string
	client *http.Client
	offset int64
}

func newTelegram(token string) *telegram {
	// Timeout exceeds the long-poll timeout so getUpdates isn't cut short.
	return &telegram{token: token, client: &http.Client{Timeout: 70 * time.Second}}
}

type tgUpdate struct {
	UpdateID int64 `json:"update_id"`
	Message  *struct {
		MessageID int64 `json:"message_id"`
		From      *struct {
			ID       int64  `json:"id"`
			Username string `json:"username"`
		} `json:"from"`
		Chat *struct {
			ID int64 `json:"id"`
		} `json:"chat"`
		Text string `json:"text"`
	} `json:"message"`
}

// getUpdates long-polls for new messages, advancing the offset so each update
// is delivered once. Returns nil on a poll timeout with no messages.
func (t *telegram) getUpdates(ctx context.Context) ([]tgUpdate, error) {
	u := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?timeout=50&offset=%d",
		t.token, t.offset)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("getUpdates: %s", resp.Status)
	}
	var out struct {
		OK     bool       `json:"ok"`
		Result []tgUpdate `json:"result"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	for _, up := range out.Result {
		if up.UpdateID >= t.offset {
			t.offset = up.UpdateID + 1
		}
	}
	return out.Result, nil
}

// send posts an HTML-formatted message. If Telegram rejects the HTML (a
// formatting slip), it falls back to plain text with tags stripped, so a
// message is never silently dropped.
func (t *telegram) send(ctx context.Context, chatID int64, text string) error {
	if err := t.post(ctx, chatID, text, "HTML"); err != nil {
		return t.post(ctx, chatID, stripTags(text), "")
	}
	return nil
}

func (t *telegram) post(ctx context.Context, chatID int64, text, parseMode string) error {
	form := url.Values{
		"chat_id":                  {strconv.FormatInt(chatID, 10)},
		"text":                     {truncate(text, 4000)},
		"disable_web_page_preview": {"true"},
	}
	if parseMode != "" {
		form.Set("parse_mode", parseMode)
	}
	endpoint := "https://api.telegram.org/bot" + t.token + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		bytes.NewBufferString(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("sendMessage: %s: %s", resp.Status, string(b))
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// esc escapes text for Telegram HTML parse mode (only <, >, & are special).
func esc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// stripTags removes HTML tags and unescapes entities for the plain-text fallback.
func stripTags(s string) string {
	var b strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag:
			b.WriteRune(r)
		}
	}
	out := b.String()
	out = strings.ReplaceAll(out, "&lt;", "<")
	out = strings.ReplaceAll(out, "&gt;", ">")
	out = strings.ReplaceAll(out, "&amp;", "&")
	return out
}
