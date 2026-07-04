package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AliMousaviSoft/sondra/internal/config"
)

// captureServer returns a test server that records the last request body.
func captureServer(t *testing.T, body *[]byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*body = b
		w.WriteHeader(http.StatusNoContent)
	}))
}

func TestWebhookSend(t *testing.T) {
	var got []byte
	srv := captureServer(t, &got)
	defer srv.Close()

	msg := Message{Title: "hello", Text: "world", Level: LevelSuccess, Fields: []Field{{Name: "k", Value: "v"}}}
	if err := NewWebhook(srv.URL).Send(context.Background(), msg); err != nil {
		t.Fatalf("send: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(got, &payload); err != nil {
		t.Fatalf("body not json: %v", err)
	}
	if payload["title"] != "hello" || payload["level"] != "success" {
		t.Fatalf("unexpected payload: %v", payload)
	}
}

func TestDiscordSendBuildsEmbed(t *testing.T) {
	var got []byte
	srv := captureServer(t, &got)
	defer srv.Close()

	msg := Message{Title: "t", Text: "d", Level: LevelError, Fields: []Field{{Name: "a", Value: "b", Inline: true}}}
	if err := NewDiscord(srv.URL).Send(context.Background(), msg); err != nil {
		t.Fatalf("send: %v", err)
	}

	var payload struct {
		Embeds []struct {
			Title string `json:"title"`
			Color int    `json:"color"`
		} `json:"embeds"`
	}
	if err := json.Unmarshal(got, &payload); err != nil {
		t.Fatalf("body not json: %v", err)
	}
	if len(payload.Embeds) != 1 || payload.Embeds[0].Title != "t" {
		t.Fatalf("embed missing/wrong: %v", payload)
	}
	if payload.Embeds[0].Color != 0xE74C3C {
		t.Fatalf("error level should be red, got %#x", payload.Embeds[0].Color)
	}
}

func TestWebhookIncludesStructuredData(t *testing.T) {
	var got []byte
	srv := captureServer(t, &got)
	defer srv.Close()

	msg := Message{
		Title: "done",
		Data: &ResultPayload{
			Domain: "example.com",
			Event:  "scan_complete",
			Stats:  map[string]int{"live_hosts": 10},
			Findings: []FindingPayload{
				{TemplateID: "cve-1", Name: "RCE", Severity: "critical", Host: "a"},
			},
		},
	}
	if err := NewWebhook(srv.URL).Send(context.Background(), msg); err != nil {
		t.Fatalf("send: %v", err)
	}

	var payload struct {
		Result *ResultPayload `json:"result"`
	}
	if err := json.Unmarshal(got, &payload); err != nil {
		t.Fatalf("body not json: %v", err)
	}
	if payload.Result == nil || payload.Result.Domain != "example.com" {
		t.Fatalf("structured result missing: %s", got)
	}
	if len(payload.Result.Findings) != 1 || payload.Result.Findings[0].Severity != "critical" {
		t.Fatalf("findings not carried: %+v", payload.Result)
	}
}

func TestChatDriversIgnoreData(t *testing.T) {
	// Discord/Telegram must not choke when Data is set — they render the human
	// fields and drop Data.
	var got []byte
	srv := captureServer(t, &got)
	defer srv.Close()
	msg := Message{Title: "t", Data: &ResultPayload{Domain: "x"}}
	if err := NewDiscord(srv.URL).Send(context.Background(), msg); err != nil {
		t.Fatalf("discord send: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("discord did not send")
	}
}

func TestSendReturnsErrorOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	if err := NewWebhook(srv.URL).Send(context.Background(), Message{Title: "x"}); err == nil {
		t.Fatal("expected error on 500, got nil")
	}
}

func TestMultiBestEffort(t *testing.T) {
	var okBody []byte
	ok := captureServer(t, &okBody)
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer bad.Close()

	m := Multi{NewWebhook(bad.URL), NewWebhook(ok.URL)}
	err := m.Send(context.Background(), Message{Title: "x"})
	if err == nil {
		t.Fatal("expected aggregated error from failing notifier")
	}
	// The healthy notifier must still have been called despite the other failing.
	if len(okBody) == 0 {
		t.Fatal("healthy notifier was not invoked")
	}
}

func TestFromConfigSelectsDrivers(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.NotifyConfig
		want int
	}{
		{"none", config.NotifyConfig{}, 0},
		{"discord", config.NotifyConfig{Discord: "u"}, 1},
		{"webhook", config.NotifyConfig{Webhook: "u"}, 1},
		{"telegram-incomplete", config.NotifyConfig{Telegram: config.TelegramConfig{Token: "t"}}, 0},
		{"telegram", config.NotifyConfig{Telegram: config.TelegramConfig{Token: "t", ChatID: "c"}}, 1},
		{"all", config.NotifyConfig{Discord: "u", Webhook: "u", Telegram: config.TelegramConfig{Token: "t", ChatID: "c"}}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FromConfig(tc.cfg)
			if len(got) != tc.want {
				t.Fatalf("want %d notifiers, got %d", tc.want, len(got))
			}
			if got.Active() != (tc.want > 0) {
				t.Fatalf("Active() mismatch")
			}
		})
	}
}
