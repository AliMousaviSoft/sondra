// Package bot implements the sondra control bot: it lets allow-listed users
// drive scans, monitors, and diffs from Telegram (text commands) and Discord
// (slash commands), streaming results back through the notification system.
package bot

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AliMousaviSoft/sondra/internal/config"
)

// Bot dispatches chat commands to the recon pipeline across transports.
type Bot struct {
	cfg     *config.Config
	cfgFile string
	version string
	tg      *telegram
	jobs    *jobs
	store   *store            // persisted monitor jobs (nil when disabled)
	discord *discordTransport // set while the Discord transport is running
	rootCtx context.Context   // daemon lifetime; jobs derive from it
}

// New builds a Bot. cfgFile is reloaded per job so each scan gets a fresh
// timestamped output directory.
func New(cfg *config.Config, cfgFile, version string) *Bot {
	return &Bot{
		cfg:     cfg,
		cfgFile: cfgFile,
		version: version,
		tg:      newTelegram(cfg.Bot.Token),
		jobs:    newJobs(),
	}
}

// Run starts the configured transports and blocks until ctx is cancelled.
func (b *Bot) Run(ctx context.Context) error {
	b.rootCtx = ctx

	// Open the job store (best-effort) before starting transports so resumed
	// jobs can rebuild their responders.
	if path := b.cfg.Bot.StateDB; path != "" && !strings.EqualFold(path, "off") {
		st, err := openStore(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bot: state db disabled (%s): %v\n", path, err)
		} else {
			b.store = st
			defer st.close()
		}
	}

	var started []string
	if b.cfg.Bot.DiscordEnabled() {
		dc, err := startDiscord(b)
		if err != nil {
			return fmt.Errorf("discord: %w", err)
		}
		b.discord = dc
		defer dc.close()
		started = append(started, "discord")
	}

	// Resume any monitors persisted before the last shutdown.
	b.resumeJobs()

	if b.cfg.Bot.TelegramEnabled() {
		started = append(started, "telegram")
		fmt.Printf("sondra bot: listening on %s\n", strings.Join(started, "+"))
		return b.pollTelegram(ctx)
	}

	// Discord-only: nothing to poll, just wait for shutdown.
	fmt.Printf("sondra bot: listening on %s\n", strings.Join(started, "+"))
	<-ctx.Done()
	return nil
}

// pollTelegram long-polls Telegram for commands until ctx is cancelled.
func (b *Bot) pollTelegram(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return nil
		}
		updates, err := b.tg.getUpdates(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			fmt.Fprintf(os.Stderr, "bot: getUpdates: %v\n", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(3 * time.Second):
			}
			continue
		}
		for _, u := range updates {
			b.handleTelegram(u)
		}
	}
}

// handleTelegram authorizes a Telegram message, parses it, and dispatches it.
func (b *Bot) handleTelegram(u tgUpdate) {
	m := u.Message
	if m == nil || m.From == nil || m.Chat == nil {
		return
	}
	text := strings.TrimSpace(m.Text)
	if !strings.HasPrefix(text, "/") {
		return
	}

	if !b.cfg.Bot.Allowed(m.From.ID) {
		fmt.Fprintf(os.Stderr, "bot: REJECTED telegram user %d (@%s): %q\n", m.From.ID, m.From.Username, text)
		b.reply(m.Chat.ID, "⛔ <b>Not authorized.</b> Ask the operator to allow-list your user id: <code>"+strconv.FormatInt(m.From.ID, 10)+"</code>")
		return
	}

	cmd, err := parseCommand(text)
	if err != nil {
		b.reply(m.Chat.ID, "❌ "+esc(err.Error())+"\nTry /help")
		return
	}
	b.dispatch(&tgResponder{bot: b, chatID: m.Chat.ID}, cmd)
}

// reply sends a Telegram message on a fresh timeout context, so it lands even
// if a job's context was cancelled.
func (b *Bot) reply(chatID int64, text string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := b.tg.send(ctx, chatID, text); err != nil {
		fmt.Fprintf(os.Stderr, "bot: reply failed: %v\n", err)
	}
}

// ── shared command text (rendered per transport) ──

func helpText(f formatter) string {
	return f.bold("🛰 sondra bot") + " — recon control\n\n" +
		f.bold("▸ Scan & monitor") + "\n" +
		"/scan " + f.esc("<domain>") + " [preset] [flags]\n" +
		"/monitor " + f.esc("<domain>") + " [flags]\n\n" +
		f.bold("▸ Presets") + "  quick(default) · full · passive · enum · vuln\n" +
		f.bold("▸ Flags") + "\n" +
		f.code("--modules") + " subfinder,crtsh,httpx,…  (overrides preset)\n" +
		f.code("--exclude") + " sub1.dom,sub2.dom\n" +
		f.code("--interval") + " 6h   (monitor cadence, min 1m)\n" +
		f.code("--on") + " all|assets|findings   (monitor alert)\n\n" +
		f.bold("▸ Jobs") + "\n" +
		"/status · /list — active jobs\n" +
		"/stop " + f.esc("<id>") + " — cancel a job · /stopall — cancel all\n\n" +
		f.bold("▸ Info") + "\n" +
		"/diff " + f.esc("<domain>") + " — changes vs previous run\n" +
		"/report " + f.esc("<domain>") + " — latest report path\n" +
		"/presets · /modules · /version · /help\n\n" +
		f.bold("▸ Examples") + "\n" +
		f.block("/scan example.com quick\n/scan example.com --modules subfinder,crtsh,httpx\n/monitor example.com --interval 2h --on findings")
}

func presetsText(f formatter) string {
	return f.bold("Presets") + "\n" + f.block(
		"quick    subfinder, crtsh, httpx, nuclei-high\n"+
			"passive  subfinder, assetfinder, crtsh\n"+
			"enum     + alterx, massdns, httpx, naabu\n"+
			"vuln     nuclei only\n"+
			"full     everything (gau, gowayback, katana, gowitness)") +
		"\nOverride any preset with " + f.code("--modules") + "."
}

func modulesText(f formatter) string {
	return f.bold("Modules") + " (use with " + f.code("--modules a,b,c") + ")\n" + f.block(
		"subfinder assetfinder crtsh   passive subdomain enum\n"+
			"alterx massdns                active DNS brute\n"+
			"httpx                         HTTP probe (needs enum first)\n"+
			"naabu                         port scan\n"+
			"gowitness                     screenshots\n"+
			"gau gowayback katana          URL collection / crawl\n"+
			"takeover                      subdomain takeover\n"+
			"nuclei                        vuln scan (nuclei-high/-medium)") +
		"\nPipeline: downstream tools (httpx/naabu/nuclei) need an enum source."
}
