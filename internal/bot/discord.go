package bot

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AliMousaviSoft/sondra/internal/notify"
	"github.com/bwmarrin/discordgo"
)

// discordTransport receives Discord slash commands and dispatches them into the
// shared command handlers.
type discordTransport struct {
	session *discordgo.Session
	bot     *Bot
}

// startDiscord opens the gateway, registers slash commands, and wires the
// interaction handler. Commands register to a guild (instant) when
// bot.discord_guild is set, otherwise globally (may take up to ~1h to appear).
func startDiscord(b *Bot) (*discordTransport, error) {
	s, err := discordgo.New("Bot " + b.cfg.Bot.DiscordToken)
	if err != nil {
		return nil, err
	}
	s.Identify.Intents = discordgo.IntentsGuilds // interactions arrive regardless

	dt := &discordTransport{session: s, bot: b}
	s.AddHandler(dt.onInteraction)

	if err := s.Open(); err != nil {
		return nil, err
	}
	appID := s.State.User.ID
	if appID == "" {
		s.Close()
		return nil, fmt.Errorf("could not determine application id")
	}
	if _, err := s.ApplicationCommandBulkOverwrite(appID, b.cfg.Bot.DiscordGuild, slashCommands()); err != nil {
		s.Close()
		return nil, fmt.Errorf("register commands: %w", err)
	}
	return dt, nil
}

func (dt *discordTransport) close() { _ = dt.session.Close() }

// onInteraction authorizes the invoker, maps the slash command to a Command,
// and dispatches it. It ACKs the interaction with a deferred response first —
// a tiny fixed call that reliably beats Discord's 3s deadline — so slow or
// failed command work never surfaces as "The application did not respond".
func (dt *discordTransport) onInteraction(s *discordgo.Session, i *discordgo.InteractionCreate) {
	if i.Type != discordgo.InteractionApplicationCommand {
		return
	}
	user := i.User
	if user == nil && i.Member != nil {
		user = i.Member.User
	}
	if user == nil {
		return
	}
	if !dt.bot.cfg.Bot.DiscordAllowed(user.ID) {
		fmt.Fprintf(os.Stderr, "bot: REJECTED discord user %s (%s)\n", user.ID, user.Username)
		if err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "⛔ Not authorized. Ask the operator to allow-list your user id: " + user.ID,
				Flags:   discordgo.MessageFlagsEphemeral,
			},
		}); err != nil {
			fmt.Fprintf(os.Stderr, "bot: discord reject ack failed: %v\n", err)
		}
		return
	}

	// Acknowledge immediately (within 3s) so dispatch has ~15m to deliver the
	// real content via the interaction token. If this fails, the responder
	// falls back to a direct response on its first reply.
	acked := true
	if err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "bot: discord ack failed: %v\n", err)
		acked = false
	}

	cmd := commandFromInteraction(i.ApplicationCommandData())
	r := &dcResponder{session: s, interaction: i.Interaction, channelID: i.ChannelID, deferred: acked}
	dt.bot.dispatch(r, cmd)
}

// commandFromInteraction maps slash-command options into a Command, reusing the
// same struct the Telegram parser produces.
func commandFromInteraction(data discordgo.ApplicationCommandInteractionData) Command {
	c := Command{Name: data.Name, Preset: "quick", OnMode: "all"}
	for _, opt := range data.Options {
		switch opt.Name {
		case "domain":
			c.Domain = strings.ToLower(strings.TrimSpace(opt.StringValue()))
			c.Arg = opt.StringValue()
		case "preset":
			c.Preset = opt.StringValue()
		case "modules":
			c.Modules = splitCSV(opt.StringValue())
		case "exclude":
			c.Exclude = splitCSV(opt.StringValue())
		case "on":
			c.OnMode = opt.StringValue()
		case "interval":
			if d, err := time.ParseDuration(opt.StringValue()); err == nil {
				c.Interval = d
			}
		case "id":
			c.Arg = strconv.FormatInt(opt.IntValue(), 10)
		}
	}
	return c
}

// ── dcResponder ──

type dcResponder struct {
	session     *discordgo.Session
	interaction *discordgo.Interaction
	channelID   string
	deferred    bool // onInteraction already sent a deferred ack
	mu          sync.Mutex
	replied     bool
}

// reply delivers the first message by editing the deferred response, and later
// ones as interaction follow-ups. These use the interaction token, so they work
// even when the app was invited with only the applications.commands scope (no
// bot-member/channel perms). Once the token expires (~15m) it falls back to a
// direct channel send, which needs the bot scope.
func (d *dcResponder) reply(text string) {
	text = truncate(text, 1900)
	d.mu.Lock()
	first := !d.replied
	d.replied = true
	d.mu.Unlock()

	if first {
		if d.deferred {
			if _, err := d.session.InteractionResponseEdit(d.interaction, &discordgo.WebhookEdit{Content: &text}); err != nil {
				fmt.Fprintf(os.Stderr, "bot: discord reply (edit) failed: %v\n", err)
			}
			return
		}
		// Ack failed earlier — respond fresh instead.
		if err := d.session.InteractionRespond(d.interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{Content: text},
		}); err != nil {
			fmt.Fprintf(os.Stderr, "bot: discord reply (respond) failed: %v\n", err)
		}
		return
	}

	if _, err := d.session.FollowupMessageCreate(d.interaction, true, &discordgo.WebhookParams{Content: text}); err != nil {
		fmt.Fprintf(os.Stderr, "bot: discord follow-up failed (%v); trying channel send\n", err)
		if _, err2 := d.session.ChannelMessageSend(d.channelID, text); err2 != nil {
			fmt.Fprintf(os.Stderr, "bot: discord channel send failed: %v\n", err2)
		}
	}
}

func (d *dcResponder) notifier() notify.Notifier {
	return &discordChannelNotifier{session: d.session, interaction: d.interaction, channelID: d.channelID}
}

func (d *dcResponder) fmtr() formatter { return mdFmt{} }

// discordChannelNotifier posts scan alerts as embeds tied to the invoking
// interaction. It prefers an interaction follow-up (works without the bot
// scope, valid ~15m) and falls back to a direct channel send once the
// interaction token has expired — e.g. the final alert after a long nuclei run.
type discordChannelNotifier struct {
	session     *discordgo.Session
	interaction *discordgo.Interaction
	channelID   string
}

func (n *discordChannelNotifier) Name() string { return "discord-bot" }

func (n *discordChannelNotifier) Send(_ context.Context, m notify.Message) error {
	embed := &discordgo.MessageEmbed{
		Title:       truncate(m.Title, 256),
		Description: truncate(m.Text, 4000),
		Color:       discordColorFor(m.Level),
	}
	for _, fld := range m.Fields {
		v := fld.Value
		if strings.TrimSpace(v) == "" {
			v = "—"
		}
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name: truncate(fld.Name, 256), Value: truncate(v, 1024), Inline: fld.Inline,
		})
	}
	if m.Footer != "" {
		embed.Footer = &discordgo.MessageEmbedFooter{Text: truncate(m.Footer, 2048)}
	}

	if n.interaction != nil {
		if _, err := n.session.FollowupMessageCreate(n.interaction, true, &discordgo.WebhookParams{
			Embeds: []*discordgo.MessageEmbed{embed},
		}); err == nil {
			return nil
		}
		// token likely expired (>15m) — fall through to a direct channel send.
	}
	_, err := n.session.ChannelMessageSendEmbed(n.channelID, embed)
	return err
}

func discordColorFor(l notify.Level) int {
	switch l {
	case notify.LevelSuccess:
		return 0x2ECC71
	case notify.LevelWarn:
		return 0xF1C40F
	case notify.LevelError:
		return 0xE74C3C
	default:
		return 0x3498DB
	}
}

// ── slash command schemas ──

func slashCommands() []*discordgo.ApplicationCommand {
	str := discordgo.ApplicationCommandOptionString
	domain := &discordgo.ApplicationCommandOption{Type: str, Name: "domain", Description: "Target domain", Required: true}
	preset := &discordgo.ApplicationCommandOption{
		Type: str, Name: "preset", Description: "Scan preset (default quick)",
		Choices: choices("quick", "full", "passive", "enum", "vuln"),
	}
	modules := &discordgo.ApplicationCommandOption{Type: str, Name: "modules", Description: "Comma-separated modules (overrides preset)"}
	exclude := &discordgo.ApplicationCommandOption{Type: str, Name: "exclude", Description: "Comma-separated subdomains to exclude"}
	interval := &discordgo.ApplicationCommandOption{Type: str, Name: "interval", Description: "Rescan cadence e.g. 6h (min 1m)"}
	on := &discordgo.ApplicationCommandOption{
		Type: str, Name: "on", Description: "Alert trigger (default all)",
		Choices: choices("all", "assets", "findings"),
	}
	id := &discordgo.ApplicationCommandOption{Type: discordgo.ApplicationCommandOptionInteger, Name: "id", Description: "Job id", Required: true}

	return []*discordgo.ApplicationCommand{
		{Name: "scan", Description: "Run a recon scan against a domain", Options: []*discordgo.ApplicationCommandOption{domain, preset, modules, exclude}},
		{Name: "monitor", Description: "Watch a domain, alert on changes", Options: []*discordgo.ApplicationCommandOption{domain, interval, on, preset, modules}},
		{Name: "diff", Description: "Show changes vs the previous run", Options: []*discordgo.ApplicationCommandOption{domain}},
		{Name: "report", Description: "Path to the latest report", Options: []*discordgo.ApplicationCommandOption{domain}},
		{Name: "stop", Description: "Cancel a running job", Options: []*discordgo.ApplicationCommandOption{id}},
		{Name: "status", Description: "List active scan/monitor jobs"},
		{Name: "stopall", Description: "Cancel every running job"},
		{Name: "presets", Description: "List scan presets"},
		{Name: "modules", Description: "List available modules"},
		{Name: "version", Description: "Show sondra version"},
		{Name: "help", Description: "Show all commands and usage"},
	}
}

func choices(vals ...string) []*discordgo.ApplicationCommandOptionChoice {
	out := make([]*discordgo.ApplicationCommandOptionChoice, 0, len(vals))
	for _, v := range vals {
		out = append(out, &discordgo.ApplicationCommandOptionChoice{Name: v, Value: v})
	}
	return out
}
