# sondra

<pre>
███████╗ ██████╗ ███╗   ██╗██████╗ ██████╗  █████╗ 
██╔════╝██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██╔══██╗
███████╗██║   ██║██╔██╗ ██║██║  ██║██████╔╝███████║
╚════██║██║   ██║██║╚██╗██║██║  ██║██╔══██╗██╔══██║
███████║╚██████╔╝██║ ╚████║██████╔╝██║  ██║██║  ██║
╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
</pre>

> Automated bug bounty recon pipeline. Named after *sonder* — the realization that every target has hidden depth.

Fast, single-binary recon tool built in Go. Fixed TUI header that never scrolls, goroutine-parallel passive enum, and a filterable HTML report on every run.

---

## Install

```bash
go install github.com/AliMousaviSoft/sondra/cmd/sondra@latest
```

Or grab a prebuilt binary from [Releases](https://github.com/AliMousaviSoft/sondra/releases):

```bash
# Linux x86_64
curl -Lo sondra.tar.gz https://github.com/AliMousaviSoft/sondra/releases/latest/download/sondra_linux_amd64.tar.gz
tar xzf sondra.tar.gz
sudo mv sondra /usr/local/bin/
```

---

## Usage

```bash
sondra scan -d target.com                    # interactive module selector
sondra scan -d target.com -p quick           # quick preset, skip selector
sondra scan -d target.com -y                 # full preset, no prompt
sondra scan -d target.com -p enum -y         # enum-only preset
sondra scan -d target.com -p quick --headless # no TUI — for VPS / cron / CI
sondra scan -d target.com -p quick --json     # newline-delimited JSON logs
sondra monitor -d target.com --interval 6h    # rescan on a loop, alert on changes
sondra monitor -d target.com --once           # single monitor pass (for cron)
sondra report -d target.com                  # regenerate HTML report
sondra diff -d target.com                    # show new subdomains vs last run
sondra version                               # show version + update status
sondra update                                # check for updates
```

### Continuous monitoring

`sondra monitor` rescans a domain on a loop and **only alerts when something
changes** vs the previous run — new subdomains, live hosts, open ports,
takeovers, or nuclei findings. It's the way to watch a program's attack surface
hands-free.

```bash
sondra monitor -d target.com --interval 6h        # loop every 6h (default)
sondra monitor -d target.com --once               # one pass, then exit (cron/systemd)
sondra monitor -d target.com --on findings        # alert only on new vulns
sondra monitor -d target.com --on assets          # alert only on new subdomains/hosts/ports
sondra monitor -d target.com --modules subfinder,crtsh,httpx   # custom module set
```

`--modules` (also on `scan`) overrides the preset with an exact module list —
e.g. watch for new live hosts without the slow nuclei phase. Valid modules:
`subfinder, assetfinder, crtsh, alterx, massdns, httpx, takeover, naabu,
gowitness, gau, gowayback, katana, nuclei` (or granular `nuclei-high` /
`nuclei-medium`). `gowayback` collects Wayback CDX URLs via gowaybackgo.
Remember the pipeline order: downstream modules (`httpx`, `naabu`, `nuclei`)
need an enum source (`subfinder`/`crtsh`/`assetfinder`) to have targets.

`--on` picks what counts as notable: `all` (default), `assets`, or `findings`.
Each pass runs a full headless scan, diffs it against the last run, and sends a
single **delta** notification (nothing is sent when nothing changed). Pair
`--once` with cron/systemd if you'd rather not keep a process running. The first
run just establishes the baseline (no alert).

### Headless mode

`--headless` runs the full pipeline without the interactive TUI, streaming
structured log/progress lines to stdout — ideal for a VPS, cron job, or CI.
It is selected automatically when stdout is not a terminal (piped or
redirected), and `--json` (which implies headless) emits newline-delimited
JSON for machine consumption. `SIGINT`/`SIGTERM` cancels a run cleanly.
Modules are resolved from `-p/--preset` (no selector prompt).

---

## Presets

| Preset    | Modules                                                          |
|-----------|------------------------------------------------------------------|
| `full`    | everything                                                       |
| `quick`   | subfinder + crt.sh + httpx + nuclei crit/high                    |
| `passive` | subfinder + assetfinder + crt.sh                                 |
| `enum`    | passive + alterx + massdns + httpx + naabu                       |
| `vuln`    | nuclei crit/high + medium (background)                           |

---

## Interactive Selector

Run without `-y` to get the full module picker:

```bash
sondra scan -d target.com
```

| Key | Action |
|-----|--------|
| `↑↓` / `jk` | navigate |
| `space` | toggle module |
| `a` | select all available |
| `n` | deselect all |
| `1` | full preset |
| `2` | quick preset |
| `3` | passive preset |
| `4` | enum preset |
| `5` | vuln preset |
| `enter` | start scan |
| `q` | quit |

---

## Go Dependencies (direct import)

- [`subfinder/v2`](https://github.com/projectdiscovery/subfinder) — passive subdomain enumeration (Go lib)

---

## External Tools (exec — install separately)

`sondra` checks for these at startup and warns if a selected module's binary is missing:

```bash
# DNS + HTTP probing
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Subdomain enum
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest

# Crawling + URL collection
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/OoS-MaMaD/gowaybackgo@latest   # Wayback CDX (better coverage than gau/waybackurls)

# Screenshots
go install github.com/sensepost/gowitness@latest

# Vulnerability scanning
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# DNS brute force (C binary)
# https://github.com/blechschmidt/massdns
```

---

## Config File

`~/.sondra.yaml` or `.sondra.yaml` in the current directory:

```yaml
concurrency: 50
rate_limit: 150
timeout: 10s
cache_age: 24h
resolvers_file: /opt/resolvers.txt
nuclei_templates: ~/nuclei-templates

# Notifications (optional) — any channel with credentials is used.
notify:
  discord: https://discord.com/api/webhooks/xxx/yyy   # Discord webhook URL
  telegram:
    token: "123456:ABC-DEF..."                        # bot token from @BotFather
    chat_id: "987654321"                              # your chat/user id
  webhook: https://example.com/hook                   # generic JSON POST (Slack/ntfy/bot)
  min_severity: high                                  # lowest nuclei severity listed in summaries
  on_start: false                                     # also notify when a scan starts (default off)
  only_notable: false                                 # only send finish msg on signal (findings/new subs/takeovers/error)

# Control bot (optional) — drive scans/monitors from Telegram and/or Discord
bot:
  token: "123456:ABC..."                              # Telegram (falls back to notify.telegram.token)
  allowed_users: "111111111,222222222"                # Telegram user ids allowed
  discord_token: "..."                                # Discord bot token (slash commands)
  discord_users: "333333333,444444444"                # Discord user ids allowed
  discord_guild: "555555555"                          # optional: instant per-guild command registration
```

Environment variables use `SONDRA_` prefix (nested keys join with `_`):

```bash
export SONDRA_CONCURRENCY=100
export SONDRA_RATE_LIMIT=200
export SONDRA_NOTIFY_DISCORD="https://discord.com/api/webhooks/xxx/yyy"
export SONDRA_NOTIFY_TELEGRAM_TOKEN="123456:ABC-DEF..."
export SONDRA_NOTIFY_TELEGRAM_CHAT_ID="987654321"
export SONDRA_NOTIFY_WEBHOOK="https://example.com/hook"
```

## Notifications

Nuclei runs **after** the recon phase, so sondra delivers results in minutes
instead of blocking ~15–20m on the vuln scan:

1. **Recon done** — once subdomains/live-hosts/URLs are collected, the report is
   generated and an interim alert fires (`✅ Recon done — 🔍 scanning vulns…`)
   with subdomain/live/URL counts, new subdomains and high-value hosts.
2. **Scan complete** — nuclei then runs in the background; when it finishes the
   report is regenerated with findings and the final alert fires with nuclei
   findings by severity (🔴🟠🟡⚪), takeovers, a list of findings at or above
   `min_severity`, and a link to the report. Its colour and title track the
   worst thing found (🚨 critical / ⚠️ high / ✅ clean).

(A recon-only run with no nuclei modules sends just the one finish message. If
`notify.on_start: true`, a start message fires too.)

To keep a busy channel quiet, set `notify.only_notable: true` — the finish
message is then sent **only** when there's signal (a finding ≥ `min_severity`, a
new subdomain, a takeover, or an error); clean runs stay silent. Supported
channels:

| Channel  | Config keys                              | Format                    |
|----------|------------------------------------------|---------------------------|
| Discord  | `notify.discord`                         | coloured embed            |
| Telegram | `notify.telegram.token` + `.chat_id`     | plain-text message        |
| Webhook  | `notify.webhook`                         | raw JSON POST (catch-all) |

The finish embed also includes a **status-code breakdown** and the **top
technologies** seen across live hosts.

Delivery is best-effort: a failing channel logs a warning and never aborts the
scan. Works in both TUI and headless modes.

### Real-time per-finding alerts

Each nuclei finding at or above `min_severity` is pushed the **moment nuclei
discovers it** (not just in the end-of-scan summary), so a live critical reaches
you immediately.

### Structured webhook payload (for bots/automation)

The generic `notify.webhook` receives, in addition to the display fields, a
`result` object with the full structured scan — ready for a bot or automation
backend to consume:

```json
{
  "title": "✅ Scan complete: target.com",
  "result": {
    "domain": "target.com",
    "event": "scan_complete",
    "stats": { "subdomains": 31, "live_hosts": 10, "findings": 0 },
    "findings": [ { "template_id": "...", "severity": "high", "host": "..." } ],
    "new_subdomains": [ "..." ],
    "high_value": [ "..." ],
    "report_path": "target.com/recon-.../master_report.html"
  }
}
```

`monitor` sends the same payload with `"event": "monitor_delta"` and `new_*`
arrays describing only what changed. Discord/Telegram ignore `result` and render
the human-readable message.

---

## Control bot (Telegram + Discord)

`sondra bot` runs a daemon so you can drive scans and monitors from chat —
**Telegram** (text commands) and/or **Discord** (native slash commands). Both
are **allow-listed** (only the configured user ids can command it) and validate
every target against a strict domain regex — input flows into the recon tools,
so this is the injection gate.

```bash
# Telegram
export SONDRA_BOT_TOKEN="123456:ABC..."          # or notify.telegram.token
export SONDRA_BOT_ALLOWED_USERS="111111111"      # your Telegram user id
# Discord (optional)
export SONDRA_BOT_DISCORD_TOKEN="..."            # Discord bot token
export SONDRA_BOT_DISCORD_USERS="333333333"      # your Discord user id
sondra bot                                       # starts whichever is configured
```

Commands (Telegram text · Discord slash):

```
/scan <domain> [preset] [--modules …] [--exclude …]
/monitor <domain> [--interval 6h] [--on all|assets|findings] [--modules …]
/diff <domain>        /status      /stop <id>     /stopall
/report <domain>      /presets     /modules       /version     /help
```

Results (recon-done, per-finding, finish alerts) stream back to the chat/channel
that issued the command **and** to your configured Discord/webhook. Jobs run in
the background — start several, watch with `/status`, cancel with `/stop`.

**Telegram setup:** message [@BotFather](https://t.me/botfather) → `/newbot` (or
reuse your notify bot) for the token; message @userinfobot for your user id.

**Discord setup:** [Developer Portal](https://discord.com/developers/applications)
→ New Application → **Bot** → copy the token → invite it to your server
(`applications.commands` scope). Slash commands register on startup — set
`discord_guild` for instant registration (global takes up to ~1h to appear).

---

## Output Structure

```
target.com/
└── recon-2026-05-24_13-50/
    ├── passive_subs.txt          ← raw enum output
    ├── alldomains.txt            ← merged + deduped
    ├── resolved.txt              ← dnsx confirmed live
    ├── live.txt                  ← httpx alive hosts
    ├── httpx_full.json           ← enriched: title, tech, status
    ├── high_value.txt            ← admin/api/dev targets
    ├── new_subdomains.txt        ← diff from previous run
    ├── subfinder.txt
    ├── master_report.html        ← filterable HTML report
    ├── naabu-output/
    │   └── open_ports.txt
    ├── wayback-data/
    │   ├── all_urls.txt
    │   ├── js_urls.txt
    │   ├── php_urls.txt
    │   ├── aspx_urls.txt
    │   ├── param_wordlist.txt
    │   └── endpoints.txt
    ├── gowitness-output/
    │   └── screenshots/
    └── nuclei-results/
        ├── crit_high.jsonl
        ├── medium.jsonl
        └── takeovers.txt
```

---

## Report

The HTML report at `master_report.html` includes:

- Stats grid: subdomains, live hosts, nuclei findings, takeovers, URLs, ports, high-value targets
- Nuclei findings table sorted by severity (critical → high → medium)
- High-value targets section
- New subdomains diff from previous run
- Live hosts table with status code filters, tech detection, web server
- Open non-standard ports
- Subdomain takeover candidates

---

## Releasing a New Version

```bash
git tag v1.x.x
git push origin v1.x.x
# goreleaser builds and publishes binaries automatically via GitHub Actions
```

Builds binaries for:
- `linux/amd64`, `linux/arm64`
- `darwin/amd64`, `darwin/arm64`
- `windows/amd64`

---

## License

MIT