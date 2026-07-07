# sondra

<pre>
███████╗ ██████╗ ███╗   ██╗██████╗ ██████╗  █████╗ 
██╔════╝██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██╔══██╗
███████╗██║   ██║██╔██╗ ██║██║  ██║██████╔╝███████║
╚════██║██║   ██║██║╚██╗██║██║  ██║██╔══██╗██╔══██║
███████║╚██████╔╝██║ ╚████║██████╔╝██║  ██║██║  ██║
╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
</pre>

> Automated bug-bounty recon pipeline. Named after *sonder* — the realization that every target has hidden depth.

![release](https://img.shields.io/github/v/release/AliMousaviSoft/sondra)
![go](https://img.shields.io/github/go-mod/go-version/AliMousaviSoft/sondra)
![license](https://img.shields.io/badge/license-MIT-blue)

**sondra** orchestrates ~a dozen recon tools into one fast, single-binary Go pipeline: passive/active subdomain enumeration → DNS resolution → HTTP probing → port scan → URL collection → JS endpoint/secret extraction → screenshots → nuclei vuln scan — then a filterable HTML report on every run. It runs as an interactive TUI, a headless daemon for a VPS/cron/CI, a continuous monitor that only alerts on change, or a Telegram/Discord control bot you drive from your phone.

---

## Features

- 🧩 **One pipeline, ~a dozen tools** — subfinder, assetfinder, crt.sh, alterx, massdns, dnsx, httpx, naabu, gau, gowaybackgo, katana, gowitness, nuclei — with per-module control.
- 🖥️ **Fixed TUI** header that never scrolls, goroutine-parallel enumeration, live per-step progress.
- 🤖 **Headless & JSON** modes for VPS / cron / CI (auto-enabled when stdout isn't a terminal).
- ⏱️ **Two-phase delivery** — recon results (and the report) land in ~minutes; the slow nuclei phase runs after and updates the report.
- 🔁 **Continuous monitoring** — rescan on a loop and alert **only when something changes**.
- 🔎 **JS analysis** — fetch collected `.js` and extract endpoints + secrets (API keys, tokens, JWTs).
- 🔔 **Notifications** — Discord embeds, Telegram, or a generic JSON webhook; real-time per-finding alerts + a structured payload for automation.
- 📱 **Control bot** — Telegram text commands *and* Discord slash commands, allow-listed, with monitors that survive a restart.
- 📄 **Filterable HTML report** on every run, plus a subdomain **diff** vs the previous run.

---

## Table of Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Usage](#usage)
  - [Continuous monitoring](#continuous-monitoring)
  - [Headless mode](#headless-mode)
- [Presets](#presets)
- [Modules](#modules)
  - [JS endpoint & secret analysis](#js-endpoint--secret-analysis)
- [Interactive selector](#interactive-selector)
- [Config file](#config-file)
- [Notifications](#notifications)
- [Control bot (Telegram + Discord)](#control-bot-telegram--discord)
- [Dependencies](#dependencies)
- [Output structure](#output-structure)
- [Report](#report)
- [Releasing a new version](#releasing-a-new-version)
- [License](#license)

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

Prebuilt binaries are published for `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, and `windows/amd64`. Then install the [external tools](#dependencies) for the modules you plan to use.

---

## Quick start

```bash
sondra scan -d target.com              # interactive module picker, then scan
sondra scan -d target.com -p quick     # quick preset, no prompt
sondra monitor -d target.com --interval 6h   # watch the attack surface, alert on change
sondra bot                             # run the Telegram/Discord control bot
```

---

## Commands

| Command | Purpose | Key flags |
|---------|---------|-----------|
| `scan` | Run the recon pipeline once | `-d`, `-p`, `-e`, `-y`, `--modules`, `--resume`, `--headless`, `--json` |
| `monitor` | Loop scans, alert only on deltas | `-d`, `-p`, `-e`, `--interval`, `--once`, `--on`, `--modules`, `--json` |
| `bot` | Telegram/Discord control daemon | `--config` |
| `report` | Regenerate the HTML report | `-d`, `--dir` |
| `diff` | Show new subdomains vs the last run | `-d` |
| `doctor` | Preflight-check tools, templates, and config | — |
| `version` | Print version + update status | — |
| `update` | Check for / apply a self-update | — |

Common flags:

| Flag | Applies to | Meaning |
|------|-----------|---------|
| `-d, --domain` | scan/monitor/report/diff | Target domain (required) |
| `-p, --preset` | scan/monitor | `full` \| `quick` \| `passive` \| `enum` \| `vuln` |
| `-e, --exclude` | scan/monitor | Subdomain(s) to drop from results (repeatable) |
| `--modules` | scan/monitor | Exact module list, overrides the preset (skips the selector) |
| `-y, --yes` | scan | Skip the interactive selector (use the preset as-is) |
| `--resume` | scan | Reuse the latest run dir for this domain — skip already-completed steps |
| `--headless` | scan | No TUI — structured stdout for VPS/cron/CI |
| `--json` | scan/monitor | Newline-delimited JSON logs (implies headless) |
| `--once` | monitor | Single pass then exit (for cron/systemd) |
| `--on` | monitor | Alert trigger: `all` \| `assets` \| `findings` |
| `--interval` | monitor | Time between passes, e.g. `30m`, `6h` |
| `--config` | all | Config file path (default `~/.sondra.yaml`) |

---

## Usage

```bash
sondra scan -d target.com                     # interactive module selector
sondra scan -d target.com -p quick            # quick preset, skip selector
sondra scan -d target.com -y                  # full preset, no prompt
sondra scan -d target.com -p enum -y          # enum-only preset
sondra scan -d target.com -e dev.target.com   # exclude a noisy subdomain
sondra scan -d target.com --modules gowayback,jsanalysis   # passive URL + JS only
sondra scan -d target.com -p full -y --resume # continue the last run — skip work already done
sondra scan -d target.com -p quick --headless # no TUI — for VPS / cron / CI
sondra scan -d target.com -p quick --json     # newline-delimited JSON logs
sondra monitor -d target.com --interval 6h    # rescan on a loop, alert on changes
sondra monitor -d target.com --once           # single monitor pass (for cron)
sondra bot                                    # Telegram/Discord control bot
sondra report -d target.com                   # regenerate HTML report
sondra diff -d target.com                     # show new subdomains vs last run
sondra version                                # show version + update status
sondra update                                 # check for updates
```

### Continuous monitoring

`sondra monitor` rescans a domain on a loop and **only alerts when something changes** vs the previous run — new subdomains, live hosts, open ports, takeovers, or nuclei findings. It's the way to watch a program's attack surface hands-free.

```bash
sondra monitor -d target.com --interval 6h        # loop every 6h (default)
sondra monitor -d target.com --once               # one pass, then exit (cron/systemd)
sondra monitor -d target.com --on findings        # alert only on new vulns
sondra monitor -d target.com --on assets          # alert only on new subdomains/hosts/ports
sondra monitor -d target.com --modules subfinder,crtsh,httpx   # custom module set
```

`--on` picks what counts as notable: `all` (default), `assets`, or `findings`. Each pass runs a full headless scan, diffs it against the last run, and sends a single **delta** notification (nothing is sent when nothing changed). Pair `--once` with cron/systemd if you'd rather not keep a process running. The first run just establishes the baseline (no alert).

### Headless mode

`--headless` runs the full pipeline without the interactive TUI, streaming structured log/progress lines to stdout — ideal for a VPS, cron job, or CI. It is selected automatically when stdout is not a terminal (piped or redirected), and `--json` (which implies headless) emits newline-delimited JSON for machine consumption. `SIGINT`/`SIGTERM` cancels a run cleanly. Modules are resolved from `-p/--preset` or `--modules` (no selector prompt).

### Reusing a run (`--resume`)

By default every `scan` starts a fresh `recon-<timestamp>` directory and re-runs everything. Pass **`--resume`** to instead continue the **most recent** run dir for the domain: steps whose output is still fresh (within `cache_age`, default 24h) are skipped, so only new or stale modules run.

```bash
sondra scan -d target.com -p quick -y            # → recon-A
sondra scan -d target.com -p full -y --resume    # reuses recon-A: subfinder/httpx cached, only the extra full modules run
```

Notes: `--resume` reuses the **merged** passive-enum / URL-collection outputs, so resuming a *smaller* preset into a *bigger* one skips the extra passive sources — run without `--resume` for a full re-enumeration. `monitor` and `diff` always use fresh dirs (they compare consecutive runs), so they're unaffected.

---

## Presets

| Preset    | Modules                                                          |
|-----------|------------------------------------------------------------------|
| `full`    | everything (enum + resolve + httpx + naabu + URL collection + jsanalysis + gowitness + nuclei) |
| `quick`   | subfinder + crt.sh + httpx + nuclei crit/high                    |
| `passive` | subfinder + assetfinder + crt.sh                                 |
| `enum`    | passive + alterx + massdns + httpx + naabu                       |
| `vuln`    | nuclei crit/high + medium (background)                           |

Override any preset with `--modules a,b,c`.

---

## Modules

Select any subset with `--modules` (comma-separated) or interactively. Valid names (and aliases):

| Module | Type | What it does | Needs |
|--------|------|--------------|-------|
| `subfinder` | Go lib | passive subdomain enum via APIs | — |
| `assetfinder` | binary | subdomains from cert transparency + web archives | — |
| `crtsh` | HTTP | certificate-transparency subdomains | — |
| `alterx` | binary | permutation-based subdomain generation | enum output |
| `massdns` | binary | high-speed DNS brute force | wordlist |
| `httpx` | binary | HTTP probe: alive check + title/tech/status/server | resolved hosts |
| `naabu` (`ports`) | binary | port scan for non-standard ports | resolved hosts |
| `takeover` (`takeovers`) | binary (nuclei) | subdomain-takeover fingerprinting | live hosts |
| `gau` | binary | URLs from Wayback / CommonCrawl | domain |
| `gowayback` (`wayback`, `gowaybackgo`) | binary | Wayback CDX URLs (better coverage than gau) | domain |
| `katana` | binary | active crawl + JS endpoint extraction | live hosts |
| `jsanalysis` (`js`, `secrets`) | HTTP + regex | extract endpoints + secrets from collected JS | `js_urls.txt` |
| `gowitness` (`screenshots`) | binary | headless screenshots of live hosts | live hosts |
| `nuclei` | binary | vuln scan (crit/high + medium) — runs after recon | live hosts |
| `nuclei-high` | binary | nuclei crit/high only | live hosts |
| `nuclei-medium` | binary | nuclei medium (async background) | live hosts |

**Pipeline order matters.** A `resolve` step (dnsx) runs automatically whenever an enum source is selected, feeding `httpx`. Modules that need live/resolved hosts (`httpx`, `naabu`, `nuclei`, `takeover`, `gowitness`, `katana`) therefore need an enum source (`subfinder`/`crtsh`/`assetfinder`/…) upstream. The **passive URL/JS** modules are the exception: `gau` and `gowayback` query the domain directly, and `jsanalysis` reads the collected `.js` list — so `--modules gowayback,jsanalysis` is a valid standalone run with no enumeration.

### JS endpoint & secret analysis

The `jsanalysis` module fetches the `.js` files that URL collection classifies into `wayback-data/js_urls.txt`, then runs two extractors over each body (bounded: up to 500 files, 5 MB each):

- **Endpoints** → `js-analysis/endpoints.txt` — absolute URLs and rooted API paths (`/api/v2/users?…`), with static assets (css/img/fonts/maps) filtered out.
- **Secrets** → `js-analysis/secrets.txt` — AWS access keys, Google API/OAuth keys, Slack tokens & webhooks, GitHub tokens, Stripe keys, JWTs, private-key blocks, and generic `api_key`/`token` assignments. Secrets are logged as a **warning** because they're worth a look.

It needs a URL source to have JS to analyze, so pair it with a collector:

```bash
sondra scan -d target.com --modules gowayback,jsanalysis   # passive
sondra scan -d target.com -p full                          # jsanalysis included
```

---

## Interactive selector

Run `scan` without `-y`/`--modules` to get the full module picker:

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

Modules whose external binary isn't installed are shown struck-through and can't be selected.

---

## Config file

`~/.sondra.yaml` or `.sondra.yaml` in the current directory. Settings merge in ascending priority: defaults → `~/.sondra.yaml` → `./.sondra.yaml` → environment (`SONDRA_` prefix) → CLI flags.

```yaml
concurrency: 50
rate_limit: 150
wayback_rate: 2        # gowaybackgo CDX requests/sec — raise for speed, lower (1) if you hit 429s
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
  state_db: "sondra-bot.db"                            # SQLite path for resuming monitors after a restart ("off" disables)
```

Environment variables use the `SONDRA_` prefix (nested keys join with `_`):

```bash
export SONDRA_CONCURRENCY=100
export SONDRA_RATE_LIMIT=200
export SONDRA_NOTIFY_DISCORD="https://discord.com/api/webhooks/xxx/yyy"
export SONDRA_NOTIFY_TELEGRAM_TOKEN="123456:ABC-DEF..."
export SONDRA_NOTIFY_TELEGRAM_CHAT_ID="987654321"
export SONDRA_NOTIFY_WEBHOOK="https://example.com/hook"
export SONDRA_BOT_TOKEN="123456:ABC..."
export SONDRA_BOT_ALLOWED_USERS="111111111"
export SONDRA_BOT_DISCORD_TOKEN="..."
export SONDRA_BOT_DISCORD_USERS="333333333"
```

---

## Notifications

Nuclei runs **after** the recon phase, so sondra delivers results in minutes instead of blocking ~15–20 m on the vuln scan:

1. **Recon done** — once subdomains/live-hosts/URLs are collected, the report is generated and an interim alert fires (`✅ Recon done — 🔍 scanning vulns…`) with subdomain/live/URL counts, new subdomains, and high-value hosts.
2. **Scan complete** — nuclei then runs in the background; when it finishes the report is regenerated with findings and the final alert fires with nuclei findings by severity (🔴🟠🟡⚪), takeovers, a list of findings at or above `min_severity`, and a link to the report. Its colour and title track the worst thing found (🚨 critical / ⚠️ high / ✅ clean).

(A recon-only run with no nuclei modules sends just the one finish message. If `notify.on_start: true`, a start message fires too.)

To keep a busy channel quiet, set `notify.only_notable: true` — the finish message is then sent **only** when there's signal (a finding ≥ `min_severity`, a new subdomain, a takeover, or an error); clean runs stay silent.

| Channel  | Config keys                              | Format                    |
|----------|------------------------------------------|---------------------------|
| Discord  | `notify.discord`                         | coloured embed            |
| Telegram | `notify.telegram.token` + `.chat_id`     | plain-text message        |
| Webhook  | `notify.webhook`                         | raw JSON POST (catch-all) |

The finish embed also includes a **status-code breakdown** and the **top technologies** seen across live hosts. Delivery is best-effort: a failing channel logs a warning and never aborts the scan. Works in both TUI and headless modes.

### Real-time per-finding alerts

Each nuclei finding at or above `min_severity` is pushed the **moment nuclei discovers it** (not just in the end-of-scan summary), so a live critical reaches you immediately.

### Structured webhook payload (for bots / automation)

The generic `notify.webhook` receives, in addition to the display fields, a `result` object with the full structured scan — ready for a bot or automation backend to consume:

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

`monitor` sends the same payload with `"event": "monitor_delta"` and `new_*` arrays describing only what changed. Discord/Telegram ignore `result` and render the human-readable message.

---

## Control bot (Telegram + Discord)

`sondra bot` runs a daemon so you can drive scans and monitors from chat — **Telegram** (text commands) and/or **Discord** (native slash commands). Both are **allow-listed** (only the configured user ids can command it) and validate every target against a strict domain regex — input flows into the recon tools, so this is the injection gate.

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
/diff [domain]        /status      /stop <id>     /stopall
/report [domain]      /presets     /modules       /version     /help
```

- Results (recon-done, per-finding, finish alerts) stream back to the chat/channel that issued the command **and** to your configured Discord/webhook.
- Jobs run in the background — start several, watch with `/status` (aliases `/list`, `/jobs`), cancel with `/stop <id>` or `/stopall`.
- `/report` and `/diff` **default to the most recently scanned domain** when you omit it.
- `/report` **uploads the actual `master_report.html`** as a file attachment (not a host-side path), so you can open it straight from your phone. It picks the latest *finished* run, skipping any scan still in progress.

**Monitors survive restarts.** Running monitors are persisted to a SQLite file (`bot.state_db`, default `sondra-bot.db`; set `off` to disable). When the daemon restarts it resumes each one — replying in the original chat/channel with a `♻️ Resumed monitor #N` note — so a redeploy or crash won't silently drop a long-running watch. A user `/stop` (or `/stopall`) forgets the job; only a shutdown keeps it for resume. One-shot `/scan` jobs are not persisted. The store uses a pure-Go SQLite driver, so release binaries stay cgo-free.

**Telegram setup:** message [@BotFather](https://t.me/botfather) → `/newbot` (or reuse your notify bot) for the token; message @userinfobot for your user id.

**Discord setup:** [Developer Portal](https://discord.com/developers/applications) → New Application → **Bot** → copy the token → invite it to your server. For slash commands the `applications.commands` scope is enough; add the **`bot`** scope with *Send Messages* if you want streamed scan results and resumed monitors to post beyond the first ~15 minutes. Slash commands register on startup — set `discord_guild` for instant registration (global takes up to ~1 h to appear).

---

## Dependencies

### Go dependency (compiled in — no install needed)

- [`subfinder/v2`](https://github.com/projectdiscovery/subfinder) — passive subdomain enumeration.

`crt.sh` and `jsanalysis` are plain HTTP + regex, also always available.

### External tools (exec — install separately)

Run **`sondra doctor`** to see what's installed, tool versions, which presets are runnable, and whether templates/notify/bot config are set up — it exits non-zero if anything's missing (handy for CI/cron):

```
$ sondra doctor
Recon tools
  ✓ httpx        1.9.0
  ✗ naabu        NOT FOUND → go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
Presets
  ✗ enum     needs naabu
```

`sondra` also checks for a selected module's binary at runtime and warns if it's missing:

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

# DNS brute force (C binary) — https://github.com/blechschmidt/massdns
```

---

## Output structure

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
    ├── js-analysis/
    │   ├── endpoints.txt         ← paths/URLs extracted from JS
    │   └── secrets.txt           ← API keys/tokens found in JS
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
- New subdomains diff from the previous run
- Live hosts table with status-code filters, tech detection, web server
- Open non-standard ports
- Subdomain takeover candidates

Regenerate it any time with `sondra report -d target.com` (add `--dir` to target a specific run).

---

## Releasing a new version

```bash
git tag v1.x.x
git push origin v1.x.x
# goreleaser builds and publishes binaries automatically via GitHub Actions
```

Builds binaries for `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, and `windows/amd64`.

> Tip: when publishing multiple tags, push the **highest** version last — GitHub marks whichever release publishes last as *Latest*.

---

## License

MIT
