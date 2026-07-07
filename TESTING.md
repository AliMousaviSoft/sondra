# sondra — Test Plan

Manual + automated test cases for validating a build before release. Most of the
pipeline needs live network + external tools, so this is primarily a **manual QA
checklist**; the automated `go test` suite covers the pure logic.

**Legend:** ✅ pass · ❌ fail · ⏭ skipped (env unavailable)

---

## 0. Setup / preconditions

| # | Check | How |
|---|-------|-----|
| 0.1 | Correct binary on PATH | `command -v sondra` → `~/go/bin/sondra`; `sondra version` shows expected version |
| 0.2 | External tools installed | `dnsx httpx naabu nuclei gau gowaybackgo katana gowitness assetfinder alterx massdns` on PATH |
| 0.3 | Test target chosen | Use an **in-scope** domain you're authorized to test (examples below use `target.com`) |
| 0.4 | Automated suite green | `go test ./...` → all pass |

---

## 1. CLI / help / version (no network)

| # | Command | Expected |
|---|---------|----------|
| 1.1 | `sondra -h` | Overview + example block + command list + footer |
| 1.2 | `sondra scan -h` | Lists `-d -p -e -y --modules --resume --headless --json --config` |
| 1.3 | `sondra monitor -h` | Lists `--interval --on --once --modules …` |
| 1.4 | `sondra version` | Banner + `version/commit/built`; banner shows `up to date` or a newer version |
| 1.5 | `sondra scan` (no `-d`) | Clear "domain is required" error, non-zero exit |
| 1.6 | `sondra scan -d t.com --modules bogus -y` | "unknown module(s): bogus (valid: …)" error |
| 1.7 | `sondra doctor` | Each tool ✓/✗ with version; presets ready/blocked; config summary; exit 0 if all present, 1 if any missing |
| 1.8 | `sondra doctor; echo $?` with a tool removed from PATH | That tool shows `✗ … → go install …`; exit code `1` |

---

## 2. Scan pipeline

| # | Command | Expected |
|---|---------|----------|
| 2.1 | `sondra scan -d target.com` | Interactive selector opens (full preset pre-checked); Enter starts |
| 2.2 | `sondra scan -d target.com -p quick -y` | Runs subfinder→resolve→httpx→nuclei(high); results box; report written |
| 2.3 | `sondra scan -d target.com -p quick --headless` | No TUI; structured stdout log lines; same outputs |
| 2.4 | `sondra scan -d target.com -p quick --json` | Newline-delimited JSON log lines |
| 2.5 | `sondra scan -d target.com -p quick -y \| cat` | Auto-headless (stdout not a TTY) |
| 2.6 | Output dir | `target.com/recon-<ts>/` contains `live.txt`, `high_value.txt`, `master_report.html` |
| 2.7 | Open `master_report.html` | Stats grid, live-host table with filters, findings by severity |

---

## 3. Module control & pipeline dependencies (regressions)

> These encode bugs already fixed — they must keep passing.

| # | Command | Expected |
|---|---------|----------|
| 3.1 | `sondra scan -d target.com --modules gowayback,jsanalysis -y` | **No "alldomains.txt" error**; gowayback collects URLs, jsanalysis runs (resolve skipped — no enum) |
| 3.2 | `sondra scan -d target.com --modules gowayback,katana -y` | katana **skipped** with a "no live hosts" warning; gowayback still runs |
| 3.3 | `sondra scan -d target.com --modules subfinder,httpx,katana -y` | katana **runs** (live hosts exist) |
| 3.4 | `sondra scan -d target.com --modules httpx -y` | Fails clearly (no enum source → no targets), not a cryptic crash |
| 3.5 | `sondra scan -d target.com -p full -y` | Full chain incl. jsanalysis; recon-done alert then scan-complete |

---

## 4. `--resume`

| # | Steps | Expected |
|---|-------|----------|
| 4.1 | `scan -d t.com -p quick -y` then `scan -d t.com -p quick -y --resume` | 2nd run **reuses the same `recon-<ts>` dir**; steps log "cache hit"; near-instant |
| 4.2 | `scan -d t.com -p quick -y` then `scan -d t.com -p full -y --resume` | Reuses dir; subfinder/httpx cached; new modules (naabu/gau/katana/jsanalysis/nuclei-medium) run |
| 4.3 | `scan -d t.com -p quick -y` (no `--resume`) | Fresh `recon-<ts>` dir each time (default) |
| 4.4 | `scan -d <new-domain> -p quick -y --resume` | No prior run → falls back to a fresh dir (no error) |

---

## 5. JS endpoint & secret analysis

| # | Steps | Expected |
|---|-------|----------|
| 5.1 | `scan -d target.com --modules gau,jsanalysis -y` | `recon-*/js-analysis/endpoints.txt` + `secrets.txt` created |
| 5.2 | Inspect `endpoints.txt` | Absolute URLs + rooted API paths; no `.css/.png/.woff` static assets |
| 5.3 | Inspect `secrets.txt` | Any AWS/Google/Slack/GitHub/Stripe/JWT/private-key matches, tab-separated with source URL |
| 5.4 | Automated | `go test ./internal/modules -run Extract` passes (endpoints, secrets, no-false-positives) |
| 5.5 | Open `master_report.html` after a jsanalysis run | **JS Analysis** section shows a secrets table (type · value · source) + collapsible endpoints; grid has a "js secrets" stat (red if >0) |

---

## 6. Wayback rate limiting

| # | Command | Expected |
|---|---------|----------|
| 6.1 | `SONDRA_WAYBACK_RATE=1 sondra scan -d hackerone.com --modules gowayback -y` | Slow but fewer/no `ERROR fetching CDX page` (429s become backoff+retry) |
| 6.2 | No `--timeout` starvation | gowaybackgo doesn't fail at ~10s with a DNS/i-o timeout (uses its 80s default) |

---

## 7. Monitoring & diff

| # | Steps | Expected |
|---|-------|----------|
| 7.1 | `scan -d t.com -p quick -y` twice, then `sondra diff -d t.com` | Lists new subdomains vs the previous run (or "no changes") |
| 7.2 | `sondra report -d target.com` | Regenerates `master_report.html` from the latest run |
| 7.3 | `sondra monitor -d t.com --interval 2m --once` | Single pass, baseline, exits (no alert on first run) |
| 7.4 | `sondra monitor -d t.com --interval 2m` (with notify configured) | Alerts only when a delta appears; silent otherwise |

---

## 8. Notifications (configure `notify` first)

| # | Trigger | Expected |
|---|---------|----------|
| 8.1 | Full scan with findings | Recon-done alert, then scan-complete alert (severity colour/emoji, report link) |
| 8.2 | `only_notable: true`, clean run | No finish message sent |
| 8.3 | Per-finding | Each finding ≥ `min_severity` pushed as nuclei discovers it |
| 8.4 | Generic webhook | POST body includes the structured `result` object |

---

## 9. Control bot (Telegram + Discord)

| # | Action | Expected |
|---|--------|----------|
| 9.1 | `sondra bot` | "listening on telegram/discord"; unauthorized user id is rejected |
| 9.2 | `/scan target.com quick` | "Scan #N started"; results stream to the chat |
| 9.3 | `/status` · `/stop <id>` · `/stopall` | Lists jobs; cancels them |
| 9.4 | `/report` (no domain) | Uploads `master_report.html` for the latest domain; skips in-progress runs |
| 9.5 | `/diff` (no domain) | Diffs the latest domain |
| 9.6 | `/monitor target.com --interval 2h --on findings` | Monitor starts; alerts on change |
| 9.7 | **Persistence:** start a monitor, restart `sondra bot` | `♻️ Resumed monitor #N` fires; `/status` shows it |
| 9.8 | Discord `/scan` | Responds within 3s (no "application did not respond"); results as embeds |

---

## 10. Robustness / lifecycle

| # | Action | Expected |
|---|--------|----------|
| 10.1 | `Ctrl-C` mid-scan | Clean cancellation; partial results saved; no panic |
| 10.2 | Missing external tool for a selected module | Clear "not in PATH — install: …" message, not a crash |
| 10.3 | No network | Modules fail gracefully with warnings; scan doesn't hang indefinitely |
| 10.4 | `Ctrl-C` during crt.sh / a retry backoff | Returns promptly (no ~6s hang) — retry backoff is ctx-aware |
| 10.5 | Automated | `go test ./internal/modules -run Retry` (success-after-failures, exhaustion, cancel-returns-immediately) |

---

## Automated tests

```bash
go test ./...          # full suite
go vet ./...
gofmt -l .             # should print nothing
# cross-compile sanity (release targets, cgo-free):
for t in linux/amd64 darwin/arm64 windows/amd64; do
  CGO_ENABLED=0 GOOS=${t%/*} GOARCH=${t#*/} go build -o /dev/null ./cmd/sondra && echo "ok $t"
done
```
