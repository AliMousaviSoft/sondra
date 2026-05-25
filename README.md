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
sondra report -d target.com                  # regenerate HTML report
sondra diff -d target.com                    # show new subdomains vs last run
sondra version                               # show version + update status
sondra update                                # check for updates
```

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
```

Environment variables use `SONDRA_` prefix:

```bash
export SONDRA_CONCURRENCY=100
export SONDRA_RATE_LIMIT=200
```

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