# sondra

> Automated bug bounty recon pipeline. Named after *sonder* — the realization that every target has hidden depth.

Fast, single-binary recon tool built in Go. Fixed TUI header that never scrolls, goroutine-parallel passive enum, and a filterable HTML report on every run.

---

## Install

```bash
go install github.com/yourusername/sondra@latest
```

Or grab a prebuilt binary from [Releases](https://github.com/yourusername/sondra/releases):

```bash
# Linux x86_64
curl -Lo sondra https://github.com/yourusername/sondra/releases/latest/download/sondra_linux_amd64.tar.gz
tar xzf sondra_linux_amd64.tar.gz
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
sondra version
```

---

## Presets

| Preset    | Modules                                               |
|-----------|-------------------------------------------------------|
| `full`    | everything                                            |
| `quick`   | subfinder + crt.sh + httpx + nuclei crit/high         |
| `passive` | subfinder + assetfinder + crt.sh                      |
| `enum`    | passive + alterx + massdns + httpx + naabu            |
| `vuln`    | nuclei crit/high + medium (background)                |

---

## Go dependencies (direct import — no subprocess)

- `subfinder` — passive subdomain enumeration
- `httpx` — 2-phase HTTP probe + enrichment
- `dnsx` — DNS resolution
- `naabu` — port scanning

## External tools (checked at startup)

Install these separately — `sondra` warns if a selected module's binary is missing:

```bash
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/gau/v2/cmd/gau@latest
go install github.com/sensepost/gowitness@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# massdns: https://github.com/blechschmidt/massdns
```

---

## Config file

`~/.sondra.yaml` or `.sondra.yaml` in current directory:

```yaml
concurrency: 50
rate_limit: 150
timeout: 10s
cache_age: 24h
resolvers_file: /opt/resolvers.txt
nuclei_templates: ~/nuclei-templates
```

Environment variables use `SONDRA_` prefix: `SONDRA_CONCURRENCY=100`.

---

## Output

```
target.com/
└── recon-2026-05-23_14-30/
    ├── passive_subs.txt
    ├── alldomains.txt
    ├── live.txt
    ├── httpx_full.json
    ├── high_value.txt
    ├── new_subdomains.txt
    ├── scan.log
    ├── master_report.html          ← filterable HTML report
    ├── naabu-output/
    ├── wayback-data/
    ├── gowitness-output/
    └── nuclei-results/
```

---

## Release a new version

```bash
git tag v1.0.0
git push origin v1.0.0
# goreleaser builds and publishes binaries automatically
```
