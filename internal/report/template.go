package report

// reportTemplate returns the master_report.html template string.
// Kept as a Go function to keep the scaffold self-contained (no embed FS needed).
func reportTemplate() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>sondra — {{ .Domain }}</title>
<style>
  :root {
    --bg: #0d0d0d;
    --surface: #161616;
    --border: #262626;
    --text: #e0e0e0;
    --muted: #555;
    --accent: #e84855;
    --green: #39d353;
    --yellow: #e3b341;
    --blue: #58a6ff;
    --purple: #bc8cff;
    --font: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font);
    font-size: 13px;
    line-height: 1.6;
    padding: 32px;
  }
  header {
    border-bottom: 1px solid var(--border);
    padding-bottom: 24px;
    margin-bottom: 32px;
  }
  .brand { color: var(--accent); font-size: 22px; font-weight: 700; letter-spacing: -0.5px; }
  .domain { color: var(--text); font-size: 18px; margin-top: 4px; }
  .meta { color: var(--muted); font-size: 11px; margin-top: 8px; }

  /* Stats grid */
  .stats {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
    gap: 12px;
    margin-bottom: 40px;
  }
  .stat {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 16px;
  }
  .stat-val {
    font-size: 28px;
    font-weight: 700;
    color: var(--accent);
    display: block;
  }
  .stat-label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }

  /* Sections */
  section { margin-bottom: 40px; }
  h2 {
    color: var(--blue);
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 12px;
    border-left: 3px solid var(--accent);
    padding-left: 10px;
  }

  /* Tables */
  table { width: 100%; border-collapse: collapse; }
  th {
    text-align: left;
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    padding: 6px 10px;
    border-bottom: 1px solid var(--border);
  }
  td {
    padding: 6px 10px;
    border-bottom: 1px solid var(--border);
    word-break: break-all;
  }
  tr:hover td { background: var(--surface); }
  .hv td { border-left: 2px solid var(--accent); }
  a { color: var(--blue); text-decoration: none; }
  a:hover { text-decoration: underline; }

  /* Severity badges */
  .sev-critical { color: #ff4d4d; font-weight: 700; }
  .sev-high     { color: var(--accent); font-weight: 700; }
  .sev-medium   { color: var(--yellow); }
  .sev-low      { color: var(--muted); }

  /* Status code badges */
  .sc { display: inline-block; border-radius: 3px; padding: 1px 6px; font-size: 11px; }
  .sc-2 { background: #1a3a1a; color: var(--green); }
  .sc-3 { background: #2a2a1a; color: var(--yellow); }
  .sc-4 { background: #3a1a1a; color: #ff9966; }
  .sc-5 { background: #2a1a1a; color: var(--accent); }

  /* Filter bar */
  .filter-bar { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
  .filter-btn {
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--muted);
    padding: 4px 12px;
    border-radius: 4px;
    cursor: pointer;
    font-family: var(--font);
    font-size: 11px;
    transition: border-color 0.15s;
  }
  .filter-btn:hover, .filter-btn.active {
    border-color: var(--accent);
    color: var(--text);
  }
  .new-badge {
    display: inline-block;
    background: #2a1a00;
    color: var(--yellow);
    border: 1px solid #4a3a00;
    border-radius: 3px;
    padding: 1px 6px;
    font-size: 10px;
    margin-left: 6px;
  }
  .empty { color: var(--muted); padding: 20px 0; text-align: center; }
  .tag {
    display: inline-block;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 1px 5px;
    font-size: 10px;
    color: var(--muted);
    margin: 1px;
  }
</style>
</head>
<body>

<header>
  <div class="brand">sondra</div>
  <div class="domain">{{ .Domain }}</div>
  <div class="meta">generated {{ .Date.Format "2006-01-02 15:04:05 UTC" }}</div>
</header>

<!-- Stats -->
<div class="stats">
  <div class="stat"><span class="stat-val">{{ .SubdomainCount }}</span><span class="stat-label">subdomains</span></div>
  <div class="stat"><span class="stat-val">{{ .LiveCount }}</span><span class="stat-label">live hosts</span></div>
  <div class="stat"><span class="stat-val" style="color:{{ if gt .NucleiHits 0 }}#e84855{{ else }}#39d353{{ end }}">{{ .NucleiHits }}</span><span class="stat-label">nuclei findings</span></div>
  <div class="stat"><span class="stat-val" style="color:{{ if gt .TakeoverCount 0 }}#e84855{{ else }}#39d353{{ end }}">{{ .TakeoverCount }}</span><span class="stat-label">takeovers</span></div>
  <div class="stat"><span class="stat-val">{{ .URLCount }}</span><span class="stat-label">urls collected</span></div>
  <div class="stat"><span class="stat-val">{{ .JSCount }}</span><span class="stat-label">js files</span></div>
  <div class="stat"><span class="stat-val">{{ .PortCount }}</span><span class="stat-label">open ports</span></div>
  <div class="stat"><span class="stat-val">{{ len .HighValue }}</span><span class="stat-label">high-value targets</span></div>
</div>

<!-- Nuclei findings -->
<section>
  <h2>Vulnerability Findings</h2>
  {{ if .Findings }}
  <table id="findings-table">
    <thead>
      <tr>
        <th>Severity</th>
        <th>Template</th>
        <th>Name</th>
        <th>Target</th>
        <th>Time</th>
      </tr>
    </thead>
    <tbody>
    {{ range .Findings }}
    <tr>
      <td><span class="{{ severityClass .Severity }}">{{ .Severity | lower }}</span></td>
      <td>{{ .TemplateID }}</td>
      <td>{{ .Name }}</td>
      <td><a href="{{ .URL }}" target="_blank">{{ .URL }}</a></td>
      <td>{{ .Timestamp }}</td>
    </tr>
    {{ end }}
    </tbody>
  </table>
  {{ else }}<div class="empty">no findings</div>{{ end }}
</section>

<!-- High-value targets -->
{{ if .HighValue }}
<section>
  <h2>High-Value Targets</h2>
  <table>
    <thead><tr><th>URL</th></tr></thead>
    <tbody>
    {{ range .HighValue }}
    <tr><td><a href="{{ . }}" target="_blank">{{ . }}</a></td></tr>
    {{ end }}
    </tbody>
  </table>
</section>
{{ end }}

<!-- New subdomains -->
{{ if .NewSubdomains }}
<section>
  <h2>New Subdomains <span class="new-badge">{{ len .NewSubdomains }} new</span></h2>
  <table>
    <thead><tr><th>Subdomain</th></tr></thead>
    <tbody>
    {{ range .NewSubdomains }}
    <tr><td>{{ . }}</td></tr>
    {{ end }}
    </tbody>
  </table>
</section>
{{ end }}

<!-- Live hosts -->
<section>
  <h2>Live Hosts</h2>
  <div class="filter-bar" id="status-filters"></div>
  {{ if .LiveHosts }}
  <table id="hosts-table">
    <thead>
      <tr>
        <th>URL</th>
        <th>Status</th>
        <th>Title</th>
        <th>Server</th>
        <th>Technologies</th>
      </tr>
    </thead>
    <tbody>
    {{ range .LiveHosts }}
    <tr{{ if .HighValue }} class="hv"{{ end }} data-status="{{ .StatusCode }}">
      <td><a href="{{ .URL }}" target="_blank">{{ .URL }}</a></td>
      <td>
        {{ $sc := .StatusCode }}
        {{ if ge $sc 500 }}<span class="sc sc-5">{{ $sc }}</span>
        {{ else if ge $sc 400 }}<span class="sc sc-4">{{ $sc }}</span>
        {{ else if ge $sc 300 }}<span class="sc sc-3">{{ $sc }}</span>
        {{ else }}<span class="sc sc-2">{{ $sc }}</span>{{ end }}
      </td>
      <td>{{ .Title }}</td>
      <td>{{ .WebServer }}</td>
      <td>{{ range .Technologies }}<span class="tag">{{ . }}</span>{{ end }}</td>
    </tr>
    {{ end }}
    </tbody>
  </table>
  {{ else }}<div class="empty">no live hosts</div>{{ end }}
</section>

<!-- Open ports -->
{{ if .OpenPorts }}
<section>
  <h2>Open Non-Standard Ports</h2>
  <table>
    <thead><tr><th>Host:Port</th></tr></thead>
    <tbody>
    {{ range .OpenPorts }}
    <tr><td>{{ . }}</td></tr>
    {{ end }}
    </tbody>
  </table>
</section>
{{ end }}

<!-- Takeovers -->
{{ if .Takeovers }}
<section>
  <h2>Subdomain Takeovers</h2>
  <table>
    <thead><tr><th>Subdomain</th></tr></thead>
    <tbody>
    {{ range .Takeovers }}
    <tr><td style="color: var(--accent)">{{ . }}</td></tr>
    {{ end }}
    </tbody>
  </table>
</section>
{{ end }}

<script>
// Status code filter buttons
(function(){
  const table = document.getElementById('hosts-table');
  if (!table) return;
  const rows = Array.from(table.querySelectorAll('tbody tr'));
  const counts = {};
  rows.forEach(r => {
    const sc = r.dataset.status;
    const group = sc[0] + 'xx';
    counts[group] = (counts[group] || 0) + 1;
  });
  const bar = document.getElementById('status-filters');
  const btn = (label, filter) => {
    const b = document.createElement('button');
    b.className = 'filter-btn';
    b.textContent = label;
    b.onclick = () => {
      document.querySelectorAll('.filter-btn').forEach(x => x.classList.remove('active'));
      b.classList.add('active');
      rows.forEach(r => {
        r.style.display = filter(r) ? '' : 'none';
      });
    };
    bar.appendChild(b);
  };
  btn('all', () => true);
  Object.entries(counts).sort().forEach(([g, c]) => {
    btn(g + ' (' + c + ')', r => r.dataset.status && r.dataset.status[0] === g[0]);
  });
  btn('high-value', r => r.classList.contains('hv'));
  // Default: show all
  bar.querySelector('.filter-btn').click();
})();
</script>
</body>
</html>`
}
