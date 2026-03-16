import json, glob, html, datetime, os

reports = sorted(glob.glob("reports/**/cve-report-*-*.json", recursive=True))

apps = {}
for rpath in reports:
    filename = os.path.basename(rpath)
    # Expected format: cve-report-NAME-ARCH.json
    parts = filename.replace("cve-report-", "").replace(".json", "").split("-")
    if len(parts) >= 2:
        arch = parts[-1]
        name = "-".join(parts[:-1])
    else:
        name = filename.replace("cve-report-", "").replace(".json", "")
        arch = "unknown"

    if name not in apps:
        apps[name] = {}

    try:
        with open(rpath) as f:
            data = json.load(f)
        matches = data.get("matches", [])
        for m in matches:
            artifact_name = m.get("artifact", {}).get("name", "unknown")
            artifact_version = m.get("artifact", {}).get("version", "unknown")
            pkg = f"{artifact_name}@{artifact_version}"
            
            for v in m.get("vulnerabilities", [m.get("vulnerability", {})]):
                vid = v.get("id", "N/A")
                key = (vid, pkg)
                
                if key not in apps[name]:
                    apps[name][key] = {
                        "id": vid,
                        "severity": v.get("severity", "Unknown"),
                        "description": v.get("description", "")[:200],
                        "package": pkg,
                        "fixed": v.get("fix", {}).get("versions", []),
                        "archs": set()
                    }
                apps[name][key]["archs"].add(arch)
    except Exception as e:
        pass

severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Negligible": 4, "Unknown": 5}
now = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M UTC")

# Summary stats
total = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
for app_vulns in apps.values():
    for v in app_vulns.values():
        sev = v["severity"]
        if sev in total:
            total[sev] += 1

page = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VegOps CVE Dashboard</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg: #0f172a;           /* slate-900 */
      --surface: #1e293b;      /* slate-800 */
      --surface-hover: #334155;/* slate-700 */
      --border: #334155;       /* slate-700 */
      --text: #f8fafc;         /* slate-50 */
      --text-muted: #94a3b8;   /* slate-400 */
      
      --critical: #ef4444;     /* red-500 */
      --critical-bg: #7f1d1d;  /* red-900 (20%) */
      
      --high: #f97316;         /* orange-500 */
      --high-bg: #7c2d12;      /* orange-900 */
      
      --medium: #eab308;       /* yellow-500 */
      --medium-bg: #713f12;    /* yellow-900 */
      
      --low: #22c55e;          /* green-500 */
      --low-bg: #14532d;       /* green-900 */
      
      --unknown: #64748b;      /* slate-500 */
      --unknown-bg: #334155;   /* slate-700 */
      
      --accent: #38bdf8;       /* sky-400 */
    }}
    
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    
    body {{ 
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg); 
      color: var(--text); 
      padding: 1rem; 
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }}
    
    @media (min-width: 768px) {{
      body {{ padding: 2rem; }}
    }}
    
    .container {{
      max-width: 1200px;
      margin: 0 auto;
    }}
    
    header {{
      margin-bottom: 2rem;
      border-bottom: 1px solid var(--border);
      padding-bottom: 1.5rem;
    }}
    
    h1 {{ 
      color: var(--text); 
      font-size: 1.75rem;
      font-weight: 700;
      letter-spacing: -0.025em;
      margin-bottom: 0.5rem;
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }}
    
    @media (min-width: 768px) {{
      h1 {{ font-size: 2.25rem; margin-bottom: 0.25rem; }}
    }}
    
    h1::before {{
      content: '';
      display: inline-block;
      width: 20px;
      height: 20px;
      background: var(--accent);
      border-radius: 5px;
      box-shadow: 0 0 15px rgba(56, 189, 248, 0.4);
    }}
    
    @media (min-width: 768px) {{
      h1::before {{ width: 24px; height: 24px; border-radius: 6px; }}
    }}
    
    .timestamp {{ 
      color: var(--text-muted); 
      font-size: 0.875rem; 
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}
    
    .summary {{ 
      display: grid; 
      grid-template-columns: 1fr; 
      gap: 1rem; 
      margin-bottom: 2.5rem; 
    }}
    
    @media (min-width: 480px) {{
      .summary {{ grid-template-columns: repeat(2, 1fr); }}
    }}
    
    @media (min-width: 1024px) {{
      .summary {{ grid-template-columns: repeat(5, 1fr); }}
    }}
    
    .card {{ 
      background: var(--surface); 
      border: 1px solid var(--border); 
      border-radius: 12px;
      padding: 1.25rem; 
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
      transition: transform 0.2s ease, box-shadow 0.2s ease;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }}
    
    .card:hover {{
      transform: translateY(-2px);
      box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
      border-color: var(--surface-hover);
    }}
    
    .card h3 {{ 
      color: var(--text-muted); 
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 0.5rem; 
    }}
    
    .card .count {{ 
      font-size: 2rem; 
      font-weight: 700; 
      line-height: 1;
    }}
    
    .count-text {{ color: var(--text); }}
    .count.critical {{ color: var(--critical); text-shadow: 0 0 12px rgba(239, 68, 68, 0.3); }}
    .count.high {{ color: var(--high); text-shadow: 0 0 12px rgba(249, 115, 22, 0.3); }}
    .count.medium {{ color: var(--medium); }}
    .count.low {{ color: var(--low); }}
    
    .image-section {{ 
      margin-bottom: 2rem; 
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }}
    
    .image-header {{
      padding: 1rem 1.25rem;
      background: rgba(15, 23, 42, 0.4);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 0.75rem;
    }}
    
    .image-section h2 {{ 
      color: var(--text); 
      font-size: 1.125rem;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}
    
    .image-section h2::before {{
      content: '📦';
      font-size: 1rem;
    }}
    
    .table-wrapper {{
      overflow-x: auto;
    }}
    
    table {{ 
      width: 100%; 
      border-collapse: collapse; 
      text-align: left;
    }}
    
    th, td {{ 
      padding: 1rem 1.25rem; 
      border-bottom: 1px solid var(--border); 
    }}
    
    th {{ 
      color: var(--text-muted); 
      font-weight: 600; 
      font-size: 0.875rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      background: rgba(15, 23, 42, 0.2);
    }}
    
    tbody tr {{
      transition: background-color 0.15s ease;
    }}
    
    tbody tr:last-child td {{
      border-bottom: none;
    }}
    
    tbody tr:hover {{
      background-color: rgba(255, 255, 255, 0.02);
    }}
    
    /* Responsive Table to Cards */
    @media (max-width: 767px) {{
      thead {{ display: none; }}
      
      table, tbody, tr, td {{ 
        display: block; 
        width: 100%;
      }}
      
      tr {{
        padding: 1rem 0;
        border-bottom: 4px solid var(--bg);
      }}
      
      tr:last-child {{
        border-bottom: none;
      }}
      
      td {{
        border: none;
        padding: 0.5rem 1.25rem;
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        text-align: right;
      }}
      
      td::before {{
        content: attr(data-label);
        font-weight: 600;
        text-transform: uppercase;
        font-size: 0.75rem;
        color: var(--text-muted);
        display: block;
        text-align: left;
        margin-right: 1rem;
        flex-shrink: 0;
        padding-top: 0.1rem;
      }}
      
      .cve-id, .package-name, .fixed-in, .description {{
        max-width: none;
        text-align: right;
      }}
      
      .description {{
        display: block;
        text-align: left;
        margin-top: 0.25rem;
      }}
      
      .description::before {{
        margin-bottom: 0.5rem;
      }}
    }}
    
    .cve-id {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.9rem;
      color: var(--text);
      font-weight: 500;
    }}
    
    .package-name {{
      font-weight: 500;
      color: var(--accent);
    }}
    
    .fixed-in {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.85rem;
      color: var(--low);
    }}
    
    .arch-badge {{
      font-size: 0.75rem;
      background: rgba(56, 189, 248, 0.1);
      color: var(--accent);
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      margin-right: 0.25rem;
      display: inline-block;
    }}

    .description {{
      color: var(--text-muted);
      font-size: 0.95rem;
      max-width: 400px;
      line-height: 1.6;
    }}
    
    .badge {{ 
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0.25rem 0.6rem; 
      border-radius: 9999px; 
      font-size: 0.75rem; 
      font-weight: 600; 
      text-transform: uppercase;
      letter-spacing: 0.05em;
      white-space: nowrap;
    }}
    
    .badge-critical {{ background: var(--critical-bg); color: var(--critical); border: 1px solid rgba(239, 68, 68, 0.2); }}
    .badge-high {{ background: var(--high-bg); color: var(--high); border: 1px solid rgba(249, 115, 22, 0.2); }}
    .badge-medium {{ background: var(--medium-bg); color: var(--medium); border: 1px solid rgba(234, 179, 8, 0.2); }}
    .badge-low {{ background: var(--low-bg); color: var(--low); border: 1px solid rgba(34, 197, 94, 0.2); }}
    .badge-unknown {{ background: var(--unknown-bg); color: var(--unknown); border: 1px solid rgba(100, 116, 139, 0.2); }}
    
    .image-title-wrapper {{
      display: flex;
      align-items: center;
      flex: 1;
      min-width: 200px;
    }}
    
    .status-badge {{
      display: inline-flex;
      align-items: center;
      gap: 0.375rem;
      padding: 0.375rem 0.75rem;
      border-radius: 6px;
      font-size: 0.875rem;
      font-weight: 500;
      background: rgba(34, 197, 94, 0.1);
      color: var(--low);
      border: 1px solid rgba(34, 197, 94, 0.2);
    }}
    
    .status-badge.has-issues {{
      background: rgba(239, 68, 68, 0.1);
      color: var(--critical);
      border-color: rgba(239, 68, 68, 0.2);
    }}
    
    .status-dot {{
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: currentColor;
    }}
    
    .status-badge.has-issues .status-dot {{
      box-shadow: 0 0 8px currentColor;
      animation: pulse 2s infinite;
    }}
    
    @keyframes pulse {{
      0% {{ opacity: 1; }}
      50% {{ opacity: 0.5; }}
      100% {{ opacity: 1; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>VegOps Security Dashboard</h1>
      <p class="timestamp">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 4px;"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
        Generated on {now}
      </p>
    </header>
"""

page += '<div class="summary">'
for sev, count in total.items():
    cls = sev.lower()
    page += f'<div class="card"><h3>{sev}</h3><div class="count {cls}">{count}</div></div>'
page += f'<div class="card"><h3>Apps Scanned</h3><div class="count count-text">{len(apps)}</div></div>'
page += "</div>"

for name in sorted(apps.keys()):
    vuln_dict = apps[name]
    vulns = list(vuln_dict.values())
    has_issues = len(vulns) > 0
    status_class = "has-issues" if has_issues else ""
    status_text = f"{len(vulns)} Issues" if has_issues else "Clean"
    
    page += f'''
    <div class="image-section">
      <div class="image-header">
        <div class="image-title-wrapper">
          <h2>{html.escape(name)}</h2>
        </div>
        <div class="status-badge {status_class}">
          <div class="status-dot"></div>
          {status_text}
        </div>
      </div>
    '''
    
    if vulns:
        vulns.sort(key=lambda v: severity_order.get(v["severity"], 99))
        page += '''
        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>CVE ID</th>
                <th>Severity</th>
                <th>Package</th>
                <th>Arch</th>
                <th>Fixed Version</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
        '''
        for v in vulns:
            sev = v["severity"]
            badge_cls = f"badge-{sev.lower()}" if sev.lower() in ["critical","high","medium","low"] else "badge-unknown"
            fixed = ", ".join(v["fixed"]) if v["fixed"] else "Unpatched"
            archs = ", ".join(sorted(list(v["archs"])))
            desc = html.escape(v["description"])
            if len(desc) > 80:
                desc = desc[:77] + "..."
                
            page += f'''
              <tr>
                <td data-label="CVE ID" class="cve-id">{html.escape(v["id"])}</td>
                <td data-label="Severity"><span class="badge {badge_cls}">{sev}</span></td>
                <td data-label="Package" class="package-name">{html.escape(v["package"])}</td>
                <td data-label="Arch"><span class="arch-badge">{html.escape(archs)}</span></td>
                <td data-label="Fixed Version" class="fixed-in">{fixed}</td>
                <td data-label="Description" class="description" title="{html.escape(v.get('description', ''))}">{desc}</td>
              </tr>
            '''
        page += "</tbody></table></div>"
    page += "</div>"
    
page += "</div></body></html>"

with open("site/index.html", "w") as f:
    f.write(page)

print(f"Generated dashboard with {len(apps)} apps")