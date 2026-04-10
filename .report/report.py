import datetime
import glob
import html
import json
import os
import shutil

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

reports = sorted(glob.glob(os.path.join(PROJECT_ROOT, "reports/**/cve-report-*-*.json"), recursive=True))

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

    try:
        with open(rpath) as f:
            data = json.load(f)
        vegops = data.get("vegops", {})
        source_image = vegops.get("sourceImage", name)
        repository = vegops.get("repository", source_image)
        release_tag = vegops.get("releaseTag")
        stream_tag = vegops.get("streamTag")
        published_tags = vegops.get("publishedTags", [])
        app_key = f"{repository}:{release_tag}" if release_tag else repository

        if app_key not in apps:
            apps[app_key] = {
                "source_images": set(),
                "repository": repository,
                "release_tag": release_tag,
                "stream_tag": stream_tag,
                "published_tags": set(),
                "archs": set(),
                "vulns": {},
            }

        app = apps[app_key]
        app["source_images"].add(source_image)
        app["archs"].add(arch)
        for tag in published_tags:
            app["published_tags"].add(tag)

        matches = data.get("matches", [])
        for m in matches:
            artifact_name = m.get("artifact", {}).get("name", "unknown")
            artifact_version = m.get("artifact", {}).get("version", "unknown")
            pkg = f"{artifact_name}@{artifact_version}"

            for v in m.get("vulnerabilities", [m.get("vulnerability", {})]):
                vid = v.get("id", "N/A")
                key = (vid, pkg)

                if key not in app["vulns"]:
                    app["vulns"][key] = {
                        "id": vid,
                        "severity": v.get("severity", "Unknown"),
                        "description": v.get("description", "")[:200],
                        "package": pkg,
                        "fixed": v.get("fix", {}).get("versions", []),
                        "archs": set()
                    }
                app["vulns"][key]["archs"].add(arch)
    except Exception:
        pass

severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Negligible": 4, "Unknown": 5}
now = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M UTC")

# Summary stats
total = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
for app in apps.values():
    for v in app["vulns"].values():
        sev = v["severity"]
        if sev in total:
            total[sev] += 1
clean_count = sum(1 for app in apps.values() if not app["vulns"])

# Read CSS
with open(os.path.join(SCRIPT_DIR, "style.css")) as f:
    css = f.read()

THEME_BOOTSTRAP_FILE = "theme-bootstrap.js"
THEME_TOGGLE_FILE = "theme-toggle.js"

SUN_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"></circle><path d="M12 2.75v2.5M12 18.75v2.5M21.25 12h-2.5M5.25 12h-2.5M18.54 5.46l-1.77 1.77M7.23 16.77l-1.77 1.77M18.54 18.54l-1.77-1.77M7.23 7.23L5.46 5.46"></path></svg>'
MOON_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3c-.17.57-.26 1.18-.26 1.8A7 7 0 0 0 19.2 13c.62 0 1.23-.09 1.8-.21Z"></path></svg>'

page = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VegOps CVE Dashboard</title>
  <link rel="icon" type="image/png" href="favicon.png">
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script src="{THEME_BOOTSTRAP_FILE}"></script>
  <style>
{css}
  </style>
  <script src="{THEME_TOGGLE_FILE}" defer></script>
</head>
<body>
  <div class="container">
    <header>
      <div class="header-row">
        <div class="header-copy">
          <h1><img src="favicon.png" alt="" class="logo">VegOps Security Dashboard</h1>
          <p class="status-line">
            <span class="prompt">$</span> scanned {len(apps)} releases <span class="status-sep">|</span> {now}
          </p>
        </div>
        <button type="button" class="theme-toggle" id="theme-toggle">
          <span class="theme-toggle__icon theme-toggle__icon--sun" aria-hidden="true">{SUN_ICON}</span>
          <span class="theme-toggle__track" aria-hidden="true"><span class="theme-toggle__thumb"></span></span>
          <span class="theme-toggle__icon theme-toggle__icon--moon" aria-hidden="true">{MOON_ICON}</span>
          <span class="theme-toggle__label" data-theme-label>Auto</span>
        </button>
      </div>
    </header>
"""

page += '<div class="summary-bar">'
for sev, count in total.items():
    cls = sev.lower()
    page += f'<div class="stat-segment stat-segment--{cls}"><span class="stat-label">{sev}</span><span class="stat-count stat-count--{cls}">{count}</span></div>'
page += f'<div class="stat-segment stat-segment--clean"><span class="stat-label">Clean</span><span class="stat-count stat-count--clean">{clean_count}</span></div>'
page += "</div>"


def app_sort_key(item):
    app = item[1]
    stream_tag = app["stream_tag"] or ""
    if stream_tag.isdigit():
        stream_key = (0, -int(stream_tag))
    else:
        stream_key = (1, stream_tag)
    return (
        app["repository"],
        stream_key,
        app["release_tag"] or "",
    )


CHIP_SVG = '<svg viewBox="0 0 10 10"><rect x="1" y="1" width="8" height="8" rx="1" fill="none" stroke="currentColor" stroke-width="1.2"/><rect x="3.5" y="3.5" width="3" height="3" rx="0.5"/></svg>'


def make_arch_chip(label, short, active):
    cls = "arch-chip" if active else "arch-chip arch-chip--dim"
    return f'<span class="{cls}" title="{label}">{CHIP_SVG}{short}</span>'


def make_arch_html(archs):
    has_arm = "aarch64" in archs
    has_x86 = "x86_64" in archs
    return '<span class="arch-indicators">' + make_arch_chip("aarch64 (ARM 64-bit)", "arm64", has_arm) + make_arch_chip("x86_64 (AMD 64-bit)", "amd64", has_x86) + '</span>'


def make_tags_html(published_tags):
    if not published_tags:
        return ""
    parts = []
    sorted_tags = sorted(published_tags, key=lambda t: (t != "latest", t))
    for i, tag in enumerate(sorted_tags):
        if tag == "latest":
            parts.append('<span class="tag-latest">latest</span>')
        else:
            if i > 0:
                parts.append('<span class="tag-sep">\u00b7</span>')
            parts.append(f'<span class="tag-version">{html.escape(tag)}</span>')
    return '<span class="tag-list">' + "".join(parts) + '</span>'


TOGGLE_CHEVRON = '<span class="toggle-icon" aria-hidden="true"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg></span>'
TOGGLE_SPACER = '<span class="toggle-spacer" aria-hidden="true"></span>'
CLEAN_CHECK = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>'


card_index = 0
for _, app in sorted(apps.items(), key=app_sort_key):
    vulns = list(app["vulns"].values())
    has_issues = len(vulns) > 0
    clean_class = "" if has_issues else " image-section--clean"

    # Build display name with optional stream integration
    repo = app["repository"]
    source_set = app["source_images"]
    stream = app["stream_tag"]
    sources_differ = source_set and source_set != {repo}

    if stream and sources_differ:
        name_html = f'{html.escape(repo)}<span class="stream-sep">/</span><span class="stream-num">{html.escape(stream)}</span>'
        if app["release_tag"]:
            name_html += f'<span class="stream-sep">:</span>{html.escape(app["release_tag"])}'
    else:
        name_html = html.escape(repo)
        if app["release_tag"]:
            name_html += f':{html.escape(app["release_tag"])}'

    # Source line (only when informative)
    source_html = ""
    if sources_differ:
        source_names = ", ".join(sorted(source_set))
        source_html = f'<span class="image-source">built from {html.escape(source_names)}</span>'

    # Arch + tags metadata row
    meta_parts = []
    if app["archs"]:
        meta_parts.append(make_arch_html(app["archs"]))
    tags_html = make_tags_html(app["published_tags"])
    if tags_html:
        meta_parts.append(tags_html)
    meta_html = ""
    if meta_parts:
        meta_html = '<div class="image-meta-row">' + "".join(meta_parts) + "</div>"

    # Status badge
    if has_issues:
        status_text = f"{len(vulns)} Issues"
        status_badge = f'<div class="status-badge has-issues"><div class="status-dot"></div>{status_text}</div>'
    else:
        status_badge = f'<div class="status-badge">{CLEAN_CHECK} Clean</div>'

    toggle = TOGGLE_CHEVRON if has_issues else TOGGLE_SPACER

    header_html = f'''
      <div class="image-title-wrapper">
        {toggle}
        <div class="image-heading">
          <h2>{name_html}</h2>
          {source_html}
          {meta_html}
        </div>
      </div>
      {status_badge}
    '''

    delay_ms = card_index * 25
    page += f'<div class="image-section{clean_class}" style="animation-delay:{delay_ms}ms">'
    card_index += 1

    if vulns:
        vulns.sort(key=lambda v: severity_order.get(v["severity"], 99))
        page += f'''
        <details class="image-collapsible">
          <summary class="image-header image-summary">
            {header_html}
          </summary>
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
            sev_lower = sev.lower()
            sev_cls = sev_lower if sev_lower in ["critical", "high", "medium", "low"] else "unknown"

            fixed_parts = v["fixed"]
            if fixed_parts:
                fixed_html = f'<span class="fixed-in">{", ".join(fixed_parts)}</span>'
            else:
                fixed_html = '<span class="fixed-in fixed-in--unpatched">Unpatched</span>'

            # Arch chips in table
            v_archs = sorted(list(v["archs"]))
            arch_chips = " ".join(
                make_arch_chip(a, "arm64" if a == "aarch64" else "amd64", True)
                for a in v_archs
            )

            desc = html.escape(v["description"])
            if len(desc) > 80:
                desc = desc[:77] + "..."

            page += f'''
              <tr class="sev-{sev_cls}">
                <td data-label="CVE ID" class="cve-id">{html.escape(v["id"])}</td>
                <td data-label="Severity"><span class="sev-dot sev-dot--{sev_cls}"></span><span class="sev-text sev-text--{sev_cls}">{sev}</span></td>
                <td data-label="Package" class="package-name">{html.escape(v["package"])}</td>
                <td data-label="Arch">{arch_chips}</td>
                <td data-label="Fixed Version">{fixed_html}</td>
                <td data-label="Description" class="description" title="{html.escape(v.get('description', ''))}">{desc}</td>
              </tr>
            '''
        page += "</tbody></table></div></details>"
    else:
        page += f'''
      <div class="image-header image-header-static">
        {header_html}
      </div>
    '''
    page += "</div>"

page += "</div></body></html>"

site_dir = os.path.join(PROJECT_ROOT, "site")
os.makedirs(site_dir, exist_ok=True)

with open(os.path.join(site_dir, "index.html"), "w") as f:
    f.write(page)

for asset in (THEME_BOOTSTRAP_FILE, THEME_TOGGLE_FILE):
    shutil.copy(os.path.join(SCRIPT_DIR, asset), os.path.join(site_dir, asset))

# Copy favicon
logo = os.path.join(PROJECT_ROOT, "logo.png")
if os.path.exists(logo):
    shutil.copy(logo, os.path.join(site_dir, "favicon.png"))

print(f"Generated dashboard with {len(apps)} releases")
