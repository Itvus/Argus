"""Standalone, self-contained HTML investigation report generator for Argus.

Adheres strictly to Anti-Slop design principles:
- Zero external CDN dependencies (fonts, styles, scripts) for OPSEC and offline viewing.
- No-referrer policy to prevent network leaks.
- Minimalist Technical Dense / DevTools aesthetic (monochrome surfaces, hairline borders).
- Inline vector SVG icons (no raw emojis).
- Print stylesheet for clean PDF export via browser print dialog.
"""

from __future__ import annotations

import html
import json
import tempfile
import webbrowser
from pathlib import Path
from typing import Optional

from argus.models import InvestigationReport

# Clean inline SVG icons (Lucide / Phosphor style, 1.5px stroke)
ICON_SHIELD = """<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>"""
ICON_USER = """<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>"""
ICON_CLOCK = """<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>"""
ICON_LINK = """<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>"""
ICON_COPY = """<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>"""
ICON_CHECK = """<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>"""
ICON_PRINT = """<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>"""
ICON_TERMINAL = """<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>"""
ICON_SEARCH = """<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>"""
ICON_ALERT = """<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>"""


def render_html_report(report: InvestigationReport) -> str:
    """Generate self-contained, standalone HTML investigation dossier."""
    target_clean = html.escape(report.target)
    target_type_clean = html.escape(report.target_type.upper())
    timestamp_clean = html.escape(report.scan_timestamp_utc)
    duration_str = f"{report.scan_duration_seconds:.2f}s"

    # Count statistics for summary KPI row
    profile_count = len(report.social_profiles)
    email_count = len(report.pivot_leads.discovered_emails)
    discord_id_count = len(report.pivot_leads.discovered_discord_ids)
    invite_count = len(report.pivot_leads.discovered_invites)
    tag_count = len(report.pivot_leads.discovered_discord_tags)
    total_leads = email_count + discord_id_count + invite_count + tag_count
    breach_count = len(report.breaches)

    # 1. Discord Snowflake card HTML
    snowflake_html = ""
    if report.snowflake:
        sf = report.snowflake
        snowflake_html = f"""
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">{ICON_TERMINAL} Discord Snowflake Telemetry</span>
            <span class="badge badge-cyan">64-Bit Offline Math</span>
          </div>
          <div class="telemetry-grid">
            <div class="telemetry-item">
              <span class="telemetry-label">Snowflake ID</span>
              <span class="telemetry-value font-mono copyable" onclick="copyText('{sf.snowflake_id}')">
                {sf.snowflake_id} <button class="btn-copy" title="Copy">{ICON_COPY}</button>
              </span>
            </div>
            <div class="telemetry-item">
              <span class="telemetry-label">Creation Timestamp (UTC)</span>
              <span class="telemetry-value font-mono">{html.escape(sf.created_at_utc)}</span>
            </div>
            <div class="telemetry-item">
              <span class="telemetry-label">Calculated Account Age</span>
              <span class="telemetry-value font-semibold text-emerald">{html.escape(sf.age_human)}</span>
            </div>
            <div class="telemetry-item">
              <span class="telemetry-label">Worker ID / Process ID</span>
              <span class="telemetry-value font-mono">{sf.worker_id} / {sf.process_id}</span>
            </div>
            <div class="telemetry-item">
              <span class="telemetry-label">Internal Increment</span>
              <span class="telemetry-value font-mono">{sf.increment}</span>
            </div>
          </div>
        </div>
        """

    # 2. Discord Profile card HTML
    profile_html = ""
    if report.discord_profile:
        dp = report.discord_profile
        avatar_img = (
            f'<img src="{html.escape(dp.avatar_url)}" alt="Avatar" class="avatar-img" referrerpolicy="no-referrer">'
            if dp.avatar_url
            else '<div class="avatar-placeholder">' + ICON_USER + "</div>"
        )

        badges_html = "".join(
            f'<span class="badge badge-accent">{html.escape(b)}</span>' for b in dp.badges
        )
        if not badges_html:
            badges_html = '<span class="text-muted text-sm">None registered</span>'

        rev_search_html = ""
        if dp.reverse_image_urls:
            rev = dp.reverse_image_urls
            rev_search_html = f"""
            <div class="reverse-search-bar">
              <span class="reverse-search-label">{ICON_SEARCH} Reverse Search Avatar:</span>
              <a href="{html.escape(rev.google_lens)}" target="_blank" rel="noopener noreferrer" class="btn-rev">Google Lens</a>
              <a href="{html.escape(rev.yandex)}" target="_blank" rel="noopener noreferrer" class="btn-rev">Yandex</a>
              <a href="{html.escape(rev.tineye)}" target="_blank" rel="noopener noreferrer" class="btn-rev">TinEye</a>
              <a href="{html.escape(rev.bing_visual)}" target="_blank" rel="noopener noreferrer" class="btn-rev">Bing Visual</a>
            </div>
            """

        banner_info = ""
        if dp.banner_color:
            banner_info = f"""
            <div class="telemetry-item">
              <span class="telemetry-label">Banner Accent Color</span>
              <span class="telemetry-value font-mono"><span class="color-swatch" style="background:{html.escape(dp.banner_color)}"></span> {html.escape(dp.banner_color)}</span>
            </div>
            """

        profile_html = f"""
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">{ICON_USER} Discord REST API Identity</span>
            <span class="badge badge-emerald">API v10 Ingest</span>
          </div>
          <div class="profile-card">
            <div class="avatar-wrap">
              {avatar_img}
            </div>
            <div class="profile-details">
              <div class="profile-title-row">
                <span class="profile-name">{html.escape(dp.global_name or dp.username)}</span>
                <span class="profile-handle font-mono">@{html.escape(dp.username)}</span>
              </div>
              <div class="badges-row">
                {badges_html}
              </div>
              <div class="telemetry-grid mt-3">
                <div class="telemetry-item">
                  <span class="telemetry-label">User ID</span>
                  <span class="telemetry-value font-mono copyable" onclick="copyText('{dp.id}')">
                    {dp.id} <button class="btn-copy" title="Copy">{ICON_COPY}</button>
                  </span>
                </div>
                {banner_info}
              </div>
              {rev_search_html}
            </div>
          </div>
        </div>
        """

    # 3. Matched Profiles HTML
    social_profiles_html = ""
    if report.social_profiles:
        rows = []
        for p in report.social_profiles:
            is_discord = p.platform.lower() == "discord" or p.url.startswith("@")
            if is_discord:
                url_display = f'<span class="font-mono text-cyan">{html.escape(p.url)}</span> <span class="badge badge-subtle">Handle Registered</span>'
            else:
                url_display = f'<a href="{html.escape(p.url)}" target="_blank" rel="noopener noreferrer" class="link-external">{html.escape(p.url)} {ICON_LINK}</a>'

            rows.append(
                f"""
                <tr>
                  <td class="font-semibold">{html.escape(p.platform)}</td>
                  <td><span class="status-indicator-dot"></span> <span class="text-emerald">{html.escape(p.status)}</span></td>
                  <td>{url_display}</td>
                </tr>
                """
            )

        social_profiles_html = f"""
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">{ICON_LINK} Matched Social Profiles ({len(report.social_profiles)})</span>
            <span class="badge badge-subtle">Maigret Engine</span>
          </div>
          <div class="table-container">
            <table class="data-table">
              <thead>
                <tr>
                  <th style="width: 22%;">Platform</th>
                  <th style="width: 18%;">Status</th>
                  <th>Profile URL / Handle</th>
                </tr>
              </thead>
              <tbody>
                {''.join(rows)}
              </tbody>
            </table>
          </div>
        </div>
        """

    # 4. Discovered Leads HTML
    leads = report.pivot_leads
    leads_html = ""
    if total_leads > 0:
        lead_cards = []

        if leads.discovered_emails:
            email_items = "".join(
                f"""<div class="lead-pill font-mono copyable" onclick="copyText('{html.escape(em)}')">
                      <span>{html.escape(em)}</span>
                      <button class="btn-copy" title="Copy">{ICON_COPY}</button>
                    </div>"""
                for em in leads.discovered_emails
            )
            lead_cards.append(
                f"""
                <div class="lead-group">
                  <span class="lead-group-title">Personal Emails ({len(leads.discovered_emails)})</span>
                  <div class="lead-pills-wrap">{email_items}</div>
                </div>
                """
            )

        if leads.discovered_discord_ids:
            id_items = "".join(
                f"""<div class="lead-pill font-mono copyable" onclick="copyText('{html.escape(uid)}')">
                      <span>{html.escape(uid)}</span>
                      <button class="btn-copy" title="Copy">{ICON_COPY}</button>
                    </div>"""
                for uid in leads.discovered_discord_ids
            )
            lead_cards.append(
                f"""
                <div class="lead-group">
                  <span class="lead-group-title">Discovered Discord IDs ({len(leads.discovered_discord_ids)})</span>
                  <div class="lead-pills-wrap">{id_items}</div>
                </div>
                """
            )

        if leads.discovered_discord_tags:
            tag_items = "".join(
                f"""<div class="lead-pill font-mono copyable" onclick="copyText('{html.escape(t)}')">
                      <span>{html.escape(t)}</span>
                      <button class="btn-copy" title="Copy">{ICON_COPY}</button>
                    </div>"""
                for t in leads.discovered_discord_tags
            )
            lead_cards.append(
                f"""
                <div class="lead-group">
                  <span class="lead-group-title">Legacy Discord Tags ({len(leads.discovered_discord_tags)})</span>
                  <div class="lead-pills-wrap">{tag_items}</div>
                </div>
                """
            )

        if leads.discovered_invites:
            inv_items = "".join(
                f"""<div class="lead-pill font-mono">
                      <a href="{html.escape(inv)}" target="_blank" rel="noopener noreferrer" class="link-external">{html.escape(inv)} {ICON_LINK}</a>
                      <button class="btn-copy" onclick="copyText('{html.escape(inv)}')" title="Copy">{ICON_COPY}</button>
                    </div>"""
                for inv in leads.discovered_invites
            )
            lead_cards.append(
                f"""
                <div class="lead-group">
                  <span class="lead-group-title">Discord Server Invites ({len(leads.discovered_invites)})</span>
                  <div class="lead-pills-wrap">{inv_items}</div>
                </div>
                """
            )

        leads_html = f"""
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">{ICON_SHIELD} Discovered Pivot Leads ({total_leads})</span>
            <span class="badge badge-accent">DOM-Extracted</span>
          </div>
          <div class="leads-container">
            {''.join(lead_cards)}
          </div>
        </div>
        """

    # 5. Enrichment HTML (CordCat, Breaches, GitHub)
    enrichment_sections = []

    # CordCat
    if report.cordcat:
        cc = report.cordcat
        aliases_html = (
            ", ".join(f'<span class="font-mono text-cyan">@{html.escape(a)}</span>' for a in cc.historical_usernames)
            if cc.historical_usernames
            else '<span class="text-muted">None recorded</span>'
        )
        fivem_html = (
            ", ".join(f'<span class="font-mono">{html.escape(fid)}</span>' for fid in cc.fivem_identifiers)
            if cc.fivem_identifiers
            else '<span class="text-muted">None found</span>'
        )
        enrichment_sections.append(
            f"""
            <div class="lead-group">
              <span class="lead-group-title">CordCat Historical Records</span>
              <div class="telemetry-grid">
                <div class="telemetry-item">
                  <span class="telemetry-label">Historical Aliases</span>
                  <span class="telemetry-value">{aliases_html}</span>
                </div>
                <div class="telemetry-item">
                  <span class="telemetry-label">FiveM / CFX Identifiers</span>
                  <span class="telemetry-value">{fivem_html}</span>
                </div>
              </div>
            </div>
            """
        )

    # Breaches
    if report.breaches:
        breach_rows = []
        for b in report.breaches:
            classes = ", ".join(html.escape(c) for c in b.data_classes) if b.data_classes else "Unknown"
            breach_rows.append(
                f"""
                <tr>
                  <td class="font-semibold text-rose">{html.escape(b.service_name)}</td>
                  <td class="font-mono text-sm">{html.escape(b.breach_date or 'N/A')}</td>
                  <td class="font-mono text-sm">{html.escape(b.query)}</td>
                  <td class="text-sm text-secondary">{classes}</td>
                </tr>
                """
            )
        enrichment_sections.append(
            f"""
            <div class="lead-group mt-3">
              <span class="lead-group-title text-rose">{ICON_ALERT} Breach Incidents ({len(report.breaches)})</span>
              <div class="table-container">
                <table class="data-table">
                  <thead>
                    <tr>
                      <th>Compromised Service</th>
                      <th>Date</th>
                      <th>Account Query</th>
                      <th>Exposed Data Classes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {''.join(breach_rows)}
                  </tbody>
                </table>
              </div>
            </div>
            """
        )

    # GitHub
    if report.github_pivot:
        gh = report.github_pivot
        commit_emails = (
            ", ".join(f'<span class="font-mono text-emerald">{html.escape(e)}</span>' for e in gh.commit_emails)
            if gh.commit_emails
            else '<span class="text-muted">None extracted</span>'
        )
        comparison_str = (
            f'<div class="telemetry-item"><span class="telemetry-label">Timeline Delta vs Discord</span><span class="telemetry-value font-semibold text-cyan">{html.escape(gh.age_comparison_discord)}</span></div>'
            if gh.age_comparison_discord
            else ""
        )
        enrichment_sections.append(
            f"""
            <div class="lead-group mt-3">
              <span class="lead-group-title">GitHub Public Activity Audit</span>
              <div class="telemetry-grid">
                <div class="telemetry-item">
                  <span class="telemetry-label">GitHub Account</span>
                  <span class="telemetry-value"><a href="{html.escape(gh.profile_url)}" target="_blank" rel="noopener noreferrer" class="link-external">@{html.escape(gh.username)} {ICON_LINK}</a></span>
                </div>
                <div class="telemetry-item">
                  <span class="telemetry-label">Public Commit Author Emails</span>
                  <span class="telemetry-value">{commit_emails}</span>
                </div>
                <div class="telemetry-item">
                  <span class="telemetry-label">Creation Date</span>
                  <span class="telemetry-value font-mono">{html.escape(gh.created_at or 'N/A')}</span>
                </div>
                {comparison_str}
              </div>
            </div>
            """
        )

    enrichment_html = ""
    if enrichment_sections:
        enrichment_html = f"""
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">{ICON_SHIELD} Threat & Transparency Indexers</span>
            <span class="badge badge-accent">Enrichment Plugins</span>
          </div>
          <div class="leads-container">
            {''.join(enrichment_sections)}
          </div>
        </div>
        """

    # 6. Raw JSON representation
    raw_json_str = html.escape(json.dumps(report.model_dump(), indent=2))

    # Self-contained CSS (Archetype B: Technical Dense Terminal with Quiet Luxury minimalism)
    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="referrer" content="no-referrer">
  <title>Argus Investigation — {target_clean}</title>
  <style>
    /* -------------------------------------------------------------
       CSS Custom Properties (Archetype B: Technical Dense Terminal)
       ------------------------------------------------------------- */
    :root {{
      --bg-canvas: #090a0f;
      --bg-surface: #10141d;
      --bg-surface-elevated: #161c28;
      --border-subtle: #1e2638;
      --border-hover: #2e3b56;
      --accent-cyan: #38bdf8;
      --accent-emerald: #10b981;
      --accent-amber: #f59e0b;
      --accent-rose: #f43f5e;
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", sans-serif;
      --font-mono: ui-monospace, "JetBrains Mono", "Cascadia Code", Consolas, monospace;
      --radius-sm: 4px;
      --radius-md: 8px;
      --radius-lg: 12px;
    }}

    *, *::before, *::after {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }}

    body {{
      background-color: var(--bg-canvas);
      color: var(--text-primary);
      font-family: var(--font-sans);
      font-size: 14px;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
      padding: 32px 20px 80px 20px;
    }}

    .container {{
      max-width: 1100px;
      margin: 0 auto;
    }}

    /* Top Action / Nav Bar */
    .top-bar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border-subtle);
    }}

    .brand {{
      display: flex;
      align-items: center;
      gap: 10px;
      font-weight: 800;
      letter-spacing: 2px;
      font-size: 16px;
      color: var(--text-primary);
    }}

    .brand-mark {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 28px;
      height: 28px;
      border-radius: var(--radius-sm);
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border-subtle);
      color: var(--accent-cyan);
    }}

    .top-actions {{
      display: flex;
      gap: 8px;
    }}

    /* Buttons */
    .btn {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 12px;
      font-size: 13px;
      font-weight: 500;
      border-radius: var(--radius-sm);
      border: 1px solid var(--border-subtle);
      background: var(--bg-surface);
      color: var(--text-secondary);
      cursor: pointer;
      user-select: none;
      transition: background-color 140ms ease-out, border-color 140ms ease-out, color 140ms ease-out, transform 60ms ease-out;
    }}

    .btn:hover {{
      background: var(--bg-surface-elevated);
      border-color: var(--border-hover);
      color: var(--text-primary);
    }}

    .btn:active {{
      transform: scale(0.97);
    }}

    .btn-copy {{
      background: transparent;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      padding: 2px 4px;
      display: inline-flex;
      align-items: center;
      border-radius: 2px;
      transition: color 120ms ease-out;
    }}

    .btn-copy:hover {{
      color: var(--accent-cyan);
    }}

    .btn-rev {{
      display: inline-flex;
      align-items: center;
      padding: 4px 8px;
      font-size: 12px;
      font-weight: 500;
      border-radius: var(--radius-sm);
      border: 1px solid var(--border-subtle);
      background: var(--bg-surface-elevated);
      color: var(--text-secondary);
      text-decoration: none;
      transition: color 120ms ease, border-color 120ms ease;
    }}

    .btn-rev:hover {{
      color: var(--accent-cyan);
      border-color: var(--accent-cyan);
    }}

    /* Overview Header Card */
    .overview-hero {{
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 20px 24px;
      margin-bottom: 20px;
    }}

    .target-title-row {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 16px;
    }}

    .target-title {{
      font-size: 24px;
      font-weight: 700;
      letter-spacing: -0.02em;
    }}

    .target-badges {{
      display: flex;
      gap: 6px;
      align-items: center;
    }}

    /* Badges & Pills */
    .badge {{
      display: inline-flex;
      align-items: center;
      padding: 2px 8px;
      border-radius: var(--radius-sm);
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.5px;
      text-transform: uppercase;
      border: 1px solid transparent;
    }}

    .badge-cyan {{
      background: rgba(56, 189, 248, 0.1);
      color: var(--accent-cyan);
      border-color: rgba(56, 189, 248, 0.25);
    }}

    .badge-emerald {{
      background: rgba(16, 185, 129, 0.1);
      color: var(--accent-emerald);
      border-color: rgba(16, 185, 129, 0.25);
    }}

    .badge-accent {{
      background: rgba(129, 140, 248, 0.1);
      color: #818cf8;
      border-color: rgba(129, 140, 248, 0.25);
    }}

    .badge-subtle {{
      background: var(--bg-surface-elevated);
      color: var(--text-secondary);
      border-color: var(--border-subtle);
    }}

    /* KPI Summary Strip */
    .kpi-strip {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      padding-top: 16px;
      border-top: 1px solid var(--border-subtle);
    }}

    .kpi-item {{
      display: flex;
      flex-direction: column;
    }}

    .kpi-label {{
      font-size: 11px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 4px;
    }}

    .kpi-value {{
      font-size: 18px;
      font-weight: 700;
      font-variant-numeric: tabular-nums;
    }}

    /* Standard Panels */
    .panel {{
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      margin-bottom: 20px;
      overflow: hidden;
    }}

    .panel-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px 18px;
      background: var(--bg-surface-elevated);
      border-bottom: 1px solid var(--border-subtle);
    }}

    .panel-title {{
      font-size: 13px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
      color: var(--text-primary);
    }}

    /* Profile Card Layout */
    .profile-card {{
      display: flex;
      gap: 20px;
      padding: 20px;
    }}

    .avatar-wrap {{
      width: 96px;
      height: 96px;
      border-radius: var(--radius-md);
      overflow: hidden;
      flex-shrink: 0;
      border: 1px solid var(--border-subtle);
      background: var(--bg-surface-elevated);
      display: flex;
      align-items: center;
      justify-content: center;
    }}

    .avatar-img {{
      width: 100%;
      height: 100%;
      object-fit: cover;
    }}

    .avatar-placeholder {{
      color: var(--text-muted);
    }}

    .profile-details {{
      flex: 1;
      min-width: 0;
    }}

    .profile-title-row {{
      display: flex;
      align-items: baseline;
      gap: 10px;
      margin-bottom: 8px;
      flex-wrap: wrap;
    }}

    .profile-name {{
      font-size: 18px;
      font-weight: 700;
    }}

    .profile-handle {{
      font-size: 14px;
      color: var(--accent-cyan);
    }}

    .badges-row {{
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      margin-bottom: 12px;
    }}

    .reverse-search-bar {{
      display: flex;
      align-items: center;
      gap: 6px;
      flex-wrap: wrap;
      margin-top: 14px;
      padding-top: 12px;
      border-top: 1px solid var(--border-subtle);
    }}

    .reverse-search-label {{
      font-size: 12px;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      gap: 4px;
      margin-right: 4px;
    }}

    /* Telemetry Grid */
    .telemetry-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
      padding: 16px 20px;
    }}

    .telemetry-item {{
      display: flex;
      flex-direction: column;
    }}

    .telemetry-label {{
      font-size: 11px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 2px;
    }}

    .telemetry-value {{
      font-size: 13px;
      color: var(--text-primary);
      display: flex;
      align-items: center;
      gap: 6px;
      word-break: break-all;
    }}

    .color-swatch {{
      display: inline-block;
      width: 12px;
      height: 12px;
      border-radius: 2px;
      border: 1px solid rgba(255, 255, 255, 0.2);
    }}

    /* Data Tables */
    .table-container {{
      overflow-x: auto;
    }}

    .data-table {{
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 13px;
    }}

    .data-table th {{
      padding: 10px 18px;
      background: var(--bg-surface-elevated);
      color: var(--text-muted);
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      border-bottom: 1px solid var(--border-subtle);
    }}

    .data-table td {{
      padding: 12px 18px;
      border-bottom: 1px solid var(--border-subtle);
      vertical-align: middle;
    }}

    .data-table tr:last-child td {{
      border-bottom: none;
    }}

    .data-table tr:hover td {{
      background: rgba(255, 255, 255, 0.015);
    }}

    .status-indicator-dot {{
      display: inline-block;
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--accent-emerald);
      margin-right: 4px;
    }}

    .link-external {{
      color: var(--accent-cyan);
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 4px;
      word-break: break-all;
    }}

    .link-external:hover {{
      text-decoration: underline;
    }}

    /* Leads & Pills */
    .leads-container {{
      padding: 16px 20px;
    }}

    .lead-group {{
      margin-bottom: 16px;
    }}

    .lead-group:last-child {{
      margin-bottom: 0;
    }}

    .lead-group-title {{
      display: block;
      font-size: 12px;
      font-weight: 600;
      color: var(--text-secondary);
      margin-bottom: 8px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}

    .lead-pills-wrap {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }}

    .lead-pill {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 4px 10px;
      border-radius: var(--radius-sm);
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border-subtle);
      font-size: 12px;
      color: var(--text-primary);
    }}

    /* Copyable hover interaction */
    .copyable {{
      cursor: pointer;
    }}

    .copyable:hover .btn-copy {{
      color: var(--accent-cyan);
    }}

    /* Collapsible Details Drawer */
    details.raw-json-drawer {{
      margin-top: 24px;
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      overflow: hidden;
    }}

    details.raw-json-drawer summary {{
      padding: 12px 18px;
      cursor: pointer;
      font-weight: 600;
      font-size: 13px;
      color: var(--text-secondary);
      user-select: none;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}

    details.raw-json-drawer summary:hover {{
      color: var(--text-primary);
    }}

    .json-code-box {{
      padding: 16px;
      background: #06070a;
      border-top: 1px solid var(--border-subtle);
      font-family: var(--font-mono);
      font-size: 12px;
      line-height: 1.6;
      color: #cbd5e1;
      overflow-x: auto;
      max-height: 500px;
    }}

    /* Utility typography */
    .font-mono {{ font-family: var(--font-mono); font-variant-numeric: tabular-nums; }}
    .font-semibold {{ font-weight: 600; }}
    .text-emerald {{ color: var(--accent-emerald); }}
    .text-cyan {{ color: var(--accent-cyan); }}
    .text-rose {{ color: var(--accent-rose); }}
    .text-secondary {{ color: var(--text-secondary); }}
    .text-muted {{ color: var(--text-muted); }}
    .text-sm {{ font-size: 12px; }}
    .mt-3 {{ margin-top: 12px; }}

    /* Print Stylesheet for clean PDF exporting */
    @media print {{
      body {{
        background: #ffffff !important;
        color: #000000 !important;
        padding: 0 !important;
      }}
      .top-actions, .btn-copy, .btn-rev, details.raw-json-drawer {{
        display: none !important;
      }}
      .panel, .overview-hero {{
        background: #ffffff !important;
        border: 1px solid #cccccc !important;
        page-break-inside: avoid;
      }}
      .panel-header, .data-table th {{
        background: #f1f5f9 !important;
        color: #000000 !important;
      }}
      .lead-pill, .badge {{
        border: 1px solid #999999 !important;
        color: #000000 !important;
        background: #f8fafc !important;
      }}
      a {{
        color: #000000 !important;
        text-decoration: none !important;
      }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <!-- Top Action Navigation -->
    <header class="top-bar">
      <div class="brand">
        <span class="brand-mark">{ICON_SHIELD}</span>
        <span>ARGUS RECONNAISSANCE DOSSIER</span>
      </div>
      <div class="top-actions">
        <button class="btn" onclick="copyFullJson()">{ICON_COPY} Copy JSON</button>
        <button class="btn" onclick="window.print()">{ICON_PRINT} Print / PDF</button>
      </div>
    </header>

    <!-- Overview Hero -->
    <div class="overview-hero">
      <div class="target-title-row">
        <div>
          <span class="telemetry-label">Primary Investigation Target</span>
          <div class="target-title font-mono">{target_clean}</div>
        </div>
        <div class="target-badges">
          <span class="badge badge-cyan">{target_type_clean}</span>
          <span class="badge badge-emerald">Scan Complete</span>
        </div>
      </div>
      <div class="kpi-strip">
        <div class="kpi-item">
          <span class="kpi-label">Matched Profiles</span>
          <span class="kpi-value text-emerald">{profile_count}</span>
        </div>
        <div class="kpi-item">
          <span class="kpi-label">Discovered Leads</span>
          <span class="kpi-value text-cyan">{total_leads}</span>
        </div>
        <div class="kpi-item">
          <span class="kpi-label">Breach Incidents</span>
          <span class="kpi-value text-rose">{breach_count}</span>
        </div>
        <div class="kpi-item">
          <span class="kpi-label">Execution Time</span>
          <span class="kpi-value font-mono">{duration_str}</span>
        </div>
        <div class="kpi-item">
          <span class="kpi-label">UTC Timestamp</span>
          <span class="kpi-value font-mono text-sm">{timestamp_clean}</span>
        </div>
      </div>
    </div>

    <!-- Main Content Flow -->
    {snowflake_html}
    {profile_html}
    {leads_html}
    {social_profiles_html}
    {enrichment_html}

    <!-- Raw JSON Collapsible Drawer -->
    <details class="raw-json-drawer">
      <summary>
        <span>{ICON_TERMINAL} Raw Structured JSON Report</span>
        <span class="badge badge-subtle">Full Telemetry</span>
      </summary>
      <pre class="json-code-box" id="jsonReportBox"><code>{raw_json_str}</code></pre>
    </details>
  </div>

  <script>
    function copyText(text) {{
      navigator.clipboard.writeText(text).then(() => {{
        showToast("Copied to clipboard");
      }}).catch(() => {{
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        showToast("Copied to clipboard");
      }});
    }}

    function copyFullJson() {{
      const el = document.getElementById("jsonReportBox");
      if (el) {{
        copyText(el.innerText);
      }}
    }}

    function showToast(msg) {{
      let toast = document.getElementById("argus-toast");
      if (!toast) {{
        toast = document.createElement("div");
        toast.id = "argus-toast";
        toast.style.position = "fixed";
        toast.style.bottom = "20px";
        toast.style.right = "20px";
        toast.style.background = "#1e2638";
        toast.style.color = "#f8fafc";
        toast.style.padding = "8px 16px";
        toast.style.borderRadius = "4px";
        toast.style.border = "1px solid #38bdf8";
        toast.style.fontSize = "13px";
        toast.style.fontFamily = "var(--font-sans)";
        toast.style.zIndex = "9999";
        toast.style.transition = "opacity 200ms ease";
        document.body.appendChild(toast);
      }}
      toast.innerText = msg;
      toast.style.opacity = "1";
      setTimeout(() => {{
        toast.style.opacity = "0";
      }}, 1500);
    }}
  </script>
</body>
</html>
"""
    return full_html


def save_html_report(report: InvestigationReport, output_path: Path) -> Path:
    """Save generated HTML investigation report to specified file path."""
    html_content = render_html_report(report)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_content, encoding="utf-8")
    return output_path


def view_html_report(report: InvestigationReport, custom_path: Optional[Path] = None) -> Path:
    """Save report to custom path or temporary file, and open in default browser."""
    html_content = render_html_report(report)

    if custom_path:
        target_path = custom_path
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(html_content, encoding="utf-8")
    else:
        with tempfile.NamedTemporaryFile(
            prefix="argus_report_",
            suffix=".html",
            delete=False,
            mode="w",
            encoding="utf-8",
        ) as tmp:
            tmp.write(html_content)
            target_path = Path(tmp.name)

    # Launch in default system browser
    webbrowser.open_new_tab(target_path.as_uri())
    return target_path
