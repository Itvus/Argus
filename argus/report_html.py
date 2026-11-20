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
from collections import defaultdict
from pathlib import Path
from typing import Optional

from argus.models import InvestigationReport

# Clean inline SVG icons (Lucide / Phosphor style, 1.5px stroke)
ICON_SHIELD = """<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>"""
ICON_USER = """<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>"""
ICON_CLOCK = """<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>"""
ICON_LINK = """<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>"""
ICON_COPY = """<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>"""
ICON_PRINT = """<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>"""
ICON_TERMINAL = """<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>"""
ICON_SEARCH = """<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>"""
ICON_ALERT = """<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>"""

PLATFORM_CATEGORIES: dict[str, str] = {
    # Gaming
    "steam": "gaming",
    "minecraft": "gaming",
    "chess.com": "gaming",
    "chess": "gaming",
    "roblox": "gaming",
    "xbox": "gaming",
    "playstation": "gaming",
    "epic games": "gaming",
    "epic": "gaming",
    "battle.net": "gaming",
    "battlenet": "gaming",
    "blizzard": "gaming",
    "osu!": "gaming",
    "osu": "gaming",
    "speedrun.com": "gaming",
    "speedrun": "gaming",
    "itch.io": "gaming",
    "itch": "gaming",
    "twitch": "gaming",
    "gog": "gaming",
    "riot games": "gaming",
    "riot": "gaming",
    "nexus mods": "gaming",
    "nexusmods": "gaming",
    "vrchat": "gaming",
    "newgrounds": "gaming",
    "kongregate": "gaming",
    "gamejolt": "gaming",
    "origin": "gaming",
    "ubisoft": "gaming",
    "namemc": "gaming",
    "tarkov": "gaming",
    "faceit": "gaming",
    "esl": "gaming",
    "raptr": "gaming",
    "pokemongo": "gaming",
    "pokemon": "gaming",
    # Developer / Tech
    "github": "developer",
    "gitlab": "developer",
    "docker hub": "developer",
    "docker": "developer",
    "pypi": "developer",
    "npm": "developer",
    "crates.io": "developer",
    "crates": "developer",
    "bitbucket": "developer",
    "replit": "developer",
    "hackernews": "developer",
    "hacker news": "developer",
    "stackoverflow": "developer",
    "stack overflow": "developer",
    "stack exchange": "developer",
    "kaggle": "developer",
    "dev.to": "developer",
    "codeberg": "developer",
    "keybase": "developer",
    "gist": "developer",
    "codeforces": "developer",
    "leetcode": "developer",
    "codewars": "developer",
    "sourceforge": "developer",
    "launchpad": "developer",
    "hugging face": "developer",
    "huggingface": "developer",
    "codepen": "developer",
    "jsfiddle": "developer",
    "pastebin": "developer",
    "pnpm": "developer",
    "rubygems": "developer",
    "packagist": "developer",
    "sourcehut": "developer",
    # Messaging / Chat
    "discord": "messaging",
    "telegram": "messaging",
    "matrix": "messaging",
    "signal": "messaging",
    "session": "messaging",
    "tox": "messaging",
    "simplex": "messaging",
    "xmpp": "messaging",
    "jabber": "messaging",
    "skype": "messaging",
    "whatsapp": "messaging",
    "wire": "messaging",
    "element": "messaging",
    "icq": "messaging",
    "viber": "messaging",
    "line": "messaging",
    "wechat": "messaging",
    "snapchat": "messaging",
    # Media / Audio
    "spotify": "media",
    "soundcloud": "media",
    "bandcamp": "media",
    "last.fm": "media",
    "audiomack": "media",
    "mixcloud": "media",
    "deezer": "media",
    "tidal": "media",
    "apple music": "media",
    # Social / Networks
    "twitter": "social",
    "x": "social",
    "x (twitter)": "social",
    "twitter/x": "social",
    "instagram": "social",
    "facebook": "social",
    "reddit": "social",
    "tiktok": "social",
    "pinterest": "social",
    "tumblr": "social",
    "mastodon": "social",
    "threads": "social",
    "bluesky": "social",
    "bsky": "social",
    "medium": "social",
    "substack": "social",
    "youtube": "social",
    "vimeo": "social",
    "linkedin": "social",
    "vk": "social",
    "vkontakte": "social",
    "weibo": "social",
    "linktree": "social",
    "patreon": "social",
    "buymeacoffee": "social",
    "disqus": "social",
    "quora": "social",
    "askfm": "social",
    "flickr": "social",
    "imgur": "social",
    "deviantart": "social",
    "artstation": "social",
    "behance": "social",
    "dribbble": "social",
    "clubhouse": "social",
    "letterboxd": "social",
    "goodreads": "social",
    "myanimelist": "social",
    "about.me": "social",
}

CATEGORY_META: dict[str, dict[str, str]] = {
    "all": {"label": "All", "color": "var(--accent-cyan)"},
    "social": {"label": "Social", "color": "#60a5fa"},
    "gaming": {"label": "Gaming", "color": "#c084fc"},
    "developer": {"label": "Developer", "color": "#38bdf8"},
    "messaging": {"label": "Messaging", "color": "#34d399"},
    "media": {"label": "Media", "color": "#fbbf24"},
    "other": {"label": "Other", "color": "#9ca3af"},
}


def categorize_platform(platform: str, url: str = "", tags: Optional[list[str]] = None) -> str:
    """Categorize a platform name or URL into social, gaming, developer, messaging, media, or other."""
    plat_lower = platform.strip().lower()
    if plat_lower in PLATFORM_CATEGORIES:
        return PLATFORM_CATEGORIES[plat_lower]

    url_lower = url.lower()
    if any(k in url_lower for k in ("steamcommunity", "roblox.com", "chess.com", "itch.io", "twitch.tv", "epicgames.com", "battle.net")):
        return "gaming"
    if any(k in url_lower for k in ("github.com", "gitlab.com", "docker.com", "pypi.org", "npmjs.com", "crates.io", "replit.com", "codeberg.org")):
        return "developer"
    if any(k in url_lower for k in ("discord.com", "t.me", "telegram.me", "matrix.to", "signal.me", "simplex.chat")):
        return "messaging"
    if any(k in url_lower for k in ("spotify.com", "soundcloud.com", "bandcamp.com", "last.fm")):
        return "media"
    if any(k in url_lower for k in ("twitter.com", "x.com", "reddit.com", "instagram.com", "facebook.com", "tiktok.com", "youtube.com", "threads.net", "bsky.app", "linkedin.com", "tumblr.com")):
        return "social"

    if tags:
        for t in tags:
            t_lower = t.lower()
            if "game" in t_lower or "gaming" in t_lower:
                return "gaming"
            if "dev" in t_lower or "code" in t_lower or "tech" in t_lower:
                return "developer"
            if "message" in t_lower or "chat" in t_lower:
                return "messaging"
            if "music" in t_lower or "audio" in t_lower:
                return "media"
            if "social" in t_lower:
                return "social"

    return "other"


def render_html_report(report: InvestigationReport) -> str:
    """Generate self-contained, standalone HTML investigation dossier."""
    target_clean = html.escape(report.target)
    target_type_clean = html.escape(report.target_type.lower())
    timestamp_clean = html.escape(report.scan_timestamp_utc)
    duration_str = f"{report.scan_duration_seconds:.2f}s"

    # Count statistics for summary
    profile_count = len(report.social_profiles)
    email_count = len(report.pivot_leads.discovered_emails)
    discord_id_count = len(report.pivot_leads.discovered_discord_ids)
    invite_count = len(report.pivot_leads.discovered_invites)
    tag_count = len(report.pivot_leads.discovered_discord_tags)
    crypto_count = len(report.pivot_leads.discovered_crypto)
    messaging_count = len(report.pivot_leads.discovered_messaging)
    total_leads = (
        email_count
        + discord_id_count
        + invite_count
        + tag_count
        + crypto_count
        + messaging_count
    )
    breach_count = len(report.breaches)

    # 1. Discord Snowflake card HTML
    snowflake_html = ""
    if report.snowflake:
        sf = report.snowflake
        snowflake_html = f"""
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">{ICON_TERMINAL} Discord Snowflake Telemetry</span>
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
              <span class="telemetry-label">Account Age</span>
              <span class="telemetry-value font-semibold text-emerald">{html.escape(sf.age_human)}</span>
            </div>
            <div class="telemetry-item">
              <span class="telemetry-label">Worker ID / Process ID</span>
              <span class="telemetry-value font-mono">{sf.worker_id} / {sf.process_id}</span>
            </div>
            <div class="telemetry-item">
              <span class="telemetry-label">Sequence Increment</span>
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
            else f'<div class="avatar-placeholder">{ICON_USER}</div>'
        )

        badges_html = "".join(
            f'<span class="tag">{html.escape(b)}</span>' for b in dp.badges
        )
        if not badges_html:
            badges_html = '<span class="text-muted text-sm">None registered</span>'

        rev_search_html = ""
        if dp.reverse_image_urls:
            rev = dp.reverse_image_urls
            rev_search_html = f"""
            <div class="reverse-search-bar">
              <span class="reverse-search-label">{ICON_SEARCH} Reverse Search Avatar:</span>
              <a href="{html.escape(rev.google_lens)}" target="_blank" rel="noopener noreferrer" class="link-rev">Google Lens</a>
              <a href="{html.escape(rev.yandex)}" target="_blank" rel="noopener noreferrer" class="link-rev">Yandex</a>
              <a href="{html.escape(rev.tineye)}" target="_blank" rel="noopener noreferrer" class="link-rev">TinEye</a>
              <a href="{html.escape(rev.bing_visual)}" target="_blank" rel="noopener noreferrer" class="link-rev">Bing Visual</a>
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

        bio_info = ""
        if dp.bio:
            bio_info = f"""
            <div class="telemetry-item" style="grid-column: 1 / -1;">
              <span class="telemetry-label">About / Bio</span>
              <span class="telemetry-value text-sm">{html.escape(dp.bio)}</span>
            </div>
            """

        profile_html = f"""
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">{ICON_USER} Discord Profile</span>
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
                {bio_info}
              </div>
              {rev_search_html}
            </div>
          </div>
        </div>
        """

    # Gaming Ecosystem HTML (Minecraft & Steam)
    gaming_html = ""
    if report.gaming and (report.gaming.minecraft or report.gaming.steam):
        gaming_cards = []
        if report.gaming.minecraft:
            mc = report.gaming.minecraft
            gaming_cards.append(
                f"""
                <div class="lead-group">
                  <span class="lead-group-title">Minecraft (Mojang API)</span>
                  <div class="telemetry-grid">
                    <div class="telemetry-item">
                      <span class="telemetry-label">Player Username</span>
                      <span class="telemetry-value font-semibold">{html.escape(mc.username)}</span>
                    </div>
                    <div class="telemetry-item">
                      <span class="telemetry-label">Formatted UUID</span>
                      <span class="telemetry-value font-mono copyable" onclick="copyText('{mc.uuid_formatted}')">
                        {mc.uuid_formatted} <button class="btn-copy" title="Copy">{ICON_COPY}</button>
                      </span>
                    </div>
                    <div class="telemetry-item">
                      <span class="telemetry-label">Raw Mojang ID</span>
                      <span class="telemetry-value font-mono">{mc.uuid}</span>
                    </div>
                  </div>
                </div>
                """
            )
        if report.gaming.steam:
            st = report.gaming.steam
            vac_badge = '<span class="text-emerald font-semibold">Clean (No Bans)</span>' if not st.vac_banned else '<span class="text-rose font-semibold">VAC Banned</span>'
            gaming_cards.append(
                f"""
                <div class="lead-group mt-3">
                  <span class="lead-group-title">Steam Community</span>
                  <div class="telemetry-grid">
                    <div class="telemetry-item">
                      <span class="telemetry-label">Custom URL</span>
                      <span class="telemetry-value font-semibold"><a href="{html.escape(st.profile_url)}" target="_blank" rel="noopener noreferrer" class="link-external">@{html.escape(st.custom_url)} {ICON_LINK}</a></span>
                    </div>
                    <div class="telemetry-item">
                      <span class="telemetry-label">SteamID64</span>
                      <span class="telemetry-value font-mono copyable" onclick="copyText('{st.steam_id_64}')">
                        {st.steam_id_64} <button class="btn-copy" title="Copy">{ICON_COPY}</button>
                      </span>
                    </div>
                    <div class="telemetry-item">
                      <span class="telemetry-label">VAC Ban Status</span>
                      <span class="telemetry-value">{vac_badge}</span>
                    </div>
                    <div class="telemetry-item">
                      <span class="telemetry-label">Real Name / Location</span>
                      <span class="telemetry-value">{html.escape(st.real_name or 'N/A')} ({html.escape(st.location or 'N/A')})</span>
                    </div>
                    {f'''<div class="telemetry-item" style="grid-column: 1 / -1;">
                      <span class="telemetry-label">Bio / Summary</span>
                      <span class="telemetry-value text-sm text-muted">{html.escape(st.summary)}</span>
                    </div>''' if st.summary else ''}
                  </div>
                </div>
                """
            )

        gaming_html = f"""
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">{ICON_SHIELD} Gaming Ecosystem Identity</span>
          </div>
          <div class="leads-container">
            {''.join(gaming_cards)}
          </div>
        </div>
        """

    # 3. Matched Profiles HTML with Category Sections
    social_profiles_html = ""
    if report.social_profiles:
        rows = []
        category_counts: dict[str, int] = defaultdict(int)

        for p in report.social_profiles:
            cat = categorize_platform(p.platform, p.url, p.tags)
            category_counts[cat] += 1

            is_discord = p.platform.lower() == "discord" or p.url.startswith("@")
            if is_discord:
                url_display = f'<span class="font-mono text-cyan">{html.escape(p.url)}</span> <span class="text-muted text-xs">(Handle Registered)</span>'
            else:
                url_display = f'<a href="{html.escape(p.url)}" target="_blank" rel="noopener noreferrer" class="link-external">{html.escape(p.url)} {ICON_LINK}</a>'

            cat_label = CATEGORY_META.get(cat, {}).get("label", cat.title())

            rows.append(
                f"""
                <tr class="profile-row" data-category="{cat}" data-platform="{html.escape(p.platform.lower())}">
                  <td class="font-semibold">{html.escape(p.platform)}</td>
                  <td><span class="category-badge category-{cat}" onclick="filterProfileCategory('{cat}')" style="cursor: pointer;" title="Filter by {cat_label}">{cat_label}</span></td>
                  <td><span class="status-indicator-dot"></span> <span class="text-emerald">{html.escape(p.status)}</span></td>
                  <td>{url_display}</td>
                </tr>
                """
            )

        # Build filter tabs: All first, followed by categories with > 0 matches
        filter_tabs_html = [
            f'<button type="button" class="filter-tab active" data-filter="all" onclick="filterProfileCategory(\'all\')">All <span class="tab-count">({len(report.social_profiles)})</span></button>'
        ]
        category_order = ["social", "gaming", "developer", "messaging", "media", "other"]
        for cat in category_order:
            if category_counts[cat] > 0:
                cat_label = CATEGORY_META.get(cat, {}).get("label", cat.title())
                filter_tabs_html.append(
                    f'<button type="button" class="filter-tab" data-filter="{cat}" onclick="filterProfileCategory(\'{cat}\')">{cat_label} <span class="tab-count">({category_counts[cat]})</span></button>'
                )

        social_profiles_html = f"""
        <div class="panel">
          <div class="panel-header" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
            <span class="panel-title">{ICON_LINK} Matched Social Profiles ({len(report.social_profiles)})</span>
            <div class="profile-filter-bar">
              {''.join(filter_tabs_html)}
            </div>
          </div>
          <div class="table-container">
            <table class="data-table" id="profilesTable">
              <thead>
                <tr>
                  <th style="width: 22%;">Platform</th>
                  <th style="width: 16%;">Section</th>
                  <th style="width: 14%;">Status</th>
                  <th>Profile URL / Handle</th>
                </tr>
              </thead>
              <tbody>
                {''.join(rows)}
                <tr id="profileEmptyRow" style="display: none;">
                  <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 24px;">No profiles found matching this section.</td>
                </tr>
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

        if leads.discovered_crypto:
            crypto_items = "".join(
                f"""<div class="lead-pill font-mono copyable" onclick="copyText('{html.escape(c.address)}')">
                      <span class="tag">{html.escape(c.network)}</span>
                      <span>{html.escape(c.address)}</span>
                      <button class="btn-copy" title="Copy">{ICON_COPY}</button>
                    </div>"""
                for c in leads.discovered_crypto
            )
            lead_cards.append(
                f"""
                <div class="lead-group">
                  <span class="lead-group-title">Crypto Wallet Addresses ({len(leads.discovered_crypto)})</span>
                  <div class="lead-pills-wrap">{crypto_items}</div>
                </div>
                """
            )

        if leads.discovered_messaging:
            msg_items = "".join(
                f"""<div class="lead-pill font-mono">
                      <span class="tag">{html.escape(m.platform)}</span>
                      <span>{html.escape(m.handle)}</span>
                      {f'<a href="{html.escape(m.url)}" target="_blank" rel="noopener noreferrer" class="link-external">{ICON_LINK}</a>' if m.url else ''}
                    </div>"""
                for m in leads.discovered_messaging
            )
            lead_cards.append(
                f"""
                <div class="lead-group">
                  <span class="lead-group-title">Messaging Handles ({len(leads.discovered_messaging)})</span>
                  <div class="lead-pills-wrap">{msg_items}</div>
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
          </div>
          <div class="leads-container">
            {''.join(enrichment_sections)}
          </div>
        </div>
        """

    # 6. Verified Email Registrations (Holehe)
    email_recon_html = ""
    if report.email_registrations:
        total_recon_accs = sum(len(r.accounts) for r in report.email_registrations)
        if total_recon_accs > 0:
            recon_cards = []
            for r in report.email_registrations:
                if not r.accounts:
                    continue
                acc_pills = "".join(
                    f"""<div class="lead-pill font-mono">
                          <span class="tag">{html.escape(acc.platform)}</span>
                          <a href="https://{html.escape(acc.domain)}" target="_blank" rel="noopener noreferrer" class="link-external font-bold">{html.escape(acc.domain)} {ICON_LINK}</a>
                          {f'<span class="text-xs text-muted">Recovery: {html.escape(acc.email_recovery)}</span>' if acc.email_recovery else ''}
                        </div>"""
                    for acc in r.accounts
                )
                recon_cards.append(
                    f"""
                    <div class="lead-group">
                      <span class="lead-group-title">Target Email: <span class="font-mono text-emerald">{html.escape(r.email)}</span> ({len(r.accounts)} confirmed)</span>
                      <div class="lead-pills-wrap">{acc_pills}</div>
                    </div>
                    """
                )
            email_recon_html = f"""
            <div class="panel">
              <div class="panel-header">
                <span class="panel-title">{ICON_SHIELD} Verified Email Registrations ({total_recon_accs} Platforms)</span>
              </div>
              <div class="leads-container">
                {''.join(recon_cards)}
              </div>
            </div>
            """

    # 7. Cross-Platform Avatar Matches
    avatar_matches_html = ""
    if report.avatar_matches:
        match_rows = "".join(
            f"""
            <tr>
              <td class="font-bold text-cyan">{html.escape(m.platform_a)}</td>
              <td class="font-bold text-emerald">{html.escape(m.platform_b)}</td>
              <td class="font-mono" style="text-align: center;"><strong>{m.hamming_distance}</strong> / 64 bits</td>
              <td>{"<span class='badge badge-cyan'>Identical Match</span>" if m.hamming_distance == 0 else "<span class='badge badge-emerald'>Perceptual Match</span>"}</td>
            </tr>
            """
            for m in report.avatar_matches
        )
        avatar_matches_html = f"""
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">{ICON_SHIELD} Cross-Platform Avatar Matches ({len(report.avatar_matches)})</span>
          </div>
          <table class="report-table">
            <thead>
              <tr>
                <th>Source Platform</th>
                <th>Matched Platform</th>
                <th style="text-align: center;">Hamming Distance</th>
                <th>Correlation Verdict</th>
              </tr>
            </thead>
            <tbody>
              {match_rows}
            </tbody>
          </table>
        </div>
        """

    # 8. Hudson Rock Infostealer Intelligence
    hudson_rock_html = ""
    hr_infections = [inf for r in report.hudson_rock for inf in r.infections]
    if hr_infections:
        hr_rows = "".join(
            f"""
            <tr>
              <td class="font-bold text-rose">{html.escape(inf.stealer_family or 'Unknown')}</td>
              <td class="font-mono">{html.escape(inf.date_compromised or 'N/A')}</td>
              <td>{html.escape(inf.computer_name or 'N/A')} <span class="text-xs text-muted">({html.escape(inf.operating_system or 'N/A')})</span></td>
              <td class="font-mono text-xs">{html.escape(', '.join(inf.top_logins[:4]) if inf.top_logins else 'N/A')}</td>
            </tr>
            """
            for inf in hr_infections
        )
        hudson_rock_html = f"""
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">{ICON_SHIELD} Hudson Rock Infostealer Compromises ({len(hr_infections)})</span>
          </div>
          <table class="report-table">
            <thead>
              <tr>
                <th>Malware Family</th>
                <th>Compromise Date</th>
                <th>Infected Host / OS</th>
                <th>Sample Compromised Logins</th>
              </tr>
            </thead>
            <tbody>
              {hr_rows}
            </tbody>
          </table>
        </div>
        """

    # 9. Correlation Banner HTML
    correlation_banner_html = ""
    if report.correlation:
        corr = report.correlation
        badge_cls = "badge-emerald" if corr.confidence_level == "HIGH" else ("badge-amber" if corr.confidence_level == "MEDIUM" else "badge-rose")
        reasons_list = "".join(f"<li>{html.escape(r)}</li>" for r in corr.reasons)
        correlation_banner_html = f"""
        <div class="summary-card" style="margin-bottom: 16px;">
          <div class="summary-main">
            <div class="target-row">
              <span class="font-semibold text-primary">Identity Correlation Confidence:</span>
              <span class="badge {badge_cls} font-mono">{corr.confidence_score}% ({corr.confidence_level})</span>
            </div>
            <ul style="margin-top: 8px; padding-left: 20px; color: var(--text-secondary); font-size: 12px;">
              {reasons_list}
            </ul>
          </div>
        </div>
        """

    # 10. Google Dorks HTML (Opt-in)
    dorks_html = ""
    if report.dorks:
        dork_pills = "".join(
            f"""<div class="lead-pill font-mono">
                  <span class="tag">{html.escape(d.category)}</span>
                  <a href="{html.escape(d.url)}" target="_blank" rel="noopener noreferrer" class="link-external">{html.escape(d.query)} {ICON_LINK}</a>
                </div>"""
            for d in report.dorks
        )
        dorks_html = f"""
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">{ICON_SHIELD} Pre-Computed Google Dorks ({len(report.dorks)})</span>
          </div>
          <div class="leads-container">
            <div class="lead-pills-wrap">{dork_pills}</div>
          </div>
        </div>
        """

    # 11. IntelX HTML (Opt-in)
    intelx_html = ""
    if report.intelx and report.intelx.records:
        ix_rows = "".join(
            f"""
            <tr>
              <td class="font-mono">{html.escape(r.name)}</td>
              <td><span class="tag">{html.escape(r.media_type or 'Record')}</span></td>
            </tr>
            """
            for r in report.intelx.records
        )
        intelx_html = f"""
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">{ICON_SHIELD} Intelligence X Darknet & Leak Archive Hits ({len(report.intelx.records)})</span>
          </div>
          <table class="report-table">
            <thead>
              <tr>
                <th>Record Selector</th>
                <th>Type</th>
              </tr>
            </thead>
            <tbody>
              {ix_rows}
            </tbody>
          </table>
        </div>
        """

    # 11b. Cryptographic Identities (Keybase & OpenPGP)
    keybase_pgp_html = ""
    if report.keybase or report.pgp_keys:
        kp_rows = []
        if report.keybase:
            kb = report.keybase
            proof_links = " ".join(
                f'<a href="{html.escape(p.proof_url or "")}" target="_blank" rel="noopener noreferrer" class="tag">{html.escape(p.service)}:{html.escape(p.username)}</a>'
                for p in kb.proofs
            ) if kb.proofs else '<span class="text-xs text-muted">None</span>'
            kp_rows.append(
                f"""
                <tr>
                  <td class="font-bold text-cyan">Keybase</td>
                  <td class="font-mono">@{html.escape(kb.username)}</td>
                  <td>{html.escape(kb.full_name or 'N/A')}</td>
                  <td>{proof_links}</td>
                </tr>
                """
            )
        for pgp in report.pgp_keys:
            kp_rows.append(
                f"""
                <tr>
                  <td class="font-bold text-emerald">{html.escape(pgp.source)}</td>
                  <td class="font-mono">{html.escape(pgp.key_id_or_fingerprint)}</td>
                  <td>{html.escape(', '.join(pgp.identities))}</td>
                  <td><a href="{html.escape(pgp.public_key_url or '')}" target="_blank" rel="noopener noreferrer" class="link-external">Public Key {ICON_LINK}</a></td>
                </tr>
                """
            )
        keybase_pgp_html = f"""
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">{ICON_SHIELD} Cryptographic Identities (Keybase & OpenPGP)</span>
          </div>
          <table class="report-table">
            <thead>
              <tr>
                <th>Source</th>
                <th>Identifier / Key</th>
                <th>Identity Claims</th>
                <th>Verified External Proofs</th>
              </tr>
            </thead>
            <tbody>
              {''.join(kp_rows)}
            </tbody>
          </table>
        </div>
        """

    # 11c. Personal Domain & Infrastructure Recon (RDAP + crt.sh)
    domain_recon_html = ""
    if report.domain_recon:
        dr_rows = "".join(
            f"""
            <tr>
              <td class="font-bold text-emerald font-mono">{html.escape(d.domain)}</td>
              <td>{html.escape(d.registrar or 'N/A')}</td>
              <td class="font-mono text-xs">{html.escape(d.created_date or 'N/A')}</td>
              <td class="font-mono text-xs">
                {', '.join(html.escape(s) for s in d.subdomains[:10]) if d.subdomains else '<span class="text-muted">None in CT logs</span>'}
                {f'<span class="text-muted"> (+{len(d.subdomains) - 10} more)</span>' if len(d.subdomains) > 10 else ''}
              </td>
            </tr>
            """
            for d in report.domain_recon
        )
        domain_recon_html = f"""
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">{ICON_SHIELD} Personal Domain Infrastructure Recon ({len(report.domain_recon)})</span>
          </div>
          <table class="report-table">
            <thead>
              <tr>
                <th>Domain Name</th>
                <th>Registrar</th>
                <th>Registration Date</th>
                <th>Discovered Subdomains (crt.sh)</th>
              </tr>
            </thead>
            <tbody>
              {dr_rows}
            </tbody>
          </table>
        </div>
        """

    # 11d. Package Registry Developer Footprint
    packages_html = ""
    if report.packages:
        pkg_rows = "".join(
            f"""
            <tr>
              <td><span class="badge badge-cyan">{html.escape(pkg.registry)}</span></td>
              <td class="font-bold"><a href="{html.escape(pkg.url)}" target="_blank" rel="noopener noreferrer" class="link-external">{html.escape(pkg.name)} {ICON_LINK}</a></td>
              <td class="font-mono">{html.escape(pkg.version or 'N/A')}</td>
              <td class="text-xs">{html.escape(pkg.description or 'No summary')}</td>
              <td class="font-mono text-xs text-emerald">{html.escape(pkg.author_email or 'N/A')}</td>
            </tr>
            """
            for pkg in report.packages
        )
        packages_html = f"""
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">{ICON_TERMINAL} Package Registry Footprint ({len(report.packages)})</span>
          </div>
          <table class="report-table">
            <thead>
              <tr>
                <th>Registry</th>
                <th>Package</th>
                <th>Version</th>
                <th>Summary</th>
                <th>Author Email</th>
              </tr>
            </thead>
            <tbody>
              {pkg_rows}
            </tbody>
          </table>
        </div>
        """

    # 11e. Wayback Machine Historical Snapshots
    wayback_html = ""
    if report.wayback_snapshots:
        wb_rows = "".join(
            f"""
            <tr>
              <td class="font-mono">{html.escape(snap.timestamp)}</td>
              <td class="font-mono text-xs">{html.escape(snap.original_url)}</td>
              <td><a href="{html.escape(snap.archive_url)}" target="_blank" rel="noopener noreferrer" class="link-external font-bold">View Archive Snapshot {ICON_LINK}</a></td>
            </tr>
            """
            for snap in report.wayback_snapshots[:12]
        )
        wayback_html = f"""
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">{ICON_TERMINAL} Internet Archive Historical Snapshots ({len(report.wayback_snapshots)})</span>
          </div>
          <table class="report-table">
            <thead>
              <tr>
                <th>Timestamp (UTC)</th>
                <th>Target Profile URL</th>
                <th>Wayback Machine Archive</th>
              </tr>
            </thead>
            <tbody>
              {wb_rows}
            </tbody>
          </table>
        </div>
        """

    # 11f. Avatar EXIF & Technical Metadata
    image_metadata_html = ""
    if report.image_metadata:
        img_rows = "".join(
            f"""
            <tr>
              <td class="font-bold text-cyan">{html.escape(im.platform)}</td>
              <td class="font-mono">{html.escape(im.format or 'Unknown')}</td>
              <td class="font-mono">{html.escape(im.dimensions or 'Unknown')}</td>
              <td>{html.escape(f"{im.make or ''} {im.model or ''}".strip() or 'N/A')}</td>
              <td class="text-xs">{html.escape(im.software or 'N/A')}</td>
              <td class="font-mono text-xs">{html.escape(im.datetime_original or 'N/A')}</td>
              <td>{"<span class='badge badge-cyan'>EXIF Found</span>" if im.has_exif else "<span class='badge badge-amber'>Stripped</span>"}</td>
            </tr>
            """
            for im in report.image_metadata
        )
        image_metadata_html = f"""
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">{ICON_SHIELD} Avatar EXIF & Technical Metadata ({len(report.image_metadata)})</span>
          </div>
          <table class="report-table">
            <thead>
              <tr>
                <th>Platform</th>
                <th>Format</th>
                <th>Dimensions</th>
                <th>Camera Make/Model</th>
                <th>Software Signature</th>
                <th>DateTime Original</th>
                <th>EXIF Status</th>
              </tr>
            </thead>
            <tbody>
              {img_rows}
            </tbody>
          </table>
        </div>
        """

    # 11g. Interactive Entity Relationship Graph Data
    graph_nodes = [{"id": "target", "label": report.target, "sub": report.target_type.upper(), "type": "target", "color": "#10b981", "radius": 18}]
    graph_edges = []

    for idx, sp in enumerate(report.social_profiles[:15]):
        nid = f"p_{idx}"
        graph_nodes.append({"id": nid, "label": sp.platform, "sub": sp.url, "type": "platform", "color": "#06b6d4", "radius": 10})
        graph_edges.append({"source": "target", "target": nid})

    for idx, em in enumerate(report.pivot_leads.discovered_emails):
        nid = f"e_{idx}"
        graph_nodes.append({"id": nid, "label": em, "sub": "Email", "type": "email", "color": "#f59e0b", "radius": 12})
        graph_edges.append({"source": "target", "target": nid})
        for b_idx, br in enumerate(report.breaches):
            if br.query.lower() == em.lower():
                bid = f"b_{idx}_{b_idx}"
                graph_nodes.append({"id": bid, "label": br.service_name, "sub": "Breach", "type": "breach", "color": "#f43f5e", "radius": 8})
                graph_edges.append({"source": nid, "target": bid})

    for idx, d in enumerate(report.domain_recon):
        nid = f"d_{idx}"
        graph_nodes.append({"id": nid, "label": d.domain, "sub": f"{len(d.subdomains)} subdomains", "type": "domain", "color": "#14b8a6", "radius": 11})
        graph_edges.append({"source": "target", "target": nid})

    for idx, pkg in enumerate(report.packages):
        nid = f"pkg_{idx}"
        graph_nodes.append({"id": nid, "label": f"{pkg.registry}:{pkg.name}", "sub": pkg.version or "", "type": "package", "color": "#a855f7", "radius": 9})
        graph_edges.append({"source": "target", "target": nid})

    if report.keybase:
        graph_nodes.append({"id": "keybase", "label": f"Keybase:@{report.keybase.username}", "sub": f"{len(report.keybase.proofs)} proofs", "type": "identity", "color": "#38bdf8", "radius": 12})
        graph_edges.append({"source": "target", "target": "keybase"})

    for idx, cl in enumerate(report.pivot_leads.discovered_crypto):
        nid = f"c_{idx}"
        graph_nodes.append({"id": nid, "label": f"{cl.network}:{cl.address[:8]}...", "sub": cl.network, "type": "crypto", "color": "#ec4899", "radius": 9})
        graph_edges.append({"source": "target", "target": nid})

    for idx, ml in enumerate(report.pivot_leads.discovered_messaging):
        nid = f"msg_{idx}"
        graph_nodes.append({"id": nid, "label": f"{ml.platform}:{ml.handle}", "sub": ml.platform, "type": "messaging", "color": "#10b981", "radius": 9, "url": ml.url or ""})
        graph_edges.append({"source": "target", "target": nid})

    graph_payload_json = (
        json.dumps({"nodes": graph_nodes, "edges": graph_edges})
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )

    graph_html = f"""
    <div class="panel" id="graphContainerPanel">
      <div class="panel-header" style="justify-content: space-between;">
        <span class="panel-title">{ICON_SHIELD} Interactive Entity Correlation Graph</span>
        <button class="btn" style="padding: 2px 8px; font-size: 11px;" onclick="resetGraphView()">Reset Graph</button>
      </div>
      <div style="position: relative; width: 100%; height: 420px; background: #0c0d0e; border-bottom: 1px solid var(--border-subtle); overflow: hidden;">
        <canvas id="entityCanvas" width="940" height="420" style="display: block; width: 100%; height: 100%; cursor: grab;"></canvas>
        <div id="graphTooltip" style="position: absolute; display: none; background: #1a1d20; color: #fff; padding: 6px 10px; border-radius: 4px; font-size: 11px; font-family: var(--font-mono); border: 1px solid var(--border-hover); pointer-events: none; z-index: 100; box-shadow: 0 4px 12px rgba(0,0,0,0.5);"></div>
      </div>
      <div style="padding: 8px 16px; font-size: 11px; color: var(--text-muted); display: flex; gap: 16px; flex-wrap: wrap;">
        <span><span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#10b981; margin-right:4px;"></span>Target</span>
        <span><span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#06b6d4; margin-right:4px;"></span>Profiles</span>
        <span><span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#f59e0b; margin-right:4px;"></span>Emails</span>
        <span><span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#f43f5e; margin-right:4px;"></span>Breaches</span>
        <span><span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#14b8a6; margin-right:4px;"></span>Domains</span>
        <span><span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#a855f7; margin-right:4px;"></span>Packages</span>
        <span><span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#ec4899; margin-right:4px;"></span>Crypto</span>
        <span style="margin-left: auto;">Drag nodes • Hover for details</span>
      </div>
    </div>
    """

    # 12. Raw JSON representation
    raw_json_str = html.escape(json.dumps(report.model_dump(), indent=2))

    # Self-contained CSS (Archetype B: Technical Dense Terminal with clean typography)
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
      --bg-canvas: #0c0d0e;
      --bg-surface: #141618;
      --bg-surface-elevated: #1a1d20;
      --border-subtle: #24282c;
      --border-hover: #383e44;
      --accent-emerald: #10b981;
      --accent-cyan: #38bdf8;
      --accent-amber: #f59e0b;
      --accent-rose: #f43f5e;
      --text-primary: #e6edf3;
      --text-secondary: #8b949e;
      --text-muted: #6e7681;
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", sans-serif;
      --font-mono: ui-monospace, "JetBrains Mono", "Cascadia Code", Consolas, monospace;
      --radius-sm: 2px;
      --radius-md: 4px;
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
      font-size: 13px;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
      padding: 24px 20px 60px 20px;
    }}

    .container {{
      max-width: 1040px;
      margin: 0 auto;
    }}

    /* Top Nav Bar */
    .top-bar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--border-subtle);
    }}

    .brand {{
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 13px;
    }}

    .brand-logo {{
      font-weight: 700;
      font-family: var(--font-mono);
      letter-spacing: 0.5px;
      color: var(--text-primary);
    }}

    .brand-divider {{
      color: var(--border-hover);
    }}

    .brand-sub {{
      color: var(--text-muted);
      font-size: 13px;
    }}

    .top-actions {{
      display: flex;
      gap: 8px;
    }}

    /* Action Buttons */
    .btn {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 5px 10px;
      font-size: 12px;
      font-weight: 500;
      border-radius: var(--radius-sm);
      border: 1px solid var(--border-subtle);
      background: var(--bg-surface);
      color: var(--text-secondary);
      cursor: pointer;
      user-select: none;
      transition: background-color 100ms ease, border-color 100ms ease, color 100ms ease;
    }}

    .btn:hover {{
      background: var(--bg-surface-elevated);
      border-color: var(--border-hover);
      color: var(--text-primary);
    }}

    .btn:active {{
      transform: scale(0.98);
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
      transition: color 100ms ease;
    }}

    .btn-copy:hover {{
      color: var(--accent-cyan);
    }}

    .link-rev {{
      display: inline-flex;
      align-items: center;
      padding: 2px 6px;
      font-size: 11px;
      font-weight: 500;
      border-radius: var(--radius-sm);
      border: 1px solid var(--border-subtle);
      background: var(--bg-surface-elevated);
      color: var(--text-secondary);
      text-decoration: none;
      transition: color 100ms ease, border-color 100ms ease;
    }}

    .link-rev:hover {{
      color: var(--accent-cyan);
      border-color: var(--border-hover);
    }}

    /* Target Summary Bar */
    .summary-card {{
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 16px 20px;
      margin-bottom: 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
    }}

    .summary-main {{
      display: flex;
      flex-direction: column;
      gap: 4px;
    }}

    .target-row {{
      display: flex;
      align-items: center;
      gap: 8px;
    }}

    .target-value {{
      font-size: 18px;
      font-weight: 600;
      color: var(--text-primary);
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }}

    .tag-type {{
      display: inline-flex;
      align-items: center;
      padding: 2px 6px;
      font-size: 11px;
      font-family: var(--font-mono);
      color: var(--accent-cyan);
      background: rgba(56, 189, 248, 0.08);
      border: 1px solid rgba(56, 189, 248, 0.2);
      border-radius: var(--radius-sm);
    }}

    .meta-row {{
      font-size: 12px;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      gap: 8px;
    }}

    .meta-dot {{
      color: var(--border-hover);
    }}

    .summary-metrics {{
      display: flex;
      gap: 20px;
      align-items: center;
    }}

    .metric-col {{
      display: flex;
      flex-direction: column;
      align-items: flex-end;
    }}

    .metric-num {{
      font-size: 16px;
      font-weight: 600;
      font-family: var(--font-mono);
      color: var(--text-primary);
    }}

    .metric-text {{
      font-size: 11px;
      color: var(--text-muted);
    }}

    /* Panels */
    .panel {{
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      margin-bottom: 16px;
      overflow: hidden;
    }}

    .panel-header {{
      display: flex;
      align-items: center;
      padding: 10px 16px;
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

    /* Profile Card */
    .profile-card {{
      display: flex;
      gap: 16px;
      padding: 16px;
    }}

    .avatar-wrap {{
      width: 80px;
      height: 80px;
      border-radius: var(--radius-sm);
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
      gap: 8px;
      margin-bottom: 6px;
      flex-wrap: wrap;
    }}

    .profile-name {{
      font-size: 16px;
      font-weight: 600;
      color: var(--text-primary);
    }}

    .profile-handle {{
      font-size: 13px;
      color: var(--text-muted);
    }}

    .badges-row {{
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      margin-bottom: 8px;
    }}

    .tag {{
      display: inline-flex;
      align-items: center;
      padding: 1px 6px;
      border-radius: var(--radius-sm);
      font-size: 11px;
      font-weight: 500;
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border-subtle);
      color: var(--text-secondary);
    }}

    .reverse-search-bar {{
      display: flex;
      align-items: center;
      gap: 6px;
      flex-wrap: wrap;
      margin-top: 12px;
      padding-top: 10px;
      border-top: 1px solid var(--border-subtle);
    }}

    .reverse-search-label {{
      font-size: 11px;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      gap: 4px;
    }}

    /* Telemetry Grid */
    .telemetry-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
      padding: 14px 16px;
    }}

    .telemetry-item {{
      display: flex;
      flex-direction: column;
    }}

    .telemetry-label {{
      font-size: 11px;
      color: var(--text-muted);
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
      width: 10px;
      height: 10px;
      border-radius: 2px;
      border: 1px solid var(--border-hover);
    }}

    /* Data Tables */
    .table-container {{
      overflow-x: auto;
    }}

    .data-table {{
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 12px;
    }}

    .data-table th {{
      padding: 8px 16px;
      background: var(--bg-surface-elevated);
      color: var(--text-muted);
      font-size: 11px;
      font-weight: 600;
      border-bottom: 1px solid var(--border-subtle);
    }}

    .data-table td {{
      padding: 10px 16px;
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

    /* Profile Category Filter Tabs & Badges */
    .profile-filter-bar {{
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      align-items: center;
    }}

    .filter-tab {{
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      color: var(--text-secondary);
      font-size: 11px;
      font-weight: 500;
      padding: 3px 10px;
      border-radius: 12px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 5px;
      user-select: none;
      transition: background-color 100ms ease, border-color 100ms ease, color 100ms ease;
    }}

    .filter-tab:hover {{
      background: var(--bg-surface-elevated);
      border-color: var(--border-hover);
      color: var(--text-primary);
    }}

    .filter-tab.active {{
      background: rgba(56, 189, 248, 0.12);
      border-color: var(--accent-cyan);
      color: var(--accent-cyan);
      font-weight: 600;
    }}

    .tab-count {{
      opacity: 0.75;
      font-size: 10px;
      font-family: var(--font-mono);
    }}

    .category-badge {{
      display: inline-flex;
      align-items: center;
      padding: 1px 7px;
      font-size: 10px;
      font-weight: 600;
      border-radius: 10px;
      text-transform: uppercase;
      letter-spacing: 0.3px;
      user-select: none;
      transition: opacity 100ms ease, transform 100ms ease;
    }}

    .category-badge:hover {{
      opacity: 0.85;
      transform: translateY(-1px);
    }}

    .category-social {{
      background: rgba(59, 130, 246, 0.12);
      color: #60a5fa;
      border: 1px solid rgba(59, 130, 246, 0.3);
    }}

    .category-gaming {{
      background: rgba(168, 85, 247, 0.12);
      color: #c084fc;
      border: 1px solid rgba(168, 85, 247, 0.3);
    }}

    .category-developer {{
      background: rgba(6, 182, 212, 0.12);
      color: #38bdf8;
      border: 1px solid rgba(6, 182, 212, 0.3);
    }}

    .category-messaging {{
      background: rgba(16, 185, 129, 0.12);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.3);
    }}

    .category-media {{
      background: rgba(245, 158, 11, 0.12);
      color: #fbbf24;
      border: 1px solid rgba(245, 158, 11, 0.3);
    }}

    .category-other {{
      background: rgba(107, 114, 128, 0.12);
      color: #9ca3af;
      border: 1px solid rgba(107, 114, 128, 0.3);
    }}

    /* Leads */
    .leads-container {{
      padding: 14px 16px;
    }}

    .lead-group {{
      margin-bottom: 14px;
    }}

    .lead-group:last-child {{
      margin-bottom: 0;
    }}

    .lead-group-title {{
      display: block;
      font-size: 12px;
      font-weight: 600;
      color: var(--text-secondary);
      margin-bottom: 6px;
    }}

    .lead-pills-wrap {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }}

    .lead-pill {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 3px 8px;
      border-radius: var(--radius-sm);
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border-subtle);
      font-size: 12px;
      color: var(--text-primary);
    }}

    .copyable {{
      cursor: pointer;
    }}

    .copyable:hover .btn-copy {{
      color: var(--accent-cyan);
    }}

    /* Collapsible JSON Drawer */
    details.raw-json-drawer {{
      margin-top: 16px;
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      overflow: hidden;
    }}

    details.raw-json-drawer summary {{
      padding: 10px 16px;
      cursor: pointer;
      font-weight: 600;
      font-size: 12px;
      color: var(--text-secondary);
      user-select: none;
      display: flex;
      align-items: center;
      gap: 6px;
    }}

    details.raw-json-drawer summary:hover {{
      color: var(--text-primary);
    }}

    .json-code-box {{
      padding: 14px 16px;
      background: #08090a;
      border-top: 1px solid var(--border-subtle);
      font-family: var(--font-mono);
      font-size: 12px;
      line-height: 1.5;
      color: var(--text-secondary);
      overflow-x: auto;
      max-height: 480px;
    }}

    /* Utility typography */
    .font-mono {{ font-family: var(--font-mono); font-variant-numeric: tabular-nums; }}
    .font-semibold {{ font-weight: 600; }}
    .text-emerald {{ color: var(--accent-emerald); }}
    .text-cyan {{ color: var(--accent-cyan); }}
    .text-rose {{ color: var(--accent-rose); }}
    .text-secondary {{ color: var(--text-secondary); }}
    .text-muted {{ color: var(--text-muted); }}
    .text-primary {{ color: var(--text-primary); }}
    .text-sm {{ font-size: 12px; }}
    .text-xs {{ font-size: 11px; }}
    .mt-3 {{ margin-top: 10px; }}

    /* Print Stylesheet for clean PDF exporting */
    @media print {{
      body {{
        background: #ffffff !important;
        color: #000000 !important;
        padding: 0 !important;
      }}
      .top-actions, .btn-copy, .link-rev, details.raw-json-drawer {{
        display: none !important;
      }}
      .panel, .summary-card {{
        background: #ffffff !important;
        border: 1px solid #d0d7de !important;
        page-break-inside: avoid;
      }}
      .panel-header, .data-table th {{
        background: #f6f8fa !important;
        color: #000000 !important;
      }}
      .lead-pill, .tag, .tag-type {{
        border: 1px solid #d0d7de !important;
        color: #000000 !important;
        background: #f6f8fa !important;
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
        <span class="brand-logo">ARGUS</span>
        <span class="brand-divider">/</span>
        <span class="brand-sub">Investigation Report</span>
      </div>
      <div class="top-actions">
        <button class="btn" onclick="copyFullJson()">{ICON_COPY} Copy JSON</button>
        <button class="btn" onclick="window.print()">{ICON_PRINT} Print / PDF</button>
      </div>
    </header>

    <!-- Target Summary Bar -->
    <div class="summary-card">
      <div class="summary-main">
        <div class="target-row">
          <span class="target-value font-mono copyable" onclick="copyText('{target_clean}')">
            {target_clean} <button class="btn-copy" title="Copy">{ICON_COPY}</button>
          </span>
          <span class="tag-type">{target_type_clean}</span>
        </div>
        <div class="meta-row">
          <span>Scanned: <span class="font-mono text-primary">{timestamp_clean}</span></span>
          <span class="meta-dot">•</span>
          <span>Duration: <span class="font-mono text-primary">{duration_str}</span></span>
        </div>
      </div>
      <div class="summary-metrics">
        <div class="metric-col">
          <span class="metric-num text-emerald">{profile_count}</span>
          <span class="metric-text">Profiles</span>
        </div>
        <div class="metric-col">
          <span class="metric-num text-cyan">{total_leads}</span>
          <span class="metric-text">Leads</span>
        </div>
        <div class="metric-col">
          <span class="metric-num text-rose">{breach_count}</span>
          <span class="metric-text">Breaches</span>
        </div>
      </div>
    </div>

    <!-- Main Content Flow -->
    {correlation_banner_html}
    {graph_html}
    {snowflake_html}
    {profile_html}
    {keybase_pgp_html}
    {gaming_html}
    {social_profiles_html}
    {avatar_matches_html}
    {image_metadata_html}
    {domain_recon_html}
    {packages_html}
    {wayback_html}
    {leads_html}
    {enrichment_html}
    {hudson_rock_html}
    {email_recon_html}
    {dorks_html}
    {intelx_html}

    <!-- Raw JSON Collapsible Drawer -->
    <details class="raw-json-drawer">
      <summary>
        <span>{ICON_TERMINAL} Raw JSON Report</span>
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
        toast.style.bottom = "16px";
        toast.style.right = "16px";
        toast.style.background = "#1a1d20";
        toast.style.color = "#e6edf3";
        toast.style.padding = "6px 12px";
        toast.style.borderRadius = "2px";
        toast.style.border = "1px solid #383e44";
        toast.style.fontSize = "12px";
        toast.style.fontFamily = "var(--font-sans)";
        toast.style.zIndex = "9999";
        toast.style.transition = "opacity 150ms ease";
        document.body.appendChild(toast);
      }}
      toast.innerText = msg;
      toast.style.opacity = "1";
      setTimeout(() => {{
        toast.style.opacity = "0";
      }}, 1200);
    }}

    function filterProfileCategory(category) {{
      const tabs = document.querySelectorAll(".filter-tab");
      tabs.forEach(tab => {{
        if (tab.getAttribute("data-filter") === category) {{
          tab.classList.add("active");
        }} else {{
          tab.classList.remove("active");
        }}
      }});

      const rows = document.querySelectorAll(".profile-row");
      let visibleCount = 0;
      rows.forEach(row => {{
        const rowCat = row.getAttribute("data-category");
        if (category === "all" || rowCat === category) {{
          row.style.display = "";
          visibleCount++;
        }} else {{
          row.style.display = "none";
        }}
      }});

      const emptyRow = document.getElementById("profileEmptyRow");
      if (emptyRow) {{
        emptyRow.style.display = visibleCount === 0 ? "" : "none";
      }}
    }}

    // Interactive Entity Force Graph
    (function initGraph() {{
      const graphData = {graph_payload_json};
      const canvas = document.getElementById("entityCanvas");
      if (!canvas || !graphData || !graphData.nodes || graphData.nodes.length === 0) return;
      const ctx = canvas.getContext("2d");
      const tooltip = document.getElementById("graphTooltip");

      const width = canvas.width;
      const height = canvas.height;
      const nodes = graphData.nodes;
      const edges = graphData.edges;

      nodes.forEach((n, i) => {{
        if (n.id === "target") {{
          n.x = width / 2;
          n.y = height / 2;
          n.vx = 0; n.vy = 0;
        }} else {{
          const angle = (i / (nodes.length - 1)) * 2 * Math.PI;
          const dist = 120 + (i % 3) * 40;
          n.x = width / 2 + Math.cos(angle) * dist;
          n.y = height / 2 + Math.sin(angle) * dist;
          n.vx = 0; n.vy = 0;
        }}
      }});

      const nodeMap = {{}};
      nodes.forEach(n => nodeMap[n.id] = n);

      let isDragging = false;
      let draggedNode = null;
      let hoveredNode = null;

      function simulate() {{
        for (let i = 0; i < nodes.length; i++) {{
          for (let j = i + 1; j < nodes.length; j++) {{
            const na = nodes[i];
            const nb = nodes[j];
            const dx = nb.x - na.x;
            const dy = nb.y - na.y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;
            if (dist < 180) {{
              const force = (180 - dist) / 180 * 0.4;
              const fx = (dx / dist) * force;
              const fy = (dy / dist) * force;
              if (na !== draggedNode && na.id !== "target") {{ na.vx -= fx; na.vy -= fy; }}
              if (nb !== draggedNode && nb.id !== "target") {{ nb.vx += fx; nb.vy += fy; }}
            }}
          }}
        }}

        edges.forEach(e => {{
          const src = nodeMap[e.source];
          const tgt = nodeMap[e.target];
          if (src && tgt) {{
            const dx = tgt.x - src.x;
            const dy = tgt.y - src.y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;
            const targetDist = 110;
            const force = (dist - targetDist) * 0.02;
            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;
            if (src !== draggedNode && src.id !== "target") {{ src.vx += fx; src.vy += fy; }}
            if (tgt !== draggedNode && tgt.id !== "target") {{ tgt.vx -= fx; tgt.vy -= fy; }}
          }}
        }});

        nodes.forEach(n => {{
          if (n !== draggedNode && n.id !== "target") {{
            n.vx += (width / 2 - n.x) * 0.001;
            n.vy += (height / 2 - n.y) * 0.001;
            n.vx *= 0.85;
            n.vy *= 0.85;
            n.x += n.vx;
            n.y += n.vy;
            n.x = Math.max(n.radius + 10, Math.min(width - n.radius - 10, n.x));
            n.y = Math.max(n.radius + 10, Math.min(height - n.radius - 10, n.y));
          }}
        }});
      }}

      function render() {{
        ctx.clearRect(0, 0, width, height);

        ctx.strokeStyle = "#24282c";
        ctx.lineWidth = 1;
        edges.forEach(e => {{
          const src = nodeMap[e.source];
          const tgt = nodeMap[e.target];
          if (src && tgt) {{
            ctx.beginPath();
            ctx.moveTo(src.x, src.y);
            ctx.lineTo(tgt.x, tgt.y);
            ctx.stroke();
          }}
        }});

        nodes.forEach(n => {{
          ctx.beginPath();
          ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
          ctx.fillStyle = n.color;
          ctx.fill();
          ctx.lineWidth = n === hoveredNode || n === draggedNode ? 3 : 1;
          ctx.strokeStyle = n === hoveredNode ? "#ffffff" : "#141618";
          ctx.stroke();

          ctx.font = n.id === "target" ? "bold 11px monospace" : "9px monospace";
          ctx.fillStyle = "#e6edf3";
          ctx.textAlign = "center";
          const shortLabel = n.label.length > 16 ? n.label.slice(0, 14) + "..." : n.label;
          ctx.fillText(shortLabel, n.x, n.y + n.radius + 12);
        }});
      }}

      function loop() {{
        simulate();
        render();
        requestAnimationFrame(loop);
      }}
      loop();

      function getNodeAt(x, y) {{
        for (let i = nodes.length - 1; i >= 0; i--) {{
          const n = nodes[i];
          const dx = x - n.x;
          const dy = y - n.y;
          if (dx * dx + dy * dy <= n.radius * n.radius + 25) {{
            return n;
          }}
        }}
        return null;
      }}

      function getCanvasPos(e) {{
        const rect = canvas.getBoundingClientRect();
        return {{
          x: (e.clientX - rect.left) * (canvas.width / rect.width),
          y: (e.clientY - rect.top) * (canvas.height / rect.height)
        }};
      }}

      canvas.addEventListener("mousedown", e => {{
        const pos = getCanvasPos(e);
        const hit = getNodeAt(pos.x, pos.y);
        if (hit) {{
          isDragging = true;
          draggedNode = hit;
          canvas.style.cursor = "grabbing";
        }}
      }});

      window.addEventListener("mouseup", () => {{
        isDragging = false;
        draggedNode = null;
        canvas.style.cursor = "grab";
      }});

      canvas.addEventListener("dblclick", e => {{
        const pos = getCanvasPos(e);
        const hit = getNodeAt(pos.x, pos.y);
        if (hit && hit.sub && hit.sub.startsWith("http")) {{
          window.open(hit.sub, "_blank", "noopener,noreferrer");
        }}
      }});

      canvas.addEventListener("mousemove", e => {{
        const pos = getCanvasPos(e);
        if (isDragging && draggedNode) {{
          draggedNode.x = pos.x;
          draggedNode.y = pos.y;
        }} else {{
          const hit = getNodeAt(pos.x, pos.y);
          hoveredNode = hit;
          if (hit && tooltip) {{
            tooltip.style.display = "block";
            tooltip.style.left = (e.clientX - canvas.getBoundingClientRect().left + 15) + "px";
            tooltip.style.top = (e.clientY - canvas.getBoundingClientRect().top + 15) + "px";
            const dblHint = (hit.sub && hit.sub.startsWith("http")) ? "<br><span style='color:#38bdf8;font-size:10px;'>Double-click to open link</span>" : "";
            tooltip.innerHTML = "<strong>" + hit.label + "</strong><br><span style='color:#94a3b8'>" + (hit.sub || hit.type) + "</span>" + dblHint;
          }} else if (tooltip) {{
            tooltip.style.display = "none";
          }}
        }}
      }});

      window.resetGraphView = function() {{
        nodes.forEach((n, i) => {{
          if (n.id === "target") {{
            n.x = width / 2; n.y = height / 2;
          }} else {{
            const angle = (i / (nodes.length - 1)) * 2 * Math.PI;
            const dist = 120 + (i % 3) * 40;
            n.x = width / 2 + Math.cos(angle) * dist;
            n.y = height / 2 + Math.sin(angle) * dist;
          }}
          n.vx = 0; n.vy = 0;
        }});
      }};
    }})();
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
