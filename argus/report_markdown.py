"""Markdown investigation report generator for Argus OSINT CLI.

Produces executive GitHub-Flavored Markdown dossiers suitable for Git repos,
Obsidian vaults, and automated documentation pipelines.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from argus.models import InvestigationReport


def render_markdown_report(report: InvestigationReport) -> str:
    """Generate structured Markdown dossier from InvestigationReport."""
    lines: list[str] = []

    # Title & Metadata
    lines.append(f"# Argus OSINT Dossier: `{report.target}`")
    lines.append("")
    lines.append(f"> **Entity Type**: `{report.target_type.upper()}` | **Scan UTC**: `{report.scan_timestamp_utc}` | **Duration**: `{report.scan_duration_seconds}s`")
    if report.correlation:
        lines.append(f"> **Confidence Assessment**: **{report.correlation.confidence_level}** ({report.correlation.confidence_score}%)")
    lines.append("")

    # Snowflake Details (if present)
    if report.snowflake:
        lines.append("## Discord Snowflake Telemetry")
        lines.append("")
        lines.append("| Parameter | Value |")
        lines.append("| :--- | :--- |")
        lines.append(f"| **Snowflake ID** | `{report.snowflake.snowflake_id}` |")
        lines.append(f"| **Created UTC** | `{report.snowflake.created_at_utc}` |")
        lines.append(f"| **Account Age** | `{report.snowflake.age_human}` |")
        lines.append(f"| **Worker / Process** | `{report.snowflake.worker_id}` / `{report.snowflake.process_id}` |")
        lines.append(f"| **Increment Counter** | `{report.snowflake.increment}` |")
        lines.append("")

    # Social Profiles Table
    if report.social_profiles:
        lines.append("## Discovered Social & Community Profiles")
        lines.append("")
        lines.append(f"Total discovered accounts: **{len(report.social_profiles)}**")
        lines.append("")
        lines.append("| Platform | Status | Profile URL |")
        lines.append("| :--- | :---: | :--- |")
        for p in report.social_profiles:
            lines.append(f"| **{p.platform}** | {p.status} | [{p.url}]({p.url}) |")
        lines.append("")

    # Pivot Leads
    leads = report.pivot_leads
    has_leads = bool(
        leads.discovered_emails
        or leads.discovered_crypto
        or leads.discovered_messaging
        or leads.discovered_phones
        or leads.discovered_discord_tags
        or leads.discovered_discord_ids
        or leads.discovered_invites
    )

    if has_leads:
        lines.append("## Discovered Identity Pivots & Contact Points")
        lines.append("")

        if leads.discovered_emails:
            lines.append("### Email Addresses")
            for em in sorted(leads.discovered_emails):
                lines.append(f"- `{em}`")
            lines.append("")

        if leads.discovered_phones:
            lines.append("### Telephone Numbers")
            lines.append("| E.164 Number | Country / Region |")
            lines.append("| :--- | :--- |")
            for p in leads.discovered_phones:
                country = p.country_name or "Unknown Region"
                lines.append(f"| `{p.e164}` | {country} |")
            lines.append("")

        if leads.discovered_crypto:
            lines.append("### Cryptocurrency Wallets")
            lines.append("| Network | Address |")
            lines.append("| :--- | :--- |")
            for c in leads.discovered_crypto:
                lines.append(f"| **{c.network}** | `{c.address}` |")
            lines.append("")

        if leads.discovered_messaging:
            lines.append("### Messaging & Payment Handles")
            lines.append("| Platform | Handle | Link |")
            lines.append("| :--- | :--- | :--- |")
            for m in leads.discovered_messaging:
                link_md = f"[{m.url}]({m.url})" if m.url else "—"
                lines.append(f"| **{m.platform}** | `{m.handle}` | {link_md} |")
            lines.append("")

        if leads.discovered_discord_tags or leads.discovered_discord_ids:
            lines.append("### Discord Identity Marks")
            for t in sorted(leads.discovered_discord_tags):
                lines.append(f"- Tag: `{t}`")
            for d in sorted(leads.discovered_discord_ids):
                lines.append(f"- Snowflake ID: `{d}`")
            lines.append("")

    # Gaming Ecosystem
    if report.gaming and (report.gaming.minecraft or report.gaming.steam or report.gaming.roblox):
        lines.append("## Gaming Ecosystem")
        lines.append("")
        if report.gaming.minecraft:
            mc = report.gaming.minecraft
            lines.append(f"- **Minecraft**: `{mc.username}` (UUID: `{mc.uuid_formatted}`)")
        if report.gaming.steam:
            st = report.gaming.steam
            lines.append(f"- **Steam**: [{st.real_name or st.custom_url}]({st.profile_url}) (ID64: `{st.steam_id_64}`)")
        if report.gaming.roblox:
            rb = report.gaming.roblox
            lines.append(f"- **Roblox**: [{rb.display_name} (@{rb.username})]({rb.profile_url}) (ID: `{rb.user_id}`)")
        lines.append("")

    # Breach Exposure
    if report.breaches:
        lines.append("## Breach Database Exposure")
        lines.append("")
        lines.append("| Exposed Query | Incident / Service | Date | Data Classes |")
        lines.append("| :--- | :--- | :---: | :--- |")
        for b in report.breaches:
            dc = ", ".join(b.data_classes[:4]) if b.data_classes else "—"
            bdate = b.breach_date or "—"
            lines.append(f"| `{b.query}` | **{b.service_name}** | {bdate} | {dc} |")
        lines.append("")

    # Infostealer Intelligence
    if report.hudson_rock:
        lines.append("## Infostealer Malware Infections (Hudson Rock)")
        lines.append("")
        for hr in report.hudson_rock:
            lines.append(f"- Query: `{hr.query}` — Total Infections: **{hr.total_stealers}**")
            for inf in hr.infections:
                lines.append(f"  - System: `{inf.computer_name}` | OS: `{inf.operating_system}` | Family: `{inf.stealer_family}` | Compromised: `{inf.date_compromised}`")
        lines.append("")

    # Package Authorship
    if report.packages:
        lines.append("## Authored Software Packages")
        lines.append("")
        lines.append("| Registry | Package Name | Version | Link |")
        lines.append("| :--- | :--- | :---: | :--- |")
        for pkg in report.packages:
            lines.append(f"| **{pkg.registry}** | `{pkg.name}` | {pkg.version or '—'} | [{pkg.url}]({pkg.url}) |")
        lines.append("")

    # Domain Recon
    if report.domain_recon:
        lines.append("## Infrastructure & Domain Reconnaissance")
        lines.append("")
        for dom in report.domain_recon:
            lines.append(f"### `{dom.domain}`")
            if dom.registrar:
                lines.append(f"- Registrar: `{dom.registrar}` (Created: `{dom.created_date or 'Unknown'}`)")
            if dom.subdomains:
                lines.append("- Discovered Subdomains via Certificate Transparency:")
                for sub in dom.subdomains[:15]:
                    lines.append(f"  - `{sub}`")
            lines.append("")

    return "\n".join(lines)


def save_markdown_report(report: InvestigationReport, output_path: Path) -> Path:
    """Save markdown dossier to target file path."""
    content = render_markdown_report(report)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    return output_path
