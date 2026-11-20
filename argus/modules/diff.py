"""Investigation report comparison and differential analysis module for Argus.

Enables analysts to track targets over time by diffing two historical JSON reports,
highlighting newly surfaced accounts, deleted profiles, and changing identity pivots.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from argus.models import InvestigationReport


def safe_escape(v: Any) -> str:
    """Escape arbitrary text for safe Rich markup interpolation."""
    if v is None:
        return ""
    return escape(str(v))


def compare_investigation_reports(
    report_a: InvestigationReport,
    report_b: InvestigationReport,
) -> dict[str, Any]:
    """Calculate structured difference between two Argus investigation reports."""
    # 1. Target and timestamp metadata
    meta = {
        "target_a": report_a.target,
        "target_b": report_b.target,
        "timestamp_a": report_a.scan_timestamp_utc,
        "timestamp_b": report_b.scan_timestamp_utc,
    }

    # 2. Social profiles comparison
    profiles_a = {(p.platform.lower(), p.url.rstrip("/")) for p in report_a.social_profiles}
    profiles_b = {(p.platform.lower(), p.url.rstrip("/")) for p in report_b.social_profiles}

    added_profiles = [
        p for p in report_b.social_profiles
        if (p.platform.lower(), p.url.rstrip("/")) not in profiles_a
    ]
    removed_profiles = [
        p for p in report_a.social_profiles
        if (p.platform.lower(), p.url.rstrip("/")) not in profiles_b
    ]

    # 3. Discovered emails
    emails_a = set(report_a.pivot_leads.discovered_emails)
    emails_b = set(report_b.pivot_leads.discovered_emails)
    added_emails = sorted(list(emails_b - emails_a))
    removed_emails = sorted(list(emails_a - emails_b))

    # 4. Crypto addresses
    crypto_a = {(c.network, c.address.lower()) for c in report_a.pivot_leads.discovered_crypto}
    crypto_b = {(c.network, c.address.lower()) for c in report_b.pivot_leads.discovered_crypto}
    added_crypto = [c for c in report_b.pivot_leads.discovered_crypto if (c.network, c.address.lower()) not in crypto_a]
    removed_crypto = [c for c in report_a.pivot_leads.discovered_crypto if (c.network, c.address.lower()) not in crypto_b]

    # 5. Messaging & payment handles
    msg_a = {(m.platform, m.handle.lower()) for m in report_a.pivot_leads.discovered_messaging}
    msg_b = {(m.platform, m.handle.lower()) for m in report_b.pivot_leads.discovered_messaging}
    added_msg = [m for m in report_b.pivot_leads.discovered_messaging if (m.platform, m.handle.lower()) not in msg_a]
    removed_msg = [m for m in report_a.pivot_leads.discovered_messaging if (m.platform, m.handle.lower()) not in msg_b]

    # 6. Phone numbers
    phones_a = {p.e164 for p in report_a.pivot_leads.discovered_phones}
    phones_b = {p.e164 for p in report_b.pivot_leads.discovered_phones}
    added_phones = [p for p in report_b.pivot_leads.discovered_phones if p.e164 not in phones_a]
    removed_phones = [p for p in report_a.pivot_leads.discovered_phones if p.e164 not in phones_b]

    # 7. Breaches
    breaches_a = {(b.query.lower(), b.service_name.lower()) for b in report_a.breaches}
    breaches_b = {(b.query.lower(), b.service_name.lower()) for b in report_b.breaches}
    added_breaches = [b for b in report_b.breaches if (b.query.lower(), b.service_name.lower()) not in breaches_a]
    removed_breaches = [b for b in report_a.breaches if (b.query.lower(), b.service_name.lower()) not in breaches_b]

    # 8. Correlation score delta
    score_a = report_a.correlation.confidence_score if report_a.correlation else 0
    score_b = report_b.correlation.confidence_score if report_b.correlation else 0

    return {
        "meta": meta,
        "profiles": {
            "added": [{"platform": p.platform, "url": p.url} for p in added_profiles],
            "removed": [{"platform": p.platform, "url": p.url} for p in removed_profiles],
        },
        "emails": {
            "added": added_emails,
            "removed": removed_emails,
        },
        "crypto": {
            "added": [{"network": c.network, "address": c.address} for c in added_crypto],
            "removed": [{"network": c.network, "address": c.address} for c in removed_crypto],
        },
        "messaging": {
            "added": [{"platform": m.platform, "handle": m.handle} for m in added_msg],
            "removed": [{"platform": m.platform, "handle": m.handle} for m in removed_msg],
        },
        "phones": {
            "added": [{"e164": p.e164, "country": p.country_name} for p in added_phones],
            "removed": [{"e164": p.e164, "country": p.country_name} for p in removed_phones],
        },
        "breaches": {
            "added": [{"service": b.service_name, "query": b.query} for b in added_breaches],
            "removed": [{"service": b.service_name, "query": b.query} for b in removed_breaches],
        },
        "score_delta": {
            "score_a": score_a,
            "score_b": score_b,
            "delta": score_b - score_a,
        },
    }


def render_diff_rich(diff: dict[str, Any], console: Optional[Console] = None) -> None:
    """Render a differential analysis report to the Rich terminal console."""
    out = console or Console()
    meta = diff["meta"]

    # Header Panel
    out.print(
        Panel(
            f"[bold cyan]Argus Investigation Diff[/bold cyan]\n"
            f"Baseline: [yellow]{safe_escape(meta['target_a'])}[/yellow] ({safe_escape(meta['timestamp_a'])})\n"
            f"Compared: [cyan]{safe_escape(meta['target_b'])}[/cyan] ({safe_escape(meta['timestamp_b'])})",
            border_style="cyan",
            title="[bold yellow]Target Comparison[/bold yellow]",
        )
    )

    # Score Delta
    score = diff.get("score_delta", {})
    delta = score.get("delta", 0)
    delta_str = f"+{delta}%" if delta > 0 else f"{delta}%"
    delta_color = "green" if delta > 0 else ("red" if delta < 0 else "white")
    out.print(f"Confidence Assessment: {score.get('score_a')}% ➔ {score.get('score_b')}% ([{delta_color}]{delta_str}[/{delta_color}])\n")

    # Main Changes Table
    table = Table(
        box=box.ROUNDED,
        header_style="bold magenta",
        title="Surfaced Intelligence Changes",
        expand=True,
    )
    table.add_column("Category", style="cyan", width=18)
    table.add_column("Change", width=10)
    table.add_column("Details", style="white")

    has_changes = False

    # Profiles
    for p in diff["profiles"]["added"]:
        has_changes = True
        table.add_row("Social Profile", "[bold green]+ ADDED[/bold green]", f"{safe_escape(p['platform'])}: {safe_escape(p['url'])}")
    for p in diff["profiles"]["removed"]:
        has_changes = True
        table.add_row("Social Profile", "[bold red]- REMOVED[/bold red]", f"{safe_escape(p['platform'])}: {safe_escape(p['url'])}")

    # Emails
    for em in diff["emails"]["added"]:
        has_changes = True
        table.add_row("Email Address", "[bold green]+ ADDED[/bold green]", safe_escape(em))
    for em in diff["emails"]["removed"]:
        has_changes = True
        table.add_row("Email Address", "[bold red]- REMOVED[/bold red]", safe_escape(em))

    # Crypto
    for c in diff["crypto"]["added"]:
        has_changes = True
        table.add_row("Crypto Wallet", "[bold green]+ ADDED[/bold green]", f"{safe_escape(c['network'])}: {safe_escape(c['address'])}")
    for c in diff["crypto"]["removed"]:
        has_changes = True
        table.add_row("Crypto Wallet", "[bold red]- REMOVED[/bold red]", f"{safe_escape(c['network'])}: {safe_escape(c['address'])}")

    # Messaging / Payment
    for m in diff["messaging"]["added"]:
        has_changes = True
        table.add_row("Handle / Payment", "[bold green]+ ADDED[/bold green]", f"{safe_escape(m['platform'])}: {safe_escape(m['handle'])}")
    for m in diff["messaging"]["removed"]:
        has_changes = True
        table.add_row("Handle / Payment", "[bold red]- REMOVED[/bold red]", f"{safe_escape(m['platform'])}: {safe_escape(m['handle'])}")

    # Phones
    for p in diff["phones"]["added"]:
        has_changes = True
        table.add_row("Phone Number", "[bold green]+ ADDED[/bold green]", f"{safe_escape(p['e164'])} ({safe_escape(p.get('country') or 'Unknown')})")
    for p in diff["phones"]["removed"]:
        has_changes = True
        table.add_row("Phone Number", "[bold red]- REMOVED[/bold red]", f"{safe_escape(p['e164'])} ({safe_escape(p.get('country') or 'Unknown')})")

    # Breaches
    for b in diff["breaches"]["added"]:
        has_changes = True
        table.add_row("Breach Incident", "[bold green]+ NEW PWN[/bold green]", f"{safe_escape(b['service'])} ({safe_escape(b['query'])})")

    if has_changes:
        out.print(table)
    else:
        out.print("[dim]No structural changes detected between investigation snapshots.[/dim]")
