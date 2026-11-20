"""Interactive Terminal User Interface (TUI) for Argus OSINT investigations.

Provides menu-driven exploration of investigation reports directly in the terminal,
including Snowflake telemetry, gaming profiles, crypto/messaging leads, and external indexers.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Optional

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from argus.models import InvestigationReport

console = Console()


def safe_escape(v: Any) -> str:
    """Escape arbitrary text for safe inclusion in Rich console markup."""
    if v is None:
        return ""
    return escape(str(v))


def display_overview_panel(report: InvestigationReport) -> None:
    """Render high-level investigation overview panel."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold yellow", justify="right")
    grid.add_column(style="white")

    grid.add_row("Target Identifier:", safe_escape(report.target))
    grid.add_row("Detected Entity Type:", safe_escape(report.target_type.upper()))
    grid.add_row("UTC Timestamp:", safe_escape(report.scan_timestamp_utc))
    grid.add_row("Scan Execution Time:", f"{report.scan_duration_seconds}s")
    grid.add_row("Matched Social Profiles:", str(len(report.social_profiles)))
    grid.add_row("Personal Emails:", str(len(report.pivot_leads.discovered_emails)))
    total_email_accs = sum(len(r.accounts) for r in report.email_registrations)
    if total_email_accs > 0:
        grid.add_row("Verified Email Accounts:", str(total_email_accs))
    grid.add_row("Crypto Wallet Addresses:", str(len(report.pivot_leads.discovered_crypto)))
    if report.keybase:
        grid.add_row("Keybase Identity:", f"[bold cyan]@{safe_escape(report.keybase.username)}[/bold cyan] ({len(report.keybase.proofs)} proofs)")
    if report.pgp_keys:
        grid.add_row("OpenPGP Keys:", str(len(report.pgp_keys)))
    if report.domain_recon:
        grid.add_row("Personal Domains:", str(len(report.domain_recon)))
    if report.packages:
        grid.add_row("Authored Packages:", str(len(report.packages)))
    if report.wayback_snapshots:
        grid.add_row("Historical Snapshots:", str(len(report.wayback_snapshots)))
    if report.image_metadata:
        grid.add_row("Image Metadata Reports:", str(len(report.image_metadata)))
    grid.add_row("Messaging Handles:", str(len(report.pivot_leads.discovered_messaging)))
    grid.add_row("Breach Incidents:", str(len(report.breaches)))
    total_hr = sum(h.total_stealers for h in report.hudson_rock)
    if total_hr > 0:
        grid.add_row("Infostealer Compromises:", f"[bold red]{total_hr}[/bold red]")
    if report.avatar_matches:
        grid.add_row("Avatar Perceptual Matches:", f"[bold magenta]{len(report.avatar_matches)}[/bold magenta]")
    if report.correlation:
        corr_color = "green" if report.correlation.confidence_level == "HIGH" else ("yellow" if report.correlation.confidence_level == "MEDIUM" else "red")
        grid.add_row("Identity Confidence:", f"[{corr_color} bold]{report.correlation.confidence_score}% ({safe_escape(report.correlation.confidence_level)})[/{corr_color} bold]")

    console.print(
        Panel(
            grid,
            title="[bold green]ARGUS INVESTIGATION OVERVIEW[/bold green]",
            border_style="green",
            box=box.ROUNDED,
        )
    )


def display_snowflake_panel(report: InvestigationReport) -> None:
    """Render Discord Snowflake bit-shift telemetry."""
    if not report.snowflake:
        console.print("[dim]No Discord Snowflake metadata available for this target.[/dim]")
        return

    sf = report.snowflake
    tbl = Table(box=box.SIMPLE_HEAVY, border_style="cyan", show_header=True)
    tbl.add_column("Property", style="bold cyan", width=24)
    tbl.add_column("Decoded Value", style="white")

    tbl.add_row("Snowflake ID", str(sf.snowflake_id))
    tbl.add_row("Creation Timestamp (UTC)", f"[bold green]{sf.created_at_utc}[/bold green]")
    tbl.add_row("Account Age", f"[bold yellow]{sf.age_human}[/bold yellow]")
    tbl.add_row("Internal Worker ID", str(sf.worker_id))
    tbl.add_row("Internal Process ID", str(sf.process_id))
    tbl.add_row("Sequence Increment", str(sf.increment))

    console.print(
        Panel(
            tbl,
            title="[bold cyan]Discord Snowflake Telemetry (Offline Bit-Shift Decoder)[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )


def display_discord_panel(report: InvestigationReport) -> None:
    """Render Discord profile metadata and avatar reverse search URLs."""
    if not report.discord_profile:
        console.print("[dim]No Discord REST API profile found for this target.[/dim]")
        return

    dp = report.discord_profile
    tbl = Table(box=box.SIMPLE, show_header=False)
    tbl.add_column("Field", style="bold magenta", width=22)
    tbl.add_column("Value", style="white")

    tbl.add_row("Username / Handle", f"@{safe_escape(dp.username)}")
    if dp.global_name:
        tbl.add_row("Display Name", safe_escape(dp.global_name))
    tbl.add_row("User ID", safe_escape(dp.id))
    tbl.add_row("Public Badges", ", ".join(safe_escape(b) for b in dp.badges) if dp.badges else "[dim]None[/dim]")
    if dp.avatar_url:
        tbl.add_row("Avatar CDN", safe_escape(dp.avatar_url))
    if dp.reverse_image_urls:
        riu = dp.reverse_image_urls
        rev_text = (
            f"• Google Lens: {safe_escape(riu.google_lens)}\n"
            f"• Yandex: {safe_escape(riu.yandex)}\n"
            f"• TinEye: {safe_escape(riu.tineye)}\n"
            f"• Bing Visual: {safe_escape(riu.bing_visual)}"
        )
        tbl.add_row("Reverse Image Search", rev_text)

    console.print(
        Panel(
            tbl,
            title="[bold magenta]Discord REST API Identity[/bold magenta]",
            border_style="magenta",
            box=box.ROUNDED,
        )
    )


def display_gaming_panel(report: InvestigationReport) -> None:
    """Render gaming ecosystem profiles (Minecraft, Steam, Roblox)."""
    if not report.gaming or (not report.gaming.minecraft and not report.gaming.steam and not report.gaming.roblox):
        console.print("[dim]No public Minecraft, Steam, or Roblox profiles matched this handle.[/dim]")
        return

    tbl = Table(box=box.SIMPLE_HEAVY, border_style="bright_blue", show_header=True)
    tbl.add_column("Gaming Platform", style="bold bright_blue", width=20)
    tbl.add_column("Identity & Identifiers", style="white")

    if report.gaming.minecraft:
        mc = report.gaming.minecraft
        details = (
            f"Player Name: [bold]{safe_escape(mc.username)}[/bold]\n"
            f"Formatted UUID: [cyan]{safe_escape(mc.uuid_formatted)}[/cyan]\n"
            f"Raw Mojang ID: {safe_escape(mc.uuid)}\n"
            f"Skin Render CDN: [dim]{safe_escape(mc.skin_render_url)}[/dim]"
        )
        tbl.add_row("Minecraft (Mojang)", details)

    if report.gaming.steam:
        st = report.gaming.steam
        status = "[bold green]Clean[/bold green]" if not st.vac_banned else "[bold red]VAC BANNED[/bold red]"
        details = (
            f"Custom URL: [bold]{safe_escape(st.custom_url)}[/bold]\n"
            f"SteamID64: [cyan]{safe_escape(st.steam_id_64)}[/cyan]\n"
            f"Profile URL: {safe_escape(st.profile_url)}\n"
            f"VAC Ban Status: {status}\n"
            f"Online State: {safe_escape(st.online_state or 'Unknown')}"
        )
        if st.real_name:
            details += f"\nReal Name: {safe_escape(st.real_name)}"
        if st.location:
            details += f"\nLocation: {safe_escape(st.location)}"
        tbl.add_row("Steam Community", details)

    if report.gaming.roblox:
        rb = report.gaming.roblox
        badge_text = " [bold green][Verified][/bold green]" if rb.has_verified_badge else ""
        ban_text = " [bold red][BANNED][/bold red]" if rb.is_banned else ""
        details = (
            f"Username: [bold]{safe_escape(rb.username)}[/bold]{badge_text}{ban_text}\n"
            f"Display Name: [cyan]{safe_escape(rb.display_name)}[/cyan]\n"
            f"User ID: [yellow]{rb.user_id}[/yellow]\n"
            f"Profile Link: {safe_escape(rb.profile_url)}"
        )
        if rb.description:
            desc_prev = rb.description if len(rb.description) <= 120 else f"{rb.description[:117]}..."
            details += f"\nBio: [dim]{safe_escape(desc_prev)}[/dim]"
        tbl.add_row("Roblox", details)

    console.print(
        Panel(
            tbl,
            title="[bold bright_blue]Gaming Ecosystem Identity Pivots[/bold bright_blue]",
            border_style="bright_blue",
            box=box.ROUNDED,
        )
    )


def display_leads_panel(report: InvestigationReport) -> None:
    """Render all extracted leads (emails, crypto, messaging, tags, invites)."""
    leads = report.pivot_leads
    tbl = Table(box=box.SIMPLE, show_header=True)
    tbl.add_column("Lead Category", style="bold yellow", width=24)
    tbl.add_column("Discovered Data", style="white")

    if leads.discovered_emails:
        tbl.add_row("Personal Emails", "\n".join(f"[bold green]{safe_escape(em)}[/bold green]" for em in leads.discovered_emails))
    if report.email_registrations:
        recon_lines = []
        for r in report.email_registrations:
            for a in r.accounts:
                rec = f" [dim](Recovery: {safe_escape(a.email_recovery)})[/dim]" if a.email_recovery else ""
                recon_lines.append(f"• [cyan]{safe_escape(a.platform)}[/cyan] ({safe_escape(a.domain)}){rec}")
        if recon_lines:
            tbl.add_row("Email Accounts (Holehe)", "\n".join(recon_lines))
    if report.avatar_matches:
        match_lines = [f"• {safe_escape(m.platform_a)} <-> {safe_escape(m.platform_b)} (distance: {m.hamming_distance}/64 bits)" for m in report.avatar_matches]
        tbl.add_row("Avatar Matches (dHash)", "\n".join(match_lines))
    if leads.discovered_crypto:
        crypto_lines = [f"[{safe_escape(c.network)}] [cyan]{safe_escape(c.address)}[/cyan]" for c in leads.discovered_crypto]
        tbl.add_row("Crypto Wallets", "\n".join(crypto_lines))
    if leads.discovered_messaging:
        msg_lines = [f"[{safe_escape(m.platform)}] [magenta]{safe_escape(m.handle)}[/magenta]" for m in leads.discovered_messaging]
        tbl.add_row("Messaging Handles", "\n".join(msg_lines))
    if leads.discovered_phones:
        phone_lines = [f"{safe_escape(p.e164)} ({safe_escape(p.country_name or 'Unknown Region')})" for p in leads.discovered_phones]
        tbl.add_row("Telephone Numbers", "\n".join(phone_lines))
    if leads.discovered_custom:
        custom_lines = [f"[{safe_escape(c.get('category', 'Custom'))}] {safe_escape(c.get('name'))}: {safe_escape(c.get('value'))}" for c in leads.discovered_custom]
        tbl.add_row("Custom Matches", "\n".join(custom_lines))
    if leads.discovered_discord_ids:
        tbl.add_row("Discovered Discord IDs", ", ".join(safe_escape(i) for i in leads.discovered_discord_ids))
    if leads.discovered_discord_tags:
        tbl.add_row("Legacy Discord Tags", ", ".join(safe_escape(t) for t in leads.discovered_discord_tags))
    if leads.discovered_invites:
        tbl.add_row("Discord Server Invites", "\n".join(safe_escape(inv) for inv in leads.discovered_invites))

    if tbl.row_count == 0:
        console.print("[dim]No high-confidence pivot leads were extracted for this target.[/dim]")
        return

    console.print(
        Panel(
            tbl,
            title="[bold yellow]Extracted High-Confidence Pivot Leads[/bold yellow]",
            border_style="yellow",
            box=box.ROUNDED,
        )
    )


def display_profiles_panel(report: InvestigationReport) -> None:
    """Render matched social profiles from Maigret sweep."""
    if not report.social_profiles:
        console.print("[dim]No matched social profiles available.[/dim]")
        return

    tbl = Table(box=box.SIMPLE, show_header=True)
    tbl.add_column("Platform", style="bold cyan", width=22)
    tbl.add_column("Status", style="green", width=14)
    tbl.add_column("Profile URL / Handle", style="white")

    for p in report.social_profiles:
        tbl.add_row(safe_escape(p.platform), safe_escape(p.status), safe_escape(p.url))

    console.print(
        Panel(
            tbl,
            title=f"[bold cyan]Matched Cross-Platform Profiles ({len(report.social_profiles)})[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )


def display_enrichment_panel(report: InvestigationReport) -> None:
    """Render CordCat historical records, breaches, and GitHub audit."""
    # 1. CordCat
    if report.cordcat and (report.cordcat.historical_usernames or report.cordcat.fivem_identifiers):
        cc = report.cordcat
        c_table = Table(box=box.SIMPLE, show_header=False)
        c_table.add_column("Field", style="bold red", width=22)
        c_table.add_column("Data", style="white")
        if cc.historical_usernames:
            c_table.add_row("Historical Aliases", ", ".join(safe_escape(u) for u in cc.historical_usernames))
        if cc.fivem_identifiers:
            c_table.add_row("FiveM Identifiers", ", ".join(safe_escape(f) for f in cc.fivem_identifiers))
        console.print(Panel(c_table, title="[bold red]CordCat Indexer[/bold red]", border_style="red", box=box.ROUNDED))

    # 2. Breaches
    if report.breaches:
        b_table = Table(box=box.SIMPLE_HEAVY, border_style="red", show_header=True)
        b_table.add_column("Compromised Service", style="bold red", width=22)
        b_table.add_column("Date", style="white", width=12)
        b_table.add_column("Query", style="cyan", width=24)
        b_table.add_column("Exposed Data Classes", style="yellow")
        for b in report.breaches:
            classes = ", ".join(safe_escape(c) for c in b.data_classes) if b.data_classes else "[dim]Unknown[/dim]"
            b_table.add_row(safe_escape(b.service_name), safe_escape(b.breach_date or "N/A"), safe_escape(b.query), classes)
        console.print(Panel(b_table, title=f"[bold red]Breach Exposure Records ({len(report.breaches)})[/bold red]", border_style="red", box=box.ROUNDED))

    # 3. GitHub
    if report.github_pivot:
        gh = report.github_pivot
        g_table = Table(box=box.SIMPLE, show_header=False)
        g_table.add_column("Field", style="bold green", width=22)
        g_table.add_column("Data", style="white")
        g_table.add_row("Username", f"@{safe_escape(gh.username)}")
        g_table.add_row("Profile URL", safe_escape(gh.profile_url))
        if gh.commit_emails:
            g_table.add_row("Commit Author Emails", ", ".join(safe_escape(e) for e in gh.commit_emails))
        if gh.created_at:
            g_table.add_row("Creation Date", safe_escape(gh.created_at))
        if gh.age_comparison_discord:
            g_table.add_row("Timeline vs Discord", safe_escape(gh.age_comparison_discord))
        console.print(Panel(g_table, title="[bold green]GitHub Public Activity Audit[/bold green]", border_style="green", box=box.ROUNDED))

    # 4. Hudson Rock
    hr_infections = [inf for r in report.hudson_rock for inf in r.infections]
    if hr_infections:
        hr_tbl = Table(box=box.SIMPLE_HEAVY, border_style="red", show_header=True)
        hr_tbl.add_column("Malware Family", style="bold red")
        hr_tbl.add_column("Compromise Date", style="white")
        hr_tbl.add_column("Computer / OS", style="dim white")
        hr_tbl.add_column("Compromised Logins Sample", style="yellow")
        for inf in hr_infections:
            comp_os = f"{safe_escape(inf.computer_name or 'N/A')} ({safe_escape(inf.operating_system or 'N/A')})"
            logins = ", ".join(safe_escape(l) for l in inf.top_logins[:4]) if inf.top_logins else "N/A"
            hr_tbl.add_row(safe_escape(inf.stealer_family or "Unknown"), safe_escape(inf.date_compromised or "N/A"), comp_os, logins)
        console.print(Panel(hr_tbl, title=f"[bold red]Hudson Rock Infostealer Malware Compromises ({len(hr_infections)})[/bold red]", border_style="red", box=box.ROUNDED))

    # 5. Keybase & OpenPGP
    if report.keybase or report.pgp_keys:
        kp_tbl = Table(box=box.SIMPLE, show_header=True)
        kp_tbl.add_column("Source", style="bold cyan", width=18)
        kp_tbl.add_column("Verified Identity & Keys", style="white")
        if report.keybase:
            kb = report.keybase
            proofs_summary = ", ".join(f"{safe_escape(p.service)}:{safe_escape(p.username)}" for p in kb.proofs) if kb.proofs else "None"
            kp_tbl.add_row("Keybase", f"@{safe_escape(kb.username)} ({safe_escape(kb.full_name or 'N/A')})\nProofs: {proofs_summary}")
        for pgp in report.pgp_keys:
            identities = ", ".join(safe_escape(i) for i in pgp.identities) if pgp.identities else "Unspecified"
            kp_tbl.add_row("OpenPGP", f"{safe_escape(pgp.key_id_or_fingerprint)} ({identities})")
        console.print(Panel(kp_tbl, title="[bold cyan]Cryptographic Identities (Keybase & OpenPGP)[/bold cyan]", border_style="cyan", box=box.ROUNDED))

    # 6. Personal Domain Recon
    if report.domain_recon:
        dr_tbl = Table(box=box.SIMPLE, show_header=True)
        dr_tbl.add_column("Domain", style="bold green", width=22)
        dr_tbl.add_column("Registrar / Date", style="white", width=26)
        dr_tbl.add_column("Subdomains (crt.sh)", style="cyan")
        for d in report.domain_recon:
            subs = ", ".join(safe_escape(s) for s in d.subdomains[:6]) if d.subdomains else "None"
            dr_tbl.add_row(safe_escape(d.domain), f"{safe_escape(d.registrar or 'N/A')}\n{safe_escape(d.created_date or 'N/A')}", subs)
        console.print(Panel(dr_tbl, title=f"[bold green]Personal Domain & Infrastructure Recon ({len(report.domain_recon)})[/bold green]", border_style="green", box=box.ROUNDED))

    # 7. Package Registries
    if report.packages:
        pkg_tbl = Table(box=box.SIMPLE, show_header=True)
        pkg_tbl.add_column("Registry", style="bold magenta", width=12)
        pkg_tbl.add_column("Package Name", style="bold white", width=20)
        pkg_tbl.add_column("Author Email", style="green")
        for pkg in report.packages:
            pkg_tbl.add_row(safe_escape(pkg.registry), safe_escape(pkg.name), safe_escape(pkg.author_email or "N/A"))
        console.print(Panel(pkg_tbl, title=f"[bold magenta]Package Registry Footprint ({len(report.packages)})[/bold magenta]", border_style="magenta", box=box.ROUNDED))

    # 8. Wayback Machine Snapshots
    if report.wayback_snapshots:
        wb_tbl = Table(box=box.SIMPLE, show_header=True)
        wb_tbl.add_column("Timestamp", style="bold yellow", width=18)
        wb_tbl.add_column("Target URL", style="white", width=35)
        wb_tbl.add_column("Archive Snapshot", style="blue underline")
        for snap in report.wayback_snapshots[:6]:
            wb_tbl.add_row(safe_escape(snap.timestamp), safe_escape(snap.original_url), safe_escape(snap.archive_url))
        console.print(Panel(wb_tbl, title=f"[bold yellow]Internet Archive Historical Snapshots ({len(report.wayback_snapshots)})[/bold yellow]", border_style="yellow", box=box.ROUNDED))

    if (
        not report.cordcat
        and not report.breaches
        and not report.github_pivot
        and not report.hudson_rock
        and not report.keybase
        and not report.pgp_keys
        and not report.domain_recon
        and not report.packages
        and not report.wayback_snapshots
    ):
        console.print("[dim]No threat, identity, or infrastructure indexer hits recorded.[/dim]")


def display_diagnostics_panel(report: InvestigationReport) -> None:
    """Render module diagnostic statuses."""
    if not report.module_statuses:
        console.print("[dim]No module execution statuses recorded.[/dim]")
        return

    tbl = Table(box=box.SIMPLE, show_header=True)
    tbl.add_column("Module Name", style="bold white", width=28)
    tbl.add_column("Status", style="bold", width=14)
    tbl.add_column("Diagnostics Message", style="dim white")

    for m in report.module_statuses:
        status_color = "green" if m.status == "success" else ("yellow" if m.status == "skipped" else "red")
        tbl.add_row(safe_escape(m.module_name), f"[{status_color}]{safe_escape(m.status.upper())}[/{status_color}]", safe_escape(m.message) or "")

    console.print(
        Panel(
            tbl,
            title="[bold white]Module Execution Diagnostics[/bold white]",
            border_style="white",
            box=box.ROUNDED,
        )
    )


def run_interactive_tui(report: InvestigationReport) -> None:
    """Run interactive terminal navigation loop for an investigation report."""
    while True:
        console.clear()
        console.print(
            Panel(
                Text(
                    f"ARGUS INTERACTIVE INVESTIGATION EXPLORER\n"
                    f"Target: {report.target} ({report.target_type.upper()}) | Scanned: {report.scan_timestamp_utc}",
                    justify="center",
                    style="bold cyan",
                ),
                box=box.HEAVY,
                border_style="cyan",
            )
        )

        menu = Table(box=box.ROUNDED, border_style="dim", show_header=False)
        menu.add_column("Key", style="bold yellow", width=6)
        menu.add_column("Navigation Section", style="white")

        menu.add_row("[1]", "Investigation Overview & Target Telemetry")
        menu.add_row("[2]", "Discord Snowflake Bit-Shift Telemetry")
        menu.add_row("[3]", "Discord REST API Profile & Avatar Searches")
        menu.add_row("[4]", "Gaming Ecosystem Identity (Minecraft & Steam)")
        menu.add_row("[5]", "Extracted Pivot Leads (Emails, Crypto, Messaging)")
        menu.add_row("[6]", f"Matched Social Profiles ({len(report.social_profiles)})")
        menu.add_row("[7]", "Threat & Transparency Indexers (CordCat, Breaches, GitHub)")
        menu.add_row("[8]", "Module Execution Diagnostics")
        menu.add_row("[9]", "Open HTML in Browser")
        menu.add_row("[0]", "Exit Explorer")

        console.print(menu)
        console.print("")

        try:
            choice = console.input("[bold cyan]Select section [0-9] (or 'q' to quit): [/bold cyan]").strip().lower()
        except (KeyboardInterrupt, EOFError):
            break

        if choice in ("0", "q", "exit", "quit"):
            break

        console.clear()
        if choice == "1":
            display_overview_panel(report)
        elif choice == "2":
            display_snowflake_panel(report)
        elif choice == "3":
            display_discord_panel(report)
        elif choice == "4":
            display_gaming_panel(report)
        elif choice == "5":
            display_leads_panel(report)
        elif choice == "6":
            display_profiles_panel(report)
        elif choice == "7":
            display_enrichment_panel(report)
        elif choice == "8":
            display_diagnostics_panel(report)
        elif choice == "9":
            from argus.report_html import view_html_report
            opened_path = view_html_report(report)
            console.print(f"[bold green]HTML Report opened in browser:[/bold green] {opened_path.resolve()}")
        else:
            console.print("[bold red]Invalid option. Please choose a number from 0 to 9.[/bold red]")

        console.print("")
        try:
            console.input("[dim]Press Enter to return to main menu...[/dim]")
        except (KeyboardInterrupt, EOFError):
            break

    console.print("[dim]Exited Argus Explorer.[/dim]")
