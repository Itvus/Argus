"""CLI entry point, Rich terminal presentation, progress tracking, and manual page for argus."""

from __future__ import annotations

import argus.compat  # noqa: F401 - apply Windows asyncio patches before any event loops run
from argus.compat import run_async

import asyncio
import io
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable, Optional

import typer
from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text
from rich.style import Style
from rich.markup import escape

from argus import __version__
from argus.config import _discover_and_load_env, get_config
from argus.models import InvestigationReport
from argus.modules.discord_api import fetch_discord_profile
from argus.modules.enrichment import query_cordcat
from argus.modules.snowflake import decode_snowflake, is_valid_snowflake
from argus.orchestrator import InvestigationOrchestrator, ProgressCallback

# Ensure UTF-8 output encoding across Windows PowerShell and CMD environments
if sys.platform == "win32":
    try:
        if isinstance(sys.stdout, io.TextIOWrapper):
            sys.stdout.reconfigure(encoding="utf-8")
        if isinstance(sys.stderr, io.TextIOWrapper):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console(highlight=False)

# Universal -h and --help flag support across root and subcommands
CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}

app = typer.Typer(
    name="argus",
    help="Fast, modular OSINT tool for Discord Snowflakes, usernames, and cross-platform pivoting.",
    add_completion=False,
    no_args_is_help=True,
    context_settings=CONTEXT_SETTINGS,
)


def print_banner() -> None:
    """Render tool ASCII banner."""
    banner = Text()
    banner.append("    _   ___  ___ _   _ ___ \n", style="bold cyan")
    banner.append("   /_\\ | _ \\/ __| | | / __|\n", style="bold cyan")
    banner.append("  / _ \\|   / (_ | |_| \\__ \\\n", style="bold blue")
    banner.append(" /_/ \\_\\_|_\\\\___|\\___/|___/\n", style="bold magenta")
    banner.append(f" [ Argus OSINT & Cross-Platform Pivoting CLI v{__version__} ]\n", style="dim white")
    console.print(banner)


def version_callback(value: bool) -> None:
    """Print version information and exit."""
    if value:
        print_banner()
        console.print(f"[bold cyan]argus[/bold cyan] version [bold green]{__version__}[/bold green]")
        raise typer.Exit()


@app.callback(context_settings=CONTEXT_SETTINGS)
def main(
    version: Optional[bool] = typer.Option(
        None,
        "-v",
        "--version",
        help="Show version information and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """Argus: Fast, modular OSINT CLI for Discord Snowflakes, usernames, and cross-platform pivoting."""
    pass


def run_with_progress(
    coro_fn: Callable[[ProgressCallback], Any],
    initial_phase: str,
    initial_service: str,
) -> Any:
    """Execute async task with an active progress bar and sub-service indicator."""
    progress = Progress(
        SpinnerColumn(spinner_name="dots", style="bold cyan"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=35, complete_style="green", finished_style="bold green"),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    )
    task_id = progress.add_task(initial_phase, total=1)
    current_service = initial_service

    def make_layout() -> Table:
        grid = Table.grid(padding=(0, 1))
        grid.add_row(progress)
        grid.add_row(f"  [dim]Scanning Service:[/dim] [bold yellow]{current_service}[/bold yellow]")
        return grid

    with Live(make_layout(), console=console, refresh_per_second=12, transient=True) as live:
        def on_progress(phase: str, completed: int, total: int, service: str) -> None:
            nonlocal current_service
            current_service = service
            progress.update(
                task_id,
                description=f"[bold cyan]{phase}",
                completed=completed,
                total=total if total > 0 else 1,
            )
            live.update(make_layout())

        result = run_async(coro_fn(on_progress))

    return result


def safe_escape(v: Any) -> str:
    """Escape arbitrary text for safe inclusion in Rich console markup."""
    if v is None:
        return ""
    return escape(str(v))


def make_link(url: Optional[str], label: Optional[str] = None) -> Text | str:
    """Create a safe clickable link for Rich console."""
    if not url:
        return ""
    display_label = label if label is not None else url
    return Text(display_label, style=Style(link=url, underline=True, color="blue"))


def render_report_rich(report: InvestigationReport) -> None:
    """Render comprehensive multi-panel terminal report using Rich."""
    # 1. Target Header Panel
    target_header = Table.grid(padding=(0, 2))
    target_header.add_column(style="bold yellow", justify="right")
    target_header.add_column(style="white")
    target_header.add_row("Investigative Target:", safe_escape(report.target))
    target_header.add_row("Detected Entity Type:", f"[bold cyan]{safe_escape(report.target_type.upper())}[/bold cyan]")
    target_header.add_row("Scan Execution Time:", f"{report.scan_duration_seconds}s")
    target_header.add_row("Timestamp (UTC):", safe_escape(report.scan_timestamp_utc))

    console.print(
        Panel(
            target_header,
            title="[bold green]ARGUS INVESTIGATION SUMMARY[/bold green]",
            border_style="green",
            box=box.ROUNDED,
        )
    )

    # 1b. Identity Correlation & Confidence Assessment
    if report.correlation:
        corr = report.correlation
        color = "green" if corr.confidence_level == "HIGH" else ("yellow" if corr.confidence_level == "MEDIUM" else "red")
        reasons_text = "\n".join(f"• {safe_escape(r)}" for r in corr.reasons)
        corr_table = Table.grid(padding=(0, 2))
        corr_table.add_column(style="bold white", width=22)
        corr_table.add_column()
        corr_table.add_row("Confidence Rating:", f"[{color} bold]{corr.confidence_score}% ({safe_escape(corr.confidence_level)})[/{color} bold]")
        corr_table.add_row("Correlation Evidence:", reasons_text)
        console.print(
            Panel(
                corr_table,
                title=f"[{color} bold]Target Identity Correlation & Confidence Assessment[/{color} bold]",
                border_style=color,
                box=box.ROUNDED,
            )
        )

    # 2. Discord Snowflake Analysis
    if report.snowflake:
        sf = report.snowflake
        sf_table = Table(box=box.SIMPLE_HEAVY, border_style="cyan", show_header=True)
        sf_table.add_column("Property", style="bold cyan", width=22)
        sf_table.add_column("Decoded Value", style="white")

        sf_table.add_row("Snowflake ID", str(sf.snowflake_id))
        sf_table.add_row("Creation Timestamp (UTC)", f"[bold green]{sf.created_at_utc}[/bold green]")
        sf_table.add_row("Account Age", f"[bold yellow]{sf.age_human}[/bold yellow]")
        sf_table.add_row("Internal Worker ID", str(sf.worker_id))
        sf_table.add_row("Internal Process ID", str(sf.process_id))
        sf_table.add_row("Sequence Increment", str(sf.increment))

        console.print(
            Panel(
                sf_table,
                title="[bold cyan]Discord Snowflake Metadata (Offline Bit-Shift Decoder)[/bold cyan]",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )

    # 3. Discord Public API Profile
    if report.discord_profile:
        dp = report.discord_profile
        dp_table = Table(box=box.SIMPLE, show_header=False)
        dp_table.add_column("Field", style="bold magenta", width=22)
        dp_table.add_column("Value", style="white")

        handle_display = f"@{safe_escape(dp.username)}"
        if dp.discriminator and dp.discriminator != "0":
            handle_display += f"#{safe_escape(dp.discriminator)}"
        dp_table.add_row("Username / Handle", handle_display)

        if dp.global_name:
            dp_table.add_row("Global Display Name", safe_escape(dp.global_name))
        dp_table.add_row("User ID", safe_escape(dp.id))

        badges_str = ", ".join(safe_escape(b) for b in dp.badges) if dp.badges else "[dim]None detected[/dim]"
        dp_table.add_row("Public Badges", f"[bold yellow]{badges_str}[/bold yellow]")

        if dp.banner_color:
            dp_table.add_row("Banner / Accent Color", safe_escape(dp.banner_color))

        if dp.avatar_url:
            dp_table.add_row("Avatar CDN (1024px)", make_link(dp.avatar_url))

        if dp.banner_url:
            dp_table.add_row("Banner CDN (1024px)", make_link(dp.banner_url))

        if dp.bio:
            dp_table.add_row("Profile Bio / About", safe_escape(dp.bio))

        # Reverse Image Search URLs
        if dp.reverse_image_urls:
            riu = dp.reverse_image_urls
            rev_text = Text()
            rev_text.append("• Google Lens: ", style="bold")
            rev_text.append(f"{riu.google_lens}\n", style="blue underline")
            rev_text.append("• Yandex: ", style="bold")
            rev_text.append(f"{riu.yandex}\n", style="blue underline")
            rev_text.append("• TinEye: ", style="bold")
            rev_text.append(f"{riu.tineye}\n", style="blue underline")
            rev_text.append("• Bing Visual: ", style="bold")
            rev_text.append(f"{riu.bing_visual}", style="blue underline")
            dp_table.add_row("Avatar Reverse Search", rev_text)

        console.print(
            Panel(
                dp_table,
                title="[bold magenta]Discord Public Profile Metadata[/bold magenta]",
                border_style="magenta",
                box=box.ROUNDED,
            )
        )

    # 4. CordCat Historical & FiveM Records
    if report.cordcat and (report.cordcat.historical_usernames or report.cordcat.fivem_identifiers):
        cc = report.cordcat
        cc_table = Table(box=box.SIMPLE, show_header=False)
        cc_table.add_column("Field", style="bold red", width=22)
        cc_table.add_column("Data", style="white")

        if cc.historical_usernames:
            cc_table.add_row("Historical Aliases", ", ".join(safe_escape(u) for u in cc.historical_usernames))
        if cc.fivem_identifiers:
            cc_table.add_row("FiveM / CFX IDs", ", ".join(safe_escape(f) for f in cc.fivem_identifiers))

        console.print(
            Panel(
                cc_table,
                title="[bold red]CordCat Community & Historical Records[/bold red]",
                border_style="red",
                box=box.ROUNDED,
            )
        )

    # 5. Cross-Platform Social Profiles (Maigret)
    if report.social_profiles:
        soc_table = Table(box=box.SIMPLE_HEAVY, border_style="blue", show_header=True)
        soc_table.add_column("Platform", style="bold cyan", width=18)
        soc_table.add_column("Status", style="green", width=12)
        soc_table.add_column("Profile URL / Handle", style="white")

        for p in report.social_profiles:
            if p.platform.lower() == "discord" or p.url.startswith("@"):
                handle_str = safe_escape(p.url if p.url.startswith("@") else f"@{p.url}")
                soc_table.add_row(
                    safe_escape(p.platform),
                    safe_escape(p.status),
                    f"[bold magenta]{handle_str}[/bold magenta] [dim](Handle Registered)[/dim]",
                )
            else:
                soc_table.add_row(safe_escape(p.platform), safe_escape(p.status), make_link(p.url))

        console.print(
            Panel(
                soc_table,
                title=f"[bold blue]Matched Social Profiles ({len(report.social_profiles)})[/bold blue]",
                border_style="blue",
                box=box.ROUNDED,
            )
        )

    # 6. Gaming Ecosystem (Minecraft, Steam, Roblox)
    if report.gaming and (report.gaming.minecraft or report.gaming.steam or report.gaming.roblox):
        game_table = Table(box=box.SIMPLE_HEAVY, border_style="bright_blue", show_header=True)
        game_table.add_column("Gaming Platform", style="bold bright_blue", width=22)
        game_table.add_column("Identity & Telemetry", style="white")

        if report.gaming.minecraft:
            mc = report.gaming.minecraft
            mc_info = (
                f"Player Username: [bold]{safe_escape(mc.username)}[/bold]\n"
                f"Formatted UUID: [cyan]{safe_escape(mc.uuid_formatted)}[/cyan]\n"
                f"Skin Render: [dim]{safe_escape(mc.skin_render_url)}[/dim]"
            )
            game_table.add_row("Minecraft (Mojang)", mc_info)

        if report.gaming.steam:
            st = report.gaming.steam
            vac_text = "[bold green]Clean (No Bans)[/bold green]" if not st.vac_banned else "[bold red]VAC BANNED[/bold red]"
            st_info = (
                f"Custom URL: [bold]{safe_escape(st.custom_url)}[/bold]\n"
                f"SteamID64: [cyan]{safe_escape(st.steam_id_64)}[/cyan]\n"
                f"Profile Link: {make_link(st.profile_url)}\n"
                f"VAC Status: {vac_text}"
            )
            if st.real_name:
                st_info += f"\nReal Name: {safe_escape(st.real_name)}"
            if st.location:
                st_info += f"\nLocation: {safe_escape(st.location)}"
            if st.summary:
                summary_preview = st.summary if len(st.summary) <= 120 else f"{st.summary[:117]}..."
                st_info += f"\nBio / Summary: [dim]{safe_escape(summary_preview)}[/dim]"
            game_table.add_row("Steam Community", st_info)

        if report.gaming.roblox:
            rb = report.gaming.roblox
            badge_text = " [bold green][Verified][/bold green]" if rb.has_verified_badge else ""
            ban_text = " [bold red][BANNED][/bold red]" if rb.is_banned else ""
            rb_info = (
                f"Username: [bold]{safe_escape(rb.username)}[/bold]{badge_text}{ban_text}\n"
                f"Display Name: [cyan]{safe_escape(rb.display_name)}[/cyan]\n"
                f"User ID: [yellow]{rb.user_id}[/yellow]\n"
                f"Profile Link: {make_link(rb.profile_url)}"
            )
            if rb.description:
                desc_prev = rb.description if len(rb.description) <= 120 else f"{rb.description[:117]}..."
                rb_info += f"\nBio: [dim]{safe_escape(desc_prev)}[/dim]"
            game_table.add_row("Roblox", rb_info)

        console.print(
            Panel(
                game_table,
                title="[bold bright_blue]Gaming Ecosystem Identity Pivots[/bold bright_blue]",
                border_style="bright_blue",
                box=box.ROUNDED,
            )
        )

    # 7. GitHub Public Pivot
    if report.github_pivot:
        gh = report.github_pivot
        gh_table = Table(box=box.SIMPLE, show_header=False)
        gh_table.add_column("Field", style="bold purple", width=22)
        gh_table.add_column("Details", style="white")

        gh_table.add_row("GitHub Profile", make_link(gh.profile_url))
        if gh.name:
            gh_table.add_row("Real Name", safe_escape(gh.name))
        if gh.company:
            gh_table.add_row("Company / Org", safe_escape(gh.company))
        if gh.location:
            gh_table.add_row("Location", safe_escape(gh.location))
        if gh.blog:
            gh_table.add_row("Website / Blog", safe_escape(gh.blog))
        if gh.bio:
            gh_table.add_row("Public Bio", safe_escape(gh.bio))
        if gh.created_at:
            gh_table.add_row("Created At", safe_escape(gh.created_at))
        if gh.age_comparison_discord:
            gh_table.add_row("Timeline Lead", f"[bold yellow]{safe_escape(gh.age_comparison_discord)}[/bold yellow]")
        if gh.commit_emails:
            gh_table.add_row("Public Commit Emails", f"[bold green]{', '.join(safe_escape(e) for e in gh.commit_emails)}[/bold green]")

        console.print(
            Panel(
                gh_table,
                title="[bold purple]GitHub Public Audit & Commit Analysis[/bold purple]",
                border_style="purple",
                box=box.ROUNDED,
            )
        )

    # 7. Breach & Exposure Check
    if report.breaches:
        b_table = Table(box=box.SIMPLE_HEAVY, border_style="red", show_header=True)
        b_table.add_column("Target Query", style="bold yellow")
        b_table.add_column("Exposed Service", style="bold red")
        b_table.add_column("Date", style="white")
        b_table.add_column("Compromised Data", style="dim white")

        for b in report.breaches:
            classes = ", ".join(safe_escape(c) for c in b.data_classes[:4])
            if len(b.data_classes) > 4:
                classes += f" (+{len(b.data_classes)-4} more)"
            b_table.add_row(safe_escape(b.query), safe_escape(b.service_name), safe_escape(b.breach_date or "N/A"), classes)

        console.print(
            Panel(
                b_table,
                title=f"[bold red]Exposed Breach Records ({len(report.breaches)})[/bold red]",
                border_style="red",
                box=box.ROUNDED,
            )
        )

    # 7b. Verified Email Registrations (Holehe)
    if report.email_registrations:
        total_accounts = sum(len(r.accounts) for r in report.email_registrations)
        if total_accounts > 0:
            reg_table = Table(box=box.SIMPLE_HEAVY, border_style="cyan", show_header=True)
            reg_table.add_column("Email", style="bold green", width=24)
            reg_table.add_column("Platform", style="bold cyan", width=18)
            reg_table.add_column("Domain", style="white", width=22)
            reg_table.add_column("Recovery / Details", style="dim white")

            for reg in report.email_registrations:
                for acc in reg.accounts:
                    extra_details = []
                    if acc.email_recovery:
                        extra_details.append(f"Recovery: [yellow]{safe_escape(acc.email_recovery)}[/yellow]")
                    if acc.phone_number:
                        extra_details.append(f"Phone: [yellow]{safe_escape(acc.phone_number)}[/yellow]")
                    if acc.rate_limit:
                        extra_details.append("[dim red](Rate Limited)[/dim red]")
                    detail_str = " | ".join(extra_details) if extra_details else "[dim]Registered Account[/dim]"

                    reg_table.add_row(safe_escape(reg.email), safe_escape(acc.platform), safe_escape(acc.domain), detail_str)

            console.print(
                Panel(
                    reg_table,
                    title=f"[bold cyan]Verified Email Accounts ({total_accounts} Across Holehe Providers)[/bold cyan]",
                    border_style="cyan",
                    box=box.ROUNDED,
                )
            )

    # 7c. Cross-Platform Avatar Perceptual Hash Matches
    if report.avatar_matches:
        match_table = Table(box=box.SIMPLE_HEAVY, border_style="bright_magenta", show_header=True)
        match_table.add_column("Source Platform", style="bold cyan")
        match_table.add_column("Matched Platform", style="bold magenta")
        match_table.add_column("Bit Distance", style="bold green", justify="center")
        match_table.add_column("Visual Correlation Verdict", style="white")

        for m in report.avatar_matches:
            verdict = "[bold green]Identical Avatar[/bold green]" if m.hamming_distance == 0 else f"[green]Perceptual Match ({m.hamming_distance}/64 bits diff)[/green]"
            match_table.add_row(safe_escape(m.platform_a), safe_escape(m.platform_b), str(m.hamming_distance), verdict)

        console.print(
            Panel(
                match_table,
                title=f"[bold bright_magenta]Avatar Perceptual Hash Matches ({len(report.avatar_matches)})[/bold bright_magenta]",
                border_style="bright_magenta",
                box=box.ROUNDED,
            )
        )

    # 7d. Hudson Rock Infostealer Intelligence
    if report.hudson_rock:
        hr_infections = [inf for r in report.hudson_rock for inf in r.infections]
        if hr_infections:
            hr_table = Table(box=box.SIMPLE_HEAVY, border_style="red", show_header=True)
            hr_table.add_column("Malware Family", style="bold red")
            hr_table.add_column("Compromise Date", style="white")
            hr_table.add_column("Computer / OS", style="dim white")
            hr_table.add_column("Compromised Logins Sample", style="yellow")

            for inf in hr_infections:
                comp_os = f"{safe_escape(inf.computer_name or 'N/A')} ({safe_escape(inf.operating_system or 'N/A')})"
                logins = ", ".join(safe_escape(l) for l in inf.top_logins[:4]) if inf.top_logins else "N/A"
                hr_table.add_row(safe_escape(inf.stealer_family or "Unknown"), safe_escape(inf.date_compromised or "N/A"), comp_os, logins)

            console.print(
                Panel(
                    hr_table,
                    title=f"[bold red]Hudson Rock Infostealer Malware Compromises ({len(hr_infections)})[/bold red]",
                    border_style="red",
                    box=box.ROUNDED,
                )
            )

    # 7e. Pre-Computed Google Dorks (Opt-in)
    if report.dorks:
        dork_table = Table(box=box.SIMPLE, show_header=True)
        dork_table.add_column("Category", style="bold cyan", width=26)
        dork_table.add_column("Search Dork & URL", style="white")

        for d in report.dorks:
            dork_table.add_row(safe_escape(d.category), f"{safe_escape(d.query)}\n[dim underline]{safe_escape(d.url)}[/dim underline]")

        console.print(
            Panel(
                dork_table,
                title=f"[bold cyan]Pre-Computed Google Dorks ({len(report.dorks)})[/bold cyan]",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )

    # 7f. Intelligence X Darknet Records (Opt-in)
    if report.intelx and report.intelx.records:
        ix_table = Table(box=box.SIMPLE, show_header=True)
        ix_table.add_column("Selector Name", style="bold white")
        ix_table.add_column("Type", style="dim cyan")
        for r in report.intelx.records[:10]:
            ix_table.add_row(safe_escape(r.name), safe_escape(r.media_type or "N/A"))

        console.print(
            Panel(
                ix_table,
                title=f"[bold purple]Intelligence X Darknet & Leak Archive Hits ({len(report.intelx.records)})[/bold purple]",
                border_style="purple",
                box=box.ROUNDED,
            )
        )

    # 7g. Keybase & OpenPGP Cryptographic Identity
    if report.keybase or report.pgp_keys:
        crypto_id_table = Table(box=box.SIMPLE, show_header=True)
        crypto_id_table.add_column("Source", style="bold cyan", width=18)
        crypto_id_table.add_column("Verified Identity & Claims", style="white")

        if report.keybase:
            kb = report.keybase
            kb_lines = [f"Username: @{safe_escape(kb.username)}"]
            if kb.full_name:
                kb_lines.append(f"Full Name: {safe_escape(kb.full_name)}")
            if kb.bio:
                kb_lines.append(f"Bio: {safe_escape(kb.bio)}")
            for proof in kb.proofs:
                kb_lines.append(f"• Proof: [{safe_escape(proof.service)}] {safe_escape(proof.username)} ({safe_escape(proof.proof_url or 'Verified')})")
            for c_addr in kb.crypto_addresses:
                kb_lines.append(f"• Wallet: [{safe_escape(c_addr.get('network', 'crypto'))}] {safe_escape(c_addr.get('address'))}")
            crypto_id_table.add_row("Keybase", "\n".join(kb_lines))

        for pgp in report.pgp_keys:
            identities_str = ", ".join(safe_escape(i) for i in pgp.identities) if pgp.identities else "Unspecified"
            crypto_id_table.add_row("OpenPGP", f"{safe_escape(pgp.key_id_or_fingerprint)}\nIdentities: {identities_str}\n[dim underline]{safe_escape(pgp.public_key_url or '')}[/dim underline]")

        console.print(
            Panel(
                crypto_id_table,
                title="[bold cyan]Cryptographic Identities (Keybase & OpenPGP)[/bold cyan]",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )

    # 7h. Personal Domain Recon & Infrastructure (RDAP + crt.sh)
    if report.domain_recon:
        domain_table = Table(box=box.SIMPLE, show_header=True)
        domain_table.add_column("Domain", style="bold green", width=22)
        domain_table.add_column("Registrar / Created", style="white", width=26)
        domain_table.add_column("Discovered Subdomains (crt.sh)", style="cyan")

        for d in report.domain_recon:
            meta_str = f"Registrar: {safe_escape(d.registrar or 'N/A')}\nCreated: {safe_escape(d.created_date or 'N/A')}"
            subs_str = ", ".join(safe_escape(s) for s in d.subdomains[:8]) if d.subdomains else "[dim]No subdomains in CT logs[/dim]"
            if len(d.subdomains) > 8:
                subs_str += f" (+{len(d.subdomains) - 8} more)"
            domain_table.add_row(safe_escape(d.domain), meta_str, subs_str)

        console.print(
            Panel(
                domain_table,
                title=f"[bold green]Personal Domain & Infrastructure Recon ({len(report.domain_recon)})[/bold green]",
                border_style="green",
                box=box.ROUNDED,
            )
        )

    # 7i. Package Registries Footprint
    if report.packages:
        pkg_table = Table(box=box.SIMPLE, show_header=True)
        pkg_table.add_column("Registry", style="bold magenta", width=12)
        pkg_table.add_column("Package Name", style="bold white", width=20)
        pkg_table.add_column("Version", style="yellow", width=10)
        pkg_table.add_column("Description / Author Email", style="white")

        for pkg in report.packages:
            desc = safe_escape(pkg.description) if pkg.description else "[dim]No description[/dim]"
            if pkg.author_email:
                desc += f"\n[bold green]Author Email:[/bold green] {safe_escape(pkg.author_email)}"
            pkg_table.add_row(safe_escape(pkg.registry), safe_escape(pkg.name), safe_escape(pkg.version or "N/A"), desc)

        console.print(
            Panel(
                pkg_table,
                title=f"[bold magenta]Package Registry Footprint (PyPI / npm / crates.io) ({len(report.packages)})[/bold magenta]",
                border_style="magenta",
                box=box.ROUNDED,
            )
        )

    # 7j. Wayback Machine Historical Snapshots
    if report.wayback_snapshots:
        wb_table = Table(box=box.SIMPLE, show_header=True)
        wb_table.add_column("Timestamp (UTC)", style="bold yellow", width=18)
        wb_table.add_column("Target URL", style="white", width=35)
        wb_table.add_column("Internet Archive Wayback Snapshot", style="blue underline")

        for snap in report.wayback_snapshots[:8]:
            wb_table.add_row(safe_escape(snap.timestamp), safe_escape(snap.original_url), make_link(snap.archive_url))

        console.print(
            Panel(
                wb_table,
                title=f"[bold yellow]Internet Archive Historical Snapshots ({len(report.wayback_snapshots)})[/bold yellow]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    # 7k. Image EXIF & Technical Metadata
    if report.image_metadata:
        img_table = Table(box=box.SIMPLE, show_header=True)
        img_table.add_column("Platform", style="bold cyan", width=18)
        img_table.add_column("Format & Size", style="white", width=20)
        img_table.add_column("EXIF Camera / Software", style="yellow")

        for img in report.image_metadata:
            size_kb = f"{img.file_size_bytes // 1024} KB" if img.file_size_bytes else "N/A"
            tech = f"{safe_escape(img.format)} ({safe_escape(img.dimensions)})\nMode: {safe_escape(img.color_mode)} | Size: {size_kb}"
            exif_desc = []
            if img.make or img.model:
                exif_desc.append(f"Camera: {safe_escape(img.make or '')} {safe_escape(img.model or '')}".strip())
            if img.software:
                exif_desc.append(f"Software: {safe_escape(img.software)}")
            if img.datetime_original:
                exif_desc.append(f"Date: {safe_escape(img.datetime_original)}")
            desc_str = "\n".join(exif_desc) if exif_desc else "[dim]Stripped (No EXIF)[/dim]"
            img_table.add_row(safe_escape(img.platform), tech, desc_str)

        console.print(
            Panel(
                img_table,
                title=f"[bold cyan]Avatar EXIF & Technical Image Metadata ({len(report.image_metadata)})[/bold cyan]",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )

    # 8. Aggregated Pivot Leads
    leads = report.pivot_leads
    has_leads = (
        leads.discovered_emails
        or leads.discovered_crypto
        or leads.discovered_messaging
        or leads.discovered_discord_ids
        or leads.discovered_discord_tags
        or leads.discovered_invites
        or leads.discovered_phones
        or leads.discovered_custom
        or leads.notes
    )
    if has_leads:
        leads_table = Table(box=box.SIMPLE, show_header=False)
        leads_table.add_column("Category", style="bold bright_cyan", width=22)
        leads_table.add_column("Values", style="white")

        if leads.discovered_emails:
            leads_table.add_row("Emails", f"[bold green]{', '.join(safe_escape(em) for em in leads.discovered_emails)}[/bold green]")
        if leads.discovered_crypto:
            crypto_lines = [f"[{safe_escape(c.network)}] [cyan]{safe_escape(c.address)}[/cyan]" for c in leads.discovered_crypto]
            leads_table.add_row("Crypto Wallets", "\n".join(crypto_lines))
        if leads.discovered_messaging:
            msg_lines = [f"[{safe_escape(m.platform)}] [magenta]{safe_escape(m.handle)}[/magenta]" for m in leads.discovered_messaging]
            leads_table.add_row("Messaging Handles", "\n".join(msg_lines))
        if leads.discovered_phones:
            phone_lines = [f"{safe_escape(p.e164)} ({safe_escape(p.country_name or 'Unknown Region')})" for p in leads.discovered_phones]
            leads_table.add_row("Telephone Numbers", "\n".join(phone_lines))
        if leads.discovered_custom:
            custom_lines = [f"[{safe_escape(c.get('category', 'Custom'))}] {safe_escape(c.get('name'))}: {safe_escape(c.get('value'))}" for c in leads.discovered_custom]
            leads_table.add_row("Custom Match Leads", "\n".join(custom_lines))
        if leads.discovered_discord_ids:
            leads_table.add_row("Discord User IDs", ", ".join(safe_escape(i) for i in leads.discovered_discord_ids))
        if leads.discovered_discord_tags:
            leads_table.add_row("Discord Tags", ", ".join(safe_escape(t) for t in leads.discovered_discord_tags))
        if leads.discovered_invites:
            leads_table.add_row("Discord Invites", ", ".join(safe_escape(inv) for inv in leads.discovered_invites))
        if leads.notes:
            leads_table.add_row("Investigative Notes", "\n".join(f"• {safe_escape(n)}" for n in leads.notes))

        console.print(
            Panel(
                leads_table,
                title="[bold bright_cyan]Key Pivot Leads & Correlation Findings[/bold bright_cyan]",
                border_style="bright_cyan",
                box=box.ROUNDED,
            )
        )

    # 9. Diagnostics / Module Status
    diag_table = Table(box=box.SIMPLE, show_header=True)
    diag_table.add_column("Module", style="bold white", width=25)
    diag_table.add_column("Status", width=14)
    diag_table.add_column("Diagnostics", style="dim white")

    for ms in report.module_statuses:
        status_style = "green" if ms.status == "success" else ("yellow" if ms.status in ("skipped", "no_hits") else "red")
        diag_table.add_row(safe_escape(ms.module_name), f"[{status_style}]{safe_escape(ms.status.upper())}[/{status_style}]", safe_escape(ms.message) or "")

    console.print(
        Panel(
            diag_table,
            title="[dim]Module Execution Status[/dim]",
            border_style="dim",
            box=box.ROUNDED,
        )
    )


# ============================================================================
# CLI Subcommands
# ============================================================================

@app.command(name="scan", context_settings=CONTEXT_SETTINGS)
def scan_command(
    target: str = typer.Argument(..., help="Discord Snowflake ID (17-20 digits) or username handle (@user)."),
    pivot: bool = typer.Option(
        False,
        "--pivot",
        "-p",
        help="When scanning a Discord Snowflake, automatically pivot into cross-platform username enumeration.",
    ),
    all_sites: bool = typer.Option(
        False,
        "--all-sites",
        "-a",
        help="Check all sites supported by Maigret instead of top-ranked sites.",
    ),
    email_sites: bool = typer.Option(
        False,
        "--email-sites",
        "-E",
        help="Check account registration on all 120+ platforms for discovered emails (Holehe).",
    ),
    dorks: bool = typer.Option(
        False,
        "--dorks",
        "-D",
        help="Generate pre-computed Google Dork URLs targeting public pastes, configs, and leaks.",
    ),
    intelx: bool = typer.Option(
        False,
        "--intelx",
        help="Query Intelligence X darknet archives and public data leaks.",
    ),
    metadata: bool = typer.Option(
        False,
        "--metadata",
        "-M",
        help="Inspect avatar image EXIF metadata and technical properties.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output raw JSON to stdout.",
    ),
    out: Optional[Path] = typer.Option(
        None,
        "--out",
        "-o",
        help="Save structured JSON investigation report to file.",
    ),
    html: Optional[Path] = typer.Option(
        None,
        "--html",
        "-H",
        help="Save standalone HTML investigation report to specified file path.",
    ),
    view: bool = typer.Option(
        False,
        "--view",
        "-w",
        help="Open HTML report in default browser (creates temporary file if --html is omitted).",
    ),
    markdown: Optional[Path] = typer.Option(
        None,
        "--md",
        "--markdown",
        help="Save executive Markdown investigation dossier to specified file path.",
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Strict offline mode: execute local decoding and parsing without sending external network packets.",
    ),
    proxy: Optional[str] = typer.Option(
        None,
        "--proxy",
        "-x",
        help="Proxy URL (e.g. socks5://127.0.0.1:9050 or http://user:pass@host:port).",
    ),
    timeout: int = typer.Option(
        15,
        "--timeout",
        "-t",
        help="HTTP timeout per module in seconds.",
    ),
) -> None:
    """Smart scan: Automatically detects Snowflake ID, username, or email and executes investigative pivots."""
    config = get_config(timeout=timeout, proxy=proxy, offline=offline)
    orchestrator = InvestigationOrchestrator(config=config)

    report: InvestigationReport

    if json_output:
        # Run silently without progress animation if JSON requested on stdout
        report = run_async(
            orchestrator.run_investigation(
                target=target,
                pivot=pivot,
                all_sites=all_sites,
                email_sites=email_sites,
                dorks=dorks,
                intelx=intelx,
                metadata=metadata,
                progress_callback=None,
            )
        )
        print(report.model_dump_json(indent=2))
    else:
        print_banner()

        def do_investigation(cb: ProgressCallback) -> Any:
            return orchestrator.run_investigation(
                target=target,
                pivot=pivot,
                all_sites=all_sites,
                email_sites=email_sites,
                dorks=dorks,
                intelx=intelx,
                metadata=metadata,
                progress_callback=cb,
            )

        report = run_with_progress(
            do_investigation,
            initial_phase="Initializing Investigation",
            initial_service="Resolving Target Entity...",
        )

        render_report_rich(report)

    # Save to file if requested
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            f.write(report.model_dump_json(indent=2))
        if not json_output:
            console.print(f"[bold green]JSON Report saved to:[/bold green] {out.resolve()}")

    if html or view:
        from argus.report_html import save_html_report, view_html_report

        if view:
            opened_path = view_html_report(report, custom_path=html)
            if not json_output:
                if html:
                    console.print(f"[bold green]HTML Report saved & opened:[/bold green] {opened_path.resolve()}")
                else:
                    console.print(f"[bold green]Temporary HTML Report opened:[/bold green] {opened_path.resolve()}")
        elif html:
            saved_path = save_html_report(report, html)
            if not json_output:
                console.print(f"[bold green]HTML Report saved to:[/bold green] {saved_path.resolve()}")

    if markdown:
        from argus.report_markdown import save_markdown_report

        saved_md = save_markdown_report(report, markdown)
        if not json_output:
            console.print(f"[bold green]Markdown Dossier saved to:[/bold green] {saved_md.resolve()}")


@app.command(name="snowflake", context_settings=CONTEXT_SETTINGS)
def snowflake_command(
    user_id: str = typer.Argument(..., help="Discord Snowflake User ID to decode and inspect."),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output raw JSON to stdout.",
    ),
    out: Optional[Path] = typer.Option(
        None,
        "--out",
        "-o",
        help="Save structured JSON investigation report to file.",
    ),
    html: Optional[Path] = typer.Option(
        None,
        "--html",
        "-H",
        help="Save standalone HTML investigation report to specified file path.",
    ),
    view: bool = typer.Option(
        False,
        "--view",
        "-w",
        help="Open HTML report in default browser (creates temporary file if --html is omitted).",
    ),
    markdown: Optional[Path] = typer.Option(
        None,
        "--md",
        "--markdown",
        help="Save executive Markdown investigation dossier to specified file path.",
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Strict offline mode: decode snowflake without network API calls.",
    ),
    proxy: Optional[str] = typer.Option(
        None,
        "--proxy",
        "-x",
        help="Proxy URL (e.g. socks5://127.0.0.1:9050 or http://user:pass@host:port).",
    ),
    timeout: int = typer.Option(
        15,
        "--timeout",
        "-t",
        help="HTTP timeout per module in seconds.",
    ),
) -> None:
    """Decode Discord Snowflake ID and query Discord API and CordCat."""
    clean_id = user_id.strip()
    if not is_valid_snowflake(clean_id):
        console.print(
            f"[bold red]Error:[/bold red] '{user_id}' is not a valid 17-20 digit Discord Snowflake ID."
        )
        raise typer.Exit(code=1)

    config = get_config(timeout=timeout, proxy=proxy, offline=offline)
    orchestrator = InvestigationOrchestrator(config=config)

    if json_output:
        report = run_async(
            orchestrator.run_investigation(
                target=clean_id,
                pivot=False,
                all_sites=False,
                progress_callback=None,
            )
        )
        print(report.model_dump_json(indent=2))
    else:
        print_banner()

        def do_snowflake(cb: ProgressCallback) -> Any:
            return orchestrator.run_investigation(
                target=clean_id,
                pivot=False,
                all_sites=False,
                progress_callback=cb,
            )

        report = run_with_progress(
            do_snowflake,
            initial_phase="Analyzing Snowflake ID",
            initial_service="Decoding 64-bit Bit Shifts...",
        )

        render_report_rich(report)

    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            f.write(report.model_dump_json(indent=2))
        if not json_output:
            console.print(f"[bold green]JSON Report saved to:[/bold green] {out.resolve()}")

    if html or view:
        from argus.report_html import save_html_report, view_html_report

        if view:
            opened_path = view_html_report(report, custom_path=html)
            if not json_output:
                if html:
                    console.print(f"[bold green]HTML Report saved & opened:[/bold green] {opened_path.resolve()}")
                else:
                    console.print(f"[bold green]Temporary HTML Report opened:[/bold green] {opened_path.resolve()}")
        elif html:
            saved_path = save_html_report(report, html)
            if not json_output:
                console.print(f"[bold green]HTML Report saved to:[/bold green] {saved_path.resolve()}")

    if markdown:
        from argus.report_markdown import save_markdown_report

        saved_md = save_markdown_report(report, markdown)
        if not json_output:
            console.print(f"[bold green]Markdown Dossier saved to:[/bold green] {saved_md.resolve()}")


@app.command(name="config", context_settings=CONTEXT_SETTINGS)
def config_command() -> None:
    """Show active configuration, discovered .env locations, and API key statuses."""
    print_banner()
    cfg = get_config()
    loaded_paths = _discover_and_load_env()

    path_text = ", ".join(str(p) for p in loaded_paths) if loaded_paths else "[dim]None (using env vars)[/dim]"

    table = Table(box=box.ROUNDED, border_style="cyan", show_header=True)
    table.add_column("Setting / API Key", style="bold white", width=24)
    table.add_column("Status / Masked Value", width=30)
    table.add_column("Description", style="dim white")

    table.add_row(
        "DISCORD_BOT_TOKEN",
        cfg.mask_key(cfg.discord_bot_token),
        "Queries Discord REST API for public profile, badges, avatar CDN",
    )
    table.add_row(
        "CORDCAT_API_KEY",
        cfg.mask_key(cfg.cordcat_api_key),
        "Queries CordCat for historical usernames & FiveM/CFX identifiers",
    )
    table.add_row(
        "HIBP_API_KEY",
        cfg.mask_key(cfg.hibp_api_key),
        "Queries Have I Been Pwned for breach notifications on emails",
    )
    table.add_row(
        "LEAKCHECK_API_KEY",
        cfg.mask_key(cfg.leakcheck_api_key),
        "Queries LeakCheck API for compromised accounts",
    )
    table.add_row(
        "GITHUB_TOKEN",
        cfg.mask_key(cfg.github_token),
        "Optional PAT raising GitHub API rate limit from 60 to 5,000 req/hr",
    )
    table.add_row(
        "INTELX_API_KEY",
        cfg.mask_key(cfg.intelx_api_key),
        "Queries Intelligence X API for darknet archives and public data leaks",
    )

    console.print(Panel(f"[bold]Active .env File(s):[/bold] {path_text}", border_style="dim"))
    console.print(table)
    console.print(
        "\n[dim]To configure keys, create a .env file in the current working directory\n"
        "or globally at ~/.argus/.env. See .env.example for a template.[/dim]"
    )


@app.command(name="tui", context_settings=CONTEXT_SETTINGS)
@app.command(name="explore", context_settings=CONTEXT_SETTINGS)
def tui_command(
    target: Optional[str] = typer.Argument(
        None,
        help="Discord Snowflake ID or username handle to scan and explore interactively.",
    ),
    file: Optional[Path] = typer.Option(
        None,
        "--file",
        "-f",
        help="Load existing JSON investigation report instead of running new scan.",
    ),
    pivot: bool = typer.Option(
        False,
        "--pivot",
        "-p",
        help="Automatically pivot into username enumeration if scanning a Snowflake.",
    ),
    all_sites: bool = typer.Option(
        False,
        "--all-sites",
        "-a",
        help="Check all sites supported by Maigret.",
    ),
    email_sites: bool = typer.Option(
        False,
        "--email-sites",
        "-E",
        help="Check account registration on all 120+ platforms for discovered emails (Holehe).",
    ),
    dorks: bool = typer.Option(
        False,
        "--dorks",
        "-D",
        help="Generate pre-computed Google Dork URLs.",
    ),
    intelx: bool = typer.Option(
        False,
        "--intelx",
        help="Query Intelligence X darknet archives and public data leaks.",
    ),
    metadata: bool = typer.Option(
        False,
        "--metadata",
        "-M",
        help="Inspect avatar image EXIF metadata and technical properties.",
    ),
    proxy: Optional[str] = typer.Option(
        None,
        "--proxy",
        "-x",
        help="Proxy URL (e.g. socks5://127.0.0.1:9050 or http://user:pass@host:port).",
    ),
    timeout: int = typer.Option(
        15,
        "--timeout",
        "-t",
        help="HTTP timeout per module in seconds.",
    ),
) -> None:
    """Launch interactive terminal dashboard to explore investigation results."""
    from argus.tui import run_interactive_tui

    if file:
        if not file.is_file():
            console.print(f"[bold red]Error:[/bold red] File not found: {file}")
            raise typer.Exit(code=1)
        try:
            report_data = json.loads(file.read_text(encoding="utf-8"))
            report = InvestigationReport.model_validate(report_data)
        except Exception as ex:
            console.print(f"[bold red]Error parsing JSON report:[/bold red] {ex}")
            raise typer.Exit(code=1)
    else:
        if not target:
            try:
                target = console.input(
                    "[bold cyan]Enter target (Discord Snowflake or username): [/bold cyan]"
                ).strip()
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Aborted.[/dim]")
                raise typer.Exit(code=0)
            if not target:
                console.print("[dim]No target provided. Aborted.[/dim]")
                raise typer.Exit(code=0)

        config = get_config(timeout=timeout, proxy=proxy)
        orchestrator = InvestigationOrchestrator(config=config)
        print_banner()

        def do_investigation(cb: ProgressCallback) -> Any:
            return orchestrator.run_investigation(
                target=target,
                pivot=pivot,
                all_sites=all_sites,
                email_sites=email_sites,
                dorks=dorks,
                intelx=intelx,
                metadata=metadata,
                progress_callback=cb,
            )

        report = run_with_progress(
            do_investigation,
            initial_phase="Initializing Investigation",
            initial_service="Resolving Target Entity...",
        )

    run_interactive_tui(report)


@app.command(name="diff", context_settings=CONTEXT_SETTINGS)
def diff_command(
    file_a: Path = typer.Argument(..., help="Path to baseline investigation report JSON."),
    file_b: Path = typer.Argument(..., help="Path to compared investigation report JSON."),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output raw JSON diff format.",
    ),
) -> None:
    """Compare two historical Argus investigation reports and highlight intelligence changes."""
    from argus.modules.diff import compare_investigation_reports, render_diff_rich

    if not file_a.exists():
        console.print(f"[bold red]Error:[/bold red] Baseline report file '{file_a}' not found.")
        raise typer.Exit(code=1)
    if not file_b.exists():
        console.print(f"[bold red]Error:[/bold red] Comparison report file '{file_b}' not found.")
        raise typer.Exit(code=1)

    try:
        report_a = InvestigationReport.model_validate_json(file_a.read_text(encoding="utf-8"))
        report_b = InvestigationReport.model_validate_json(file_b.read_text(encoding="utf-8"))
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] Failed to parse report JSON: {exc}")
        raise typer.Exit(code=1)

    diff = compare_investigation_reports(report_a, report_b)
    if json_output:
        import json
        print(json.dumps(diff, indent=2))
    else:
        render_diff_rich(diff, console=console)


@app.command(name="man", context_settings=CONTEXT_SETTINGS)
def man_command(
    roff: bool = typer.Option(
        False,
        "--roff",
        help="Output raw UNIX troff man page format to stdout.",
    ),
) -> None:
    """Display the full interactive manual page (or output UNIX troff format)."""
    if roff:
        man_path = Path(__file__).resolve().parent.parent / "argus.1"
        if man_path.is_file():
            print(man_path.read_text(encoding="utf-8"))
        else:
            print(_generate_troff_man())
        return

    print_banner()

    console.print("[bold yellow]NAME[/bold yellow]")
    console.print("    [bold white]argus[/bold white] - Discord Snowflake decoder, username pivot, and cross-platform OSINT tool\n")

    console.print("[bold yellow]SYNOPSIS[/bold yellow]")
    console.print("    [bold cyan]argus[/bold cyan] [[bold green]-v[/bold green]|--version] [[bold green]-h[/bold green]|--help] <COMMAND> [ARGS]...")
    console.print("    [bold cyan]argus scan[/bold cyan] [[bold green]-p[/bold green]|--pivot] [[bold green]-a[/bold green]|--all-sites] [[bold green]-j[/bold green]|--json] [[bold green]-o[/bold green]|--out <FILE>] [[bold green]-t[/bold green]|--timeout <SEC>] <TARGET>")
    console.print("    [bold cyan]argus snowflake[/bold cyan] [[bold green]-j[/bold green]|--json] [[bold green]-o[/bold green]|--out <FILE>] [[bold green]-t[/bold green]|--timeout <SEC>] <USER_ID>")
    console.print("    [bold cyan]argus config[/bold cyan]")
    console.print("    [bold cyan]argus man[/bold cyan] [--roff]\n")

    console.print("[bold yellow]DESCRIPTION[/bold yellow]")
    desc_text = (
        "    [bold white]argus[/bold white] is a high-performance OSINT reconnaissance CLI engineered to pivot\n"
        "    seamlessly from an alphanumeric username handle or 64-bit Discord Snowflake ID\n"
        "    into public Discord metadata, cross-platform profiles, and third-party indexers.\n\n"
        "    It executes concurrent asynchronous queries, performs pure offline bit-shift math\n"
        "    on Discord IDs, scans profile biographies for leaked invites, tags, and emails,\n"
        "    and aggregates findings into unified Pydantic reports with rich terminal styling or JSON."
    )
    console.print(desc_text + "\n")

    console.print("[bold yellow]COMMANDS[/bold yellow]")
    cmd_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    cmd_table.add_column("Command", style="bold cyan", width=22)
    cmd_table.add_column("Description", style="white")

    cmd_table.add_row(
        "scan <target>",
        "Smart scan: automatically detects Snowflake ID vs username handle and dispatches tailored investigative modules and automated pivot chaining.",
    )
    cmd_table.add_row(
        "snowflake <id>",
        "Pure offline 64-bit Snowflake bit-shift decoding (timestamp, worker ID, process ID, increment) + Discord Bot API & CordCat indexer.",
    )
    cmd_table.add_row(
        "config",
        "Inspect active configuration files, displaying discovered .env paths and masked statuses for all API keys.",
    )
    cmd_table.add_row(
        "tui / explore <target>",
        "Launch interactive terminal dashboard with menu-driven navigation across investigation sections.",
    )
    cmd_table.add_row(
        "diff <file_a> <file_b>",
        "Compare two historical JSON investigation reports and highlight intelligence changes.",
    )
    cmd_table.add_row(
        "man [--roff]",
        "Display this terminal manual page or emit standard UNIX troff format.",
    )
    console.print(cmd_table)
    console.print("")

    console.print("[bold yellow]OPTIONS & FLAGS[/bold yellow]")
    opt_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    opt_table.add_column("Option", style="bold green", width=22)
    opt_table.add_column("Description", style="white")

    opt_table.add_row("-v, --version", "Display tool version and exit.")
    opt_table.add_row("-h, --help", "Display help synopsis and exit (available on all commands).")
    opt_table.add_row("--offline", "Run in strict offline mode without sending external network packets.")
    opt_table.add_row("-p, --pivot", "Automatically pivot into cross-platform username sweep when scanning a Snowflake ID.")
    opt_table.add_row("-a, --all-sites", "Check all sites in the Maigret database instead of top-ranked dev/gaming platforms.")
    opt_table.add_row("-E, --email-sites", "Check account registrations on all 120+ platforms for discovered emails via Holehe.")
    opt_table.add_row("-D, --dorks", "Generate pre-computed Google Dork URLs targeting pastes, leaks, and docs.")
    opt_table.add_row("--intelx", "Query Intelligence X darknet archives and public data leaks.")
    opt_table.add_row("-M, --metadata", "Inspect avatar image EXIF metadata, camera specifications, and technical properties.")
    opt_table.add_row("-j, --json", "Output raw formatted JSON to stdout for pipelines or jq.")
    opt_table.add_row("-o, --out <PATH>", "Save structured JSON investigation report to file.")
    opt_table.add_row("-H, --html <PATH>", "Save standalone HTML investigation report to file.")
    opt_table.add_row("--md <PATH>", "Save executive Markdown investigation dossier to specified file path.")
    opt_table.add_row("-w, --view", "Open standalone HTML report in default browser (creates temporary file if --html is omitted).")
    opt_table.add_row("-x, --proxy <URL>", "Route network requests through HTTP/HTTPS or SOCKS5 proxy (e.g. socks5://127.0.0.1:9050).")
    opt_table.add_row("-t, --timeout <SEC>", "Configurable HTTP timeout in seconds per module (default: 15s).")
    console.print(opt_table)
    console.print("")

    console.print("[bold yellow]ENVIRONMENT VARIABLES & API KEYS[/bold yellow]")
    env_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    env_table.add_column("Variable", style="bold magenta", width=22)
    env_table.add_column("Description", style="white")

    env_table.add_row("DISCORD_BOT_TOKEN", "Discord Bot token for Discord REST API v10 user lookups, badges, and CDN URLs.")
    env_table.add_row("CORDCAT_API_KEY", "CordCat API key for historical usernames & FiveM/CFX lookups.")
    env_table.add_row("HIBP_API_KEY", "Have I Been Pwned API key for breach notifications on discovered emails.")
    env_table.add_row("LEAKCHECK_API_KEY", "LeakCheck API key for exposed service records.")
    env_table.add_row("GITHUB_TOKEN", "Optional GitHub Personal Access Token to raise rate limits from 60 to 5,000 req/hr.")
    console.print(env_table)
    console.print("")

    console.print("[bold yellow]EXAMPLES[/bold yellow]")
    console.print("    [dim]# Decode Discord Snowflake ID offline:[/dim]")
    console.print("    [bold cyan]argus snowflake 155149108183695360[/bold cyan]\n")
    console.print("    [dim]# Smart scan a Snowflake ID and pivot to discovered username handle:[/dim]")
    console.print("    [bold cyan]argus scan 155149108183695360 --pivot[/bold cyan]\n")
    console.print("    [dim]# Smart scan a username across top platforms and export to JSON:[/dim]")
    console.print("    [bold cyan]argus scan torvalds --out report.json[/bold cyan]\n")
    console.print("    [dim]# Stream JSON output directly into jq:[/dim]")
    console.print("    [bold cyan]argus scan 155149108183695360 --json | jq .snowflake[/bold cyan]\n")

    console.print("[bold yellow]EXIT STATUS[/bold yellow]")
    console.print("    [bold green]0[/bold green]    Successful execution.")
    console.print("    [bold red]1[/bold red]    Invalid input arguments or fatal execution error.\n")


def _generate_troff_man() -> str:
    """Fallback generator for troff manual page content."""
    man_path = Path(__file__).resolve().parent.parent / "argus.1"
    if man_path.is_file():
        return man_path.read_text(encoding="utf-8")
    return '.TH ARGUS 1 "November 2026" "argus 0.1.0" "User Commands"\n.SH NAME\nargus \\- OSINT CLI tool'


if __name__ == "__main__":
    app()
