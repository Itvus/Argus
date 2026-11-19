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


def render_report_rich(report: InvestigationReport) -> None:
    """Render comprehensive multi-panel terminal report using Rich."""
    # 1. Target Header Panel
    target_header = Table.grid(padding=(0, 2))
    target_header.add_column(style="bold yellow", justify="right")
    target_header.add_column(style="white")
    target_header.add_row("Investigative Target:", report.target)
    target_header.add_row("Detected Entity Type:", f"[bold cyan]{report.target_type.upper()}[/bold cyan]")
    target_header.add_row("Scan Execution Time:", f"{report.scan_duration_seconds}s")
    target_header.add_row("Timestamp (UTC):", report.scan_timestamp_utc)

    console.print(
        Panel(
            target_header,
            title="[bold green]ARGUS INVESTIGATION SUMMARY[/bold green]",
            border_style="green",
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

        handle_display = f"@{dp.username}"
        if dp.discriminator and dp.discriminator != "0":
            handle_display += f"#{dp.discriminator}"
        dp_table.add_row("Username / Handle", handle_display)

        if dp.global_name:
            dp_table.add_row("Global Display Name", dp.global_name)
        dp_table.add_row("User ID", dp.id)

        badges_str = ", ".join(dp.badges) if dp.badges else "[dim]None detected[/dim]"
        dp_table.add_row("Public Badges", f"[bold yellow]{badges_str}[/bold yellow]")

        if dp.banner_color:
            dp_table.add_row("Banner / Accent Color", dp.banner_color)

        if dp.avatar_url:
            dp_table.add_row("Avatar CDN (1024px)", f"[link={dp.avatar_url}]{dp.avatar_url}[/link]")

        if dp.banner_url:
            dp_table.add_row("Banner CDN (1024px)", f"[link={dp.banner_url}]{dp.banner_url}[/link]")

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
            cc_table.add_row("Historical Aliases", ", ".join(cc.historical_usernames))
        if cc.fivem_identifiers:
            cc_table.add_row("FiveM / CFX IDs", ", ".join(cc.fivem_identifiers))

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
                handle_str = p.url if p.url.startswith("@") else f"@{p.url}"
                soc_table.add_row(
                    p.platform,
                    p.status,
                    f"[bold magenta]{handle_str}[/bold magenta] [dim](Handle Registered)[/dim]",
                )
            else:
                soc_table.add_row(p.platform, p.status, f"[link={p.url}]{p.url}[/link]")

        console.print(
            Panel(
                soc_table,
                title=f"[bold blue]Matched Social Profiles ({len(report.social_profiles)})[/bold blue]",
                border_style="blue",
                box=box.ROUNDED,
            )
        )

    # 6. Gaming Ecosystem (Minecraft & Steam)
    if report.gaming and (report.gaming.minecraft or report.gaming.steam):
        game_table = Table(box=box.SIMPLE_HEAVY, border_style="bright_blue", show_header=True)
        game_table.add_column("Gaming Platform", style="bold bright_blue", width=22)
        game_table.add_column("Identity & Telemetry", style="white")

        if report.gaming.minecraft:
            mc = report.gaming.minecraft
            mc_info = (
                f"Player Username: [bold]{mc.username}[/bold]\n"
                f"Formatted UUID: [cyan]{mc.uuid_formatted}[/cyan]\n"
                f"Skin Render: [dim]{mc.skin_render_url}[/dim]"
            )
            game_table.add_row("Minecraft (Mojang)", mc_info)

        if report.gaming.steam:
            st = report.gaming.steam
            vac_text = "[bold green]Clean (No Bans)[/bold green]" if not st.vac_banned else "[bold red]VAC BANNED[/bold red]"
            st_info = (
                f"Custom URL: [bold]{st.custom_url}[/bold]\n"
                f"SteamID64: [cyan]{st.steam_id_64}[/cyan]\n"
                f"Profile Link: [link={st.profile_url}]{st.profile_url}[/link]\n"
                f"VAC Status: {vac_text}"
            )
            if st.real_name:
                st_info += f"\nReal Name: {st.real_name}"
            if st.location:
                st_info += f"\nLocation: {st.location}"
            game_table.add_row("Steam Community", st_info)

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

        gh_table.add_row("GitHub Profile", f"[link={gh.profile_url}]{gh.profile_url}[/link]")
        if gh.name:
            gh_table.add_row("Real Name", gh.name)
        if gh.company:
            gh_table.add_row("Company / Org", gh.company)
        if gh.location:
            gh_table.add_row("Location", gh.location)
        if gh.blog:
            gh_table.add_row("Website / Blog", gh.blog)
        if gh.bio:
            gh_table.add_row("Public Bio", gh.bio)
        if gh.created_at:
            gh_table.add_row("Created At", gh.created_at)
        if gh.age_comparison_discord:
            gh_table.add_row("Timeline Lead", f"[bold yellow]{gh.age_comparison_discord}[/bold yellow]")
        if gh.commit_emails:
            gh_table.add_row("Public Commit Emails", f"[bold green]{', '.join(gh.commit_emails)}[/bold green]")

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
            classes = ", ".join(b.data_classes[:4])
            if len(b.data_classes) > 4:
                classes += f" (+{len(b.data_classes)-4} more)"
            b_table.add_row(b.query, b.service_name, b.breach_date or "N/A", classes)

        console.print(
            Panel(
                b_table,
                title=f"[bold red]Exposed Breach Records ({len(report.breaches)})[/bold red]",
                border_style="red",
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
        or leads.notes
    )
    if has_leads:
        leads_table = Table(box=box.SIMPLE, show_header=False)
        leads_table.add_column("Category", style="bold bright_cyan", width=22)
        leads_table.add_column("Values", style="white")

        if leads.discovered_emails:
            leads_table.add_row("Emails", f"[bold green]{', '.join(leads.discovered_emails)}[/bold green]")
        if leads.discovered_crypto:
            crypto_lines = [f"[{c.network}] [cyan]{c.address}[/cyan]" for c in leads.discovered_crypto]
            leads_table.add_row("Crypto Wallets", "\n".join(crypto_lines))
        if leads.discovered_messaging:
            msg_lines = [f"[{m.platform}] [magenta]{m.handle}[/magenta]" for m in leads.discovered_messaging]
            leads_table.add_row("Messaging Handles", "\n".join(msg_lines))
        if leads.discovered_discord_ids:
            leads_table.add_row("Discord User IDs", ", ".join(leads.discovered_discord_ids))
        if leads.discovered_discord_tags:
            leads_table.add_row("Discord Tags", ", ".join(leads.discovered_discord_tags))
        if leads.discovered_invites:
            leads_table.add_row("Discord Invites", ", ".join(leads.discovered_invites))
        if leads.notes:
            leads_table.add_row("Investigative Notes", "\n".join(f"• {n}" for n in leads.notes))

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
        diag_table.add_row(ms.module_name, f"[{status_style}]{ms.status.upper()}[/{status_style}]", ms.message or "")

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
    """Smart scan: Automatically detects Snowflake ID or username and executes investigative pivots."""
    config = get_config(timeout=timeout, proxy=proxy)
    orchestrator = InvestigationOrchestrator(config=config)

    report: InvestigationReport

    if json_output:
        # Run silently without progress animation if JSON requested on stdout
        report = run_async(
            orchestrator.run_investigation(
                target=target,
                pivot=pivot,
                all_sites=all_sites,
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

    config = get_config(timeout=timeout, proxy=proxy)
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
    elif target:
        config = get_config(timeout=timeout, proxy=proxy)
        orchestrator = InvestigationOrchestrator(config=config)
        print_banner()

        def do_investigation(cb: ProgressCallback) -> Any:
            return orchestrator.run_investigation(
                target=target,
                pivot=pivot,
                all_sites=all_sites,
                progress_callback=cb,
            )

        report = run_with_progress(
            do_investigation,
            initial_phase="Initializing Investigation",
            initial_service="Resolving Target Entity...",
        )
    else:
        console.print("[bold red]Error:[/bold red] Provide either a target argument or --file <path>.")
        raise typer.Exit(code=1)

    run_interactive_tui(report)


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
    opt_table.add_row("-p, --pivot", "Automatically pivot into cross-platform username sweep when scanning a Snowflake ID.")
    opt_table.add_row("-a, --all-sites", "Check all sites in the Maigret database instead of top-ranked dev/gaming platforms.")
    opt_table.add_row("-j, --json", "Output raw formatted JSON to stdout for pipelines or jq.")
    opt_table.add_row("-o, --out <PATH>", "Save structured JSON investigation report to file.")
    opt_table.add_row("-H, --html <PATH>", "Save standalone HTML investigation report to file.")
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
