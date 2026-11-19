"""Investigation Orchestrator for argus.

Manages target detection, concurrent module dispatch, automated pivot chaining,
and aggregation into an InvestigationReport.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Callable, Optional

from argus.config import Config
from argus.models import (
    InvestigationReport,
    ModuleStatus,
    PivotLeads,
)
from argus.modules.discord_api import fetch_discord_profile
from argus.modules.enrichment import check_breaches, fetch_github_pivot, query_cordcat
from argus.modules.snowflake import decode_snowflake, is_valid_snowflake
from argus.modules.username_pivot import run_username_pivot

# Callback: (phase_title, completed_count, total_count, current_service_description)
ProgressCallback = Callable[[str, int, int, str], None]


class InvestigationOrchestrator:
    """Coordinates OSINT module execution and automated investigative pivots."""

    def __init__(self, config: Config):
        self.config = config

    async def run_investigation(
        self,
        target: str,
        pivot: bool = False,
        all_sites: bool = False,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> InvestigationReport:
        """Run complete investigation on target (Snowflake ID or username)."""
        start_time = time.monotonic()
        clean_target = target.strip()
        timestamp_now = datetime.now(timezone.utc).isoformat()

        # Step 1: Detect Target Type
        is_snowflake = is_valid_snowflake(clean_target)
        target_type = "snowflake" if is_snowflake else "username"

        report = InvestigationReport(
            target=clean_target,
            target_type=target_type,
            scan_timestamp_utc=timestamp_now,
            scan_duration_seconds=0.0,
        )

        if progress_callback:
            progress_callback(
                "Target Identification",
                1,
                1,
                f"Classified target as {target_type.upper()}: {clean_target}",
            )

        if is_snowflake:
            await self._investigate_snowflake(
                user_id=clean_target,
                report=report,
                pivot=pivot,
                all_sites=all_sites,
                progress_callback=progress_callback,
            )
        else:
            await self._investigate_username(
                raw_username=clean_target,
                report=report,
                all_sites=all_sites,
                progress_callback=progress_callback,
            )

        report.scan_duration_seconds = round(time.monotonic() - start_time, 2)
        if progress_callback:
            progress_callback(
                "Investigation Complete",
                1,
                1,
                f"Completed all modules in {report.scan_duration_seconds}s",
            )

        return report

    async def _investigate_snowflake(
        self,
        user_id: str,
        report: InvestigationReport,
        pivot: bool,
        all_sites: bool,
        progress_callback: Optional[ProgressCallback],
    ) -> None:
        """Execute Snowflake analysis and Discord/CordCat lookups, then optional pivot."""
        # 1. Offline Snowflake decoding
        if progress_callback:
            progress_callback(
                "Snowflake Analysis",
                0,
                1,
                "Discord Epoch Bit-Shift: (id >> 22) + 1420070400000",
            )
        try:
            report.snowflake = decode_snowflake(user_id)
            report.module_statuses.append(
                ModuleStatus(
                    module_name="Snowflake Decoder",
                    status="success",
                    message=f"Created {report.snowflake.created_at_utc} (Worker {report.snowflake.worker_id}, Process {report.snowflake.process_id})",
                )
            )
            if progress_callback:
                progress_callback(
                    "Snowflake Analysis",
                    1,
                    1,
                    f"Decoded: Created {report.snowflake.created_at_utc}",
                )
        except Exception as ex:
            report.module_statuses.append(
                ModuleStatus(
                    module_name="Snowflake Decoder",
                    status="error",
                    message=str(ex),
                )
            )

        # 2. Concurrently query Discord Bot API and CordCat
        discord_task = fetch_discord_profile(
            user_id=user_id,
            bot_token=self.config.discord_bot_token,
            timeout=self.config.timeout,
            progress_callback=progress_callback,
        )
        cordcat_task = query_cordcat(
            user_id=user_id,
            api_key=self.config.cordcat_api_key,
            timeout=self.config.timeout,
            progress_callback=progress_callback,
        )

        (discord_res, cordcat_res) = await asyncio.gather(
            discord_task, cordcat_task, return_exceptions=True
        )

        # Handle Discord API result
        discovered_username: Optional[str] = None
        if isinstance(discord_res, tuple) and len(discord_res) == 3:
            prof, d_status, d_msg = discord_res
            report.discord_profile = prof
            report.module_statuses.append(
                ModuleStatus(module_name="Discord API", status=d_status, message=d_msg)
            )
            if prof and prof.username:
                discovered_username = prof.username

        # Handle CordCat result
        if isinstance(cordcat_res, tuple) and len(cordcat_res) == 2:
            cord_rec, c_status = cordcat_res
            report.cordcat = cord_rec
            report.module_statuses.append(c_status)
            if not discovered_username and cord_rec and cord_rec.historical_usernames:
                discovered_username = cord_rec.historical_usernames[0]

        # 3. Automated or requested pivot to username
        if discovered_username:
            report.pivot_leads.notes.append(
                f"Resolved Discord user ID {user_id} to handle @{discovered_username}"
            )
            if pivot:
                if progress_callback:
                    progress_callback(
                        "Pivoting to Username",
                        0,
                        1,
                        f"Resolved handle @{discovered_username} from Snowflake",
                    )
                await self._run_username_pivot_flow(
                    username=discovered_username,
                    report=report,
                    all_sites=all_sites,
                    discord_dt_str=report.snowflake.created_at_utc if report.snowflake else None,
                    progress_callback=progress_callback,
                )

    async def _investigate_username(
        self,
        raw_username: str,
        report: InvestigationReport,
        all_sites: bool,
        progress_callback: Optional[ProgressCallback],
    ) -> None:
        """Execute username enumeration and automatic lead pivoting."""
        clean_name = raw_username.lstrip("@").strip()
        await self._run_username_pivot_flow(
            username=clean_name,
            report=report,
            all_sites=all_sites,
            discord_dt_str=None,
            progress_callback=progress_callback,
        )

        # Chained Pivot: If Discord Snowflake IDs were discovered during sweep, decode them
        if report.pivot_leads.discovered_discord_ids and not report.snowflake:
            lead_id = report.pivot_leads.discovered_discord_ids[0]
            if progress_callback:
                progress_callback(
                    "Chained Snowflake Pivot",
                    0,
                    1,
                    f"Found Discord ID: {lead_id} in profile leads",
                )
            try:
                report.snowflake = decode_snowflake(lead_id)
                report.module_statuses.append(
                    ModuleStatus(
                        module_name="Snowflake Decoder (Pivot Lead)",
                        status="success",
                        message=f"Decoded lead ID {lead_id} (Created {report.snowflake.created_at_utc})",
                    )
                )
            except Exception:
                pass

            # Query Discord profile and CordCat for this discovered ID
            d_prof, d_stat, d_m = await fetch_discord_profile(
                user_id=lead_id,
                bot_token=self.config.discord_bot_token,
                timeout=self.config.timeout,
                progress_callback=progress_callback,
            )
            report.discord_profile = d_prof
            report.module_statuses.append(
                ModuleStatus(module_name="Discord API (Pivot Lead)", status=d_stat, message=d_m)
            )

            cord_rec, c_stat = await query_cordcat(
                user_id=lead_id,
                api_key=self.config.cordcat_api_key,
                timeout=self.config.timeout,
                progress_callback=progress_callback,
            )
            report.cordcat = cord_rec
            report.module_statuses.append(c_stat)

    async def _run_username_pivot_flow(
        self,
        username: str,
        report: InvestigationReport,
        all_sites: bool,
        discord_dt_str: Optional[str],
        progress_callback: Optional[ProgressCallback],
    ) -> None:
        """Run Maigret username sweep and GitHub audit in parallel, then chain breach lookups."""
        discord_dt: Optional[datetime] = None
        if discord_dt_str:
            try:
                discord_dt = datetime.fromisoformat(discord_dt_str)
            except Exception:
                pass

        # 1. Parallel execution: Maigret sweep + GitHub pivot
        sweep_task = run_username_pivot(
            username=username,
            all_sites=all_sites,
            timeout=self.config.timeout,
            progress_callback=progress_callback,
        )
        github_task = fetch_github_pivot(
            username=username,
            github_token=self.config.github_token,
            discord_created_at_dt=discord_dt,
            timeout=self.config.timeout,
            progress_callback=progress_callback,
        )

        (sweep_res, github_res) = await asyncio.gather(
            sweep_task, github_task, return_exceptions=True
        )

        # Process Maigret sweep results
        if isinstance(sweep_res, tuple) and len(sweep_res) == 3:
            profiles, leads, sweep_msg = sweep_res
            report.social_profiles.extend(profiles)
            self._merge_leads(report.pivot_leads, leads)
            report.module_statuses.append(
                ModuleStatus(
                    module_name="Username Pivot (Maigret)",
                    status="success" if profiles else "no_hits",
                    message=f"{sweep_msg} (Found {len(profiles)} profiles)",
                )
            )

        # Process GitHub pivot results
        if isinstance(github_res, tuple) and len(github_res) == 2:
            gh_lead, gh_status = github_res
            report.github_pivot = gh_lead
            report.module_statuses.append(gh_status)
            if gh_lead and gh_lead.commit_emails:
                for email in gh_lead.commit_emails:
                    if email not in report.pivot_leads.discovered_emails:
                        report.pivot_leads.discovered_emails.append(email)

        # 2. Automated Pivot into Breach Databases
        all_emails = list(set(report.pivot_leads.discovered_emails))
        if all_emails:
            breaches, b_status = await check_breaches(
                queries=all_emails,
                hibp_api_key=self.config.hibp_api_key,
                leakcheck_api_key=self.config.leakcheck_api_key,
                timeout=self.config.timeout,
                progress_callback=progress_callback,
            )
            report.breaches.extend(breaches)
            report.module_statuses.append(b_status)
        else:
            report.module_statuses.append(
                ModuleStatus(
                    module_name="Breach Exposure",
                    status="skipped",
                    message="No email addresses discovered during pivot to check against breach databases.",
                )
            )

    @staticmethod
    def _merge_leads(target_leads: PivotLeads, new_leads: PivotLeads) -> None:
        """Merge new investigative leads into target without duplicates."""
        for inv in new_leads.discovered_invites:
            if inv not in target_leads.discovered_invites:
                target_leads.discovered_invites.append(inv)
        for tag in new_leads.discovered_discord_tags:
            if tag not in target_leads.discovered_discord_tags:
                target_leads.discovered_discord_tags.append(tag)
        for d_id in new_leads.discovered_discord_ids:
            if d_id not in target_leads.discovered_discord_ids:
                target_leads.discovered_discord_ids.append(d_id)
        for em in new_leads.discovered_emails:
            if em not in target_leads.discovered_emails:
                target_leads.discovered_emails.append(em)
        for n in new_leads.notes:
            if n not in target_leads.notes:
                target_leads.notes.append(n)
