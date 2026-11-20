"""Investigation Orchestrator for argus.

Manages target detection, concurrent module dispatch, automated pivot chaining,
and aggregation into an InvestigationReport.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from datetime import datetime, timezone
from typing import Callable, Optional

from argus.config import Config
from argus.models import (
    InvestigationReport,
    ModuleStatus,
    PivotLeads,
)
from argus.modules.avatar_hash import fetch_and_hash_avatars
from argus.modules.correlation import calculate_correlation_score
from argus.modules.crypto_pivot import extract_crypto_wallets
from argus.modules.discord_api import fetch_discord_profile
from argus.modules.domain_recon import extract_custom_domains, recon_domain
from argus.modules.dorks import generate_google_dorks
from argus.modules.email_recon import check_email_registrations
from argus.modules.enrichment import check_breaches, fetch_github_pivot, query_cordcat
from argus.modules.gaming import fetch_gaming_profiles
from argus.modules.hudson_rock import fetch_hudson_rock_intel
from argus.modules.intelx import query_intelx
from argus.modules.metadata_exif import inspect_avatar_metadata
from argus.modules.package_registries import fetch_package_registries
from argus.modules.pgp_keybase import lookup_keybase, lookup_openpgp_keys
from argus.modules.snowflake import decode_snowflake, is_valid_snowflake
from argus.modules.username_pivot import run_username_pivot
from argus.modules.wayback import fetch_wayback_snapshots

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
        email_sites: bool = False,
        dorks: bool = False,
        intelx: bool = False,
        metadata: bool = False,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> InvestigationReport:
        """Run complete investigation on target (Snowflake ID, username, or email)."""
        start_time = time.monotonic()
        clean_target = target.strip()
        timestamp_now = datetime.now(timezone.utc).isoformat()

        # Step 1: Detect Target Type
        is_snowflake = is_valid_snowflake(clean_target)
        is_email = "@" in clean_target and "." in clean_target.split("@")[-1]
        target_type = "snowflake" if is_snowflake else ("email" if is_email else "username")

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
                email_sites=email_sites,
                progress_callback=progress_callback,
            )
        else:
            await self._investigate_username(
                raw_username=clean_target,
                report=report,
                all_sites=all_sites,
                email_sites=email_sites,
                progress_callback=progress_callback,
            )

        # -------------------------------------------------------------
        # S-Tier Base 2: Cross-Platform Avatar Perceptual Hashing (dHash)
        # -------------------------------------------------------------
        avatar_sources: list[tuple[str, str]] = []
        if report.discord_profile and report.discord_profile.avatar_url:
            avatar_sources.append(("Discord", report.discord_profile.avatar_url))
        if report.gaming and report.gaming.steam and report.gaming.steam.avatar_url:
            avatar_sources.append(("Steam", report.gaming.steam.avatar_url))
        if report.github_pivot and report.github_pivot.username:
            avatar_sources.append(("GitHub", f"https://avatars.githubusercontent.com/{report.github_pivot.username}"))
        for em in report.pivot_leads.discovered_emails:
            gravatar_hash = hashlib.md5(em.strip().lower().encode("utf-8")).hexdigest()
            avatar_sources.append((f"Gravatar ({em})", f"https://www.gravatar.com/avatar/{gravatar_hash}?d=404"))

        if avatar_sources:
            hashes, matches = await fetch_and_hash_avatars(
                avatar_sources=avatar_sources,
                timeout=self.config.timeout,
                proxy=self.config.proxy,
                progress_callback=progress_callback,
            )
            report.avatar_hashes.extend(hashes)
            report.avatar_matches.extend(matches)

        # -------------------------------------------------------------
        # Crypto Ecosystem Extraction & Block Explorer References
        # -------------------------------------------------------------
        text_corpus: list[str] = list(report.pivot_leads.notes)
        if report.github_pivot and report.github_pivot.bio:
            text_corpus.append(report.github_pivot.bio)
        if report.keybase and report.keybase.bio:
            text_corpus.append(report.keybase.bio)
        for p in report.social_profiles:
            if "bio" in p.extracted_data:
                text_corpus.append(str(p.extracted_data["bio"]))
        crypto_details, crypto_leads = extract_crypto_wallets(text_corpus)
        report.crypto_details = crypto_details
        for cl in crypto_leads:
            if not any(existing.address.lower() == cl.address.lower() for existing in report.pivot_leads.discovered_crypto):
                report.pivot_leads.discovered_crypto.append(cl)

        # -------------------------------------------------------------
        # Wayback Machine / CDX Historical Snapshots
        # -------------------------------------------------------------
        profile_urls: list[str] = []
        if report.github_pivot and report.github_pivot.profile_url:
            profile_urls.append(report.github_pivot.profile_url)
        for sp in report.social_profiles:
            if sp.status == "Claimed" and sp.url not in profile_urls:
                profile_urls.append(sp.url)
        if profile_urls:
            wb_snaps, wb_status = await fetch_wayback_snapshots(
                urls=profile_urls,
                timeout=self.config.timeout,
                proxy=self.config.proxy,
                progress_callback=progress_callback,
            )
            report.wayback_snapshots.extend(wb_snaps)
            report.module_statuses.append(wb_status)

        # -------------------------------------------------------------
        # Image Technical & EXIF Metadata Inspection (--metadata / -M)
        # -------------------------------------------------------------
        if metadata and avatar_sources:
            img_reports, img_status = await inspect_avatar_metadata(
                avatar_sources=avatar_sources,
                timeout=self.config.timeout,
                proxy=self.config.proxy,
                progress_callback=progress_callback,
            )
            report.image_metadata.extend(img_reports)
            report.module_statuses.append(img_status)

        # -------------------------------------------------------------
        # S-Tier Base 3: Algorithmic Correlation & Confidence Scoring
        # -------------------------------------------------------------
        report.correlation = calculate_correlation_score(report)

        # -------------------------------------------------------------
        # B-Tier Flag 1: Google Dork Pre-Computed Search Links
        # -------------------------------------------------------------
        if dorks:
            report.dorks = generate_google_dorks(
                target=clean_target,
                emails=report.pivot_leads.discovered_emails,
            )

        # -------------------------------------------------------------
        # B-Tier Flag 2: Intelligence X Darknet & Leak Archive Lookup
        # -------------------------------------------------------------
        if intelx or self.config.intelx_api_key:
            ix_report, ix_status = await query_intelx(
                selector=clean_target,
                api_key=self.config.intelx_api_key,
                timeout=self.config.timeout,
                proxy=self.config.proxy,
                progress_callback=progress_callback,
            )
            if ix_report:
                report.intelx = ix_report
            report.module_statuses.append(ix_status)

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
        email_sites: bool,
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
            proxy=self.config.proxy,
            progress_callback=progress_callback,
        )
        cordcat_task = query_cordcat(
            user_id=user_id,
            api_key=self.config.cordcat_api_key,
            timeout=self.config.timeout,
            proxy=self.config.proxy,
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
                    email_sites=email_sites,
                    discord_dt_str=report.snowflake.created_at_utc if report.snowflake else None,
                    progress_callback=progress_callback,
                )

    async def _investigate_username(
        self,
        raw_username: str,
        report: InvestigationReport,
        all_sites: bool,
        email_sites: bool,
        progress_callback: Optional[ProgressCallback],
    ) -> None:
        """Execute username enumeration and automatic lead pivoting."""
        clean_name = raw_username.lstrip("@").strip()
        # If target itself is an email address, register it as a discovered email lead
        if "@" in clean_name and "." in clean_name.split("@")[-1]:
            if clean_name not in report.pivot_leads.discovered_emails:
                report.pivot_leads.discovered_emails.append(clean_name)
            sweep_name = clean_name.split("@")[0]
        else:
            sweep_name = clean_name

        await self._run_username_pivot_flow(
            username=sweep_name,
            report=report,
            all_sites=all_sites,
            email_sites=email_sites,
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
                proxy=self.config.proxy,
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
                proxy=self.config.proxy,
                progress_callback=progress_callback,
            )
            report.cordcat = cord_rec
            report.module_statuses.append(c_stat)

    async def _run_username_pivot_flow(
        self,
        username: str,
        report: InvestigationReport,
        all_sites: bool,
        email_sites: bool,
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

        # 1. Parallel execution: Maigret sweep + GitHub pivot + Gaming ecosystem
        sweep_task = run_username_pivot(
            username=username,
            all_sites=all_sites,
            timeout=self.config.timeout,
            proxy=self.config.proxy,
            progress_callback=progress_callback,
        )
        github_task = fetch_github_pivot(
            username=username,
            github_token=self.config.github_token,
            discord_created_at_dt=discord_dt,
            timeout=self.config.timeout,
            proxy=self.config.proxy,
            progress_callback=progress_callback,
        )
        gaming_task = fetch_gaming_profiles(
            username=username,
            timeout=self.config.timeout,
            proxy=self.config.proxy,
            progress_callback=progress_callback,
        )
        hudson_task = fetch_hudson_rock_intel(
            query=username,
            query_type="username",
            timeout=self.config.timeout,
            proxy=self.config.proxy,
            progress_callback=progress_callback,
        )
        keybase_task = lookup_keybase(
            username=username,
            timeout=self.config.timeout,
            proxy=self.config.proxy,
            progress_callback=progress_callback,
        )
        package_task = fetch_package_registries(
            username=username,
            timeout=self.config.timeout,
            proxy=self.config.proxy,
            progress_callback=progress_callback,
        )

        (sweep_res, github_res, gaming_res, hudson_res, keybase_res, package_res) = await asyncio.gather(
            sweep_task, github_task, gaming_task, hudson_task, keybase_task, package_task, return_exceptions=True
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

        # Process Gaming pivot results
        if isinstance(gaming_res, tuple) and len(gaming_res) == 2:
            gaming_data, gaming_status = gaming_res
            report.gaming = gaming_data
            report.module_statuses.append(gaming_status)

        # Process Hudson Rock infostealer results
        if isinstance(hudson_res, tuple) and len(hudson_res) == 2:
            hr_data, hr_status = hudson_res
            if hr_data and hr_data.total_stealers > 0:
                report.hudson_rock.append(hr_data)
            report.module_statuses.append(hr_status)

        # Process Keybase identity results
        if isinstance(keybase_res, tuple) and len(keybase_res) == 2:
            kb_prof, kb_stat = keybase_res
            if kb_prof:
                report.keybase = kb_prof
            report.module_statuses.append(kb_stat)

        # Process Package Registries results
        if isinstance(package_res, tuple) and len(package_res) == 2:
            pkgs, pkg_stat = package_res
            report.packages.extend(pkgs)
            report.module_statuses.append(pkg_stat)

        # 2. Automated Pivot into Breach Databases & Infostealer Intelligence
        all_emails = list(set(report.pivot_leads.discovered_emails))
        if all_emails:
            breaches, b_status = await check_breaches(
                queries=all_emails,
                hibp_api_key=self.config.hibp_api_key,
                leakcheck_api_key=self.config.leakcheck_api_key,
                timeout=self.config.timeout,
                proxy=self.config.proxy,
                progress_callback=progress_callback,
            )
            report.breaches.extend(breaches)
            report.module_statuses.append(b_status)

            # Query Hudson Rock for discovered emails
            for em in all_emails:
                em_hr_data, em_hr_status = await fetch_hudson_rock_intel(
                    query=em,
                    query_type="email",
                    timeout=self.config.timeout,
                    proxy=self.config.proxy,
                    progress_callback=progress_callback,
                )
                if em_hr_data and em_hr_data.total_stealers > 0:
                    report.hudson_rock.append(em_hr_data)
                report.module_statuses.append(em_hr_status)

            # Query OpenPGP key servers
            pgp_records, pgp_status = await lookup_openpgp_keys(
                emails=all_emails,
                timeout=self.config.timeout,
                proxy=self.config.proxy,
                progress_callback=progress_callback,
            )
            report.pgp_keys.extend(pgp_records)
            report.module_statuses.append(pgp_status)

            # Custom domain infrastructure reconnaissance (RDAP + crt.sh)
            custom_domains = extract_custom_domains(all_emails)
            for c_dom in custom_domains:
                d_rec, d_stat = await recon_domain(
                    domain=c_dom,
                    timeout=self.config.timeout,
                    proxy=self.config.proxy,
                    progress_callback=progress_callback,
                )
                if d_rec:
                    report.domain_recon.append(d_rec)
                report.module_statuses.append(d_stat)
        else:
            report.module_statuses.append(
                ModuleStatus(
                    module_name="Breach Exposure",
                    status="skipped",
                    message="No email addresses discovered during pivot to check against breach databases.",
                )
            )

        # 3. Opt-in: Holehe Email Account Registration Checks
        if email_sites:
            all_emails = list(dict.fromkeys(report.pivot_leads.discovered_emails))
            if all_emails:
                for em in all_emails:
                    reg_report, reg_status = await check_email_registrations(
                        email=em,
                        timeout=self.config.timeout,
                        proxy=self.config.proxy,
                        progress_callback=progress_callback,
                    )
                    if reg_report:
                        report.email_registrations.append(reg_report)
                    report.module_statuses.append(reg_status)
            else:
                report.module_statuses.append(
                    ModuleStatus(
                        module_name="Email Recon (Holehe)",
                        status="skipped",
                        message="No email addresses discovered to probe for registered accounts.",
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
        for cr in new_leads.discovered_crypto:
            if not any(existing.address.lower() == cr.address.lower() for existing in target_leads.discovered_crypto):
                target_leads.discovered_crypto.append(cr)
        for msg in new_leads.discovered_messaging:
            if not any(existing.platform == msg.platform and existing.handle.lower() == msg.handle.lower() for existing in target_leads.discovered_messaging):
                target_leads.discovered_messaging.append(msg)
        for n in new_leads.notes:
            if n not in target_leads.notes:
                target_leads.notes.append(n)
