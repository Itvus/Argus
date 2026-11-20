"""Email account registration reconnaissance module using Holehe across all providers.

Checks if discovered or target email addresses are registered across 120+ platforms
(Discord, GitHub, Twitter, Spotify, Instagram, etc.) via password recovery/registration endpoints.
"""

from __future__ import annotations

import asyncio
from typing import Callable, Optional, Tuple

import httpx

from argus.models import EmailAccountResult, EmailRegistrationReport, ModuleStatus

ProgressCallback = Callable[[str, int, int, str], None]


async def check_email_registrations(
    email: str,
    timeout: int = 10,
    proxy: Optional[str] = None,
    concurrency: int = 15,
    progress_callback: Optional[ProgressCallback] = None,
) -> Tuple[Optional[EmailRegistrationReport], ModuleStatus]:
    """Check if an email address is registered across all Holehe providers."""
    clean_email = email.strip()
    if not clean_email or "@" not in clean_email or "." not in clean_email.split("@")[-1]:
        return None, ModuleStatus(
            module_name="Email Recon (Holehe)",
            status="skipped",
            message=f"Invalid email address: '{email}'",
        )

    try:
        import holehe.core

        modules = holehe.core.import_submodules("holehe.modules")
        websites = holehe.core.get_functions(modules)
    except Exception as ex:
        return None, ModuleStatus(
            module_name="Email Recon (Holehe)",
            status="error",
            message=f"Failed to load Holehe modules: {ex}",
        )

    if not websites:
        return None, ModuleStatus(
            module_name="Email Recon (Holehe)",
            status="skipped",
            message="No Holehe website modules available",
        )

    total_sites = len(websites)
    completed_count = 0
    sem = asyncio.Semaphore(concurrency)
    out: list[dict] = []

    if progress_callback:
        progress_callback(
            "Email Recon (Holehe)",
            0,
            total_sites,
            f"Probing {clean_email} across {total_sites} platforms...",
        )

    async def worker(website_func, client: httpx.AsyncClient) -> None:
        nonlocal completed_count
        async with sem:
            try:
                await holehe.core.launch_module(website_func, clean_email, client, out)
            except Exception:
                pass
            finally:
                completed_count += 1
                if progress_callback and (completed_count % 10 == 0 or completed_count == total_sites):
                    site_name = getattr(website_func, "__name__", "provider")
                    progress_callback(
                        "Email Recon (Holehe)",
                        completed_count,
                        total_sites,
                        f"Checking {site_name} ({completed_count}/{total_sites})...",
                    )

    try:
        async with httpx.AsyncClient(timeout=timeout, proxy=proxy) as client:
            tasks = [worker(w, client) for w in websites]
            await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as ex:
        return None, ModuleStatus(
            module_name="Email Recon (Holehe)",
            status="error",
            message=f"Holehe scan error: {ex}",
        )

    discovered_accounts: list[EmailAccountResult] = []
    seen_domains: set[str] = set()

    for item in out:
        if item.get("exists") is True:
            platform_name = item.get("name", "unknown")
            domain_name = item.get("domain", f"{platform_name}.com")
            if domain_name not in seen_domains:
                seen_domains.add(domain_name)
                discovered_accounts.append(
                    EmailAccountResult(
                        platform=platform_name,
                        domain=domain_name,
                        rate_limit=bool(item.get("rateLimit", False)),
                        email_recovery=item.get("emailrecovery") or None,
                        phone_number=item.get("phoneNumber") or None,
                        other_info=str(item.get("others")) if item.get("others") else None,
                    )
                )

    # Sort discovered accounts alphabetically by platform name
    discovered_accounts.sort(key=lambda a: a.platform.lower())

    report = EmailRegistrationReport(
        email=clean_email,
        total_checked=total_sites,
        accounts=discovered_accounts,
    )

    if discovered_accounts:
        status = ModuleStatus(
            module_name=f"Email Recon ({clean_email})",
            status="success",
            message=f"Registered on {len(discovered_accounts)} platform(s) out of {total_sites} checked",
        )
    else:
        status = ModuleStatus(
            module_name=f"Email Recon ({clean_email})",
            status="no_hits",
            message=f"No registrations confirmed across {total_sites} platforms checked",
        )

    return report, status
