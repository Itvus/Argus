"""Wayback Machine / Internet Archive CDX historical profile snapshot discovery."""

from __future__ import annotations

import asyncio
import urllib.parse
from typing import Callable, Optional
import httpx

from argus.models import ModuleStatus, WaybackSnapshot


async def fetch_wayback_snapshots(
    urls: list[str],
    timeout: int = 10,
    proxy: Optional[str] = None,
    progress_callback: Optional[Callable[[str, int, int, str], None]] = None,
) -> tuple[list[WaybackSnapshot], ModuleStatus]:
    """Query Internet Archive CDX API for historical snapshots of target profile URLs."""
    if not urls:
        return [], ModuleStatus(
            module_name="Wayback Machine",
            status="skipped",
            message="No profile URLs to check for historical snapshots",
        )

    if progress_callback:
        progress_callback("Wayback Snapshots", 0, len(urls), "Querying Internet Archive CDX API...")

    snapshots: list[WaybackSnapshot] = []
    client_kwargs = {
        "timeout": timeout,
        "follow_redirects": True,
        "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Argus-OSINT/1.0"},
    }
    if proxy:
        client_kwargs["proxy"] = proxy

    # Check top 5 most valuable URLs (e.g. GitHub, Reddit, Steam, personal sites)
    candidate_urls = urls[:5]

    async with httpx.AsyncClient(**client_kwargs) as client:
        async def fetch_single_cdx(idx: int, target_url: str) -> None:
            if progress_callback:
                progress_callback("Wayback Snapshots", idx, len(candidate_urls), f"Checking {target_url}")
            try:
                encoded_target = urllib.parse.quote(target_url, safe="")
                cdx_url = (
                    f"https://web.archive.org/cdx/search/cdx"
                    f"?url={encoded_target}&output=json&limit=3&fl=timestamp,original,statuscode&filter=statuscode:200"
                )
                resp = await client.get(cdx_url)
                if resp.status_code == 200:
                    rows = resp.json()
                    # CDX returns header row first: ["timestamp", "original", "statuscode"]
                    if len(rows) > 1:
                        for row in rows[1:]:
                            if len(row) >= 3:
                                ts, orig, st = row[0], row[1], row[2]
                                archive_link = f"https://web.archive.org/web/{ts}/{orig}"
                                snapshots.append(
                                    WaybackSnapshot(
                                        original_url=orig,
                                        archive_url=archive_link,
                                        timestamp=ts,
                                        status_code=st,
                                    )
                                )
            except Exception:
                pass

        tasks = [fetch_single_cdx(idx, u) for idx, u in enumerate(candidate_urls, start=1)]
        await asyncio.gather(*tasks, return_exceptions=True)

    status = "success" if snapshots else "no_hits"
    msg = f"Discovered {len(snapshots)} historical archive snapshots" if snapshots else "No historical snapshots found"
    return snapshots, ModuleStatus(module_name="Wayback Machine", status=status, message=msg)
