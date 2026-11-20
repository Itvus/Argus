"""Intelligence X (intelx.io) darknet and data leak search module for Argus.

Queries Intelligence X for darknet archives, public pastes, and leaked records.
Operates as an opt-in enrichment module (--intelx).
"""

from __future__ import annotations

import asyncio
from typing import Callable, Optional, Tuple

import httpx

from argus import __version__
from argus.models import IntelXRecord, IntelXReport, ModuleStatus

ProgressCallback = Callable[[str, int, int, str], None]


async def query_intelx(
    selector: str,
    api_key: Optional[str] = None,
    timeout: int = 15,
    proxy: Optional[str] = None,
    progress_callback: Optional[ProgressCallback] = None,
) -> Tuple[Optional[IntelXReport], ModuleStatus]:
    """Query Intelligence X API for selector records (emails, domains, usernames)."""
    clean_selector = selector.strip()
    if not clean_selector:
        return None, ModuleStatus(
            module_name="Intelligence X",
            status="skipped",
            message="Empty selector query",
        )

    if not api_key or not api_key.strip():
        if progress_callback:
            progress_callback("Intelligence X", 1, 1, "Skipped (No API key)")
        return None, ModuleStatus(
            module_name="Intelligence X",
            status="skipped",
            message="INTELX_API_KEY is not configured in .env. Intelligence X queries skipped.",
        )

    headers = {
        "User-Agent": f"argus/{__version__} (+https://github.com/Itvus/Argus)",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "x-key": api_key.strip(),
    }

    if progress_callback:
        progress_callback("Intelligence X", 0, 1, f"Querying darknet archives for '{clean_selector}'...")

    try:
        async with httpx.AsyncClient(timeout=timeout, proxy=proxy) as client:
            # Step 1: Submit search request to Phonebook API
            init_url = "https://2.intelx.io/phonebook/search"
            payload = {
                "term": clean_selector,
                "maxresults": 15,
                "media": 0,
                "target": 0,
                "terminate": [],
            }
            init_resp = await client.post(init_url, headers=headers, json=payload)
            if init_resp.status_code != 200:
                return None, ModuleStatus(
                    module_name="Intelligence X",
                    status="skipped" if init_resp.status_code in (401, 403, 429) else "error",
                    message=f"IntelX API returned status {init_resp.status_code}",
                )

            search_id = init_resp.json().get("id")
            if not search_id:
                return None, ModuleStatus(
                    module_name="Intelligence X",
                    status="no_hits",
                    message="No search task ID returned by IntelX",
                )

            # Step 2: Bounded polling for results (up to 4 attempts)
            records: list[IntelXRecord] = []
            res_url = f"https://2.intelx.io/phonebook/search/result?id={search_id}&limit=15"
            last_status = 200
            for attempt in range(4):
                if attempt > 0:
                    await asyncio.sleep(1.0)
                res_resp = await client.get(res_url, headers=headers)
                last_status = res_resp.status_code
                if res_resp.status_code == 200:
                    res_data = res_resp.json()
                    selectors_raw = res_data.get("selectors", [])
                    status_code = res_data.get("status")
                    if selectors_raw:
                        for s in selectors_raw:
                            val = s.get("selectorvalue") or s.get("selector") or ""
                            if val:
                                records.append(
                                    IntelXRecord(
                                        system_id=search_id,
                                        name=val,
                                        media_type=str(s.get("selectortype")),
                                    )
                                )
                        break
                    if status_code in (2, 3):
                        break

            report = IntelXReport(
                query=clean_selector,
                total_results=len(records),
                records=records,
            )
            if records:
                return report, ModuleStatus(
                    module_name="Intelligence X",
                    status="success",
                    message=f"Discovered {len(records)} darknet/leak selector(s)",
                )
            elif last_status != 200:
                return None, ModuleStatus(
                    module_name="Intelligence X",
                    status="no_hits",
                    message=f"IntelX result fetch status: {last_status}",
                )
            else:
                return report, ModuleStatus(
                    module_name="Intelligence X",
                    status="no_hits",
                    message=f"No Intelligence X records found for '{clean_selector}'",
                )

    except Exception as ex:
        return None, ModuleStatus(
            module_name="Intelligence X",
            status="error",
            message=f"IntelX query error: {ex}",
        )
