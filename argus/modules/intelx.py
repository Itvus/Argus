"""Intelligence X (intelx.io) darknet and data leak search module for Argus.

Queries Intelligence X for darknet archives, public pastes, and leaked records.
Operates as an opt-in enrichment module (--intelx).
"""

from __future__ import annotations

import asyncio
from typing import Callable, Optional, Tuple

import httpx

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

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    # Free tier / public phonebook uses default public access if no key provided
    key = api_key.strip() if api_key else "2bbba20f-08e0-4a87-9d7a-1941a4a16999"
    headers["x-key"] = key

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

            # Wait briefly for results to populate
            await asyncio.sleep(1.0)

            # Step 2: Fetch results
            res_url = f"https://2.intelx.io/phonebook/search/result?id={search_id}&limit=15"
            res_resp = await client.get(res_url, headers=headers)
            if res_resp.status_code == 200:
                res_data = res_resp.json()
                selectors_raw = res_data.get("selectors", [])
                records: list[IntelXRecord] = []
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
                else:
                    return report, ModuleStatus(
                        module_name="Intelligence X",
                        status="no_hits",
                        message=f"No Intelligence X records found for '{clean_selector}'",
                    )
            else:
                return None, ModuleStatus(
                    module_name="Intelligence X",
                    status="no_hits",
                    message=f"IntelX result fetch status: {res_resp.status_code}",
                )

    except Exception as ex:
        return None, ModuleStatus(
            module_name="Intelligence X",
            status="error",
            message=f"IntelX query error: {ex}",
        )
