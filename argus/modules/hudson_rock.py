"""Hudson Rock Cavalier infostealer cybercrime intelligence module for Argus.

Queries Hudson Rock's public OSINT API to identify infostealer malware infections
(RedLine, Lumma, Vidar, Raccoon, etc.) associated with a target username or email address.
Zero API key required; fast concurrent passive reconnaissance.
"""

from __future__ import annotations

import urllib.parse
from typing import Callable, Optional, Tuple

import httpx

from argus.models import HudsonRockReport, ModuleStatus, StealerInfection

ProgressCallback = Callable[[str, int, int, str], None]


async def fetch_hudson_rock_intel(
    query: str,
    query_type: str = "username",  # "username" or "email"
    timeout: int = 10,
    proxy: Optional[str] = None,
    progress_callback: Optional[ProgressCallback] = None,
) -> Tuple[Optional[HudsonRockReport], ModuleStatus]:
    """Query Hudson Rock Cavalier API for infostealer malware compromises."""
    clean_query = query.strip()
    if not clean_query:
        return None, ModuleStatus(
            module_name="Hudson Rock Infostealer Intel",
            status="skipped",
            message="Empty query provided",
        )

    endpoint = (
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"
        if query_type == "email" or "@" in clean_query
        else "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username"
    )
    param_key = "email" if (query_type == "email" or "@" in clean_query) else "username"
    url = f"{endpoint}?{param_key}={urllib.parse.quote(clean_query)}"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json",
    }

    if progress_callback:
        progress_callback("Hudson Rock Intel", 0, 1, f"Checking infostealer compromises for '{clean_query}'...")

    try:
        async with httpx.AsyncClient(timeout=timeout, proxy=proxy) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                stealers_raw = data.get("stealers", [])
                total_stealers = len(stealers_raw)
                total_corp = data.get("total_corporate_services", 0)
                total_user = data.get("total_user_services", 0)

                infections: list[StealerInfection] = []
                for s in stealers_raw:
                    top_log = s.get("top_logins") or []
                    infections.append(
                        StealerInfection(
                            stealer_family=s.get("stealer_family") or s.get("malware_family") or "Unknown Stealer",
                            date_compromised=s.get("date_compromised"),
                            computer_name=s.get("computer_name") if s.get("computer_name") != "Not Found" else None,
                            operating_system=s.get("operating_system") if s.get("operating_system") != "Not Found" else None,
                            ip=s.get("ip") if s.get("ip") != "Not Found" else None,
                            malware_path=s.get("malware_path"),
                            top_logins=top_log[:8],
                        )
                    )

                report = HudsonRockReport(
                    query=clean_query,
                    query_type=query_type,
                    total_stealers=total_stealers,
                    total_corporate_services=total_corp,
                    total_user_services=total_user,
                    infections=infections,
                )

                if total_stealers > 0:
                    status = ModuleStatus(
                        module_name="Hudson Rock Infostealer Intel",
                        status="success",
                        message=f"Discovered {total_stealers} infostealer infection(s) for '{clean_query}'",
                    )
                else:
                    status = ModuleStatus(
                        module_name="Hudson Rock Infostealer Intel",
                        status="no_hits",
                        message=f"No infostealer infections found for '{clean_query}'",
                    )
                return report, status
            elif resp.status_code == 404:
                return HudsonRockReport(query=clean_query, query_type=query_type), ModuleStatus(
                    module_name="Hudson Rock Infostealer Intel",
                    status="no_hits",
                    message=f"No infostealer records for '{clean_query}'",
                )
            else:
                return None, ModuleStatus(
                    module_name="Hudson Rock Infostealer Intel",
                    status="error",
                    message=f"HTTP {resp.status_code} from Hudson Rock API",
                )
    except Exception as ex:
        return None, ModuleStatus(
            module_name="Hudson Rock Infostealer Intel",
            status="error",
            message=f"Hudson Rock query error: {ex}",
        )
