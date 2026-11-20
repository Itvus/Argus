"""Modular enrichment plugins for CordCat, breach notifications, and GitHub public pivots."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Callable, Optional, Tuple

import httpx

from argus.models import (
    BreachRecord,
    CordCatRecord,
    GitHubPivotLead,
    ModuleStatus,
)
from argus.modules.snowflake import format_human_age


# ============================================================================
# 1. CordCat Plugin (Historical Usernames & FiveM Records)
# ============================================================================
async def query_cordcat(
    user_id: str,
    api_key: Optional[str],
    timeout: int = 15,
    proxy: Optional[str] = None,
    progress_callback: Optional[Callable[[str, int, int, str], None]] = None,
) -> Tuple[Optional[CordCatRecord], ModuleStatus]:
    """Query CordCat API v2 for historical usernames and FiveM identifiers with progress reporting."""
    if progress_callback:
        progress_callback("CordCat Indexer", 0, 1, f"CordCat API v2 (User ID: {user_id})")

    if not api_key or not api_key.strip():
        if progress_callback:
            progress_callback("CordCat Indexer", 1, 1, "Skipped (API key not set)")
        return None, ModuleStatus(
            module_name="CordCat",
            status="skipped",
            message="CORDCAT_API_KEY is not configured in .env. Historical username & FiveM lookups skipped.",
        )

    headers = {
        "X-API-Key": api_key.strip(),
        "User-Agent": "argus/0.1.0 (OSINT tool)",
        "Accept": "application/json",
    }
    url = f"https://api.cord.cat/v2/query/{user_id}"

    async with httpx.AsyncClient(timeout=timeout, proxy=proxy) as client:
        try:
            resp = await client.get(url, headers=headers)
            if progress_callback:
                progress_callback("CordCat Indexer", 1, 1, f"HTTP {resp.status_code}")

            if resp.status_code == 200:
                data = resp.json()
                historical: list[str] = []
                fivem_ids: list[str] = []
                records: list[dict[str, Any]] = []

                # Extract historical names
                raw_history = data.get("usernames", []) or data.get("historical_usernames", [])
                if isinstance(raw_history, list):
                    for h in raw_history:
                        if isinstance(h, str) and h not in historical:
                            historical.append(h)
                        elif isinstance(h, dict) and "username" in h:
                            historical.append(h["username"])

                # Extract FiveM / CFX identifiers
                raw_fivem = data.get("fivem", []) or data.get("cfx", []) or data.get("identifiers", [])
                if isinstance(raw_fivem, list):
                    for f in raw_fivem:
                        if isinstance(f, str) and f not in fivem_ids:
                            fivem_ids.append(f)
                        elif isinstance(f, dict):
                            identifier = f.get("identifier") or f.get("name") or str(f)
                            fivem_ids.append(identifier)

                raw_records = data.get("records", [])
                if isinstance(raw_records, list):
                    records = [r for r in raw_records if isinstance(r, dict)]

                record = CordCatRecord(
                    user_id=user_id,
                    historical_usernames=historical,
                    fivem_identifiers=fivem_ids,
                    records=records,
                    status="success",
                )
                hit_info = f"Found {len(historical)} historical names, {len(fivem_ids)} FiveM records."
                return record, ModuleStatus(module_name="CordCat", status="success", message=hit_info)

            if resp.status_code == 404:
                return None, ModuleStatus(
                    module_name="CordCat",
                    status="no_hits",
                    message="No historical records found on CordCat for this Discord ID.",
                )

            if resp.status_code in (401, 403):
                return None, ModuleStatus(
                    module_name="CordCat",
                    status="unauthorized",
                    message="CordCat API returned 401/403. Check your CORDCAT_API_KEY in .env.",
                )

            if resp.status_code == 429:
                return None, ModuleStatus(
                    module_name="CordCat",
                    status="rate_limited",
                    message="CordCat API rate limit exceeded.",
                )

            return None, ModuleStatus(
                module_name="CordCat",
                status="error",
                message=f"CordCat returned HTTP {resp.status_code}",
            )

        except httpx.TimeoutException:
            return None, ModuleStatus(module_name="CordCat", status="timeout", message="CordCat API timed out.")
        except Exception as ex:
            return None, ModuleStatus(module_name="CordCat", status="error", message=f"CordCat error: {ex}")


# ============================================================================
# 2. Breach / Exposure Check Plugin (HIBP & LeakCheck)
# ============================================================================
async def _check_hibp(
    account: str,
    api_key: str,
    client: httpx.AsyncClient,
) -> Tuple[list[BreachRecord], Optional[str]]:
    """Query Have I Been Pwned breachedaccount endpoint."""
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{account}?truncateResponse=false"
    headers = {
        "hibp-api-key": api_key.strip(),
        "user-agent": "argus-osint-research-tool",
        "Accept": "application/json",
    }
    records: list[BreachRecord] = []
    try:
        resp = await client.get(url, headers=headers)
        if resp.status_code == 200:
            for b in resp.json():
                records.append(
                    BreachRecord(
                        query=account,
                        service_name=b.get("Name", "Unknown"),
                        breach_date=b.get("BreachDate"),
                        pwn_count=b.get("PwnCount"),
                        data_classes=b.get("DataClasses", []),
                        description=b.get("Description"),
                    )
                )
            return records, None

        if resp.status_code == 404:
            return [], None

        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After", "2")
            await asyncio.sleep(min(float(retry_after), 3.0))
            resp2 = await client.get(url, headers=headers)
            if resp2.status_code == 200:
                for b in resp2.json():
                    records.append(
                        BreachRecord(
                            query=account,
                            service_name=b.get("Name", "Unknown"),
                            breach_date=b.get("BreachDate"),
                            pwn_count=b.get("PwnCount"),
                            data_classes=b.get("DataClasses", []),
                            description=b.get("Description"),
                        )
                    )
                return records, None
            return [], "HIBP rate limit exceeded (HTTP 429)."

        if resp.status_code in (401, 403):
            return [], "HIBP API key is invalid or unauthorized (HTTP 401/403)."

        return [], f"HIBP returned HTTP {resp.status_code}"
    except Exception as e:
        return [], f"HIBP error: {e}"


async def _check_leakcheck(
    query: str,
    api_key: str,
    client: httpx.AsyncClient,
) -> Tuple[list[BreachRecord], Optional[str]]:
    """Query LeakCheck API."""
    url = f"https://leakcheck.io/api/v2/query/{query}"
    headers = {
        "X-API-Key": api_key.strip(),
        "Accept": "application/json",
    }
    records: list[BreachRecord] = []
    try:
        resp = await client.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("result", [])
            for item in results:
                sources = item.get("sources", [])
                fields = item.get("fields", [])
                date = item.get("date")
                for s in sources:
                    records.append(
                        BreachRecord(
                            query=query,
                            service_name=s if isinstance(s, str) else s.get("name", "Unknown"),
                            breach_date=date,
                            data_classes=fields if isinstance(fields, list) else [],
                        )
                    )
            return records, None
        if resp.status_code == 404:
            return [], None
        return [], f"LeakCheck returned HTTP {resp.status_code}"
    except Exception as e:
        return [], f"LeakCheck error: {e}"


async def check_breaches(
    queries: list[str],
    hibp_api_key: Optional[str] = None,
    leakcheck_api_key: Optional[str] = None,
    timeout: int = 15,
    proxy: Optional[str] = None,
    progress_callback: Optional[Callable[[str, int, int, str], None]] = None,
) -> Tuple[list[BreachRecord], ModuleStatus]:
    """Check emails or usernames against configured breach notification providers with progress reporting."""
    if not hibp_api_key and not leakcheck_api_key:
        if progress_callback:
            progress_callback("Breach Exposure", 1, 1, "Skipped (No HIBP/LeakCheck key)")
        return [], ModuleStatus(
            module_name="Breach Exposure",
            status="skipped",
            message="Neither HIBP_API_KEY nor LEAKCHECK_API_KEY configured. Breach checks skipped.",
        )

    if not queries:
        return [], ModuleStatus(
            module_name="Breach Exposure",
            status="no_queries",
            message="No emails or query handles available for breach lookup.",
        )

    all_records: list[BreachRecord] = []
    error_notes: list[str] = []
    total_q = len(queries)

    async with httpx.AsyncClient(timeout=timeout, proxy=proxy) as client:
        for idx, q in enumerate(queries, start=1):
            service_label = "Have I Been Pwned" if (hibp_api_key and "@" in q) else "LeakCheck"
            if progress_callback:
                progress_callback("Breach Exposure", idx, total_q, f"{service_label}: {q}")

            if hibp_api_key and "@" in q:
                records, err = await _check_hibp(q, hibp_api_key, client)
                all_records.extend(records)
                if err and err not in error_notes:
                    error_notes.append(err)
            elif leakcheck_api_key:
                records, err = await _check_leakcheck(q, leakcheck_api_key, client)
                all_records.extend(records)
                if err and err not in error_notes:
                    error_notes.append(err)

    status_str = "success" if all_records else ("error" if error_notes else "no_hits")
    msg = f"Found {len(all_records)} breach records across {len(queries)} queries."
    if error_notes:
        msg += f" (Notices: {'; '.join(error_notes)})"

    return all_records, ModuleStatus(module_name="Breach Exposure", status=status_str, message=msg)


# ============================================================================
# 3. GitHub Public Pivot Plugin (Commits, Emails, Account Creation)
# ============================================================================
async def fetch_github_pivot(
    username: str,
    github_token: Optional[str] = None,
    discord_created_at_dt: Optional[datetime] = None,
    timeout: int = 15,
    proxy: Optional[str] = None,
    progress_callback: Optional[Callable[[str, int, int, str], None]] = None,
) -> Tuple[Optional[GitHubPivotLead], ModuleStatus]:
    """Audit a GitHub profile and public commit events with live progress reporting."""
    clean_username = username.lstrip("@").strip()
    headers = {
        "User-Agent": "argus-osint/0.1.0 (+https://github.com/argus)",
        "Accept": "application/vnd.github.v3+json",
    }
    if github_token and github_token.strip():
        headers["Authorization"] = f"token {github_token.strip()}"

    profile_url = f"https://api.github.com/users/{clean_username}"
    events_url = f"https://api.github.com/users/{clean_username}/events/public"

    if progress_callback:
        progress_callback("GitHub Audit", 0, 2, f"Profile: https://github.com/{clean_username}")

    async with httpx.AsyncClient(timeout=timeout, proxy=proxy) as client:
        try:
            # 1. Fetch GitHub profile
            p_resp = await client.get(profile_url, headers=headers)
            if progress_callback:
                progress_callback("GitHub Audit", 1, 2, f"Public Events: /users/{clean_username}/events/public")

            if p_resp.status_code == 404:
                return None, ModuleStatus(
                    module_name="GitHub Pivot",
                    status="no_hits",
                    message=f"GitHub user '{clean_username}' does not exist.",
                )

            if p_resp.status_code in (401, 403):
                msg = "Rate limited" if p_resp.status_code == 403 else "Unauthorized"
                return None, ModuleStatus(
                    module_name="GitHub Pivot",
                    status="rate_limited",
                    message=f"GitHub API {msg} (HTTP {p_resp.status_code}). Configure GITHUB_TOKEN to raise limits.",
                )

            if p_resp.status_code != 200:
                return None, ModuleStatus(
                    module_name="GitHub Pivot",
                    status="error",
                    message=f"GitHub API returned HTTP {p_resp.status_code}",
                )

            p_data = p_resp.json()
            gh_created_str = p_data.get("created_at")
            gh_created_dt: Optional[datetime] = None
            account_age_days: Optional[int] = None
            if gh_created_str:
                try:
                    gh_created_dt = datetime.fromisoformat(gh_created_str.replace("Z", "+00:00"))
                    now = datetime.now(timezone.utc)
                    account_age_days = (now - gh_created_dt).days
                except Exception:
                    pass

            # Calculate creation date comparison with Discord snowflake
            age_comparison: Optional[str] = None
            if gh_created_dt and discord_created_at_dt:
                diff_seconds = (discord_created_at_dt - gh_created_dt).total_seconds()
                formatted_diff = format_human_age(abs(diff_seconds))
                if diff_seconds > 0:
                    age_comparison = f"GitHub created {formatted_diff} BEFORE Discord account."
                else:
                    age_comparison = f"GitHub created {formatted_diff} AFTER Discord account."

            # 2. Fetch public commit events
            commit_emails: set[str] = set()
            try:
                e_resp = await client.get(events_url, headers=headers)
                if progress_callback:
                    progress_callback("GitHub Audit", 2, 2, "Public commit author emails parsed")
                if e_resp.status_code == 200:
                    events = e_resp.json()
                    for event in events:
                        if event.get("type") == "PushEvent":
                            commits = event.get("payload", {}).get("commits", [])
                            for c in commits:
                                author = c.get("author", {})
                                email = author.get("email", "")
                                if email and "@" in email:
                                    email_lower = email.strip().lower()
                                    if not email_lower.endswith("@users.noreply.github.com") and not email_lower.endswith(".local"):
                                        commit_emails.add(email_lower)
            except Exception:
                pass

            # Check for public profile email
            public_email = p_data.get("email")
            if public_email and "@" in public_email:
                clean_pub = public_email.strip().lower()
                if not clean_pub.endswith("@users.noreply.github.com") and not clean_pub.endswith(".local"):
                    commit_emails.add(clean_pub)

            lead = GitHubPivotLead(
                username=clean_username,
                profile_url=p_data.get("html_url") or f"https://github.com/{clean_username}",
                name=p_data.get("name"),
                company=p_data.get("company"),
                blog=p_data.get("blog"),
                location=p_data.get("location"),
                bio=p_data.get("bio"),
                created_at=gh_created_str,
                account_age_days=account_age_days,
                commit_emails=sorted(list(commit_emails)),
                age_comparison_discord=age_comparison,
            )

            msg = f"Audited GitHub profile. Discovered {len(commit_emails)} public commit email(s)."
            return lead, ModuleStatus(module_name="GitHub Pivot", status="success", message=msg)

        except httpx.TimeoutException:
            return None, ModuleStatus(module_name="GitHub Pivot", status="timeout", message="GitHub API timed out.")
        except Exception as ex:
            return None, ModuleStatus(module_name="GitHub Pivot", status="error", message=f"GitHub Pivot error: {ex}")
