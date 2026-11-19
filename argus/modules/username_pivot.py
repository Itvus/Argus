"""Username enumeration module using Maigret and regex profile lead extraction."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys
import tempfile
from typing import Any, Callable, Optional, Set, Tuple
from urllib.parse import urlparse

from bs4 import BeautifulSoup
import httpx

from argus.models import CryptoLead, MessagingLead, PivotLeads, SocialProfile
from argus.modules.snowflake import is_valid_snowflake

logger = logging.getLogger("argus.username_pivot")

# Priority platforms to examine for developers and gamers
PRIORITY_SITES = [
    "GitHub",
    "GitLab",
    "Steam",
    "Reddit",
    "Twitch",
    "Keybase",
    "Telegram",
    "Twitter",
    "Discord",
    "YouTube",
    "Spotify",
    "HackerNews",
    "Docker Hub",
    "Patreon",
]

# Regex extractors for OSINT pivot leads
DISCORD_INVITE_REGEX = re.compile(
    r"discord(?:\.gg|app\.com/invite)/([a-zA-Z0-9-]+)", re.IGNORECASE
)
DISCORD_TAG_REGEX = re.compile(
    r"(?<![a-zA-Z0-9_#])([a-zA-Z0-9_.]{2,32}#[0-9]{4})\b"
)
# Matches explicit Discord IDs, Discord mentions, Discord profile links, or labeled ID prefixes
DISCORD_ID_REGEX = re.compile(
    r"(?:(?:discord(?:\s*(?:user|id|uid|snowflake|account))?|dc\s*id|user\s*id|my\s*id|uid|snowflake)[\s:=-]*(?:is\s+)?|<@!?|discord(?:app)?\.com/users/)([1-9][0-9]{16,19})",
    re.IGNORECASE,
)
# Strict RFC-5322 compliant regex requiring valid alphabetic TLD
EMAIL_REGEX = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,10}\b"
)

# Common noisy domains/patterns to filter out from regex-extracted emails
IGNORED_EMAIL_DOMAINS = {
    "example.com",
    "schema.org",
    "w3.org",
    "sentry.io",
    "github.com",
    "users.noreply.github.com",
    "cloudflare.com",
    "googleapis.com",
    "gravatar.com",
    "discord.com",
    "discordapp.com",
    "google.com",
    "facebook.com",
    "twitter.com",
    "x.com",
    "instagram.com",
}
# Generic role-based / operational email prefixes that belong to platforms, not individual users
ROLE_PREFIXES = {
    "support",
    "helpdesk",
    "partners",
    "staff",
    "admin",
    "contact",
    "info",
    "sales",
    "billing",
    "press",
    "jobs",
    "careers",
    "privacy",
    "security",
    "legal",
    "abuse",
    "marketing",
    "team",
    "media",
    "office",
    "hr",
    "feedback",
    "hello",
    "newsletter",
    "compliance",
    "service",
    "inquiries",
    "dev",
    "developer",
    "developers",
    "root",
    "webmaster",
    "postmaster",
    "hostmaster",
    "operations",
    "ops",
    "media-relations",
    "editorial",
    "general",
}
# Known platform/company Discord servers to exclude from pivot leads
IGNORED_COMMUNITY_INVITES = {
    "discord",
    "discord-developers",
    "discord-api",
    "discord-testers",
    "react",
    "reactiflux",
    "python",
    "rust",
    "vue",
    "angular",
    "nextjs",
    "midjourney",
    "openai",
    "github",
    "gitlab",
    "steam",
    "twitter",
    "reddit",
    "telegram",
    "spotify",
    "youtube",
    "community",
    "support",
    "official",
}
IGNORED_EXTENSIONS = (".png", ".jpg", ".jpeg", ".svg", ".gif", ".webp", ".js", ".css")


def get_base_domain(url: str) -> str:
    """Extract root domain without www or subdomains from URL."""
    try:
        host = urlparse(url).netloc.lower()
        if host.startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return ""


def clean_emails(raw_emails: list[str], site_url: str = "", target_username: str = "") -> set[str]:
    """Filter out noise, npm versions, role-based mailboxes, and platform-owned emails."""
    site_domain = get_base_domain(site_url)
    cleaned: set[str] = set()
    for email in raw_emails:
        email_clean = email.strip().lower()
        if any(email_clean.endswith(ext) for ext in IGNORED_EXTENSIONS):
            continue
        if "@" not in email_clean:
            continue
        local_part, domain = email_clean.split("@", 1)

        # Discard generic corporate role prefixes unless the target's username is literally that prefix
        if local_part in ROLE_PREFIXES and local_part != target_username.lower():
            continue

        if domain in IGNORED_EMAIL_DOMAINS:
            continue
        if domain.endswith(".internal") or domain.endswith(".local"):
            continue

        # If the email's domain matches the host platform, it's the platform's email, not the user's
        if site_domain and (domain == site_domain or domain.endswith("." + site_domain)):
            if local_part != target_username.lower():
                continue

        # Ensure domain has valid alphabetic TLD and no version-like digits
        parts = domain.split(".")
        if len(parts) < 2 or any(p.isdigit() for p in parts) or not re.match(r"^[a-zA-Z]{2,}$", parts[-1]):
            continue

        cleaned.add(email_clean)
    return cleaned


def clean_discord_invites(raw_invites: list[str], site_url: str = "") -> set[str]:
    """Filter out official/corporate community servers and return canonical discord.gg URLs."""
    site_domain = get_base_domain(site_url)
    site_name = site_domain.split(".")[0] if site_domain else ""
    cleaned: set[str] = set()
    for inv in raw_invites:
        inv_code = inv.strip()
        code_lower = inv_code.lower()
        if code_lower in IGNORED_COMMUNITY_INVITES:
            continue
        # Exclude platform's own community server if the code contains or matches the site name
        if site_name and len(site_name) >= 3:
            if site_name in code_lower or code_lower in site_name:
                continue
        # Canonical invite code must be valid alphanumeric or hyphen
        if not re.match(r"^[a-zA-Z0-9-]{2,32}$", inv_code):
            continue
        cleaned.add(f"https://discord.gg/{inv_code}")
    return cleaned


def extract_crypto_leads(text: str) -> list[CryptoLead]:
    """Extract Bitcoin, Ethereum, and Solana addresses with strict anti-false-positive validation."""
    leads: list[CryptoLead] = []
    seen: set[str] = set()

    # 1. Bitcoin Bech32 (bc1...)
    for m in re.finditer(r"\b(bc1[ac-hj-np-z02-9]{38,59})\b", text, re.IGNORECASE):
        addr = m.group(1).lower()
        if addr not in seen:
            seen.add(addr)
            leads.append(CryptoLead(network="Bitcoin", address=addr))

    # 2. Bitcoin Base58 (starts with 1 or 3, length 26-35) - strictly requires crypto context window
    for m in re.finditer(r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", text):
        addr = m.group(1)
        start = max(0, m.start() - 40)
        end = min(len(text), m.end() + 40)
        window = text[start:end].lower()
        if re.search(r"\b(btc|bitcoin|wallet|donate|tip|crypto)\b", window):
            if addr not in seen:
                seen.add(addr)
                leads.append(CryptoLead(network="Bitcoin", address=addr))

    # 3. Ethereum (0x... 40 hex chars)
    for m in re.finditer(r"\b(0x[a-fA-F0-9]{40})\b", text):
        addr = m.group(1)
        # Check immediate segment bounded by newline or proximity
        seg_start = max(0, m.start() - 30)
        nl_before = text.rfind("\n", seg_start, m.start())
        if nl_before != -1:
            seg_start = nl_before + 1

        seg_end = min(len(text), m.end() + 30)
        nl_after = text.find("\n", m.end(), seg_end)
        if nl_after != -1:
            seg_end = nl_after

        local_seg = text[seg_start:seg_end].lower()
        if re.search(r"\b(commit|tree|blob|sha1?)\b", local_seg):
            continue

        # Broader context window (40 chars) for crypto relevance
        ctx_start = max(0, m.start() - 40)
        ctx_end = min(len(text), m.end() + 40)
        ctx_window = text[ctx_start:ctx_end].lower()

        # Require crypto context or mixed-case address (EIP-55 standard)
        has_mixed_case = any(c.isupper() for c in addr[2:]) and any(c.islower() for c in addr[2:])
        has_context = bool(re.search(r"\b(eth|ethereum|wallet|address|donate|tip|crypto|web3|ens|polygon|arbitrum|optimism)\b", ctx_window))
        if has_mixed_case or has_context:
            if addr.lower() not in seen:
                seen.add(addr.lower())
                leads.append(CryptoLead(network="Ethereum", address=addr))

    # 4. Solana (Base58 32-44 chars) - strictly requires explicit solana context
    for m in re.finditer(r"\b([1-9A-HJ-NP-Za-km-z]{32,44})\b", text):
        addr = m.group(1)
        start = max(0, m.start() - 25)
        end = min(len(text), m.end() + 25)
        window = text[start:end].lower()
        if re.search(r"\b(sol|solana|phantom|backpack|sollet)\b", window):
            if addr not in seen:
                seen.add(addr)
                leads.append(CryptoLead(network="Solana", address=addr))

    return leads


def extract_messaging_leads(text: str, site_url: str = "") -> list[MessagingLead]:
    """Extract Telegram, Matrix, and Signal handles with anti-noise platform filtering."""
    leads: list[MessagingLead] = []
    seen: set[str] = set()

    site_name = ""
    if site_url:
        site_name = get_base_domain(site_url).split(".")[0]

    ignored_tg = {
        "share", "joinchat", "addstickers", "proxy", "socks", "setlanguage",
        "iv", "telegram", "bot", "s", "c", "login", "app", "channel", "group",
        "help", "support", "faq", "terms", "privacy", "about"
    }
    if site_name:
        ignored_tg.add(site_name)

    # 1. Telegram links (t.me/<username>)
    for m in re.finditer(r"(?:https?://)?(?:t\.me|telegram\.me)/([a-zA-Z0-9_]{5,32})\b", text, re.IGNORECASE):
        handle = m.group(1)
        if handle.lower() not in ignored_tg and handle.lower() not in seen:
            seen.add(handle.lower())
            leads.append(MessagingLead(platform="Telegram", handle=f"@{handle}", url=f"https://t.me/{handle}"))

    # Explicit Telegram text labels ("telegram: @username" or "tg: username")
    for m in re.finditer(r"(?:telegram|tg)[\s:=]+@?([a-zA-Z0-9_]{5,32})\b", text, re.IGNORECASE):
        handle = m.group(1)
        if handle.lower() not in ignored_tg and handle.lower() not in seen:
            seen.add(handle.lower())
            leads.append(MessagingLead(platform="Telegram", handle=f"@{handle}", url=f"https://t.me/{handle}"))

    # 2. Matrix handles (@username:matrix.org)
    for m in re.finditer(r"@([a-zA-Z0-9_.-]{2,64}:[a-zA-Z0-9_.-]+\.[a-zA-Z]{2,10})\b", text):
        handle = m.group(1)
        if handle.lower() not in seen:
            seen.add(handle.lower())
            leads.append(MessagingLead(platform="Matrix", handle=f"@{handle}"))

    # 3. Signal links and text markers
    for m in re.finditer(r"(?:https?://)?signal\.me/#p/([a-zA-Z0-9_.-]+)\b", text, re.IGNORECASE):
        handle = m.group(1)
        if handle.lower() not in seen:
            seen.add(handle.lower())
            leads.append(MessagingLead(platform="Signal", handle=handle, url=f"https://signal.me/#p/{handle}"))

    for m in re.finditer(r"(?:signal)[\s:=]+@?([a-zA-Z0-9_.-]{3,32})\b", text, re.IGNORECASE):
        handle = m.group(1)
        if handle.lower() not in seen and handle.lower() not in ("desktop", "messenger", "protocol", "app"):
            seen.add(handle.lower())
            leads.append(MessagingLead(platform="Signal", handle=handle))

    return leads


class MaigretProgressNotifier:
    """Custom notifier forwarding per-service scan progress events to argus."""

    def __init__(
        self,
        total_sites: int,
        on_site_check: Optional[Callable[[int, int, str], None]] = None,
    ):
        self.total = total_sites
        self.count = 0
        self.on_site_check = on_site_check

    def start(self, message=None, id_type="username"):
        pass

    def update(self, result, is_similar=False):
        self.count += 1
        site_name = getattr(result, "site_name", "Unknown Service")
        if self.on_site_check:
            self.on_site_check(self.count, self.total, site_name)

    def warning(self, *args, **kwargs):
        pass

    def success(self, *args, **kwargs):
        pass

    def info(self, *args, **kwargs):
        pass

    def finish(self, *args, **kwargs):
        pass


async def _fetch_and_extract_leads(
    url: str,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    target_username: str = "",
) -> Tuple[set[str], set[str], set[str], set[str], list[CryptoLead], list[MessagingLead]]:
    """Fetch profile URL content and scan clean user bio text for pivot leads."""
    invites: set[str] = set()
    tags: set[str] = set()
    ids: set[str] = set()
    emails: set[str] = set()
    crypto: list[CryptoLead] = []
    messaging: list[MessagingLead] = []

    async with semaphore:
        try:
            resp = await client.get(url, follow_redirects=True)
            if resp.status_code != 200:
                return invites, tags, ids, emails, crypto, messaging

            soup = BeautifulSoup(resp.text, "html.parser")

            # 1. Extract metadata description and title content (highest quality bio sources)
            meta_texts: list[str] = []
            for meta in soup.find_all("meta"):
                name = (meta.get("name") or "").lower()
                prop = (meta.get("property") or "").lower()
                if name in ("description", "twitter:description") or prop in ("og:description",):
                    content = meta.get("content")
                    if content and isinstance(content, str):
                        meta_texts.append(content)

            # 2. Decompose site chrome, navigation, scripts, styling, footer, and interactive elements
            for el in soup([
                "script",
                "style",
                "noscript",
                "header",
                "footer",
                "nav",
                "aside",
                "svg",
                "iframe",
                "form",
                "button",
                "input",
                "select",
                "canvas",
                "dialog",
                "template",
            ]):
                el.decompose()

            # Decompose layout / cookie / advertisement / sidebar containers
            for el in soup.find_all(True):
                class_str = (
                    " ".join(el.get("class", [])).lower()
                    if isinstance(el.get("class"), list)
                    else str(el.get("class") or "").lower()
                )
                id_str = str(el.get("id") or "").lower()
                for noise in (
                    "footer",
                    "cookie",
                    "banner",
                    "advertisement",
                    "ad-",
                    "header",
                    "nav",
                    "sidebar",
                    "widget",
                ):
                    if noise in class_str or noise in id_str:
                        el.decompose()
                        break

            # 3. Find dedicated bio / profile containers
            bio_elements: list[str] = []
            for el in soup.find_all(True):
                class_str = (
                    " ".join(el.get("class", [])).lower()
                    if isinstance(el.get("class"), list)
                    else str(el.get("class") or "").lower()
                )
                id_str = str(el.get("id") or "").lower()
                itemprop = str(el.get("itemprop") or "").lower()
                if itemprop == "description" or any(
                    b in class_str or b in id_str
                    for b in [
                        "bio",
                        "user-bio",
                        "profile-bio",
                        "user-description",
                        "profile-description",
                        "p-note",
                        "author-description",
                        "profile_summary",
                        "tgme_page_description",
                        "custom-status",
                        "user-status",
                        "about-me",
                        "profile-about",
                        "biography",
                    ]
                ):
                    bio_elements.append(el.get_text(separator=" ", strip=True))

            # Combine bio texts
            bio_text_blob = " \n ".join(meta_texts + bio_elements)
            # General cleaned page text
            page_text_blob = soup.get_text(separator=" ", strip=True)

            # Target text: If bio text exists, search bio text; otherwise fall back to cleaned page text
            text_to_search = bio_text_blob if bio_text_blob.strip() else page_text_blob

            # 1. Invites (only from bio text if present, to avoid site-level community invites)
            invite_source = bio_text_blob if bio_text_blob.strip() else page_text_blob
            raw_invites = DISCORD_INVITE_REGEX.findall(invite_source)
            invites.update(clean_discord_invites(raw_invites, site_url=url))

            # 2. Legacy Discord tags
            for tag in DISCORD_TAG_REGEX.findall(text_to_search):
                tags.add(tag)

            # 3. Discord Snowflake IDs (contextual prefix required)
            for raw_id in DISCORD_ID_REGEX.findall(text_to_search):
                if is_valid_snowflake(raw_id):
                    ids.add(raw_id)

            # 4. Emails
            found_emails = EMAIL_REGEX.findall(text_to_search)
            emails.update(clean_emails(found_emails, site_url=url, target_username=target_username))

            # 5. Cryptocurrency wallet addresses (Bitcoin, Ethereum, Solana)
            crypto.extend(extract_crypto_leads(text_to_search))

            # 6. Messaging handles (Telegram, Matrix, Signal)
            messaging.extend(extract_messaging_leads(text_to_search, site_url=url))

        except Exception:
            pass

    return invites, tags, ids, emails, crypto, messaging


async def _run_maigret_library(
    username: str,
    all_sites: bool = False,
    timeout: int = 10,
    proxy: Optional[str] = None,
    on_site_check: Optional[Callable[[int, int, str], None]] = None,
) -> list[SocialProfile]:
    """Run Maigret using direct Python library import with live per-service progress."""
    from maigret.db_updater import BUNDLED_DB_PATH
    from maigret import MaigretDatabase
    from maigret.maigret import maigret

    db = MaigretDatabase().load_from_path(BUNDLED_DB_PATH)

    if all_sites:
        sites = db.ranked_sites_dict(top=sys.maxsize)
    else:
        # Prioritize key developer/gaming platforms plus top 40 sites
        priority_dict = db.ranked_sites_dict(names=PRIORITY_SITES)
        top_dict = db.ranked_sites_dict(top=40)
        sites = {**priority_dict, **top_dict}

    m_logger = logging.getLogger("maigret_internal")
    m_logger.setLevel(logging.CRITICAL)

    notifier = MaigretProgressNotifier(total_sites=len(sites), on_site_check=on_site_check)

    raw_results = await maigret(
        username=username,
        site_dict=sites,
        logger=m_logger,
        query_notify=notifier,
        timeout=timeout,
        proxy=proxy,
        no_progressbar=True,
    )

    profiles: list[SocialProfile] = []
    for site_name, res in raw_results.items():
        if not isinstance(res, dict):
            continue
        status_obj = res.get("status")
        # Check if profile is claimed
        status_name = str(getattr(status_obj, "name", "") or str(status_obj or "")).lower()
        if "claimed" in status_name or "found" in status_name:
            if site_name.lower() == "discord":
                # Discord has no public profile web pages; the platform identifier is the username handle
                profiles.append(
                    SocialProfile(
                        platform="Discord",
                        url=f"@{username}",
                        status="Claimed",
                    )
                )
            else:
                url = res.get("url_user") or res.get("url_probe") or ""
                # Ignore root domain fallbacks that have no user path
                if url and url.rstrip("/") not in ("https://discord.com", "http://discord.com"):
                    profiles.append(
                        SocialProfile(
                            platform=site_name,
                            url=url,
                            status="Claimed",
                        )
                    )

    return profiles


async def _run_maigret_subprocess(
    username: str,
    all_sites: bool = False,
    timeout: int = 15,
    proxy: Optional[str] = None,
) -> list[SocialProfile]:
    """Fallback runner executing Maigret as an external subprocess."""
    profiles: list[SocialProfile] = []
    with tempfile.TemporaryDirectory() as tmpdir:
        cmd = [
            sys.executable,
            "-m",
            "maigret",
            username,
            "--timeout",
            str(timeout),
            "--no-progressbar",
            "--no-color",
            "--json",
            "simple",
            "--folderoutput",
            tmpdir,
        ]
        if not all_sites:
            cmd.extend(["--top-sites", "40"])
        if proxy:
            cmd.extend(["--proxy", proxy])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=timeout * 3)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return profiles

        # Look for report file
        for fname in os.listdir(tmpdir):
            if fname.endswith(".json"):
                fpath = os.path.join(tmpdir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        for site, details in data.items():
                            if isinstance(details, dict):
                                if site.lower() == "discord":
                                    profiles.append(
                                        SocialProfile(
                                            platform="Discord",
                                            url=f"@{username}",
                                            status="Claimed",
                                        )
                                    )
                                else:
                                    url = details.get("url_user") or details.get("url_main")
                                    if url and url.rstrip("/") not in (
                                        "https://discord.com",
                                        "http://discord.com",
                                    ):
                                        profiles.append(
                                            SocialProfile(
                                                platform=site,
                                                url=url,
                                                status="Claimed",
                                            )
                                        )
                except Exception:
                    pass

    return profiles


async def run_username_pivot(
    username: str,
    all_sites: bool = False,
    timeout: int = 15,
    proxy: Optional[str] = None,
    progress_callback: Optional[Callable[[str, int, int, str], None]] = None,
) -> Tuple[list[SocialProfile], PivotLeads, str]:
    """Execute username enumeration across platforms and extract OSINT leads with progress reporting.

    Returns:
        Tuple[profiles, pivot_leads, status_message]
    """
    clean_username = username.lstrip("@").strip()
    profiles: list[SocialProfile] = []
    status_msg = "Maigret search completed successfully."

    def on_site_check(completed: int, total: int, site_name: str) -> None:
        if progress_callback:
            progress_callback("Enumerating Platforms", completed, total, f"{site_name}")

    # 1. Attempt library execution, fall back to subprocess
    try:
        profiles = await _run_maigret_library(
            clean_username,
            all_sites=all_sites,
            timeout=timeout,
            proxy=proxy,
            on_site_check=on_site_check,
        )
    except Exception as lib_ex:
        logger.warning(f"Maigret library invocation failed ({lib_ex}), falling back to subprocess.")
        try:
            if progress_callback:
                progress_callback("Enumerating Platforms", 1, 1, "Subprocess Maigret Fallback")
            profiles = await _run_maigret_subprocess(clean_username, all_sites=all_sites, timeout=timeout, proxy=proxy)
            status_msg = "Completed via Maigret subprocess fallback."
        except Exception as sub_ex:
            return [], PivotLeads(), f"Maigret enumeration failed: {sub_ex}"

    # 2. Extract pivot leads from matched profiles
    leads = PivotLeads()

    # Only attempt scraping on profiles that have actual HTTP user profile URLs (skip Discord @username handles)
    scrapable_profiles = [
        p
        for p in profiles
        if p.url.startswith("http") and not p.url.rstrip("/").endswith("discord.com")
    ]

    if scrapable_profiles:
        semaphore = asyncio.Semaphore(10)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        async with httpx.AsyncClient(timeout=10.0, headers=headers, proxy=proxy) as client:
            done_count = 0
            total_scrapable = len(scrapable_profiles)

            async def wrapped_fetch(p: SocialProfile):
                nonlocal done_count
                res = await _fetch_and_extract_leads(
                    p.url, client, semaphore, target_username=clean_username
                )
                done_count += 1
                if progress_callback:
                    short_url = p.url if len(p.url) <= 45 else f"{p.url[:42]}..."
                    progress_callback(
                        "Extracting Profile Leads",
                        done_count,
                        total_scrapable,
                        f"{p.platform}: {short_url}",
                    )
                return res

            tasks = [wrapped_fetch(p) for p in scrapable_profiles]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            raw_crypto: list[CryptoLead] = []
            raw_messaging: list[MessagingLead] = []

            for res in batch_results:
                if isinstance(res, tuple) and len(res) == 6:
                    invites, tags, ids, emails, cr, msg = res
                    leads.discovered_invites.extend(invites)
                    leads.discovered_discord_tags.extend(tags)
                    leads.discovered_discord_ids.extend(ids)
                    leads.discovered_emails.extend(emails)
                    raw_crypto.extend(cr)
                    raw_messaging.extend(msg)

        # De-duplicate leads
        leads.discovered_invites = sorted(list(set(leads.discovered_invites)))
        leads.discovered_discord_tags = sorted(list(set(leads.discovered_discord_tags)))
        leads.discovered_discord_ids = sorted(list(set(leads.discovered_discord_ids)))
        leads.discovered_emails = sorted(list(set(leads.discovered_emails)))

        seen_crypto = set()
        for c in raw_crypto:
            key = (c.network, c.address.lower())
            if key not in seen_crypto:
                seen_crypto.add(key)
                leads.discovered_crypto.append(c)

        seen_msg = set()
        for m in raw_messaging:
            key = (m.platform, m.handle.lower())
            if key not in seen_msg:
                seen_msg.add(key)
                leads.discovered_messaging.append(m)

    return profiles, leads, status_msg
