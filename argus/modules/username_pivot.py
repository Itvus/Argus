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
from argus.modules.custom_patterns import extract_custom_leads
from argus.modules.phone_recon import extract_phone_leads
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
    """Extract root/apex domain without www or subdomains from URL."""
    try:
        host = urlparse(url).netloc.lower().split(":")[0]
        if host.startswith("www."):
            host = host[4:]
        parts = host.split(".")
        if len(parts) <= 2:
            return host
        # Handle ccTLD combinations like .co.uk, .com.au, .org.uk, .co.jp
        if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "edu", "ac") and len(parts[-1]) == 2:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
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

        # Discard explicit non-email URI schemes / prefixes
        if any(email_clean.startswith(prefix) for prefix in ("xmpp:", "jabber:", "jid:")):
            continue

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

    # 5. Monero (Base58 starts with 4 or 8, length 95 or 106)
    for m in re.finditer(r"\b([48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}(?:[1-9A-HJ-NP-Za-km-z]{11})?)\b", text):
        addr = m.group(1)
        if len(addr) in (95, 106):
            if addr not in seen:
                seen.add(addr)
                leads.append(CryptoLead(network="Monero", address=addr))

    return leads


def extract_messaging_leads(text: str, site_url: str = "") -> list[MessagingLead]:
    """Extract Telegram, Matrix, Signal, Session, Tox, SimpleX, and XMPP leads."""
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
        k = f"telegram:{handle.lower()}"
        if handle.lower() not in ignored_tg and k not in seen:
            seen.add(k)
            leads.append(MessagingLead(platform="Telegram", handle=f"@{handle}", url=f"https://t.me/{handle}"))

    # Explicit Telegram text labels ("telegram: @username" or "tg: username")
    for m in re.finditer(r"(?:telegram|tg)[\s:=]+@?([a-zA-Z0-9_]{5,32})\b", text, re.IGNORECASE):
        handle = m.group(1)
        k = f"telegram:{handle.lower()}"
        if handle.lower() not in ignored_tg and k not in seen:
            seen.add(k)
            leads.append(MessagingLead(platform="Telegram", handle=f"@{handle}", url=f"https://t.me/{handle}"))

    # 2. Matrix handles (@username:matrix.org)
    for m in re.finditer(r"@([a-zA-Z0-9_.-]{2,64}:[a-zA-Z0-9_.-]+\.[a-zA-Z]{2,10})\b", text):
        handle = m.group(1)
        k = f"matrix:{handle.lower()}"
        if k not in seen:
            seen.add(k)
            leads.append(MessagingLead(platform="Matrix", handle=f"@{handle}"))

    # 3. Signal links and text markers
    for m in re.finditer(r"(?:https?://)?signal\.me/#p/([a-zA-Z0-9_.-]+)\b", text, re.IGNORECASE):
        handle = m.group(1)
        k = f"signal:{handle.lower()}"
        if k not in seen:
            seen.add(k)
            leads.append(MessagingLead(platform="Signal", handle=handle, url=f"https://signal.me/#p/{handle}"))

    for m in re.finditer(r"(?:signal)[\s:=]+@?([a-zA-Z0-9_.-]{3,32})\b", text, re.IGNORECASE):
        handle = m.group(1)
        k = f"signal:{handle.lower()}"
        if k not in seen and handle.lower() not in ("desktop", "messenger", "protocol", "app"):
            seen.add(k)
            leads.append(MessagingLead(platform="Signal", handle=handle))

    # 4. Session IDs (66 hex characters starting with 05) - requires label or contextual window
    for m in re.finditer(r"(?:session(?:[\s_-]?id)?)[\s:=]+([0-9a-fA-F]{66})\b", text, re.IGNORECASE):
        s_id = m.group(1).lower()
        k = f"session:{s_id}"
        if k not in seen:
            seen.add(k)
            leads.append(MessagingLead(platform="Session", handle=s_id))

    for m in re.finditer(r"\b(05[0-9a-fA-F]{64})\b", text):
        s_id = m.group(1).lower()
        start = max(0, m.start() - 35)
        end = min(len(text), m.end() + 35)
        window = text[start:end].lower()
        if re.search(r"\b(session|oxen|messenger)\b", window):
            k = f"session:{s_id}"
            if k not in seen:
                seen.add(k)
                leads.append(MessagingLead(platform="Session", handle=s_id))

    # 5. Tox IDs (76 hex characters) - requires label or contextual window
    for m in re.finditer(r"(?:tox(?:[\s_-]?id)?)[\s:=]+([0-9a-fA-F]{76})\b", text, re.IGNORECASE):
        t_id = m.group(1).upper()
        k = f"tox:{t_id}"
        if k not in seen:
            seen.add(k)
            leads.append(MessagingLead(platform="Tox", handle=t_id))

    for m in re.finditer(r"\b([0-9a-fA-F]{76})\b", text):
        t_id = m.group(1).upper()
        start = max(0, m.start() - 35)
        end = min(len(text), m.end() + 35)
        window = text[start:end].lower()
        if re.search(r"\b(tox|qtox|utox|toxic)\b", window):
            k = f"tox:{t_id}"
            if k not in seen:
                seen.add(k)
                leads.append(MessagingLead(platform="Tox", handle=t_id))

    # 6. SimpleX Chat links & handles
    for m in re.finditer(r"(?:https?://)?simplex\.chat/contact#/?([^\s\"'<>]+)", text, re.IGNORECASE):
        h = m.group(1).strip()
        k = f"simplex:{h.lower()}"
        if k not in seen:
            seen.add(k)
            leads.append(MessagingLead(platform="SimpleX", handle=f"simplex.chat/contact#/?{h}", url=f"https://simplex.chat/contact#/?{h}"))

    # 7. XMPP / Jabber handles (prefixed or suffixed)
    for m in re.finditer(
        r"(?:xmpp:|jabber:|jid:|(?:xmpp|jabber|jid)[\s:=]+)([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b",
        text,
        re.IGNORECASE,
    ):
        jid = m.group(1).lower()
        k = f"xmpp:{jid}"
        if k not in seen and not jid.endswith((".png", ".jpg", ".jpeg", ".webp")):
            seen.add(k)
            leads.append(MessagingLead(platform="XMPP", handle=jid, url=f"xmpp:{jid}"))

    for m in re.finditer(
        r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s*[\(\[](?:xmpp|jabber|jid)[\)\]]",
        text,
        re.IGNORECASE,
    ):
        jid = m.group(1).lower()
        k = f"xmpp:{jid}"
        if k not in seen and not jid.endswith((".png", ".jpg", ".jpeg", ".webp")):
            seen.add(k)
            leads.append(MessagingLead(platform="XMPP", handle=jid, url=f"xmpp:{jid}"))

    # 8. CashApp ($cashtag or cash.app/$cashtag)
    for m in re.finditer(r"(?:https?://)?(?:www\.)?cash\.app/\$([a-zA-Z][a-zA-Z0-9_-]{0,19})\b", text, re.IGNORECASE):
        tag = m.group(1)
        k = f"cashapp:{tag.lower()}"
        if k not in seen:
            seen.add(k)
            leads.append(MessagingLead(platform="CashApp", handle=f"${tag}", url=f"https://cash.app/${tag}"))

    for m in re.finditer(r"(?:cashapp|cash\s*app)[\s:=]+\$?([a-zA-Z][a-zA-Z0-9_-]{0,19})\b", text, re.IGNORECASE):
        tag = m.group(1)
        k = f"cashapp:{tag.lower()}"
        if k not in seen:
            seen.add(k)
            leads.append(MessagingLead(platform="CashApp", handle=f"${tag}", url=f"https://cash.app/${tag}"))

    # 9. Venmo (venmo.com/u/handle or venmo: @handle)
    for m in re.finditer(r"(?:https?://)?(?:www\.)?venmo\.com/(?:u/)?([a-zA-Z0-9_-]{3,30})\b", text, re.IGNORECASE):
        h = m.group(1)
        k = f"venmo:{h.lower()}"
        if k not in seen and h.lower() not in ("about", "business", "security", "terms", "privacy"):
            seen.add(k)
            leads.append(MessagingLead(platform="Venmo", handle=f"@{h}", url=f"https://venmo.com/u/{h}"))

    for m in re.finditer(r"\bvenmo[\s:=]+@?([a-zA-Z0-9_-]{3,30})\b", text, re.IGNORECASE):
        h = m.group(1)
        k = f"venmo:{h.lower()}"
        if k not in seen and h.lower() not in ("about", "business", "security", "terms", "privacy"):
            seen.add(k)
            leads.append(MessagingLead(platform="Venmo", handle=f"@{h}", url=f"https://venmo.com/u/{h}"))

    # 10. PayPal.me (paypal.me/handle)
    for m in re.finditer(r"(?:https?://)?(?:www\.)?paypal\.me/([a-zA-Z0-9_.-]{3,50})\b", text, re.IGNORECASE):
        h = m.group(1)
        k = f"paypal:{h.lower()}"
        if k not in seen and h.lower() not in ("terms", "privacy", "help", "home"):
            seen.add(k)
            leads.append(MessagingLead(platform="PayPal", handle=h, url=f"https://paypal.me/{h}"))

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


def extract_leads_from_text(
    text: str, site_url: str = "", target_username: str = ""
) -> PivotLeads:
    """Extract Discord invites, tags, snowflake IDs, emails, crypto, and messaging leads from free text."""
    if not text:
        return PivotLeads()

    raw_invites = DISCORD_INVITE_REGEX.findall(text)
    invites = list(clean_discord_invites(raw_invites, site_url=site_url))

    tags = list(set(DISCORD_TAG_REGEX.findall(text)))

    ids: list[str] = []
    for raw_id in DISCORD_ID_REGEX.findall(text):
        if is_valid_snowflake(raw_id) and raw_id not in ids:
            ids.append(raw_id)

    # Extract emails, excluding addresses explicitly designated as XMPP / Jabber / JID
    found_emails: list[str] = []
    for m in EMAIL_REGEX.finditer(text):
        start = m.start()
        end = m.end()
        prefix = text[max(0, start - 20) : start].lower()
        suffix = text[end : min(len(text), end + 20)].lower()
        # Skip if preceded by xmpp:, jabber:, jid: or labelled with xmpp/jabber/jid
        if re.search(r"(?:xmpp:|jabber:|jid:|\b(?:xmpp|jabber|jid)[\s:=]*)$", prefix):
            continue
        # Skip if followed by (xmpp), [jabber], etc.
        if re.search(r"^\s*[\(\[]\s*(?:xmpp|jabber|jid)\s*[\)\]]", suffix):
            continue
        found_emails.append(m.group(0))

    emails = list(clean_emails(found_emails, site_url=site_url, target_username=target_username))

    crypto = extract_crypto_leads(text)
    messaging = extract_messaging_leads(text, site_url=site_url)

    # Discard any email that was extracted as an XMPP JID, unless explicitly designated as email
    xmpp_jids = {m.handle.lower() for m in messaging if m.platform == "XMPP"}
    if xmpp_jids and emails:
        filtered_emails: list[str] = []
        for em in emails:
            if em.lower() in xmpp_jids:
                em_esc = re.escape(em)
                if re.search(rf"(?:mailto:|email[\s:=]+|e-mail[\s:=]+|mail[\s:=]+){em_esc}", text, re.IGNORECASE):
                    filtered_emails.append(em)
            else:
                filtered_emails.append(em)
        emails = filtered_emails

    phones = extract_phone_leads(text)
    custom = extract_custom_leads(text)

    return PivotLeads(
        discovered_emails=emails,
        discovered_discord_ids=ids,
        discovered_discord_tags=tags,
        discovered_invites=invites,
        discovered_crypto=crypto,
        discovered_messaging=messaging,
        discovered_phones=phones,
        discovered_custom=custom,
    )


class LeadsResult(tuple):
    """Custom 6-element tuple subclass providing standard unpack while carrying phones and custom leads."""

    def __new__(cls, invites, tags, ids, emails, crypto, messaging, phones=None, custom=None):
        return super().__new__(cls, (invites, tags, ids, emails, crypto, messaging))

    def __init__(self, invites, tags, ids, emails, crypto, messaging, phones=None, custom=None):
        self.invites = invites
        self.tags = tags
        self.ids = ids
        self.emails = emails
        self.crypto = crypto
        self.messaging = messaging
        self.phones = phones or []
        self.custom = custom or []


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
    phones: list[Any] = []
    custom: list[dict[str, str]] = []

    async with semaphore:
        try:
            resp = await client.get(url, follow_redirects=True)
            if resp.status_code != 200:
                return LeadsResult(invites, tags, ids, emails, crypto, messaging, phones, custom)

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

            extracted = extract_leads_from_text(text_to_search, site_url=url, target_username=target_username)
            # If bio text was present, ensure invites were checked specifically against bio text
            if bio_text_blob.strip() and bio_text_blob != text_to_search:
                bio_extracted = extract_leads_from_text(bio_text_blob, site_url=url, target_username=target_username)
                invites.update(bio_extracted.discovered_invites)
            else:
                invites.update(extracted.discovered_invites)

            tags.update(extracted.discovered_discord_tags)
            ids.update(extracted.discovered_discord_ids)
            emails.update(extracted.discovered_emails)
            crypto.extend(extracted.discovered_crypto)
            messaging.extend(extracted.discovered_messaging)
            phones.extend(extracted.discovered_phones)
            custom.extend(extracted.discovered_custom)

        except Exception:
            pass

    return LeadsResult(invites, tags, ids, emails, crypto, messaging, phones, custom)


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
            counter_lock = asyncio.Lock()
            total_scrapable = len(scrapable_profiles)

            async def wrapped_fetch(p: SocialProfile):
                nonlocal done_count
                res = await _fetch_and_extract_leads(
                    p.url, client, semaphore, target_username=clean_username
                )
                async with counter_lock:
                    done_count += 1
                    current_done = done_count
                if progress_callback:
                    short_url = p.url if len(p.url) <= 45 else f"{p.url[:42]}..."
                    progress_callback(
                        "Extracting Profile Leads",
                        current_done,
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
                    if hasattr(res, "phones"):
                        leads.discovered_phones.extend(res.phones)
                    if hasattr(res, "custom"):
                        leads.discovered_custom.extend(res.custom)

        # De-duplicate leads
        leads.discovered_invites = sorted(list(set(leads.discovered_invites)))
        leads.discovered_discord_tags = sorted(list(set(leads.discovered_discord_tags)))
        leads.discovered_discord_ids = sorted(list(set(leads.discovered_discord_ids)))
        leads.discovered_emails = sorted(list(set(leads.discovered_emails)))

        seen_phones = set()
        unique_phones = []
        for p in leads.discovered_phones:
            if p.e164 not in seen_phones:
                seen_phones.add(p.e164)
                unique_phones.append(p)
        leads.discovered_phones = unique_phones

        seen_custom = set()
        unique_custom = []
        for c in leads.discovered_custom:
            k = (c.get("name"), c.get("value"))
            if k not in seen_custom:
                seen_custom.add(k)
                unique_custom.append(c)
        leads.discovered_custom = unique_custom

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
