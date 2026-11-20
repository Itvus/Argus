"""Discord Public API client for user profile lookup, badge decoding, and reverse image search URL generation."""

from __future__ import annotations

import asyncio
import urllib.parse
from typing import Callable, Optional, Tuple

import httpx

from argus.models import DiscordProfile, ReverseImageUrls

DISCORD_API_BASE = "https://discord.com/api/v10"

# Public flags bitmask -> Human-readable badge names
DISCORD_FLAGS: dict[int, str] = {
    1 << 0: "Discord Staff",
    1 << 1: "Partnered Server Owner",
    1 << 2: "HypeSquad Events Member",
    1 << 3: "Bug Hunter Level 1",
    1 << 6: "House Bravery (HypeSquad)",
    1 << 7: "House Brilliance (HypeSquad)",
    1 << 8: "House Balance (HypeSquad)",
    1 << 9: "Early Nitro Supporter",
    1 << 10: "Team Pseudo User",
    1 << 14: "Bug Hunter Level 2",
    1 << 16: "Verified Bot",
    1 << 17: "Early Verified Bot Developer",
    1 << 18: "Discord Certified Moderator Alumni",
    1 << 19: "Bot HTTP Interactions",
    1 << 22: "Active Developer",
}


def decode_discord_badges(flags: int) -> list[str]:
    """Decode public_flags integer bitmask into badge strings."""
    badges: list[str] = []
    for bitmask, name in DISCORD_FLAGS.items():
        if flags & bitmask:
            badges.append(name)
    return badges


def build_avatar_url(user_id: str, avatar_hash: Optional[str], discriminator: str = "0") -> str:
    """Build full-resolution Discord CDN avatar URL or default fallback."""
    if avatar_hash:
        ext = "gif" if avatar_hash.startswith("a_") else "png"
        return f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.{ext}?size=1024"

    # Default avatar calculation
    try:
        if discriminator == "0" or not discriminator:
            # Modern Discord username: based on snowflake shifted right 22 modulo 6
            idx = (int(user_id) >> 22) % 6
        else:
            # Legacy discriminator modulo 5
            idx = int(discriminator) % 5
    except (ValueError, TypeError):
        idx = 0
    return f"https://cdn.discordapp.com/embed/avatars/{idx}.png"


def build_banner_url(user_id: str, banner_hash: Optional[str]) -> Optional[str]:
    """Build full-resolution Discord CDN banner URL."""
    if not banner_hash:
        return None
    ext = "gif" if banner_hash.startswith("a_") else "png"
    return f"https://cdn.discordapp.com/banners/{user_id}/{banner_hash}.{ext}?size=1024"


def generate_reverse_image_urls(image_url: str) -> ReverseImageUrls:
    """Generate direct reverse image search URLs across multiple engines."""
    encoded_url = urllib.parse.quote(image_url, safe="")
    return ReverseImageUrls(
        google_lens=f"https://lens.google.com/uploadbyurl?url={encoded_url}",
        yandex=f"https://yandex.com/images/search?rpt=imageview&url={encoded_url}",
        tineye=f"https://tineye.com/search?url={encoded_url}",
        bing_visual=f"https://www.bing.com/images/search?view=detailv2&iss=sbi&FORM=SBIHMP&sbisrc=UrlPaste&q=imgurl:{encoded_url}",
    )


async def fetch_discord_profile(
    user_id: str,
    bot_token: Optional[str],
    timeout: int = 15,
    proxy: Optional[str] = None,
    progress_callback: Optional[Callable[[str, int, int, str], None]] = None,
) -> Tuple[Optional[DiscordProfile], str, Optional[str]]:
    """Fetch user profile metadata from Discord REST API v10 with progress reporting.

    Returns:
        Tuple[profile, status, diagnostic_message]
        status: 'success', 'skipped', 'not_found', 'rate_limited', 'unauthorized', 'error'
    """
    if progress_callback:
        progress_callback("Discord API Lookup", 0, 1, f"Discord REST API v10 (/users/{user_id})")

    if not bot_token or not bot_token.strip():
        if progress_callback:
            progress_callback("Discord API Lookup", 1, 1, "Skipped (Token not set)")
        return (
            None,
            "skipped",
            "DISCORD_BOT_TOKEN is not configured. Set DISCORD_BOT_TOKEN in .env for Discord API profile retrieval.",
        )

    headers = {
        "Authorization": f"Bot {bot_token.strip()}",
        "User-Agent": "argus/0.1.0 (OSINT investigation tool; +https://github.com/argus)",
        "Accept": "application/json",
    }
    url = f"{DISCORD_API_BASE}/users/{user_id}"

    async with httpx.AsyncClient(timeout=timeout, proxy=proxy) as client:
        try:
            resp = await client.get(url, headers=headers)
            if progress_callback:
                progress_callback("Discord API Lookup", 1, 1, f"HTTP {resp.status_code}")

            if resp.status_code == 200:
                data = resp.json()
                flags = data.get("public_flags", 0) or 0
                avatar_hash = data.get("avatar")
                discriminator = data.get("discriminator", "0")
                avatar_url = build_avatar_url(user_id, avatar_hash, discriminator)
                banner_hash = data.get("banner")
                banner_url = build_banner_url(user_id, banner_hash)

                accent_color = data.get("accent_color")
                banner_color = data.get("banner_color")
                if not banner_color and accent_color is not None:
                    banner_color = f"#{accent_color:06x}"

                profile = DiscordProfile(
                    id=str(data.get("id", user_id)),
                    username=data.get("username", ""),
                    global_name=data.get("global_name"),
                    discriminator=discriminator,
                    avatar_hash=avatar_hash,
                    avatar_url=avatar_url,
                    banner_hash=banner_hash,
                    banner_url=banner_url,
                    accent_color=accent_color,
                    banner_color=banner_color,
                    public_flags=flags,
                    badges=decode_discord_badges(flags),
                    bot=bool(data.get("bot", False)),
                    system=bool(data.get("system", False)),
                    reverse_image_urls=generate_reverse_image_urls(avatar_url),
                    bio=data.get("bio") or None,
                )
                return profile, "success", None

            if resp.status_code == 404:
                return None, "not_found", f"Discord user ID {user_id} not found."

            if resp.status_code == 401:
                return (
                    None,
                    "unauthorized",
                    "Discord API returned 401 Unauthorized. Check that DISCORD_BOT_TOKEN is valid.",
                )

            if resp.status_code == 403:
                return (
                    None,
                    "forbidden",
                    "Discord API returned 403 Forbidden. Bot lacks permission to fetch users.",
                )

            if resp.status_code == 429:
                retry_after = resp.json().get("retry_after", 5)
                await asyncio.sleep(min(float(retry_after), 3.0))
                resp2 = await client.get(url, headers=headers)
                if resp2.status_code == 200:
                    data = resp2.json()
                    flags = data.get("public_flags", 0) or 0
                    avatar_hash = data.get("avatar")
                    discriminator = data.get("discriminator", "0")
                    avatar_url = build_avatar_url(user_id, avatar_hash, discriminator)
                    banner_hash = data.get("banner")
                    banner_url = build_banner_url(user_id, banner_hash)
                    accent_color = data.get("accent_color")
                    banner_color = data.get("banner_color")
                    if not banner_color and accent_color is not None:
                        banner_color = f"#{accent_color:06x}"

                    profile = DiscordProfile(
                        id=str(data.get("id", user_id)),
                        username=data.get("username", ""),
                        global_name=data.get("global_name"),
                        discriminator=discriminator,
                        avatar_hash=avatar_hash,
                        avatar_url=avatar_url,
                        banner_hash=banner_hash,
                        banner_url=banner_url,
                        accent_color=accent_color,
                        banner_color=banner_color,
                        public_flags=flags,
                        badges=decode_discord_badges(flags),
                        bot=bool(data.get("bot", False)),
                        system=bool(data.get("system", False)),
                        reverse_image_urls=generate_reverse_image_urls(avatar_url),
                    )
                    return profile, "success", None
                return (
                    None,
                    "rate_limited",
                    f"Discord API rate limit reached (HTTP 429, retry-after: {retry_after}s).",
                )

            return (
                None,
                "error",
                f"Discord API returned HTTP {resp.status_code}: {resp.text[:100]}",
            )

        except httpx.TimeoutException:
            return None, "timeout", f"Discord API request timed out after {timeout}s."
        except Exception as ex:
            return None, "error", f"Discord API error: {str(ex)}"
