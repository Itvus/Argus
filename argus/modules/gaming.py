"""Gaming ecosystem OSINT reconnaissance module for Argus.

Pivots target username into Minecraft (Mojang API) and Steam (Community XML).
Adheres strictly to targeting precision: Only queries and matches the exact target username.
"""

from __future__ import annotations

import asyncio
import re
import xml.etree.ElementTree as ET
from typing import Callable, Optional, Tuple

import httpx

from argus.models import GamingProfiles, MinecraftProfile, ModuleStatus, SteamProfile

ProgressCallback = Callable[[str, int, int, str], None]


async def fetch_minecraft_profile(
    username: str,
    timeout: int = 15,
    proxy: Optional[str] = None,
) -> Optional[MinecraftProfile]:
    """Resolve Minecraft player UUID and skin render from Mojang REST API."""
    clean_username = username.strip()
    if not clean_username or len(clean_username) > 16:
        return None

    url = f"https://api.mojang.com/users/profiles/minecraft/{clean_username}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=timeout, proxy=proxy) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                raw_id = data.get("id")
                name = data.get("name")
                # Strict target verification: ensure returned player name matches target
                if raw_id and name and name.lower() == clean_username.lower():
                    formatted_uuid = (
                        f"{raw_id[:8]}-{raw_id[8:12]}-{raw_id[12:16]}-{raw_id[16:20]}-{raw_id[20:]}"
                    )
                    skin_url = f"https://crafatar.com/renders/body/{raw_id}?overlay=true"
                    return MinecraftProfile(
                        username=name,
                        uuid=raw_id,
                        uuid_formatted=formatted_uuid,
                        skin_render_url=skin_url,
                    )
    except Exception:
        pass

    return None


async def fetch_steam_profile(
    username: str,
    timeout: int = 15,
    proxy: Optional[str] = None,
) -> Optional[SteamProfile]:
    """Resolve Steam vanity URL to 64-bit SteamID, location, and ban history via Community XML."""
    clean_username = username.strip()
    if not clean_username:
        return None

    url = f"https://steamcommunity.com/id/{clean_username}/?xml=1"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/xml,application/xml",
    }

    try:
        async with httpx.AsyncClient(timeout=timeout, proxy=proxy) as client:
            resp = await client.get(url, headers=headers, follow_redirects=True)
            if resp.status_code == 200 and resp.text:
                root = ET.fromstring(resp.text)
                # Anti-noise check: Steam returns <response><error>...</error></response> if unassigned
                if root.tag == "response" or root.find("error") is not None:
                    return None

                steam_id_64 = root.findtext("steamID64")
                if steam_id_64 and steam_id_64.isdigit() and len(steam_id_64) >= 17:
                    display_name = root.findtext("steamID") or clean_username
                    real_name = root.findtext("realname")
                    location = root.findtext("location")
                    avatar_url = root.findtext("avatarFull") or root.findtext("avatarMedium")
                    member_since = root.findtext("memberSince")
                    vac_banned = root.findtext("vacBanned") == "1"
                    trade_ban_state = root.findtext("tradeBanState")
                    online_state = root.findtext("onlineState")

                    summary_raw = root.findtext("summary")
                    summary = None
                    if summary_raw:
                        clean_summary = re.sub(r"<[^>]+>", " ", summary_raw).strip()
                        clean_summary = re.sub(r"\s+", " ", clean_summary)
                        if clean_summary:
                            summary = clean_summary

                    return SteamProfile(
                        steam_id_64=steam_id_64,
                        custom_url=clean_username,
                        profile_url=f"https://steamcommunity.com/id/{clean_username}",
                        real_name=real_name or None,
                        location=location or None,
                        avatar_url=avatar_url or None,
                        summary=summary,
                        member_since=member_since or None,
                        vac_banned=vac_banned,
                        trade_ban_state=trade_ban_state or None,
                        online_state=online_state or None,
                    )
    except Exception:
        pass

    return None


async def fetch_gaming_profiles(
    username: str,
    timeout: int = 15,
    proxy: Optional[str] = None,
    progress_callback: Optional[ProgressCallback] = None,
) -> Tuple[Optional[GamingProfiles], ModuleStatus]:
    """Concurrently query Mojang and Steam APIs for target handle."""
    if progress_callback:
        progress_callback("Gaming Ecosystem Pivot", 0, 2, "Checking Mojang API & Steam Community...")

    minecraft_task = fetch_minecraft_profile(username=username, timeout=timeout, proxy=proxy)
    steam_task = fetch_steam_profile(username=username, timeout=timeout, proxy=proxy)

    mc_res, steam_res = await asyncio.gather(minecraft_task, steam_task, return_exceptions=True)

    mc_profile = mc_res if isinstance(mc_res, MinecraftProfile) else None
    steam_profile = steam_res if isinstance(steam_res, SteamProfile) else None

    if not mc_profile and not steam_profile:
        if progress_callback:
            progress_callback("Gaming Ecosystem Pivot", 2, 2, "No registered Minecraft or Steam profiles found")
        return None, ModuleStatus(
            module_name="Gaming Ecosystem",
            status="no_hits",
            message=f"No public Minecraft or Steam profiles matched handle '{username}'.",
        )

    found_parts = []
    if mc_profile:
        found_parts.append(f"Minecraft (UUID {mc_profile.uuid[:8]}...)")
    if steam_profile:
        found_parts.append(f"Steam (ID {steam_profile.steam_id_64})")

    summary_msg = f"Discovered: {', '.join(found_parts)}"
    if progress_callback:
        progress_callback("Gaming Ecosystem Pivot", 2, 2, summary_msg)

    gaming_data = GamingProfiles(minecraft=mc_profile, steam=steam_profile)
    return gaming_data, ModuleStatus(
        module_name="Gaming Ecosystem",
        status="success",
        message=summary_msg,
    )
