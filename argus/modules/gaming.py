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

from argus.models import GamingProfiles, MinecraftProfile, ModuleStatus, RobloxProfile, SteamProfile

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


async def fetch_roblox_profile(
    username: str,
    timeout: int = 15,
    proxy: Optional[str] = None,
) -> Optional[RobloxProfile]:
    """Resolve Roblox user ID, display name, account age, and avatar via public Roblox APIs."""
    clean_username = username.strip()
    if not clean_username or len(clean_username) > 20:
        return None

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=timeout, proxy=proxy) as client:
            # 1. Lookup username to resolve numeric User ID
            lookup_url = "https://users.roblox.com/v1/usernames/users"
            payload = {"usernames": [clean_username], "excludeBannedUsers": False}
            resp = await client.post(lookup_url, json=payload, headers=headers)
            if resp.status_code != 200:
                return None

            data = resp.json().get("data", [])
            if not data or not isinstance(data, list):
                return None

            user_entry = data[0]
            user_id = user_entry.get("id")
            resolved_name = user_entry.get("name")
            display_name = user_entry.get("displayName") or resolved_name

            if not user_id or not resolved_name or resolved_name.lower() != clean_username.lower():
                return None

            # 2. Get user profile metadata (bio, created date, bans, badges)
            user_url = f"https://users.roblox.com/v1/users/{user_id}"
            user_resp = await client.get(user_url, headers=headers)
            description = None
            created_at = None
            is_banned = False
            has_verified_badge = False

            if user_resp.status_code == 200:
                user_info = user_resp.json()
                description = user_info.get("description") or None
                created_at = user_info.get("created")
                is_banned = bool(user_info.get("isBanned", False))
                has_verified_badge = bool(user_info.get("hasVerifiedBadge", False))

            # 3. Get avatar thumbnail
            avatar_url = None
            thumb_url = f"https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds={user_id}&size=150x150&format=Png&isCircular=false"
            thumb_resp = await client.get(thumb_url, headers=headers)
            if thumb_resp.status_code == 200:
                thumb_data = thumb_resp.json().get("data", [])
                if thumb_data and isinstance(thumb_data, list):
                    avatar_url = thumb_data[0].get("imageUrl")

            return RobloxProfile(
                user_id=int(user_id),
                username=resolved_name,
                display_name=display_name,
                description=description,
                created_at=created_at,
                is_banned=is_banned,
                has_verified_badge=has_verified_badge,
                avatar_url=avatar_url,
                profile_url=f"https://www.roblox.com/users/{user_id}/profile",
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
    """Concurrently query Mojang, Steam, and Roblox APIs for target handle."""
    if progress_callback:
        progress_callback("Gaming Ecosystem Pivot", 0, 3, "Checking Mojang, Steam, and Roblox APIs...")

    minecraft_task = fetch_minecraft_profile(username=username, timeout=timeout, proxy=proxy)
    steam_task = fetch_steam_profile(username=username, timeout=timeout, proxy=proxy)
    roblox_task = fetch_roblox_profile(username=username, timeout=timeout, proxy=proxy)

    mc_res, steam_res, roblox_res = await asyncio.gather(
        minecraft_task, steam_task, roblox_task, return_exceptions=True
    )

    mc_profile = mc_res if isinstance(mc_res, MinecraftProfile) else None
    steam_profile = steam_res if isinstance(steam_res, SteamProfile) else None
    roblox_profile = roblox_res if isinstance(roblox_res, RobloxProfile) else None

    if not mc_profile and not steam_profile and not roblox_profile:
        if progress_callback:
            progress_callback("Gaming Ecosystem Pivot", 3, 3, "No registered gaming profiles found")
        return None, ModuleStatus(
            module_name="Gaming Ecosystem",
            status="no_hits",
            message=f"No public Minecraft, Steam, or Roblox profiles matched handle '{username}'.",
        )

    found_parts = []
    if mc_profile:
        found_parts.append(f"Minecraft (UUID {mc_profile.uuid[:8]}...)")
    if steam_profile:
        found_parts.append(f"Steam (ID {steam_profile.steam_id_64})")
    if roblox_profile:
        found_parts.append(f"Roblox (ID {roblox_profile.user_id})")

    summary_msg = f"Discovered: {', '.join(found_parts)}"
    if progress_callback:
        progress_callback("Gaming Ecosystem Pivot", 3, 3, summary_msg)

    gaming_data = GamingProfiles(minecraft=mc_profile, steam=steam_profile, roblox=roblox_profile)
    return gaming_data, ModuleStatus(
        module_name="Gaming Ecosystem",
        status="success",
        message=summary_msg,
    )
