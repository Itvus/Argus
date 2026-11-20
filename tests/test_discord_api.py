"""Unit tests for Discord REST API v10 helpers and reverse image search generators."""

import pytest
import httpx

from argus.modules.discord_api import (
    build_avatar_url,
    build_banner_url,
    decode_discord_badges,
    fetch_discord_profile,
    generate_reverse_image_urls,
)


def test_decode_discord_badges():
    # Bitmask 1 = Discord Staff
    assert decode_discord_badges(1) == ["Discord Staff"]

    # Bitmask 64 = House Bravery
    assert decode_discord_badges(64) == ["House Bravery (HypeSquad)"]

    # Combined: 1 + 64 + 4194304 (Active Developer)
    combined = decode_discord_badges(1 | 64 | 4194304)
    assert "Discord Staff" in combined
    assert "House Bravery (HypeSquad)" in combined
    assert "Active Developer" in combined

    # Zero flags
    assert decode_discord_badges(0) == []


def test_build_avatar_url_static_and_animated():
    user_id = "155149108183695360"

    # Static avatar hash -> .png
    static_url = build_avatar_url(user_id, "3b169543e5828de3176ef109282b0e69")
    assert static_url == f"https://cdn.discordapp.com/avatars/{user_id}/3b169543e5828de3176ef109282b0e69.png?size=1024"

    # Animated avatar hash -> .gif
    anim_url = build_avatar_url(user_id, "a_3b169543e5828de3176ef109282b0e69")
    assert anim_url == f"https://cdn.discordapp.com/avatars/{user_id}/a_3b169543e5828de3176ef109282b0e69.gif?size=1024"

    # Default fallback with modern username (discriminator 0)
    def_url = build_avatar_url(user_id, None, discriminator="0")
    assert "https://cdn.discordapp.com/embed/avatars/" in def_url
    assert def_url.endswith(".png")


def test_build_banner_url():
    user_id = "155149108183695360"
    assert build_banner_url(user_id, None) is None

    b_static = build_banner_url(user_id, "bannerhash123")
    assert b_static == f"https://cdn.discordapp.com/banners/{user_id}/bannerhash123.png?size=1024"

    b_anim = build_banner_url(user_id, "a_bannerhash123")
    assert b_anim == f"https://cdn.discordapp.com/banners/{user_id}/a_bannerhash123.gif?size=1024"


def test_generate_reverse_image_urls():
    test_img = "https://cdn.discordapp.com/avatars/123/abc.png?size=1024"
    urls = generate_reverse_image_urls(test_img)

    assert "lens.google.com" in urls.google_lens
    assert "yandex.com/images" in urls.yandex
    assert "tineye.com" in urls.tineye
    assert "bing.com/images" in urls.bing_visual
    assert "https%3A%2F%2Fcdn.discordapp.com" in urls.google_lens


@pytest.mark.asyncio
async def test_fetch_discord_profile_missing_token():
    profile, status, msg = await fetch_discord_profile("155149108183695360", bot_token=None)
    assert profile is None
    assert status == "skipped"
    assert "not configured" in msg


def test_parse_discord_profile_payload():
    from argus.modules.discord_api import parse_discord_profile_payload

    payload = {
        "id": "155149108183695360",
        "username": "investigator",
        "global_name": "Senior Investigator",
        "discriminator": "0",
        "avatar": "3b169543e5828de3176ef109282b0e69",
        "banner": "banner12345",
        "accent_color": 16711680,
        "public_flags": 4194305,  # 1 (Staff) + 4194304 (Active Developer)
        "bot": False,
        "bio": "Lead researcher. Contact at lead@threatintel.org",
    }

    profile = parse_discord_profile_payload(payload, "155149108183695360")
    assert profile.id == "155149108183695360"
    assert profile.username == "investigator"
    assert profile.global_name == "Senior Investigator"
    assert profile.banner_color == "#ff0000"
    assert "Discord Staff" in profile.badges
    assert "Active Developer" in profile.badges
    assert profile.bio == "Lead researcher. Contact at lead@threatintel.org"
    assert "3b169543e5828de3176ef109282b0e69" in profile.avatar_url
