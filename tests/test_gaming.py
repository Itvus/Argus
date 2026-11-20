"""Unit tests for gaming ecosystem reconnaissance module (Minecraft & Steam)."""

import pytest
import unittest.mock
from argus.modules.gaming import (
    fetch_minecraft_profile,
    fetch_steam_profile,
    fetch_gaming_profiles,
)
from argus.models import MinecraftProfile, SteamProfile


@pytest.mark.asyncio
async def test_fetch_minecraft_profile_success():
    mock_resp = unittest.mock.MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "id": "069a79f444e94726a5befca90e38aaf5",
        "name": "Notch",
    }

    mock_client = unittest.mock.AsyncMock()
    mock_client.get.return_value = mock_resp
    mock_client.__aenter__.return_value = mock_client

    with unittest.mock.patch("httpx.AsyncClient", return_value=mock_client):
        profile = await fetch_minecraft_profile("notch")

    assert profile is not None
    assert profile.username == "Notch"
    assert profile.uuid == "069a79f444e94726a5befca90e38aaf5"
    assert profile.uuid_formatted == "069a79f4-44e9-4726-a5be-fca90e38aaf5"
    assert "069a79f444e94726a5befca90e38aaf5" in profile.skin_render_url


@pytest.mark.asyncio
async def test_fetch_minecraft_profile_mismatch_and_404():
    # Long username (>16 chars) returns None without network call
    assert await fetch_minecraft_profile("this_name_is_way_too_long_for_minecraft") is None

    # Target mismatch rejected
    mock_resp_mismatch = unittest.mock.MagicMock()
    mock_resp_mismatch.status_code = 200
    mock_resp_mismatch.json.return_value = {
        "id": "11111111111111111111111111111111",
        "name": "different_user",
    }
    mock_client = unittest.mock.AsyncMock()
    mock_client.get.return_value = mock_resp_mismatch
    mock_client.__aenter__.return_value = mock_client

    with unittest.mock.patch("httpx.AsyncClient", return_value=mock_client):
        assert await fetch_minecraft_profile("target_user") is None

    # 404 Not Found returns None
    mock_resp_404 = unittest.mock.MagicMock()
    mock_resp_404.status_code = 404
    mock_client.get.return_value = mock_resp_404

    with unittest.mock.patch("httpx.AsyncClient", return_value=mock_client):
        assert await fetch_minecraft_profile("nonexistent") is None


@pytest.mark.asyncio
async def test_fetch_steam_profile_success():
    xml_data = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <profile>
        <steamID64>76561198000000000</steamID64>
        <steamID><![CDATA[GamerTag]]></steamID>
        <realname><![CDATA[John Doe]]></realname>
        <location><![CDATA[United States]]></location>
        <avatarFull><![CDATA[https://avatars.steamstatic.com/avatar_full.jpg]]></avatarFull>
        <memberSince>January 1, 2012</memberSince>
        <vacBanned>0</vacBanned>
        <tradeBanState>None</tradeBanState>
        <onlineState>online</onlineState>
        <summary><![CDATA[Welcome! Reach me on Discord: Investigator#1337 or dev@example.com]]></summary>
    </profile>
    """
    mock_resp = unittest.mock.MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = xml_data

    mock_client = unittest.mock.AsyncMock()
    mock_client.get.return_value = mock_resp
    mock_client.__aenter__.return_value = mock_client

    with unittest.mock.patch("httpx.AsyncClient", return_value=mock_client):
        profile = await fetch_steam_profile("gamertag")

    assert profile is not None
    assert profile.steam_id_64 == "76561198000000000"
    assert profile.custom_url == "gamertag"
    assert profile.profile_url == "https://steamcommunity.com/id/gamertag"
    assert profile.real_name == "John Doe"
    assert profile.location == "United States"
    assert profile.vac_banned is False
    assert "Investigator#1337" in profile.summary


@pytest.mark.asyncio
async def test_fetch_steam_profile_unassigned_error():
    # Steam unassigned profile returns error XML
    error_xml = """<response><error>The specified profile could not be found.</error></response>"""
    mock_resp = unittest.mock.MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = error_xml

    mock_client = unittest.mock.AsyncMock()
    mock_client.get.return_value = mock_resp
    mock_client.__aenter__.return_value = mock_client

    with unittest.mock.patch("httpx.AsyncClient", return_value=mock_client):
        assert await fetch_steam_profile("nobody_assigned_1234") is None


@pytest.mark.asyncio
async def test_fetch_gaming_profiles_aggregation():
    with unittest.mock.patch(
        "argus.modules.gaming.fetch_minecraft_profile",
        new_callable=unittest.mock.AsyncMock,
    ) as mock_mc, unittest.mock.patch(
        "argus.modules.gaming.fetch_steam_profile",
        new_callable=unittest.mock.AsyncMock,
    ) as mock_steam:
        # Both found
        mock_mc.return_value = MinecraftProfile(
            username="notch",
            uuid="069a79f444e94726a5befca90e38aaf5",
            uuid_formatted="069a79f4-44e9-4726-a5be-fca90e38aaf5",
        )
        mock_steam.return_value = SteamProfile(
            steam_id_64="76561198000000000",
            custom_url="notch",
            profile_url="https://steamcommunity.com/id/notch",
        )

        gaming, status = await fetch_gaming_profiles("notch")
        assert gaming is not None
        assert gaming.minecraft is not None
        assert gaming.steam is not None
        assert status.status == "success"
        assert "Minecraft" in status.message
        assert "Steam" in status.message

        # Neither found
        mock_mc.return_value = None
        mock_steam.return_value = None

        gaming_none, status_none = await fetch_gaming_profiles("notch")
        assert gaming_none is None
        assert status_none.status == "no_hits"
        assert "No public Minecraft or Steam profiles" in status_none.message
