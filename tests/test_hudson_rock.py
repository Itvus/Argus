"""Unit tests for Hudson Rock infostealer intelligence module."""

import pytest
import unittest.mock
from argus.modules.hudson_rock import fetch_hudson_rock_intel


@pytest.mark.asyncio
async def test_fetch_hudson_rock_intel_success():
    mock_resp = unittest.mock.MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "stealers": [
            {
                "stealer_family": "RedLine",
                "date_compromised": "2026-11-15T07:56:38.000Z",
                "computer_name": "DESKTOP-98ABC",
                "operating_system": "Windows 11 Pro",
                "ip": "198.51.100.42",
                "malware_path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\update.exe",
                "top_logins": ["discord.com", "steamcommunity.com", "binance.com"],
            }
        ],
        "total_corporate_services": 1,
        "total_user_services": 4,
    }

    mock_client = unittest.mock.AsyncMock()
    mock_client.get.return_value = mock_resp
    mock_client.__aenter__.return_value = mock_client

    with unittest.mock.patch("httpx.AsyncClient", return_value=mock_client):
        report, status = await fetch_hudson_rock_intel("victim@example.com", query_type="email")

    assert report is not None
    assert report.total_stealers == 1
    assert report.total_corporate_services == 1
    assert len(report.infections) == 1
    assert report.infections[0].stealer_family == "RedLine"
    assert report.infections[0].computer_name == "DESKTOP-98ABC"
    assert "discord.com" in report.infections[0].top_logins
    assert status.status == "success"


@pytest.mark.asyncio
async def test_fetch_hudson_rock_intel_no_hits():
    mock_resp = unittest.mock.MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "stealers": [],
        "total_corporate_services": 0,
        "total_user_services": 0,
    }

    mock_client = unittest.mock.AsyncMock()
    mock_client.get.return_value = mock_resp
    mock_client.__aenter__.return_value = mock_client

    with unittest.mock.patch("httpx.AsyncClient", return_value=mock_client):
        report, status = await fetch_hudson_rock_intel("clean_user", query_type="username")

    assert report is not None
    assert report.total_stealers == 0
    assert len(report.infections) == 0
    assert status.status == "no_hits"


@pytest.mark.asyncio
async def test_fetch_hudson_rock_intel_error():
    mock_client = unittest.mock.AsyncMock()
    mock_client.get.side_effect = Exception("Connection reset")
    mock_client.__aenter__.return_value = mock_client

    with unittest.mock.patch("httpx.AsyncClient", return_value=mock_client):
        report, status = await fetch_hudson_rock_intel("some_user")

    assert report is None
    assert status.status == "error"
    assert "Connection reset" in status.message
