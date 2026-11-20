"""Unit tests for Holehe email account registration reconnaissance module."""

import pytest
import unittest.mock
from argus.modules.email_recon import check_email_registrations


@pytest.mark.asyncio
async def test_check_email_registrations_invalid_email():
    report, status = await check_email_registrations("not-an-email")
    assert report is None
    assert status.status == "skipped"
    assert "Invalid email" in status.message


@pytest.mark.asyncio
async def test_check_email_registrations_success():
    # Mock holehe website functions
    async def mock_discord(email, client, out):
        out.append({
            "name": "discord",
            "domain": "discord.com",
            "exists": True,
            "rateLimit": False,
            "emailrecovery": None,
            "phoneNumber": None,
            "others": None,
        })

    async def mock_twitter(email, client, out):
        out.append({
            "name": "twitter",
            "domain": "twitter.com",
            "exists": True,
            "rateLimit": False,
            "emailrecovery": "t***@gmail.com",
            "phoneNumber": None,
            "others": None,
        })

    async def mock_github(email, client, out):
        out.append({
            "name": "github",
            "domain": "github.com",
            "exists": False,
            "rateLimit": False,
            "emailrecovery": None,
            "phoneNumber": None,
            "others": None,
        })

    with unittest.mock.patch("holehe.core.import_submodules") as mock_import, \
         unittest.mock.patch("holehe.core.get_functions") as mock_get_fns, \
         unittest.mock.patch("holehe.core.launch_module") as mock_launch:

        mock_get_fns.return_value = [mock_discord, mock_twitter, mock_github]

        async def fake_launch(fn, email, client, out):
            await fn(email, client, out)

        mock_launch.side_effect = fake_launch

        report, status = await check_email_registrations("target@example.com")

        assert report is not None
        assert report.email == "target@example.com"
        assert report.total_checked == 3
        assert len(report.accounts) == 2
        assert status.status == "success"

        platforms = {acc.platform: acc for acc in report.accounts}
        assert "discord" in platforms
        assert "twitter" in platforms
        assert platforms["twitter"].email_recovery == "t***@gmail.com"
        assert "github" not in platforms


@pytest.mark.asyncio
async def test_check_email_registrations_no_hits():
    async def mock_site(email, client, out):
        out.append({
            "name": "site",
            "domain": "site.com",
            "exists": False,
            "rateLimit": False,
        })

    with unittest.mock.patch("holehe.core.import_submodules"), \
         unittest.mock.patch("holehe.core.get_functions") as mock_get_fns, \
         unittest.mock.patch("holehe.core.launch_module") as mock_launch:

        mock_get_fns.return_value = [mock_site]

        async def fake_launch(fn, email, client, out):
            await fn(email, client, out)

        mock_launch.side_effect = fake_launch

        report, status = await check_email_registrations("nobody@example.com")

        assert report is not None
        assert len(report.accounts) == 0
        assert status.status == "no_hits"
