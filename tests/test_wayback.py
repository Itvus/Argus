"""Unit tests for Internet Archive Wayback Machine CDX snapshots."""

import unittest.mock
import pytest

from argus.modules.wayback import fetch_wayback_snapshots


@pytest.mark.asyncio
async def test_fetch_wayback_snapshots():
    """Verify CDX rows are parsed into WaybackSnapshot models."""
    mock_cdx_rows = [
        ["timestamp", "original", "statuscode"],
        ["20220101120000", "https://github.com/target", "200"],
        ["20230501183000", "https://github.com/target", "200"],
    ]

    def mock_get(url, *args, **kwargs):
        resp = unittest.mock.MagicMock()
        resp.status_code = 200
        resp.json.return_value = mock_cdx_rows
        return resp

    mock_client = unittest.mock.AsyncMock()
    mock_client.get.side_effect = mock_get
    mock_client.__aenter__.return_value = mock_client

    with unittest.mock.patch("httpx.AsyncClient", return_value=mock_client):
        snapshots, status = await fetch_wayback_snapshots(["https://github.com/target"], timeout=5)
        assert status.status == "success"
        assert len(snapshots) == 2
        assert snapshots[0].timestamp == "20220101120000"
        assert snapshots[0].archive_url == "https://web.archive.org/web/20220101120000/https://github.com/target"
