"""Unit tests for Intelligence X darknet and data leak search module."""

import pytest
import unittest.mock
from argus.modules.intelx import query_intelx


@pytest.mark.asyncio
async def test_query_intelx_success():
    init_resp = unittest.mock.MagicMock()
    init_resp.status_code = 200
    init_resp.json.return_value = {"id": "1111-2222-3333-4444", "status": 0}

    res_resp = unittest.mock.MagicMock()
    res_resp.status_code = 200
    res_resp.json.return_value = {
        "selectors": [
            {"selectorvalue": "leak_record_1.txt", "selectortype": 1},
            {"selectorvalue": "paste_dump_2.json", "selectortype": 2},
        ]
    }

    mock_client = unittest.mock.AsyncMock()
    mock_client.post.return_value = init_resp
    mock_client.get.return_value = res_resp
    mock_client.__aenter__.return_value = mock_client

    with unittest.mock.patch("httpx.AsyncClient", return_value=mock_client):
        report, status = await query_intelx("target_email@example.com", api_key="mock_key")

    assert report is not None
    assert report.total_results == 2
    assert len(report.records) == 2
    assert report.records[0].name == "leak_record_1.txt"
    assert status.status == "success"


@pytest.mark.asyncio
async def test_query_intelx_rate_limit():
    init_resp = unittest.mock.MagicMock()
    init_resp.status_code = 429

    mock_client = unittest.mock.AsyncMock()
    mock_client.post.return_value = init_resp
    mock_client.__aenter__.return_value = mock_client

    with unittest.mock.patch("httpx.AsyncClient", return_value=mock_client):
        report, status = await query_intelx("some_user", api_key="mock_key")

    assert report is None
    assert status.status == "skipped"
    assert "429" in status.message


@pytest.mark.asyncio
async def test_query_intelx_skipped_no_key():
    report, status = await query_intelx("some_user", api_key=None)
    assert report is None
    assert status.status == "skipped"
    assert "INTELX_API_KEY" in status.message
