"""Unit tests for modular enrichment plugins (CordCat, breach checks, GitHub audit)."""

import pytest
from datetime import datetime, timezone
import httpx

from argus.modules.enrichment import check_breaches, fetch_github_pivot, query_cordcat


@pytest.mark.asyncio
async def test_query_cordcat_missing_key():
    record, status = await query_cordcat("155149108183695360", api_key=None)
    assert record is None
    assert status.status == "skipped"
    assert "CORDCAT_API_KEY is not configured" in status.message


@pytest.mark.asyncio
async def test_check_breaches_missing_keys():
    records, status = await check_breaches(["victim@target.com"], hibp_api_key=None, leakcheck_api_key=None)
    assert records == []
    assert status.status == "skipped"
    assert "Neither HIBP_API_KEY nor LEAKCHECK_API_KEY" in status.message


@pytest.mark.asyncio
async def test_check_breaches_no_queries():
    records, status = await check_breaches([], hibp_api_key="dummy_key")
    assert records == []
    assert status.status == "no_queries"


@pytest.mark.asyncio
async def test_fetch_github_pivot_mocked(monkeypatch):
    """Test GitHub pivot with deterministic mocked responses."""
    class MockResponse:
        def __init__(self, status_code: int, json_data: dict | list):
            self.status_code = status_code
            self._json = json_data

        def json(self):
            return self._json

    class MockAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get(self, url: str, **kwargs):
            if "/users/" in url and "/events" not in url:
                return MockResponse(
                    200,
                    {
                        "login": "testuser",
                        "html_url": "https://github.com/testuser",
                        "name": "Test User",
                        "company": "OpenSource Org",
                        "created_at": "2018-05-10T12:00:00Z",
                    },
                )
            if "/events/public" in url:
                return MockResponse(
                    200,
                    [
                        {
                            "type": "PushEvent",
                            "payload": {
                                "commits": [
                                    {"author": {"email": "dev@testuser.com"}},
                                    {"author": {"email": "testuser@users.noreply.github.com"}},
                                ]
                            },
                        }
                    ],
                )
            return MockResponse(404, {})

    monkeypatch.setattr(httpx, "AsyncClient", MockAsyncClient)

    discord_created = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    lead, status = await fetch_github_pivot("testuser", discord_created_at_dt=discord_created)

    assert status.status == "success"
    assert lead is not None
    assert lead.username == "testuser"
    assert lead.name == "Test User"
    assert "dev@testuser.com" in lead.commit_emails
    # Noreply email must be filtered out
    assert not any("noreply" in em for em in lead.commit_emails)
    assert lead.age_comparison_discord is not None
    assert "BEFORE Discord account" in lead.age_comparison_discord


@pytest.mark.asyncio
async def test_cordcat_mocked(monkeypatch):
    """Test CordCat query with mocked response."""
    class MockResponse:
        def __init__(self, status_code: int, json_data: dict):
            self.status_code = status_code
            self._json = json_data

        def json(self):
            return self._json

    class MockAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get(self, url: str, **kwargs):
            return MockResponse(
                200,
                {
                    "usernames": ["old_handle_2020", "gamer_tag_1"],
                    "fivem": ["fivem:123456"],
                },
            )

    monkeypatch.setattr(httpx, "AsyncClient", MockAsyncClient)

    record, status = await query_cordcat("155149108183695360", api_key="test_cordcat_key")
    assert status.status == "success"
    assert record is not None
    assert "old_handle_2020" in record.historical_usernames
    assert "fivem:123456" in record.fivem_identifiers
