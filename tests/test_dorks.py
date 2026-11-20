"""Unit tests for pre-computed Google Dork URL generation."""

from argus.modules.dorks import generate_google_dorks


def test_generate_google_dorks():
    dorks = generate_google_dorks("cyber_operative", emails=["operative@proton.me"])
    assert len(dorks) >= 6

    categories = {d.category for d in dorks}
    assert "Pastes & Text Dumps" in categories
    assert "Telegram Channels & Chats" in categories
    assert "Source Code Secrets & Configs" in categories
    assert "Email Web Presence" in categories

    for d in dorks:
        assert d.url.startswith("https://www.google.com/search?q=")
        assert "cyber_operative" in d.query or "operative@proton.me" in d.query


def test_generate_google_dorks_snowflake():
    dorks = generate_google_dorks("155149108183695360")
    assert len(dorks) >= 4
    categories = {d.category for d in dorks}
    assert "Discord Channel & Message Archives" in categories
    assert "Bot Audit & Moderation Logs" in categories
    assert "GitHub Code Search (Bots & Configs)" in categories
    for d in dorks:
        assert "155149108183695360" in d.query
