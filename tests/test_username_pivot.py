"""Unit tests for regex lead extraction, bio parsing, and false-positive filtering."""

import pytest
from argus.modules.username_pivot import (
    DISCORD_ID_REGEX,
    DISCORD_INVITE_REGEX,
    DISCORD_TAG_REGEX,
    EMAIL_REGEX,
    clean_discord_invites,
    clean_emails,
)


def test_regex_discord_invites():
    sample = "Join our community at discord.gg/cyber-defense or https://discordapp.com/invite/ops-room today!"
    invites = DISCORD_INVITE_REGEX.findall(sample)
    assert "cyber-defense" in invites
    assert "ops-room" in invites


def test_clean_discord_invites():
    raw = ["cyber-defense", "moonbeam", "openweaver-official", "discord-developers", "react"]
    cleaned = clean_discord_invites(raw, site_url="https://moonbeam.foundation/profile")
    assert "https://discord.gg/cyber-defense" in cleaned
    # Site community server matching site_name or known official server must be filtered out
    assert not any("moonbeam" in inv for inv in cleaned)
    assert not any("discord-developers" in inv for inv in cleaned)
    assert not any("react" in inv for inv in cleaned)


def test_regex_discord_tags():
    sample = "Reach me on Discord: Investigator#1337 or test_user#0001, not user#abcd."
    tags = DISCORD_TAG_REGEX.findall(sample)
    assert "Investigator#1337" in tags
    assert "test_user#0001" in tags
    assert not any("abcd" in t for t in tags)


def test_regex_snowflake_ids():
    sample = (
        "My Discord user ID is 155149108183695360 and alt discord: 136445063681700379, "
        "test 12345, pin data-id 251005447920758264."
    )
    ids = DISCORD_ID_REGEX.findall(sample)
    assert "155149108183695360" in ids
    assert "136445063681700379" in ids
    assert "12345" not in ids
    # Unprefixed Pinterest pin IDs must not match
    assert "251005447920758264" not in ids


def test_clean_emails():
    raw = [
        "valid.investigator@gmail.com",
        "avatar@schema.org",
        "noreply@users.noreply.github.com",
        "badge@example.com",
        "icon.png",
        "script.js",
        "dev.investigator@targetdomain.org",
        "bundle@1.2.1",
        "fontawesome-free@1.0.4",
        "bootswatch@5.3.8",
        "helpdesk@moonbeam.foundation",
        "partners@openweaver.com",
        "staff@engadget.com",
        "support@discord.com",
    ]
    cleaned = clean_emails(raw, site_url="https://openweaver.com/users/target", target_username="target")
    assert "valid.investigator@gmail.com" in cleaned
    assert "dev.investigator@targetdomain.org" in cleaned
    assert "avatar@schema.org" not in cleaned
    assert "noreply@users.noreply.github.com" not in cleaned
    assert "icon.png" not in cleaned
    # npm-style version strings must be filtered out
    assert "bundle@1.2.1" not in cleaned
    assert "fontawesome-free@1.0.4" not in cleaned
    assert "bootswatch@5.3.8" not in cleaned
    # Site role/footer emails must be filtered out
    assert "helpdesk@moonbeam.foundation" not in cleaned
    assert "partners@openweaver.com" not in cleaned
    assert "staff@engadget.com" not in cleaned
    assert "support@discord.com" not in cleaned


@pytest.mark.asyncio
async def test_fetch_and_extract_leads_strips_noise():
    import asyncio
    import unittest.mock
    from argus.modules.username_pivot import _fetch_and_extract_leads

    html_content = """
    <html>
    <head>
        <script src="https://cdn.example.com/bootswatch@5.3.8/lux.js"></script>
        <meta name="description" content="Official handle for SecurityDev. Discord: 155149108183695360, tag: SecGuy#4321, invite: discord.gg/sec-clan">
    </head>
    <body>
        <header><a href="https://discord.gg/openweaver">Community</a></header>
        <main>
            <div class="user-bio">Contact me at securitydev@secops.io</div>
            <div data-pin="251005447920758264">Random pin 251005447920758264</div>
        </main>
        <footer>
            <a href="mailto:support@openweaver.com">support@openweaver.com</a>
            <a href="mailto:partners@openweaver.com">partners@openweaver.com</a>
        </footer>
    </body>
    </html>
    """
    mock_resp = unittest.mock.MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = html_content

    mock_client = unittest.mock.AsyncMock()
    mock_client.get.return_value = mock_resp

    sem = asyncio.Semaphore(1)
    invites, tags, ids, emails, crypto, messaging = await _fetch_and_extract_leads(
        "https://openweaver.com/user/SecurityDev",
        mock_client,
        sem,
        target_username="SecurityDev",
    )

    assert "https://discord.gg/sec-clan" in invites
    # Corporate/platform community invite in header should be stripped
    assert not any("openweaver" in inv for inv in invites)
    assert "SecGuy#4321" in tags
    assert "155149108183695360" in ids
    # Random pin without discord prefix should not be matched
    assert "251005447920758264" not in ids
    # Personal email in bio should be matched
    assert "securitydev@secops.io" in emails
    # Footer and script emails should be completely absent
    assert not any("openweaver.com" in em for em in emails)
    assert not any("bootswatch" in em for em in emails)


def test_extract_crypto_leads():
    from argus.modules.username_pivot import extract_crypto_leads

    sample = (
        "Donate BTC at bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq or tip 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa.\n"
        "ETH wallet: 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045.\n"
        "Here is a git commit: 0x4f3c8a9e1234567890abcdef1234567890abcdef (commit).\n"
        "Solana tip: HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH (phantom/sol).\n"
        "Random base58 string 5Hn7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YW without context."
    )
    leads = extract_crypto_leads(sample)
    networks = {lead.network: lead.address for lead in leads}

    assert "Bitcoin" in networks
    assert "Ethereum" in networks
    assert "Solana" in networks

    # Check addresses
    assert "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" in [l.address for l in leads]
    assert "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045" in [l.address for l in leads]
    assert "HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH" in [l.address for l in leads]

    # Verify commit hash was rejected
    assert not any("0x4f3c8a9e" in l.address for l in leads)
    # Verify un-contextualized base58 was rejected
    assert not any("5Hn7cABqLq46Es1jh92dQQisAq" in l.address for l in leads)


def test_extract_messaging_leads():
    from argus.modules.username_pivot import extract_messaging_leads

    sample = (
        "Reach me on Telegram: t.me/sec_operative or tg: @devops_lead. "
        "Ignore platform link t.me/share and t.me/joinchat. "
        "Matrix: @alice:matrix.org or @bob:federation.chat. "
        "Signal: https://signal.me/#p/sec.42 or signal: my_alias."
    )
    leads = extract_messaging_leads(sample, site_url="https://secops.com/profile")
    handles = {l.handle for l in leads}

    assert "@sec_operative" in handles
    assert "@devops_lead" in handles
    assert "@alice:matrix.org" in handles
    assert "@bob:federation.chat" in handles

    # Verify platform noise rejected
    assert "@share" not in handles
    assert "@joinchat" not in handles
    assert "@secops" not in handles
