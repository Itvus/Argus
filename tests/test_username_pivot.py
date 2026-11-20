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

    session_id = "05" + "ab" * 32
    tox_id = "1234567890ABCDEF" * 4 + "1234567890ABCDEF"[:12]

    sample = (
        "Reach me on Telegram: t.me/sec_operative or tg: @devops_lead. "
        "Ignore platform link t.me/share and t.me/joinchat. "
        "Matrix: @alice:matrix.org or @bob:federation.chat. "
        "Signal: https://signal.me/#p/sec.42 or signal: my_alias. "
        f"Session ID: {session_id}. "
        f"Tox ID: {tox_id}. "
        "SimpleX: https://simplex.chat/contact#/?v=1&smp=test_link. "
        "XMPP: user.name@jabber.ccc.de or xmpp:secops@calyxinstitute.org."
    )
    leads = extract_messaging_leads(sample, site_url="https://secops.com/profile")
    handles = {l.handle for l in leads}
    platforms = {l.platform for l in leads}

    assert "@sec_operative" in handles
    assert "@devops_lead" in handles
    assert "@alice:matrix.org" in handles
    assert "@bob:federation.chat" in handles
    assert session_id in handles
    assert tox_id in handles
    assert "user.name@jabber.ccc.de" in handles
    assert "secops@calyxinstitute.org" in handles

    assert "Session" in platforms
    assert "Tox" in platforms
    assert "SimpleX" in platforms
    assert "XMPP" in platforms

    # Verify platform noise rejected
    assert "@share" not in handles
    assert "@joinchat" not in handles
    assert "@secops" not in handles


def test_extract_leads_from_text():
    from argus.modules.username_pivot import extract_leads_from_text

    sample = (
        "Hello! Discord: @investigator, user ID discord: 155149108183695360, "
        "Join discord.gg/cyber-defense. Email me at lead@domain.org. "
        "BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa. "
        "Session: 050102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20."
    )
    leads = extract_leads_from_text(sample, site_url="https://example.com")
    assert "lead@domain.org" in leads.discovered_emails
    assert "155149108183695360" in leads.discovered_discord_ids
    assert "https://discord.gg/cyber-defense" in leads.discovered_invites
    assert any(c.network == "Bitcoin" for c in leads.discovered_crypto)
    assert any(m.platform == "Session" for m in leads.discovered_messaging)


def test_get_base_domain_and_subdomain_email_filtering():
    from argus.modules.username_pivot import get_base_domain, clean_emails

    # Base domain parsing across apex domains, multi-level subdomains, and ccTLDs
    assert get_base_domain("https://example.com") == "example.com"
    assert get_base_domain("https://blog.example.com/user/alice") == "example.com"
    assert get_base_domain("http://dev.community.site.co.uk/profile") == "site.co.uk"
    assert get_base_domain("https://www.github.com/foo") == "github.com"
    assert get_base_domain("https://member.portal.agency.org.au") == "agency.org.au"

    # clean_emails should filter out site emails matching apex domain even if on subdomains
    raw_emails = [
        "target@proton.me",
        "support@blog.example.com",
        "staff@mail.example.com",
        "contact@example.com",
        "researcher@external-service.org",
    ]
    cleaned = clean_emails(raw_emails, site_url="https://blog.example.com/u/target")
    assert "target@proton.me" in cleaned
    assert "researcher@external-service.org" in cleaned
    assert "support@blog.example.com" not in cleaned
    assert "staff@mail.example.com" not in cleaned
    assert "contact@example.com" not in cleaned


def test_xmpp_addresses_not_extracted_as_emails():
    from argus.modules.username_pivot import extract_leads_from_text, clean_emails

    # BUG-22: XMPP URI should yield XMPP messaging lead, NOT an email lead
    sample1 = "Contact me via xmpp:alice@jabber.ccc.de"
    leads1 = extract_leads_from_text(sample1)
    assert "alice@jabber.ccc.de" not in leads1.discovered_emails
    assert len(leads1.discovered_emails) == 0
    assert any(m.platform == "XMPP" and m.handle == "alice@jabber.ccc.de" for m in leads1.discovered_messaging)

    # Labeled XMPP / Jabber / JID should not become email leads
    sample2 = "My email is engineer@securecorp.io. XMPP: operator@xmpp.is. Jabber: bob@jabber.org. JID: charlie@conversations.im."
    leads2 = extract_leads_from_text(sample2)
    assert leads2.discovered_emails == ["engineer@securecorp.io"]
    xmpp_handles = {m.handle for m in leads2.discovered_messaging if m.platform == "XMPP"}
    assert "operator@xmpp.is" in xmpp_handles
    assert "bob@jabber.org" in xmpp_handles
    assert "charlie@conversations.im" in xmpp_handles

    # Suffix notation: user@domain (XMPP)
    sample3 = "reach out: alice@jabber.ccc.de (XMPP) or founder@mycompany.org"
    leads3 = extract_leads_from_text(sample3)
    assert "alice@jabber.ccc.de" not in leads3.discovered_emails
    assert "founder@mycompany.org" in leads3.discovered_emails
    assert any(m.platform == "XMPP" and m.handle == "alice@jabber.ccc.de" for m in leads3.discovered_messaging)

    # clean_emails direct call with xmpp: / jabber: / jid: prefixes
    cleaned_direct = clean_emails(["xmpp:alice@jabber.ccc.de", "jabber:bob@domain.org", "valid@domain.org"])
    assert "valid@domain.org" in cleaned_direct
    assert not any("alice@jabber.ccc.de" in e for e in cleaned_direct)
    assert not any("bob@domain.org" in e for e in cleaned_direct)


def test_unlabeled_hex_does_not_match_tox_or_session():
    from argus.modules.username_pivot import extract_messaging_leads

    # 76-char hex without Tox label/context should NOT be matched
    raw_hash_76 = "0a" * 38
    leads_tox = extract_messaging_leads(f"Git commit checksum {raw_hash_76} verified.")
    assert not any(m.platform == "Tox" for m in leads_tox)

    # 66-char 05-prefixed hex without Session label/context should NOT be matched
    raw_session_66 = "05" + "ff" * 32
    leads_session = extract_messaging_leads(f"Payload nonce {raw_session_66} in header.")
    assert not any(m.platform == "Session" for m in leads_session)


def test_extract_monero_crypto_leads():
    from argus.modules.username_pivot import extract_crypto_leads

    # Standard Monero 95-char address starting with 4
    xmr_addr = "44AFFq5AxmMNParseMZaaSt5Ftdq3kK8K7fW21QJmGy1c7dC19s4iQ9L13d8d6tV1z1nZk2h8N6iP3iP2r8p8m4B9oFpYQZ"
    # Subaddress 95-char starting with 8
    xmr_sub = "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkFxbANsAnJYPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H"

    text = f"Donate Monero: {xmr_addr} or subaddress {xmr_sub}"
    leads = extract_crypto_leads(text)
    xmr_leads = [c for c in leads if c.network == "Monero"]

    assert len(xmr_leads) == 2
    assert xmr_leads[0].address == xmr_addr
    assert xmr_leads[1].address == xmr_sub


def test_extract_payment_messaging_leads():
    from argus.modules.username_pivot import extract_messaging_leads

    text = """
    Support the project:
    CashApp: $OSINTDev or https://cash.app/$SecurityPro
    Venmo: @Analyst_Fund or https://venmo.com/u/OpsLead
    PayPal: https://paypal.me/ResearchOrg
    """
    leads = extract_messaging_leads(text)
    cashapp = [m for m in leads if m.platform == "CashApp"]
    venmo = [m for m in leads if m.platform == "Venmo"]
    paypal = [m for m in leads if m.platform == "PayPal"]

    assert any(m.handle == "$OSINTDev" for m in cashapp)
    assert any(m.handle == "$SecurityPro" for m in cashapp)
    assert any(m.handle == "@Analyst_Fund" for m in venmo)
    assert any(m.handle == "@OpsLead" for m in venmo)
    assert any(m.handle == "ResearchOrg" for m in paypal)
