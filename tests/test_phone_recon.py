"""Unit tests for phone number reconnaissance and E.164 country resolution."""

import pytest
from argus.modules.phone_recon import extract_phone_leads, resolve_country


def test_resolve_country():
    code, country = resolve_country("15551234567")
    assert code == "1"
    assert "United States" in country

    code, country = resolve_country("447911123456")
    assert code == "44"
    assert country == "United Kingdom"

    code, country = resolve_country("4915123456789")
    assert code == "49"
    assert country == "Germany"

    code, country = resolve_country("380501234567")
    assert code == "380"
    assert country == "Ukraine"


def test_extract_phone_leads():
    bio = """
    Contact me:
    WhatsApp: +1 (555) 234-5678
    Work phone: +44 7911 123456
    Mobile: +49 151 23456789
    Telegram @alice
    Discord Snowflake: 155149108183695360
    Git commit: a1b2c3d4e5f60718293a4b5c6d7e8f9012345678
    """
    leads = extract_phone_leads(bio)
    e164_list = [p.e164 for p in leads]

    assert "+15552345678" in e164_list
    assert "+447911123456" in e164_list
    assert "+4915123456789" in e164_list

    # Ensure Discord Snowflake and git commit hashes are not extracted as phone numbers
    assert not any("155149108183695360" in p.e164 for p in leads)
    assert not any("a1b2c3d4" in p.e164 for p in leads)

    # Check country mapping
    us_lead = next(p for p in leads if p.e164 == "+15552345678")
    assert us_lead.country_code == "1"
    assert "United States" in us_lead.country_name

    uk_lead = next(p for p in leads if p.e164 == "+447911123456")
    assert uk_lead.country_code == "44"
    assert uk_lead.country_name == "United Kingdom"


def test_extract_phone_leads_anti_noise():
    # Repetitive uniform digits are rejected
    assert len(extract_phone_leads("+11111111111")) == 0
    assert len(extract_phone_leads("+0000000000")) == 0

    # Short numbers (<7 digits) or long numbers (>15 digits) rejected
    assert len(extract_phone_leads("+12345")) == 0
    assert len(extract_phone_leads("+1234567890123456789")) == 0
