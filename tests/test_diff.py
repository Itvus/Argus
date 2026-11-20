"""Unit tests for investigation report differential analysis."""

import pytest
from argus.models import (
    BreachRecord,
    CryptoLead,
    InvestigationReport,
    MessagingLead,
    PhoneLead,
    PivotLeads,
    SocialProfile,
)
from argus.modules.diff import compare_investigation_reports, render_diff_rich


def test_compare_investigation_reports_detects_changes():
    report_a = InvestigationReport(
        target="alice",
        target_type="username",
        scan_timestamp_utc="2026-01-01T00:00:00Z",
        social_profiles=[
            SocialProfile(platform="GitHub", url="https://github.com/alice", status="Claimed"),
            SocialProfile(platform="Twitter", url="https://twitter.com/alice", status="Claimed"),
        ],
        pivot_leads=PivotLeads(
            discovered_emails=["old@domain.com"],
            discovered_crypto=[CryptoLead(network="Bitcoin", address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")],
            discovered_messaging=[MessagingLead(platform="Telegram", handle="@alice_old")],
            discovered_phones=[PhoneLead(raw_number="+15551112222", e164="+15551112222", country_code="1", country_name="United States")],
        ),
        breaches=[],
    )

    report_b = InvestigationReport(
        target="alice",
        target_type="username",
        scan_timestamp_utc="2026-02-01T00:00:00Z",
        social_profiles=[
            SocialProfile(platform="GitHub", url="https://github.com/alice", status="Claimed"),
            SocialProfile(platform="Mastodon", url="https://mastodon.social/@alice", status="Claimed"),
        ],
        pivot_leads=PivotLeads(
            discovered_emails=["new@domain.com"],
            discovered_crypto=[
                CryptoLead(network="Bitcoin", address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
                CryptoLead(network="Monero", address="44AFFq5AxmMNParseMZaaSt5Ftdq3kK8K7fW21QJmGy1c7dC19s4iQ9L13d8d6tV1z1nZk2h8N6iP3iP2r8p8m4B9oFpYQZ"),
            ],
            discovered_messaging=[
                MessagingLead(platform="Signal", handle="alice.01"),
                MessagingLead(platform="CashApp", handle="$AlicePay"),
            ],
            discovered_phones=[PhoneLead(raw_number="+447911123456", e164="+447911123456", country_code="44", country_name="United Kingdom")],
        ),
        breaches=[
            BreachRecord(query="new@domain.com", service_name="ExploitData", data_classes=["passwords"]),
        ],
    )

    diff = compare_investigation_reports(report_a, report_b)

    # Added / removed profiles
    added_profiles = [p["platform"] for p in diff["profiles"]["added"]]
    removed_profiles = [p["platform"] for p in diff["profiles"]["removed"]]
    assert "Mastodon" in added_profiles
    assert "Twitter" in removed_profiles

    # Added / removed emails
    assert diff["emails"]["added"] == ["new@domain.com"]
    assert diff["emails"]["removed"] == ["old@domain.com"]

    # Crypto diff
    added_crypto = [c["network"] for c in diff["crypto"]["added"]]
    assert "Monero" in added_crypto

    # Messaging diff
    added_msg = [m["platform"] for m in diff["messaging"]["added"]]
    assert "Signal" in added_msg
    assert "CashApp" in added_msg

    # Phone diff
    assert any(p["e164"] == "+447911123456" for p in diff["phones"]["added"])
    assert any(p["e164"] == "+15551112222" for p in diff["phones"]["removed"])

    # Breaches
    assert len(diff["breaches"]["added"]) == 1
    assert diff["breaches"]["added"][0]["service"] == "ExploitData"

    # Render without raising
    render_diff_rich(diff)
