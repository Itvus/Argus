"""Unit tests for Markdown investigation report generation."""

from pathlib import Path
import pytest
from argus.models import (
    BreachRecord,
    CorrelationScore,
    CryptoLead,
    GamingProfiles,
    InvestigationReport,
    MessagingLead,
    MinecraftProfile,
    PhoneLead,
    PivotLeads,
    RobloxProfile,
    SnowflakeMetadata,
    SocialProfile,
    SteamProfile,
)
from argus.report_markdown import render_markdown_report, save_markdown_report


def test_render_and_save_markdown_report(tmp_path: Path):
    report = InvestigationReport(
        target="target_user",
        target_type="username",
        scan_timestamp_utc="2026-11-20T21:00:00Z",
        scan_duration_seconds=3.5,
        correlation=CorrelationScore(confidence_score=85, confidence_level="HIGH"),
        snowflake=SnowflakeMetadata(
            snowflake_id=155149108183695360,
            timestamp_ms=1457059479000,
            created_at_utc="2016-03-04 02:44:39 UTC",
            age_human="10 years, 8 months",
            worker_id=1,
            process_id=1,
            increment=0,
        ),
        social_profiles=[
            SocialProfile(platform="GitHub", url="https://github.com/target_user", status="Claimed"),
        ],
        gaming=GamingProfiles(
            minecraft=MinecraftProfile(username="target_user", uuid="069a79f444e94726a5befca90e38aaf5", uuid_formatted="069a79f4-44e9-4726-a5be-fca90e38aaf5"),
            steam=SteamProfile(steam_id_64="76561198000000000", custom_url="target_user", profile_url="https://steamcommunity.com/id/target_user"),
            roblox=RobloxProfile(user_id=1234567, username="target_user", display_name="TargetDisplayName", profile_url="https://www.roblox.com/users/1234567/profile"),
        ),
        pivot_leads=PivotLeads(
            discovered_emails=["target@secure.org"],
            discovered_crypto=[CryptoLead(network="Monero", address="44AFFq5AxmMNParseMZaaSt5Ftdq3kK8K7fW21QJmGy1c7dC19s4iQ9L13d8d6tV1z1nZk2h8N6iP3iP2r8p8m4B9oFpYQZ")],
            discovered_messaging=[MessagingLead(platform="CashApp", handle="$TargetPay", url="https://cash.app/$TargetPay")],
            discovered_phones=[PhoneLead(raw_number="+1 (555) 019-2834", e164="+15550192834", country_code="1", country_name="United States / Canada")],
        ),
        breaches=[
            BreachRecord(query="target@secure.org", service_name="DataExposure", data_classes=["passwords"]),
        ],
    )

    md = render_markdown_report(report)

    # Core sections and values present in markdown
    assert "# Argus OSINT Dossier: `target_user`" in md
    assert "Discord Snowflake Telemetry" in md
    assert "155149108183695360" in md
    assert "Discovered Social & Community Profiles" in md
    assert "[https://github.com/target_user](https://github.com/target_user)" in md
    assert "target@secure.org" in md
    assert "Monero" in md
    assert "$TargetPay" in md
    assert "+15550192834" in md
    assert "Roblox" in md
    assert "DataExposure" in md

    # Test file saving
    out_file = tmp_path / "report.md"
    saved = save_markdown_report(report, out_file)
    assert saved.exists()
    assert saved.read_text(encoding="utf-8") == md
