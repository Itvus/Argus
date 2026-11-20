"""Unit tests for the algorithmic correlation confidence engine."""

from argus.models import (
    AvatarMatch,
    InvestigationReport,
    PivotLeads,
    SocialProfile,
    HudsonRockReport,
    StealerInfection,
)
from argus.modules.correlation import calculate_correlation_score


def test_calculate_correlation_score_high_confidence():
    report = InvestigationReport(
        target="secops",
        target_type="username",
        scan_timestamp_utc="2026-11-20T12:00:00Z",
        avatar_matches=[
            AvatarMatch(
                platform_a="Discord",
                url_a="https://cdn.discordapp.com/a.png",
                platform_b="Steam",
                url_b="https://avatars.steam.com/b.png",
                hamming_distance=1,
            )
        ],
        pivot_leads=PivotLeads(
            discovered_discord_ids=["155149108183695360"],
            discovered_emails=["secops@target.org"],
        ),
        social_profiles=[
            SocialProfile(platform="GitHub", url="https://github.com/secops"),
            SocialProfile(platform="Twitter", url="https://twitter.com/secops"),
            SocialProfile(platform="Reddit", url="https://reddit.com/user/secops"),
        ],
        hudson_rock=[
            HudsonRockReport(
                query="secops",
                query_type="username",
                total_stealers=1,
                infections=[StealerInfection(stealer_family="Lumma")],
            )
        ],
    )

    corr = calculate_correlation_score(report)
    assert corr.confidence_score >= 80
    assert corr.confidence_level == "HIGH"
    assert any("Visual proof" in r for r in corr.reasons)
    assert any("Direct link" in r for r in corr.reasons)


def test_calculate_correlation_score_low_confidence():
    report = InvestigationReport(
        target="unknown_random",
        target_type="username",
        scan_timestamp_utc="2026-11-20T12:00:00Z",
    )

    corr = calculate_correlation_score(report)
    assert corr.confidence_score < 40
    assert corr.confidence_level == "LOW"
    assert any("Preliminary finding" in r for r in corr.reasons)
