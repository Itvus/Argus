"""Unit tests for standalone anti-slop HTML report generation and viewing."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from argus.cli import app
from argus.models import (
    BreachRecord,
    DiscordProfile,
    GitHubPivotLead,
    InvestigationReport,
    ModuleStatus,
    PivotLeads,
    ReverseImageUrls,
    SnowflakeMetadata,
    SocialProfile,
)
from argus.report_html import render_html_report, save_html_report, view_html_report

runner = CliRunner(env={"NO_COLOR": "1", "TERM": "dumb"})


@pytest.fixture
def sample_report() -> InvestigationReport:
    """Fixture providing a fully populated InvestigationReport."""
    return InvestigationReport(
        target="155149108183695360",
        target_type="snowflake",
        scan_timestamp_utc="2026-11-19T21:00:00+00:00",
        scan_duration_seconds=1.23,
        snowflake=SnowflakeMetadata(
            snowflake_id=155149108183695360,
            timestamp_ms=1457060829922,
            created_at_utc="2016-03-04T03:07:09.922000+00:00",
            age_human="10 years, 262 days",
            worker_id=1,
            process_id=0,
            increment=0,
        ),
        discord_profile=DiscordProfile(
            id="155149108183695360",
            username="investigator",
            global_name="Investigator Display",
            avatar_url="https://cdn.discordapp.com/avatars/155149108183695360/abc.png",
            badges=["Active Developer", "HypeSquad Bravery"],
            reverse_image_urls=ReverseImageUrls(
                google_lens="https://lens.google.com/search?p=1",
                yandex="https://yandex.com/images/search?rpt=imageview",
                tineye="https://tineye.com/search?url=1",
                bing_visual="https://www.bing.com/images/search?view=detailv2",
            ),
        ),
        social_profiles=[
            SocialProfile(platform="GitHub", url="https://github.com/investigator", status="Claimed"),
            SocialProfile(platform="Twitter", url="https://x.com/investigator", status="Claimed"),
            SocialProfile(platform="Discord", url="@investigator", status="Claimed"),
        ],
        breaches=[
            BreachRecord(
                query="test@example.com",
                service_name="TestBreach",
                breach_date="2020-01-01",
                pwn_count=1000,
                data_classes=["Email", "Passwords"],
            )
        ],
        github_pivot=GitHubPivotLead(
            username="investigator",
            profile_url="https://github.com/investigator",
            commit_emails=["investigator@gmail.com"],
            created_at="2018-05-12T10:00:00Z",
            age_comparison_discord="Created 2 years after Discord account",
        ),
        pivot_leads=PivotLeads(
            discovered_emails=["investigator@gmail.com"],
            discovered_discord_ids=["155149108183695360"],
            discovered_discord_tags=["investigator#0001"],
            discovered_invites=["https://discord.gg/investigate"],
            notes=["Active coder"],
        ),
        module_statuses=[
            ModuleStatus(module_name="Snowflake Decoder", status="success", message="OK"),
            ModuleStatus(module_name="Discord API", status="success", message="Retrieved"),
        ],
    )


def test_render_html_report_anti_slop_compliance(sample_report: InvestigationReport):
    """Verify generated HTML report complies with strict anti-slop guidelines."""
    html = render_html_report(sample_report)

    # 1. Structure & self-containment
    assert "<!DOCTYPE html>" in html
    assert '<meta name="referrer" content="no-referrer">' in html
    assert "Argus Investigation" in html
    assert "155149108183695360" in html

    # 2. Zero CDN script/link tags
    assert "<script src=" not in html
    assert '<link rel="stylesheet"' not in html

    # 3. Inline SVG vector icons
    assert "<svg" in html

    # 4. Content population
    assert "Discord Snowflake Telemetry" in html
    assert "10 years, 262 days" in html
    assert "investigator" in html
    assert "TestBreach" in html
    assert "investigator@gmail.com" in html
    assert "https://discord.gg/investigate" in html
    assert "@media print" in html


def test_save_html_report(sample_report: InvestigationReport, tmp_path: Path):
    """Verify save_html_report writes valid file to destination."""
    out_file = tmp_path / "reports" / "investigation.html"
    saved = save_html_report(sample_report, out_file)

    assert saved == out_file
    assert out_file.is_file()
    content = out_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "155149108183695360" in content


def test_render_html_report_script_breakout_escaping(sample_report: InvestigationReport):
    """Verify that graphData payload escapes HTML tags to prevent script injection."""
    sample_report.social_profiles.append(
        SocialProfile(platform="XSS", url="https://evil.com/</script><script>alert(1)</script>", status="Claimed")
    )
    rendered = render_html_report(sample_report)
    assert "</script><script>" not in rendered.split("const graphData =")[1].split(";</script>")[0]
    assert "\\u003c/script\\u003e" in rendered


def test_view_html_report_custom_path(sample_report: InvestigationReport, tmp_path: Path):
    """Verify view_html_report opens custom path in browser."""
    out_file = tmp_path / "custom_view.html"
    with patch("webbrowser.open_new_tab") as mock_open:
        res = view_html_report(sample_report, custom_path=out_file)
        assert res == out_file
        assert out_file.is_file()
        mock_open.assert_called_once_with(out_file.as_uri())


def test_view_html_report_temp_path(sample_report: InvestigationReport):
    """Verify view_html_report creates and opens temporary file when path omitted."""
    with patch("webbrowser.open_new_tab") as mock_open:
        res = view_html_report(sample_report, custom_path=None)
        assert res.is_file()
        assert res.name.startswith("argus_report_")
        assert res.suffix == ".html"
        mock_open.assert_called_once_with(res.as_uri())
        # Clean up temp file
        res.unlink(missing_ok=True)


def test_cli_snowflake_html_generation(tmp_path: Path):
    """Verify CLI --html flag generates standalone report."""
    target_html = tmp_path / "test_cli_report.html"
    result = runner.invoke(app, ["snowflake", "155149108183695360", "--html", str(target_html)])
    assert result.exit_code == 0
    assert target_html.is_file()
    content = target_html.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "155149108183695360" in content


def test_html_report_profile_categories_and_tabs(sample_report: InvestigationReport):
    """Verify HTML report includes category filter tabs, badges, and clientside filter logic."""
    from argus.report_html import categorize_platform

    # 1. Categorization unit tests
    assert categorize_platform("Steam") == "gaming"
    assert categorize_platform("Chess.com") == "gaming"
    assert categorize_platform("Roblox") == "gaming"
    assert categorize_platform("GitHub") == "developer"
    assert categorize_platform("GitLab") == "developer"
    assert categorize_platform("PyPI") == "developer"
    assert categorize_platform("Twitter") == "social"
    assert categorize_platform("Reddit") == "social"
    assert categorize_platform("Discord") == "messaging"
    assert categorize_platform("Telegram") == "messaging"
    assert categorize_platform("Spotify") == "media"

    # Add a gaming profile to sample_report
    sample_report.social_profiles.append(
        SocialProfile(platform="Steam", url="https://steamcommunity.com/id/gamer", status="Claimed")
    )

    rendered = render_html_report(sample_report)

    # 2. Check filter tabs (All active by default, plus category buttons)
    assert 'class="filter-tab active" data-filter="all"' in rendered
    assert 'data-filter="gaming"' in rendered
    assert 'data-filter="developer"' in rendered
    assert 'data-filter="social"' in rendered
    assert 'data-filter="messaging"' in rendered

    # 3. Check table rows have category attributes & badges
    assert 'data-category="gaming"' in rendered
    assert 'data-category="developer"' in rendered
    assert 'data-category="social"' in rendered
    assert 'data-category="messaging"' in rendered
    assert 'class="category-badge category-gaming"' in rendered
    assert 'class="category-badge category-developer"' in rendered

    # 4. Check clientside filter function
    assert "function filterProfileCategory(category)" in rendered
