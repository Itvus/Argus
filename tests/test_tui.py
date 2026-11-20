"""Tests for Argus Interactive Terminal User Interface (TUI)."""

import pytest
from argus.models import (
    AvatarMatch,
    BreachRecord,
    CordCatRecord,
    CorrelationScore,
    CryptoLead,
    DiscordProfile,
    DomainReconRecord,
    EmailAccountResult,
    EmailRegistrationReport,
    GamingProfiles,
    GitHubPivotLead,
    GoogleDork,
    HudsonRockReport,
    ImageMetadataReport,
    IntelXRecord,
    IntelXReport,
    InvestigationReport,
    KeybaseProfile,
    KeybaseProof,
    MessagingLead,
    MinecraftProfile,
    ModuleStatus,
    PackageRecord,
    PGPKeyRecord,
    PivotLeads,
    SnowflakeMetadata,
    SocialProfile,
    SteamProfile,
    StealerInfection,
    WaybackSnapshot,
)
from argus.tui import (
    display_diagnostics_panel,
    display_discord_panel,
    display_enrichment_panel,
    display_gaming_panel,
    display_leads_panel,
    display_overview_panel,
    display_profiles_panel,
)


@pytest.fixture
def hostile_report() -> InvestigationReport:
    """Fixture returning an InvestigationReport populated with hostile Rich markup."""
    return InvestigationReport(
        target="victim[/]test",
        target_type="username[/]",
        scan_timestamp_utc="2026-11-20T17:00:00Z[/]",
        scan_duration_seconds=1.2,
        correlation=CorrelationScore(
            confidence_score=85,
            confidence_level="HIGH[/]",
            reasons=["Matched on avatar hash [/] and username [foo]"],
        ),
        snowflake=SnowflakeMetadata(
            snowflake_id=155149108183695360,
            timestamp_ms=1457059479000,
            created_at_utc="2016-03-04 02:44:39 UTC[/]",
            age_human="8 years, 8 months[/]",
            worker_id=1,
            process_id=1,
            increment=0,
        ),
        pivot_leads=PivotLeads(
            discovered_emails=["bad[/]@evil.com"],
            discovered_crypto=[CryptoLead(network="Bitcoin[/]", address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa[/]")],
            discovered_messaging=[MessagingLead(platform="Telegram[/]", handle="@hostile[/]")],
            discovered_discord_tags=["hostile#1234[/]"],
            discovered_discord_ids=["155149108183695360[/]"],
            discovered_invites=["https://discord.gg/evil[/]"],
            notes=["hostile note with [/] markup and unclosed [tag"],
        ),
        breaches=[
            BreachRecord(
                query="a@b.c",
                service_name="Ex[/]ploit",
                data_classes=["passwords[/]", "emails[test]"],
            )
        ],
        github_pivot=GitHubPivotLead(
            username="u",
            profile_url="https://github.com/u",
            name="Hostile[/]Name",
            company="[evil]corp[/]",
            bio="[malicious]tag[/] in bio",
        ),
        discord_profile=DiscordProfile(
            id="155149108183695360",
            username="hostile_user",
            global_name="[bad]global[/]",
            bio="bio with [closing] [/] tags",
        ),
        cordcat=CordCatRecord(
            user_id="155149108183695360",
            historical_usernames=["bad_alias[/]"],
            fivem_identifiers=["fivem:123[/]"],
        ),
        gaming=GamingProfiles(
            steam=SteamProfile(
                steam_id_64="76561198000000000[/]",
                custom_url="gamer[/]",
                persona_name="Gamer[/]Tag",
                profile_url="https://steamcommunity.com/id/gamer[/]",
                avatar_url="https://steam.com/avatar.jpg[/]",
                summary="summary with [/] tags",
            ),
            minecraft=MinecraftProfile(
                uuid="069a79f444e94726a5befca90e38aaf5[/]",
                uuid_formatted="069a79f4-44e9-4726-a5be-fca90e38aaf5[/]",
                username="Crafter[/]",
            ),
        ),
        social_profiles=[
            SocialProfile(
                platform="Bad[/]Platform",
                url="https://bad.com/u[/]",
                status="Claimed[/]",
            )
        ],
        packages=[
            PackageRecord(
                registry="pypi[/]",
                name="bad-pkg[/]",
                version="1.0.0[/]",
                url="https://pypi.org/project/bad[/]",
                description="desc with [tag][/]",
                author_email="author[/]@pkg.org",
            )
        ],
        domain_recon=[
            DomainReconRecord(
                domain="evil.com[/]",
                registrar="Registrar[/]",
                created_date="2020[/]",
                subdomains=["sub[/].evil.com"],
            )
        ],
        keybase=KeybaseProfile(
            username="kb_user[/]",
            bio="kb bio with [/]",
            proofs=[KeybaseProof(service="twitter[/]", username="t[/]", proof_url="https://proof[/]")],
            crypto_addresses=[{"currency": "btc[/]", "address": "addr[/]"}],
        ),
        pgp_keys=[
            PGPKeyRecord(
                key_id_or_fingerprint="FINGERPRINT[/]",
                identities=["Jane Doe <jane@evil.com>[/]"],
            )
        ],
        hudson_rock=[
            HudsonRockReport(
                query="u[/]",
                query_type="username",
                total_stealers=1,
                infections=[
                    StealerInfection(
                        computer_name="PC[/]",
                        operating_system="Windows[/]",
                        stealer_family="RedLine[/]",
                        date_compromised="2024[/]",
                    )
                ],
            )
        ],
        dorks=[
            GoogleDork(
                category="Twitter[/]",
                query="site:twitter.com evil[/]",
                url="https://google.com/search?q=[/]",
            )
        ],
        intelx=IntelXReport(
            query="u[/]",
            total_results=1,
            records=[
                IntelXRecord(
                    system_id="sid[/]",
                    name="Leak[/]",
                    date="2024[/]",
                )
            ],
        ),
        wayback_snapshots=[
            WaybackSnapshot(
                original_url="https://bad.com[/]",
                archive_url="https://web.archive.org/web/2020/bad.com[/]",
                timestamp="2020[/]",
            )
        ],
        image_metadata=[
            ImageMetadataReport(
                platform="Discord[/]",
                url="https://img.com/a.jpg[/]",
                make="Canon[/]",
                model="EOS[/]",
                software="Photoshop[/]",
                datetime_original="2024[/]",
            )
        ],
        avatar_matches=[
            AvatarMatch(
                platform_a="Discord[/]",
                url_a="https://avatar.com/1.png[/]",
                platform_b="GitHub[/]",
                url_b="https://avatar.com/2.png[/]",
                hamming_distance=0,
                is_match=True,
            )
        ],
        email_registrations=[
            EmailRegistrationReport(
                email="test@evil.com[/]",
                total_checked=1,
                accounts=[
                    EmailAccountResult(
                        platform="Twitter[/]",
                        domain="twitter.com[/]",
                    )
                ],
            )
        ],
        module_statuses=[
            ModuleStatus(
                module_name="Test[/]",
                status="success[/]",
                message="Ran with [/] error",
            )
        ],
    )


def test_tui_all_panels_hostile_markup(hostile_report):
    """Verify that all 7 TUI panels render without raising rich.errors.MarkupError."""
    display_overview_panel(hostile_report)
    display_discord_panel(hostile_report)
    display_gaming_panel(hostile_report)
    display_leads_panel(hostile_report)
    display_profiles_panel(hostile_report)
    display_enrichment_panel(hostile_report)
    display_diagnostics_panel(hostile_report)
