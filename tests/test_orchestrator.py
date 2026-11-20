"""Unit tests for InvestigationOrchestrator dispatch, chaining, and error resilience."""

import unittest.mock
import pytest

from argus.config import Config
from argus.models import (
    InvestigationReport,
    KeybaseProfile,
    KeybaseProof,
    ModuleStatus,
    PackageRecord,
    SocialProfile,
)
from argus.orchestrator import InvestigationOrchestrator


@pytest.fixture
def mock_config() -> Config:
    return Config(
        discord_bot_token=None,
        cordcat_api_key=None,
        hibp_api_key=None,
        leakcheck_api_key=None,
        github_token=None,
        intelx_api_key=None,
        timeout=5,
    )


@pytest.mark.asyncio
async def test_orchestrator_keybase_proofs_chaining(mock_config: Config):
    """Verify Keybase verified proofs are added as SocialProfiles without NameError."""
    orchestrator = InvestigationOrchestrator(mock_config)

    kb_profile = KeybaseProfile(
        username="secops",
        proofs=[
            KeybaseProof(service="github", username="secops", proof_url="https://github.com/secops"),
            KeybaseProof(service="twitter", username="secops", proof_url="https://twitter.com/secops"),
        ],
        crypto_addresses=[{"network": "bitcoin", "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}],
    )

    with unittest.mock.patch(
        "argus.orchestrator.run_username_pivot",
        new_callable=unittest.mock.AsyncMock,
        return_value=([], None, "No profiles"),
    ), unittest.mock.patch(
        "argus.orchestrator.fetch_github_pivot",
        new_callable=unittest.mock.AsyncMock,
        return_value=(None, ModuleStatus(module_name="GitHub", status="skipped")),
    ), unittest.mock.patch(
        "argus.orchestrator.fetch_gaming_profiles",
        new_callable=unittest.mock.AsyncMock,
        return_value=(None, ModuleStatus(module_name="Gaming", status="skipped")),
    ), unittest.mock.patch(
        "argus.orchestrator.fetch_hudson_rock_intel",
        new_callable=unittest.mock.AsyncMock,
        return_value=(None, ModuleStatus(module_name="Hudson Rock", status="skipped")),
    ), unittest.mock.patch(
        "argus.orchestrator.lookup_keybase",
        new_callable=unittest.mock.AsyncMock,
        return_value=(kb_profile, ModuleStatus(module_name="Keybase", status="success")),
    ), unittest.mock.patch(
        "argus.orchestrator.fetch_package_registries",
        new_callable=unittest.mock.AsyncMock,
        return_value=([], ModuleStatus(module_name="Packages", status="skipped")),
    ), unittest.mock.patch(
        "argus.orchestrator.fetch_wayback_snapshots",
        new_callable=unittest.mock.AsyncMock,
        return_value=([], ModuleStatus(module_name="Wayback", status="skipped")),
    ), unittest.mock.patch(
        "argus.orchestrator.fetch_and_hash_avatars",
        new_callable=unittest.mock.AsyncMock,
        return_value=([], []),
    ):
        report = await orchestrator.run_investigation("secops")

    assert report is not None
    assert report.target == "secops"
    assert report.target_type == "username"
    # Keybase proofs chained to social profiles
    proof_urls = [p.url for p in report.social_profiles]
    assert "https://github.com/secops" in proof_urls
    assert "https://twitter.com/secops" in proof_urls
    # Crypto address chained
    assert any(c.address == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" for c in report.pivot_leads.discovered_crypto)


@pytest.mark.asyncio
async def test_orchestrator_package_email_chaining(mock_config: Config):
    """Verify package author emails are chained into discovered_emails."""
    orchestrator = InvestigationOrchestrator(mock_config)

    packages = [
        PackageRecord(
            registry="PyPI",
            name="sec-toolkit",
            url="https://pypi.org/project/sec-toolkit",
            version="1.0.0",
            author_email="author@domain.org",
        )
    ]

    with unittest.mock.patch(
        "argus.orchestrator.run_username_pivot",
        new_callable=unittest.mock.AsyncMock,
        return_value=([], None, "No profiles"),
    ), unittest.mock.patch(
        "argus.orchestrator.fetch_github_pivot",
        new_callable=unittest.mock.AsyncMock,
        return_value=(None, ModuleStatus(module_name="GitHub", status="skipped")),
    ), unittest.mock.patch(
        "argus.orchestrator.fetch_gaming_profiles",
        new_callable=unittest.mock.AsyncMock,
        return_value=(None, ModuleStatus(module_name="Gaming", status="skipped")),
    ), unittest.mock.patch(
        "argus.orchestrator.fetch_hudson_rock_intel",
        new_callable=unittest.mock.AsyncMock,
        return_value=(None, ModuleStatus(module_name="Hudson Rock", status="skipped")),
    ), unittest.mock.patch(
        "argus.orchestrator.lookup_keybase",
        new_callable=unittest.mock.AsyncMock,
        return_value=(None, ModuleStatus(module_name="Keybase", status="skipped")),
    ), unittest.mock.patch(
        "argus.orchestrator.fetch_package_registries",
        new_callable=unittest.mock.AsyncMock,
        return_value=(packages, ModuleStatus(module_name="Packages", status="success")),
    ), unittest.mock.patch(
        "argus.orchestrator.fetch_wayback_snapshots",
        new_callable=unittest.mock.AsyncMock,
        return_value=([], ModuleStatus(module_name="Wayback", status="skipped")),
    ), unittest.mock.patch(
        "argus.orchestrator.fetch_and_hash_avatars",
        new_callable=unittest.mock.AsyncMock,
        return_value=([], []),
    ), unittest.mock.patch(
        "argus.orchestrator.check_breaches",
        new_callable=unittest.mock.AsyncMock,
        return_value=([], ModuleStatus(module_name="Breaches", status="skipped")),
    ), unittest.mock.patch(
        "argus.orchestrator.lookup_openpgp_keys",
        new_callable=unittest.mock.AsyncMock,
        return_value=([], ModuleStatus(module_name="OpenPGP", status="skipped")),
    ):
        report = await orchestrator.run_investigation("dev_author")

    assert "author@domain.org" in report.pivot_leads.discovered_emails
