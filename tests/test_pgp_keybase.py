"""Unit tests for Keybase and OpenPGP key server modules."""

import unittest.mock
import pytest

from argus.modules.pgp_keybase import lookup_keybase, lookup_openpgp_keys


@pytest.mark.asyncio
async def test_lookup_openpgp_keys():
    """Verify keys.openpgp.org public key lookup."""
    def mock_get(url, *args, **kwargs):
        resp = unittest.mock.MagicMock()
        if "keys.openpgp.org" in url:
            resp.status_code = 200
            resp.text = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQENBF2...-----END PGP PUBLIC KEY BLOCK-----"
        else:
            resp.status_code = 404
        return resp

    mock_client = unittest.mock.AsyncMock()
    mock_client.get.side_effect = mock_get
    mock_client.__aenter__.return_value = mock_client

    with unittest.mock.patch("httpx.AsyncClient", return_value=mock_client):
        keys, status = await lookup_openpgp_keys(["target@example.com"], timeout=5)
        assert status.status == "success"
        assert len(keys) == 1
        assert "target@example.com" in keys[0].identities


@pytest.mark.asyncio
async def test_lookup_keybase():
    """Verify Keybase profile and proofs summary extraction."""
    mock_kb_data = {
        "them": [
            {
                "profile": {"full_name": "Target Person", "bio": "Security researcher"},
                "proofs_summary": {
                    "all": [
                        {"proof_type": "twitter", "nametag": "target_tw", "service_url": "https://x.com/target_tw"},
                        {"proof_type": "github", "nametag": "target_gh", "service_url": "https://github.com/target_gh"},
                    ]
                },
                "cryptocurrency_addresses": {
                    "bitcoin": [{"address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}],
                    "zcash": [{"address": "t1abc123"}],
                },
            }
        ]
    }

    def mock_get(url, *args, **kwargs):
        resp = unittest.mock.MagicMock()
        resp.status_code = 200
        resp.json.return_value = mock_kb_data
        return resp

    mock_client = unittest.mock.AsyncMock()
    mock_client.get.side_effect = mock_get
    mock_client.__aenter__.return_value = mock_client

    with unittest.mock.patch("httpx.AsyncClient", return_value=mock_client):
        profile, status = await lookup_keybase("target", timeout=5)
        assert status.status == "success"
        assert profile is not None
        assert profile.username == "target"
        assert profile.full_name == "Target Person"
        assert len(profile.proofs) == 2
        assert profile.proofs[0].service == "twitter"
        assert len(profile.crypto_addresses) == 2
