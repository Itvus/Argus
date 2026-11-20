"""Unit tests for domain reconnaissance and certificate transparency."""

import unittest.mock
import pytest

from argus.modules.domain_recon import extract_custom_domains, recon_domain


def test_extract_custom_domains():
    """Verify free webmail filtering isolates personal custom domains."""
    emails = [
        "user@gmail.com",
        "dev@proton.me",
        "target@customcorp.xyz",
        "ADMIN@MYPERSONALDOMAIN.DEV",
        "invalid-email",
        "another@yahoo.com",
    ]
    domains = extract_custom_domains(emails)
    assert domains == ["customcorp.xyz", "mypersonaldomain.dev"]


@pytest.mark.asyncio
async def test_recon_domain_success():
    """Verify RDAP and crt.sh responses are parsed into DomainReconRecord."""
    mock_rdap_data = {
        "nameservers": [{"ldhName": "ns1.customcorp.xyz"}],
        "events": [{"eventAction": "registration", "eventDate": "2021-04-12T00:00:00Z"}],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "NameCheap, Inc."]]],
            }
        ],
    }
    mock_crt_data = [
        {"common_name": "api.customcorp.xyz", "name_value": "customcorp.xyz\n*.customcorp.xyz"},
        {"common_name": "mail.customcorp.xyz", "name_value": "mail.customcorp.xyz"},
    ]

    def mock_get(url, *args, **kwargs):
        resp = unittest.mock.MagicMock()
        if "rdap.org" in url:
            resp.status_code = 200
            resp.json.return_value = mock_rdap_data
        elif "crt.sh" in url:
            resp.status_code = 200
            resp.json.return_value = mock_crt_data
        else:
            resp.status_code = 404
        return resp

    mock_client = unittest.mock.AsyncMock()
    mock_client.get.side_effect = mock_get
    mock_client.__aenter__.return_value = mock_client

    with unittest.mock.patch("httpx.AsyncClient", return_value=mock_client):
        record, status = await recon_domain("customcorp.xyz", timeout=5)
        assert record is not None
        assert status.status == "success"
        assert record.domain == "customcorp.xyz"
        assert record.registrar == "NameCheap, Inc."
        assert record.created_date == "2021-04-12T00:00:00Z"
        assert "ns1.customcorp.xyz" in record.nameservers
        assert "api.customcorp.xyz" in record.subdomains
        assert "mail.customcorp.xyz" in record.subdomains
