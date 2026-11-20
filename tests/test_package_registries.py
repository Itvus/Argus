"""Unit tests for package registry footprint reconnaissance."""

import unittest.mock
import pytest

from argus.modules.package_registries import fetch_package_registries


@pytest.mark.asyncio
async def test_fetch_package_registries():
    """Verify package registry queries across npm, PyPI, and crates.io."""
    mock_npm_data = {
        "objects": [
            {
                "package": {
                    "name": "target-tool",
                    "version": "1.0.4",
                    "description": "A developer tool",
                    "author": {"email": "dev@target.com"},
                    "links": {"npm": "https://www.npmjs.com/package/target-tool"},
                }
            }
        ]
    }
    mock_pypi_data = {
        "info": {
            "name": "target-cli",
            "version": "0.2.1",
            "summary": "PyPI CLI tool",
            "author_email": "dev@target.com",
            "package_url": "https://pypi.org/project/target-cli/",
        }
    }
    mock_crates_data = {
        "crates": [
            {
                "name": "target-rs",
                "max_version": "0.1.0",
                "description": "Rust utility",
            }
        ]
    }

    def mock_get(url, *args, **kwargs):
        resp = unittest.mock.MagicMock()
        if "registry.npmjs.org" in url:
            resp.status_code = 200
            resp.json.return_value = mock_npm_data
        elif "pypi.org" in url:
            resp.status_code = 200
            resp.json.return_value = mock_pypi_data
        elif "crates.io" in url:
            resp.status_code = 200
            resp.json.return_value = mock_crates_data
        else:
            resp.status_code = 404
        return resp

    mock_client = unittest.mock.AsyncMock()
    mock_client.get.side_effect = mock_get
    mock_client.__aenter__.return_value = mock_client

    with unittest.mock.patch("httpx.AsyncClient", return_value=mock_client):
        packages, status = await fetch_package_registries("target", timeout=5)
        assert status.status == "success"
        assert len(packages) == 3
        reg_names = {p.registry for p in packages}
        assert reg_names == {"npm", "PyPI", "crates.io"}
        npm_pkg = next(p for p in packages if p.registry == "npm")
        assert npm_pkg.name == "target-tool"
        assert npm_pkg.author_email == "dev@target.com"
