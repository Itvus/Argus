"""Package registry footprint reconnaissance across PyPI, npm, and crates.io."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional
import httpx

from argus.models import ModuleStatus, PackageRecord


async def fetch_package_registries(
    username: str,
    timeout: int = 10,
    proxy: Optional[str] = None,
    progress_callback: Optional[Callable[[str, int, int, str], None]] = None,
) -> tuple[list[PackageRecord], ModuleStatus]:
    """Search for published packages authored or maintained by username across PyPI, npm, and crates.io."""
    clean_name = username.strip()
    if progress_callback:
        progress_callback("Package Registries", 0, 1, f"Auditing package registries for {clean_name}...")

    packages: list[PackageRecord] = []
    client_kwargs = {
        "timeout": timeout,
        "follow_redirects": True,
        "headers": {
            "User-Agent": f"Argus-OSINT/1.0 ({clean_name})",
            "Accept": "application/json",
        },
    }
    if proxy:
        client_kwargs["proxy"] = proxy

    async with httpx.AsyncClient(**client_kwargs) as client:
        # 1. npm author search
        try:
            npm_url = f"https://registry.npmjs.org/-/v1/search?text=author:{clean_name}&size=10"
            npm_resp = await client.get(npm_url)
            if npm_resp.status_code == 200:
                data = npm_resp.json()
                for obj in data.get("objects", []):
                    pkg = obj.get("package", {})
                    pkg_name = pkg.get("name")
                    if pkg_name:
                        publisher = pkg.get("publisher", {})
                        author = pkg.get("author", {})
                        author_email = author.get("email") or publisher.get("email")
                        packages.append(
                            PackageRecord(
                                registry="npm",
                                name=pkg_name,
                                url=pkg.get("links", {}).get("npm", f"https://www.npmjs.com/package/{pkg_name}"),
                                version=pkg.get("version"),
                                description=pkg.get("description"),
                                author_email=author_email,
                            )
                        )
        except Exception:
            pass

        # 2. PyPI lookup (check if package with this name exists)
        try:
            pypi_url = f"https://pypi.org/pypi/{clean_name}/json"
            pypi_resp = await client.get(pypi_url)
            if pypi_resp.status_code == 200:
                pdata = pypi_resp.json()
                info = pdata.get("info", {})
                pkg_name = info.get("name", clean_name)
                author_email = info.get("author_email")
                packages.append(
                    PackageRecord(
                        registry="PyPI",
                        name=pkg_name,
                        url=info.get("package_url") or f"https://pypi.org/project/{pkg_name}/",
                        version=info.get("version"),
                        description=info.get("summary"),
                        author_email=author_email,
                    )
                )
        except Exception:
            pass

        # 3. Crates.io lookup
        try:
            crates_url = f"https://crates.io/api/v1/crates?q={clean_name}&per_page=5"
            crates_resp = await client.get(crates_url)
            if crates_resp.status_code == 200:
                cdata = crates_resp.json()
                for c in cdata.get("crates", []):
                    c_name = c.get("name")
                    # If crate name matches or closely related
                    if c_name and clean_name.lower() in c_name.lower():
                        packages.append(
                            PackageRecord(
                                registry="crates.io",
                                name=c_name,
                                url=f"https://crates.io/crates/{c_name}",
                                version=c.get("max_version") or c.get("newest_version"),
                                description=c.get("description"),
                                author_email=None,
                            )
                        )
        except Exception:
            pass

    status = "success" if packages else "no_hits"
    msg = f"Discovered {len(packages)} packages authored across registries" if packages else "No packages authored by target"
    return packages, ModuleStatus(module_name="Package Registries", status=status, message=msg)
