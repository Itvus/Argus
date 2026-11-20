"""Keybase identity and OpenPGP key server (keys.openpgp.org) intelligence."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional
import httpx

from argus.models import KeybaseProfile, KeybaseProof, ModuleStatus, PGPKeyRecord


async def lookup_openpgp_keys(
    emails: list[str],
    timeout: int = 10,
    proxy: Optional[str] = None,
    progress_callback: Optional[Callable[[str, int, int, str], None]] = None,
) -> tuple[list[PGPKeyRecord], ModuleStatus]:
    """Query keys.openpgp.org for published OpenPGP keys associated with discovered emails."""
    if not emails:
        return [], ModuleStatus(
            module_name="OpenPGP Keys",
            status="skipped",
            message="No email addresses to query against OpenPGP keyservers",
        )

    if progress_callback:
        progress_callback("OpenPGP Keys", 0, len(emails), "Querying keys.openpgp.org...")

    records: list[PGPKeyRecord] = []
    client_kwargs = {
        "timeout": timeout,
        "follow_redirects": True,
        "headers": {"User-Agent": "Argus-OSINT/1.0"},
    }
    if proxy:
        client_kwargs["proxy"] = proxy

    async with httpx.AsyncClient(**client_kwargs) as client:
        async def fetch_single_email(idx: int, email: str) -> None:
            if progress_callback:
                progress_callback("OpenPGP Keys", idx, len(emails), f"Auditing {email}")
            try:
                url = f"https://keys.openpgp.org/vks/v1/by-email/{email}"
                resp = await client.get(url)
                if resp.status_code == 200 and "-----BEGIN PGP PUBLIC KEY BLOCK-----" in resp.text:
                    records.append(
                        PGPKeyRecord(
                            source="keys.openpgp.org",
                            key_id_or_fingerprint=f"Key for <{email}>",
                            identities=[email],
                            created_at=None,
                            public_key_url=url,
                        )
                    )
            except Exception:
                pass

        tasks = [fetch_single_email(idx, em) for idx, em in enumerate(emails, start=1)]
        await asyncio.gather(*tasks, return_exceptions=True)

    status = "success" if records else "no_hits"
    msg = f"Found {len(records)} OpenPGP public key(s)" if records else "No keys found on keys.openpgp.org"
    return records, ModuleStatus(module_name="OpenPGP Keys", status=status, message=msg)


async def lookup_keybase(
    username: str,
    timeout: int = 10,
    proxy: Optional[str] = None,
    progress_callback: Optional[Callable[[str, int, int, str], None]] = None,
) -> tuple[Optional[KeybaseProfile], ModuleStatus]:
    """Query Keybase public API for cryptographically verified identity proofs and wallet addresses."""
    clean_name = username.strip()
    if progress_callback:
        progress_callback("Keybase Identity", 0, 1, f"Checking Keybase profile for {clean_name}...")

    client_kwargs = {
        "timeout": timeout,
        "follow_redirects": True,
        "headers": {"User-Agent": "Argus-OSINT/1.0"},
    }
    if proxy:
        client_kwargs["proxy"] = proxy

    async with httpx.AsyncClient(**client_kwargs) as client:
        try:
            url = f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={clean_name}"
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                them = data.get("them", [])
                if them and them[0] is not None:
                    user_data = them[0]
                    profile_info = user_data.get("profile") or {}
                    full_name = profile_info.get("full_name")
                    bio = profile_info.get("bio")

                    # Extract proofs
                    proofs: list[KeybaseProof] = []
                    proofs_summary = user_data.get("proofs_summary", {})
                    for p in proofs_summary.get("all", []):
                        proofs.append(
                            KeybaseProof(
                                service=p.get("proof_type", "unknown"),
                                username=p.get("nametag", ""),
                                proof_url=p.get("service_url"),
                            )
                        )

                    # Extract crypto addresses
                    crypto_addrs: list[dict[str, str]] = []
                    c_addrs = user_data.get("cryptocurrency_addresses", {})
                    for net, addrs in c_addrs.items():
                        for a in addrs:
                            addr_val = a.get("address")
                            if addr_val:
                                crypto_addrs.append({"network": net, "address": addr_val})

                    profile = KeybaseProfile(
                        username=clean_name,
                        full_name=full_name,
                        bio=bio,
                        proofs=proofs,
                        crypto_addresses=crypto_addrs,
                    )
                    return profile, ModuleStatus(
                        module_name="Keybase Identity",
                        status="success",
                        message=f"Verified {len(proofs)} external identity proofs on Keybase",
                    )
        except Exception:
            pass

    return None, ModuleStatus(
        module_name="Keybase Identity",
        status="no_hits",
        message=f"No Keybase identity registered for @{clean_name}",
    )
