"""Domain reconnaissance and infrastructure intelligence via RDAP and Certificate Transparency (crt.sh)."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional
import httpx

from argus.models import DomainReconRecord, ModuleStatus

FREE_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com",
    "hotmail.com", "outlook.com", "live.com", "msn.com",
    "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com",
    "pm.me", "mail.ru", "yandex.ru", "yandex.com", "zoho.com",
    "aol.com", "gmx.com", "gmx.net", "tutanota.com", "tutamail.com",
    "duck.com", "fastmail.com", "hushmail.com", "inbox.com",
}


def extract_custom_domains(emails: list[str]) -> list[str]:
    """Filter out common free webmail providers to isolate target's personal domains."""
    custom: list[str] = []
    for em in emails:
        clean = em.strip().lower()
        if "@" in clean:
            domain = clean.split("@")[-1].strip()
            if domain and domain not in FREE_MAIL_DOMAINS and "." in domain:
                if domain not in custom:
                    custom.append(domain)
    return custom


async def recon_domain(
    domain: str,
    timeout: int = 10,
    proxy: Optional[str] = None,
    progress_callback: Optional[Callable[[str, int, int, str], None]] = None,
) -> tuple[Optional[DomainReconRecord], ModuleStatus]:
    """Perform RDAP WHOIS lookup and crt.sh certificate transparency enumeration."""
    clean_domain = domain.strip().lower()
    if progress_callback:
        progress_callback("Domain Recon", 0, 1, f"Querying RDAP and crt.sh for {clean_domain}...")

    registrar: Optional[str] = None
    created_date: Optional[str] = None
    nameservers: list[str] = []
    subdomains: list[str] = []

    client_kwargs = {"timeout": timeout, "follow_redirects": True}
    if proxy:
        client_kwargs["proxy"] = proxy

    async with httpx.AsyncClient(**client_kwargs) as client:
        # 1. Query RDAP
        try:
            rdap_resp = await client.get(
                f"https://rdap.org/domain/{clean_domain}",
                headers={"Accept": "application/json", "User-Agent": "Argus-OSINT/1.0"},
            )
            if rdap_resp.status_code == 200:
                data = rdap_resp.json()
                # Extract nameservers
                ns_list = data.get("nameservers", [])
                for ns in ns_list:
                    ldh = ns.get("ldhName")
                    if ldh and ldh.lower() not in nameservers:
                        nameservers.append(ldh.lower())
                # Extract events (registration date)
                events = data.get("events", [])
                for ev in events:
                    if ev.get("eventAction") == "registration":
                        created_date = ev.get("eventDate")
                        break
                # Extract entities / registrar
                entities = data.get("entities", [])
                for ent in entities:
                    roles = ent.get("roles", [])
                    if "registrar" in roles:
                        vcard = ent.get("vcardArray", [])
                        if len(vcard) > 1 and isinstance(vcard[1], list):
                            for prop in vcard[1]:
                                if len(prop) > 3 and prop[0] == "fn":
                                    registrar = str(prop[3])
                                    break
        except Exception:
            pass

        # 2. Query Certificate Transparency (crt.sh)
        try:
            crt_resp = await client.get(
                f"https://crt.sh/?q=%.{clean_domain}&output=json",
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            )
            if crt_resp.status_code == 200:
                crt_entries = crt_resp.json()
                if isinstance(crt_entries, list):
                    for entry in crt_entries:
                        name_val = entry.get("name_value", "")
                        common_name = entry.get("common_name", "")
                        for candidate in f"{name_val}\n{common_name}".split("\n"):
                            cand = candidate.strip().lower()
                            if cand.startswith("*."):
                                cand = cand[2:]
                            if cand.endswith(f".{clean_domain}") or cand == clean_domain:
                                if cand not in subdomains and len(subdomains) < 30:
                                    subdomains.append(cand)
        except Exception:
            pass

    if not registrar and not created_date and not nameservers and not subdomains:
        return None, ModuleStatus(
            module_name=f"Domain Recon ({clean_domain})",
            status="no_hits",
            message=f"No RDAP records or certificate logs found for {clean_domain}",
        )

    record = DomainReconRecord(
        domain=clean_domain,
        registrar=registrar,
        created_date=created_date,
        nameservers=nameservers,
        subdomains=sorted(subdomains),
    )
    return record, ModuleStatus(
        module_name=f"Domain Recon ({clean_domain})",
        status="success",
        message=f"Resolved infrastructure ({len(subdomains)} subdomains, {len(nameservers)} nameservers)",
    )
