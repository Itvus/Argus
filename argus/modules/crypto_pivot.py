"""Cryptocurrency address and blockchain ecosystem pivoting."""

from __future__ import annotations

import re
from typing import Optional
from argus.models import CryptoLead, CryptoLeadDetail, ModuleStatus

ETH_PATTERN = re.compile(r"\b(0x[a-fA-F0-9]{40})\b")
BTC_PATTERN = re.compile(r"\b(bc1[a-zA-HJ-NP-Z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
SOL_PATTERN = re.compile(r"(?:sol(?:ana)?[:\s]+|\b)([1-9A-HJ-NP-Za-km-z]{32,44})\b", re.IGNORECASE)
ENS_PATTERN = re.compile(r"\b([a-zA-Z0-9-]{3,}\.eth)\b", re.IGNORECASE)


def extract_crypto_wallets(text_sources: list[str]) -> tuple[list[CryptoLeadDetail], list[CryptoLead]]:
    """Scan collected text strings for cryptocurrency wallet addresses and ENS domains."""
    details: list[CryptoLeadDetail] = []
    leads: list[CryptoLead] = []
    seen: set[str] = set()

    for text in text_sources:
        if not text:
            continue

        # Ethereum / EVM
        for match in ETH_PATTERN.finditer(text):
            addr = match.group(1)
            if addr.lower() not in seen:
                seen.add(addr.lower())
                details.append(
                    CryptoLeadDetail(
                        network="Ethereum",
                        address=addr,
                        explorer_url=f"https://etherscan.io/address/{addr}",
                    )
                )
                leads.append(CryptoLead(network="Ethereum", address=addr))

        # Bitcoin
        for match in BTC_PATTERN.finditer(text):
            addr = match.group(1)
            if addr not in seen:
                seen.add(addr)
                details.append(
                    CryptoLeadDetail(
                        network="Bitcoin",
                        address=addr,
                        explorer_url=f"https://mempool.space/address/{addr}",
                    )
                )
                leads.append(CryptoLead(network="Bitcoin", address=addr))

        # ENS Domains
        for match in ENS_PATTERN.finditer(text):
            domain = match.group(1).lower()
            if domain not in seen:
                seen.add(domain)
                details.append(
                    CryptoLeadDetail(
                        network="ENS",
                        address=domain,
                        explorer_url=f"https://app.ens.domains/{domain}",
                    )
                )
                leads.append(CryptoLead(network="ENS", address=domain))

        # Solana
        for match in SOL_PATTERN.finditer(text):
            addr = match.group(1)
            # Filter out false positives from pure alphanumeric words or btc addresses
            if len(addr) >= 32 and addr not in seen and not addr.startswith("0x") and not addr.startswith("bc1"):
                seen.add(addr)
                details.append(
                    CryptoLeadDetail(
                        network="Solana",
                        address=addr,
                        explorer_url=f"https://solscan.io/account/{addr}",
                    )
                )
                leads.append(CryptoLead(network="Solana", address=addr))

    return details, leads
