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
            # Filter out git commit/tree/blob hashes labeled with commit or blob
            seg_start = max(0, match.start() - 30)
            seg_end = min(len(text), match.end() + 30)
            local_seg = text[seg_start:seg_end].lower()
            if re.search(r"\b(commit|tree|blob|sha1?)\b", local_seg):
                continue

            ctx_start = max(0, match.start() - 40)
            ctx_end = min(len(text), match.end() + 40)
            ctx_window = text[ctx_start:ctx_end].lower()

            has_mixed_case = any(c.isupper() for c in addr[2:]) and any(c.islower() for c in addr[2:])
            has_context = bool(re.search(r"\b(eth|ethereum|wallet|address|donate|tip|crypto|web3|ens|polygon|arbitrum|optimism)\b", ctx_window))

            if has_mixed_case or has_context or "0x" in match.group(0):
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
            # If Bech32 (bc1...), it's unambiguously Bitcoin
            is_bech32 = addr.lower().startswith("bc1")
            if not is_bech32:
                # Require crypto context for Base58 (1... or 3...)
                ctx_start = max(0, match.start() - 40)
                ctx_end = min(len(text), match.end() + 40)
                ctx_window = text[ctx_start:ctx_end].lower()
                if not re.search(r"\b(btc|bitcoin|wallet|donate|tip|crypto)\b", ctx_window):
                    continue

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
