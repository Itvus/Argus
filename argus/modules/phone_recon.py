"""Phone number extraction and ITU-T E.164 country resolution module.

Extracts international telephone numbers from unstructured text (profile bios, posts)
with anti-false-positive filters against Discord Snowflakes, timestamps, and commit hashes.
"""

from __future__ import annotations

import re
from typing import Optional

from argus.models import PhoneLead

# Dialing prefixes ordered by length descending for greedy prefix matching
COUNTRY_DIALING_CODES: list[tuple[str, str]] = [
    ("1", "United States / Canada"),
    ("7", "Russia / Kazakhstan"),
    ("20", "Egypt"),
    ("27", "South Africa"),
    ("30", "Greece"),
    ("31", "Netherlands"),
    ("32", "Belgium"),
    ("33", "France"),
    ("34", "Spain"),
    ("36", "Hungary"),
    ("39", "Italy"),
    ("40", "Romania"),
    ("41", "Switzerland"),
    ("43", "Austria"),
    ("44", "United Kingdom"),
    ("45", "Denmark"),
    ("46", "Sweden"),
    ("47", "Norway"),
    ("48", "Poland"),
    ("49", "Germany"),
    ("51", "Peru"),
    ("52", "Mexico"),
    ("54", "Argentina"),
    ("55", "Brazil"),
    ("56", "Chile"),
    ("57", "Colombia"),
    ("60", "Malaysia"),
    ("61", "Australia"),
    ("62", "Indonesia"),
    ("63", "Philippines"),
    ("64", "New Zealand"),
    ("65", "Singapore"),
    ("66", "Thailand"),
    ("81", "Japan"),
    ("82", "South Korea"),
    ("84", "Vietnam"),
    ("86", "China"),
    ("90", "Turkey"),
    ("91", "India"),
    ("92", "Pakistan"),
    ("94", "Sri Lanka"),
    ("95", "Myanmar"),
    ("98", "Iran"),
    ("212", "Morocco"),
    ("213", "Algeria"),
    ("216", "Tunisia"),
    ("234", "Nigeria"),
    ("254", "Kenya"),
    ("351", "Portugal"),
    ("352", "Luxembourg"),
    ("353", "Ireland"),
    ("354", "Iceland"),
    ("358", "Finland"),
    ("370", "Lithuania"),
    ("371", "Latvia"),
    ("372", "Estonia"),
    ("380", "Ukraine"),
    ("381", "Serbia"),
    ("385", "Croatia"),
    ("420", "Czech Republic"),
    ("852", "Hong Kong"),
    ("886", "Taiwan"),
    ("961", "Lebanon"),
    ("962", "Jordan"),
    ("964", "Iraq"),
    ("965", "Kuwait"),
    ("966", "Saudi Arabia"),
    ("971", "United Arab Emirates"),
    ("972", "Israel"),
    ("974", "Qatar"),
]
# Sort descending by code length so longer codes match before shorter prefixes (e.g. 380 before 3)
COUNTRY_DIALING_CODES.sort(key=lambda x: len(x[0]), reverse=True)


def resolve_country(digits_without_plus: str) -> tuple[Optional[str], Optional[str]]:
    """Resolve country calling code and name from digit string."""
    for code, country in COUNTRY_DIALING_CODES:
        if digits_without_plus.startswith(code):
            return code, country
    return None, None


# International format pattern: require explicit + prefix or preceding phone context
INTL_PHONE_REGEX = re.compile(
    r"(?:(?<=\bphone[:\s])|(?<=\btel[:\s])|(?<=\bcall[:\s])|(?<=\bwhatsapp[:\s])|(?<=\bmobile[:\s])|(?<=\bcell[:\s])|\b)"
    r"(\+[1-9]\d{0,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{1,4}[\s.-]?\d{1,9})\b",
    re.IGNORECASE,
)

CONTEXT_PHONE_REGEX = re.compile(
    r"(?:phone|tel|call|whatsapp|mobile|cell)[\s:=]+(?:\+?([0-9\(\)\s.-]{7,20}))\b",
    re.IGNORECASE,
)


def extract_phone_leads(text: str) -> list[PhoneLead]:
    """Extract and validate phone numbers, returning normalized E.164 records."""
    leads: list[PhoneLead] = []
    seen_e164: set[str] = set()

    candidates: list[str] = []

    # 1. Numbers with explicit '+' international prefix
    for m in INTL_PHONE_REGEX.finditer(text):
        raw = m.group(1).strip()
        candidates.append(raw)

    # 2. Numbers following phone context keywords
    for m in CONTEXT_PHONE_REGEX.finditer(text):
        raw = m.group(1).strip()
        if not raw.startswith("+"):
            # If no +, check if length of digits looks like a phone number
            digits = re.sub(r"\D", "", raw)
            if 7 <= len(digits) <= 15:
                raw = f"+{digits}"
        candidates.append(raw)

    for raw in candidates:
        digits = re.sub(r"\D", "", raw)
        # E.164 specifies between 7 and 15 digits total
        if not (7 <= len(digits) <= 15):
            continue

        # Reject uniform repetition (e.g., +1111111111, +0000000000)
        if len(set(digits)) <= 2:
            continue

        e164 = f"+{digits}"
        if e164 in seen_e164:
            continue

        code, country = resolve_country(digits)
        seen_e164.add(e164)
        leads.append(
            PhoneLead(
                raw_number=raw,
                e164=e164,
                country_code=code,
                country_name=country,
            )
        )

    return leads
