"""Discord Snowflake ID offline bit-shifting decoder.

Discord Snowflakes are 64-bit integers formatted as:
- Timestamp: (id >> 22) + 1420070400000 (milliseconds since Discord Epoch: Jan 1, 2015)
- Internal Worker ID: (id & 0x3E0000) >> 17 (5 bits)
- Internal Process ID: (id & 0x1F000) >> 12 (5 bits)
- Increment: id & 0xFFF (12 bits)
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Union

from argus.models import SnowflakeMetadata

DISCORD_EPOCH = 1420070400000  # 2015-01-01 00:00:00.000 UTC
SNOWFLAKE_REGEX = re.compile(r"^\d{17,20}$")


def is_valid_snowflake(target: Union[str, int]) -> bool:
    """Validate whether target matches a Discord Snowflake ID pattern."""
    target_str = str(target).strip()
    if not SNOWFLAKE_REGEX.match(target_str):
        return False
    try:
        val = int(target_str)
        # Ensure timestamp is at least Discord Epoch and not decades in future
        timestamp_ms = (val >> 22) + DISCORD_EPOCH
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        return DISCORD_EPOCH <= timestamp_ms <= (now_ms + 86400000 * 365)
    except (ValueError, OverflowError):
        return False


def format_human_age(delta_seconds: float) -> str:
    """Format total seconds into a clean human-readable age string."""
    if delta_seconds < 0:
        return "Just now"

    total_days = int(delta_seconds // 86400)
    years = total_days // 365
    days = total_days % 365
    hours = int((delta_seconds % 86400) // 3600)

    parts: list[str] = []
    if years > 0:
        parts.append(f"{years} year{'s' if years != 1 else ''}")
    if days > 0 or years > 0:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if years == 0:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")

    return ", ".join(parts) if parts else "0 hours"


def decode_snowflake(snowflake: Union[str, int]) -> SnowflakeMetadata:
    """Decode a Discord Snowflake ID into timestamp, worker ID, process ID, and increment."""
    target_str = str(snowflake).strip()
    if not SNOWFLAKE_REGEX.match(target_str):
        raise ValueError(
            f"Invalid Discord Snowflake ID '{snowflake}'. Must be a 17-20 digit integer."
        )

    val = int(target_str)
    timestamp_ms = (val >> 22) + DISCORD_EPOCH
    worker_id = (val & 0x3E0000) >> 17
    process_id = (val & 0x1F000) >> 12
    increment = val & 0xFFF

    created_dt = datetime.fromtimestamp(timestamp_ms / 1000.0, tz=timezone.utc)
    now_dt = datetime.now(timezone.utc)
    delta_seconds = (now_dt - created_dt).total_seconds()

    return SnowflakeMetadata(
        snowflake_id=val,
        timestamp_ms=timestamp_ms,
        created_at_utc=created_dt.isoformat(),
        age_human=format_human_age(delta_seconds),
        worker_id=worker_id,
        process_id=process_id,
        increment=increment,
    )
