"""Unit tests for offline Discord Snowflake bit-shift decoding."""

import pytest
from datetime import datetime, timezone

from argus.modules.snowflake import (
    DISCORD_EPOCH,
    clean_snowflake,
    decode_snowflake,
    format_human_age,
    is_valid_snowflake,
)


def test_clean_snowflake():
    assert clean_snowflake("<@155149108183695360>") == "155149108183695360"
    assert clean_snowflake("<@!155149108183695360>") == "155149108183695360"
    assert clean_snowflake("https://discord.com/users/155149108183695360") == "155149108183695360"
    assert clean_snowflake("https://canary.discord.com/users/155149108183695360") == "155149108183695360"
    assert clean_snowflake("  '155149108183695360'  ") == "155149108183695360"


def test_is_valid_snowflake():
    # Valid 17-19 digit Discord IDs and mentions
    assert is_valid_snowflake("155149108183695360") is True
    assert is_valid_snowflake(155149108183695360) is True
    assert is_valid_snowflake("<@155149108183695360>") is True
    assert is_valid_snowflake("https://discord.com/users/155149108183695360") is True
    assert is_valid_snowflake("136445063681700379") is True
    assert is_valid_snowflake("100000000000000000") is True

    # Invalid: usernames, too short, too long, special characters
    assert is_valid_snowflake("torvalds") is False
    assert is_valid_snowflake("12345") is False
    assert is_valid_snowflake("1234567890123456789012345") is False
    assert is_valid_snowflake("15514910818369536a") is False
    assert is_valid_snowflake("") is False


def test_decode_snowflake_known_id():
    # Discord user ID 155149108183695360
    # Timestamp: (155149108183695360 >> 22) + 1420070400000 = 1457060829922
    # 1457060829922 ms = 2016-03-04 03:07:09.922 UTC
    meta = decode_snowflake("155149108183695360")

    assert meta.snowflake_id == 155149108183695360
    assert meta.timestamp_ms == 1457060829922
    assert meta.created_at_utc.startswith("2016-03-04T03:07:09")
    assert meta.worker_id == 1
    assert meta.process_id == 0
    assert meta.increment == 0
    assert "year" in meta.age_human

    # Decode mention syntax
    meta_mention = decode_snowflake("<@155149108183695360>")
    assert meta_mention.snowflake_id == 155149108183695360


def test_decode_snowflake_invalid_raises():
    with pytest.raises(ValueError):
        decode_snowflake("invalid_user_id")

    with pytest.raises(ValueError):
        decode_snowflake("1234")


def test_format_human_age():
    assert format_human_age(-5) == "Just now"
    assert "day" in format_human_age(86400 * 2)
    assert "year" in format_human_age(86400 * 400)
