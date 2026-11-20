"""Unit tests for user-defined custom pattern extraction."""

import json
from pathlib import Path
import pytest
from argus.modules.custom_patterns import extract_custom_leads, load_custom_patterns


def test_load_and_extract_custom_patterns(tmp_path: Path):
    rule_file = tmp_path / "corp_rules.json"
    rules = [
        {
            "name": "Employee Badge",
            "pattern": r"EMP-[0-9]{5}",
            "category": "Identifier",
        },
        {
            "name": "Internal Server",
            "pattern": r"srv-[a-z0-9]+\.corp\.net",
            "category": "Infrastructure",
        },
    ]
    rule_file.write_text(json.dumps(rules), encoding="utf-8")

    loaded = load_custom_patterns(tmp_path)
    assert len(loaded) == 2
    assert loaded[0]["name"] == "Employee Badge"

    text = """
    Alice Smith | EMP-48291
    Deployed on srv-db01.corp.net
    Other noise: EMP-123 (too short)
    """
    matches = extract_custom_leads(text, patterns_dir=tmp_path)
    assert len(matches) == 2

    badge_match = next(m for m in matches if m["name"] == "Employee Badge")
    assert badge_match["value"] == "EMP-48291"
    assert badge_match["category"] == "Identifier"

    srv_match = next(m for m in matches if m["name"] == "Internal Server")
    assert srv_match["value"] == "srv-db01.corp.net"
