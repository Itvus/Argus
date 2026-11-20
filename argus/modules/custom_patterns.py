"""User-defined regex pattern loader and custom lead extractor.

Allows analysts and intelligence teams to drop JSON pattern definitions into
`~/.argus/patterns/*.json` to extract domain-specific or corporate identifiers
without modifying Argus source code.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger("argus.custom_patterns")

DEFAULT_PATTERNS_DIR = Path.home() / ".argus" / "patterns"


def load_custom_patterns(patterns_dir: Optional[Path] = None) -> list[dict[str, str]]:
    """Load and validate all JSON pattern definitions from patterns directory."""
    target_dir = patterns_dir or DEFAULT_PATTERNS_DIR
    if not target_dir.exists():
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            return []

    rules: list[dict[str, str]] = []
    for json_file in target_dir.glob("*.json"):
        try:
            content = json_file.read_text(encoding="utf-8")
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "pattern" in item:
                        rules.append({
                            "name": str(item.get("name", json_file.stem)),
                            "pattern": str(item["pattern"]),
                            "category": str(item.get("category", "Custom")),
                        })
        except Exception as exc:
            logger.debug(f"Failed to read custom pattern file {json_file}: {exc}")

    return rules


def extract_custom_leads(text: str, patterns_dir: Optional[Path] = None) -> list[dict[str, str]]:
    """Evaluate text against user-defined regex rules and return matched leads."""
    rules = load_custom_patterns(patterns_dir)
    if not rules or not text:
        return []

    matches: list[dict[str, str]] = []
    seen: set[str] = set()

    for rule in rules:
        try:
            pattern = re.compile(rule["pattern"])
            for m in pattern.finditer(text):
                val = m.group(0).strip()
                k = f"{rule['name']}:{val}"
                if k not in seen:
                    seen.add(k)
                    matches.append({
                        "name": rule["name"],
                        "category": rule["category"],
                        "value": val,
                    })
        except re.error as err:
            logger.debug(f"Invalid regex in pattern rule {rule.get('name')}: {err}")

    return matches
