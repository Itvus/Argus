"""Configuration management for argus.

Loads configuration from .env files in the current working directory,
~/.argus/.env, and standard environment variables.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv


def _discover_and_load_env() -> list[Path]:
    """Find and load .env files from standard locations."""
    loaded_paths: list[Path] = []
    
    # 1. ~/.argus/.env
    home_env = Path.home() / ".argus" / ".env"
    if home_env.is_file():
        load_dotenv(dotenv_path=home_env, override=False)
        loaded_paths.append(home_env)

    # 2. Local working directory .env (takes precedence if both exist)
    local_env = Path.cwd() / ".env"
    if local_env.is_file():
        load_dotenv(dotenv_path=local_env, override=True)
        if local_env not in loaded_paths:
            loaded_paths.append(local_env)

    return loaded_paths


@dataclass(frozen=True)
class Config:
    discord_bot_token: Optional[str]
    cordcat_api_key: Optional[str]
    hibp_api_key: Optional[str]
    leakcheck_api_key: Optional[str]
    github_token: Optional[str]
    timeout: int = 15
    proxy: Optional[str] = None

    @classmethod
    def load(cls, timeout: int = 15, proxy: Optional[str] = None) -> Config:
        _discover_and_load_env()
        resolved_proxy = (
            proxy
            or os.getenv("ARGUS_PROXY")
            or os.getenv("ALL_PROXY")
            or os.getenv("HTTPS_PROXY")
            or os.getenv("HTTP_PROXY")
            or None
        )
        return cls(
            discord_bot_token=os.getenv("DISCORD_BOT_TOKEN") or None,
            cordcat_api_key=os.getenv("CORDCAT_API_KEY") or None,
            hibp_api_key=os.getenv("HIBP_API_KEY") or None,
            leakcheck_api_key=os.getenv("LEAKCHECK_API_KEY") or None,
            github_token=os.getenv("GITHUB_TOKEN") or None,
            timeout=timeout,
            proxy=resolved_proxy,
        )

    def mask_key(self, key: Optional[str]) -> str:
        """Return masked key or '[Not Configured]'."""
        if not key or not key.strip():
            return "[dim]Not Configured[/dim]"
        clean = key.strip()
        if len(clean) <= 6:
            return "******"
        return f"{clean[:4]}...{clean[-4:]}"


def get_config(timeout: int = 15, proxy: Optional[str] = None) -> Config:
    return Config.load(timeout=timeout, proxy=proxy)
