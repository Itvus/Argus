"""Unit tests for argus CLI flags, version, help, and man page."""

import re
import pytest
from typer.testing import CliRunner

from argus import __version__
from argus.cli import app

runner = CliRunner(env={"NO_COLOR": "1", "TERM": "dumb"})
ANSI_REGEX = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def clean_output(text: str) -> str:
    """Strip ANSI color escape codes from CLI test output."""
    return ANSI_REGEX.sub("", text)


def test_cli_version_flag_short():
    result = runner.invoke(app, ["-v"])
    assert result.exit_code == 0
    out = clean_output(result.stdout)
    assert __version__ in out
    assert "argus version" in out


def test_cli_version_flag_long():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    out = clean_output(result.stdout)
    assert __version__ in out


def test_cli_help_flag_short():
    result = runner.invoke(app, ["-h"])
    assert result.exit_code == 0
    out = clean_output(result.stdout)
    assert "Usage: argus" in out
    assert "scan" in out
    assert "snowflake" in out
    assert "config" in out
    assert "man" in out


def test_cli_subcommand_help_short():
    result = runner.invoke(app, ["scan", "-h"])
    assert result.exit_code == 0
    out = clean_output(result.stdout)
    assert "--pivot" in out
    assert "--all-sites" in out


def test_cli_man_command_interactive():
    result = runner.invoke(app, ["man"])
    assert result.exit_code == 0
    out = clean_output(result.stdout)
    assert "NAME" in out
    assert "SYNOPSIS" in out
    assert "DESCRIPTION" in out
    assert "COMMANDS" in out
    assert "OPTIONS & FLAGS" in out
    assert "ENVIRONMENT VARIABLES" in out


def test_cli_man_command_roff():
    result = runner.invoke(app, ["man", "--roff"])
    assert result.exit_code == 0
    out = clean_output(result.stdout)
    assert ".TH ARGUS 1" in out
    assert ".SH NAME" in out


def test_cli_proxy_flags_in_help():
    scan_help = clean_output(runner.invoke(app, ["scan", "-h"]).stdout)
    assert "--proxy" in scan_help
    assert "-x" in scan_help
    assert "--email-sites" in scan_help
    assert "-E" in scan_help

    sf_help = clean_output(runner.invoke(app, ["snowflake", "-h"]).stdout)
    assert "--proxy" in sf_help
    assert "-x" in sf_help


def test_cli_tui_help():
    tui_help = clean_output(runner.invoke(app, ["tui", "-h"]).stdout)
    assert "interactive" in tui_help.lower() or "explore" in tui_help.lower()

    explore_help = clean_output(runner.invoke(app, ["explore", "-h"]).stdout)
    assert "interactive" in explore_help.lower() or "explore" in explore_help.lower()


def test_cli_tui_prompt_abort():
    result = runner.invoke(app, ["tui"], input="\n")
    assert result.exit_code == 0
    assert "Enter target" in result.stdout or "Aborted" in result.stdout


def test_config_proxy_precedence(monkeypatch):
    from argus.config import Config

    # Explicit argument takes top priority
    monkeypatch.setenv("ARGUS_PROXY", "socks5://127.0.0.1:9050")
    cfg = Config.load(proxy="http://10.0.0.1:8080")
    assert cfg.proxy == "http://10.0.0.1:8080"

    # ARGUS_PROXY takes precedence over standard env vars
    monkeypatch.setenv("HTTP_PROXY", "http://corporate-proxy:3128")
    cfg2 = Config.load(proxy=None)
    assert cfg2.proxy == "socks5://127.0.0.1:9050"

    # Falls back to standard env vars when ARGUS_PROXY absent
    monkeypatch.delenv("ARGUS_PROXY", raising=False)
    cfg3 = Config.load(proxy=None)
    assert cfg3.proxy == "http://corporate-proxy:3128"
