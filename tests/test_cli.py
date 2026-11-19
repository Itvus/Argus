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
