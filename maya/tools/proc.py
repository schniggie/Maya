"""Shared subprocess boundary for CLI tool wrappers.

Tool functions call ``run_cli`` instead of ``subprocess.run`` so timeout and
missing-binary failures become result dicts, and tests can mock one runner.
"""

from __future__ import annotations

import subprocess
from collections.abc import Mapping, Sequence
from typing import Any


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _binary_name(command: Sequence[str] | str) -> str:
    if isinstance(command, str):
        return command.split()[0] if command.split() else command
    if not command:
        return "command"
    return str(command[0])


def run_cli(
    command: Sequence[str] | str,
    *,
    timeout: int,
    shell: bool = False,
    env: Mapping[str, str] | None = None,
    cwd: str | None = None,
) -> dict[str, Any]:
    """Run a command and always return a dict.

    Non-zero exits are returned as ``exit_code`` plus captured streams.
    ``TimeoutExpired`` and ``FileNotFoundError`` set ``error`` and leave
    ``exit_code`` as ``None``.
    """
    argv: Sequence[str] | str = command if shell else list(command)
    try:
        proc = subprocess.run(  # noqa: S602
            argv,
            text=True,
            capture_output=True,
            timeout=timeout,
            shell=shell,
            env=None if env is None else dict(env),
            cwd=cwd,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "error": f"timeout after {timeout}s",
            "stdout": _as_text(exc.stdout),
            "stderr": _as_text(exc.stderr),
            "exit_code": None,
            "timed_out": True,
        }
    except FileNotFoundError as exc:
        return {
            "error": f"missing binary: {_binary_name(command)}",
            "stdout": "",
            "stderr": str(exc),
            "exit_code": None,
            "missing_binary": True,
        }

    return {
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
        "exit_code": proc.returncode,
    }
