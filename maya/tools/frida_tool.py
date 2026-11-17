from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .frida_scripts import load_script
from .proc import run_cli
from .registry import register_tool


def _run(command: list[str], timeout: int = 90) -> dict:
    return run_cli(command, timeout=timeout)


def _frida_target_args(package_name: str) -> list[str]:
    frida_host = os.environ.get("FRIDA_HOST")
    if frida_host:
        return ["-H", frida_host, "-n", package_name]
    return ["-U", "-n", package_name]


@register_tool(sandbox_execution=True)
def frida_attach(package_name: str, timeout: str = "60") -> dict:
    """Attach to app process and verify connection."""
    cmd = ["frida", *_frida_target_args(package_name), "-q"]
    return _run(cmd, timeout=int(timeout))


@register_tool(sandbox_execution=True)
def frida_spawn(package_name: str, timeout: str = "60") -> dict:
    """Spawn app process under Frida control."""
    frida_host = os.environ.get("FRIDA_HOST")
    if frida_host:
        cmd = ["frida", "-H", frida_host, "-f", package_name, "-q"]
    else:
        cmd = ["frida", "-U", "-f", package_name, "-q"]
    return _run(cmd, timeout=int(timeout))


@register_tool(sandbox_execution=True)
def frida_run_script(package_name: str, script: str, timeout: str = "90") -> dict:
    """Run an arbitrary Frida JavaScript script against a package."""
    try:
        timeout_s = int(timeout)
    except (TypeError, ValueError):
        return {"error": "timeout must be numeric", "exit_code": None}
    if timeout_s <= 0:
        return {"error": "timeout must be positive", "exit_code": None}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False, encoding="utf-8") as tmp:
        tmp.write(script)
        script_path = Path(tmp.name)

    try:
        cmd = [
            "frida",
            *_frida_target_args(package_name),
            "-l",
            str(script_path),
            "--no-pause",
            "-q",
        ]
        result = _run(cmd, timeout=timeout_s)
        result["script_path"] = str(script_path)
        return result
    finally:
        script_path.unlink(missing_ok=True)


@register_tool(sandbox_execution=True)
def frida_run_named_script(package_name: str, name: str, timeout: str = "90") -> dict:
    """Load one library script by name and inject it with frida_run_script.

    Unknown, unreadable, or invalid names return an error dict and do not spawn Frida.
    """
    loaded = load_script(name)
    if loaded.get("status") != "ok":
        return loaded
    result = frida_run_script(package_name, loaded["source"], timeout=timeout)
    result["script"] = loaded["name"]
    result["category"] = loaded["category"]
    return result
