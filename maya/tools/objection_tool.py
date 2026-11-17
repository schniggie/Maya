from __future__ import annotations

from .proc import run_cli
from .registry import register_tool


@register_tool(sandbox_execution=True)
def objection_run_command(package_name: str, command: str, timeout: str = "90") -> dict:
    """Run a single Objection command against package."""
    return run_cli(
        ["objection", "-g", package_name, "explore", "-c", command],
        timeout=int(timeout),
    )


@register_tool(sandbox_execution=True)
def objection_explore(package_name: str) -> dict:
    """Show available Objection command context."""
    return objection_run_command(package_name=package_name, command="help")
