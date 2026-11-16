from __future__ import annotations

from click.testing import CliRunner

import maya.tools  # noqa: F401
from maya.main import cli
from maya.skills import get_all_skill_names, list_available_skills_with_sources, load_skills
from maya.tools.registry import get_tool, get_tools_prompt, tools


def test_builtin_tools_are_registered() -> None:
    names = {entry["name"] for entry in tools}
    assert "analyze_manifest" in names
    assert "apktool_decompile" in names
    assert "frida_run_script" in names
    assert get_tool("analyze_manifest") is not None
    prompt = get_tools_prompt(include_modules={"apk_tool"})
    assert "analyze_manifest" in prompt
    assert "<apk_tool_tools>" in prompt


def test_core_skills_load() -> None:
    skill_names = get_all_skill_names(include_hidden=True)
    assert "root_orchestrator" in skill_names
    assert "static_analyzer" in skill_names
    loaded = load_skills(["root_orchestrator"], resolve_dependencies=False)
    assert "root_orchestrator" in loaded
    assert "orchestrator" in loaded["root_orchestrator"].lower()


def test_list_skills_cli() -> None:
    entries = list_available_skills_with_sources()
    assert entries
    runner = CliRunner()
    result = runner.invoke(cli, ["--list-skills"])
    assert result.exit_code == 0
    assert "Available skills:" in result.output
    assert "root_orchestrator" in result.output
