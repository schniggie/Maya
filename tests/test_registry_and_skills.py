from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

import maya.tools  # noqa: F401
from maya.main import cli
from maya.skills import (
    get_all_skill_names,
    get_skill_frontmatter,
    list_available_skills_with_sources,
    load_skills,
    resolve_skill_dependencies,
)
from maya.tools.registry import get_tool, get_tools_prompt, tools

_SKILLS_ROOT = Path(__file__).resolve().parents[1] / "maya" / "skills"
_TARGET_PACKS = {
    "fintech_mobile_banking": "targets",
    "flutter_apps": "frameworks",
    "owasp_masvs": "standards",
}
_MASVS_GROUPS = (
    "MASVS-STORAGE",
    "MASVS-CRYPTO",
    "MASVS-AUTH",
    "MASVS-NETWORK",
    "MASVS-PLATFORM",
    "MASVS-CODE",
    "MASVS-RESILIENCE",
)
_REQUIRED_FRONTMATTER = ("name", "description", "category", "applies_to")


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
    for name in _TARGET_PACKS:
        assert name in result.output


def test_builtin_skill_frontmatter_parses() -> None:
    files = sorted(_SKILLS_ROOT.glob("*/*.md"))
    assert files
    names = get_all_skill_names(include_hidden=True)
    for path in files:
        assert path.read_text(encoding="utf-8").startswith("---\n")
        meta = get_skill_frontmatter(path.stem)
        assert meta.get("name") == path.stem
        assert meta.get("description")
        assert meta.get("category") == path.parent.name
        assert path.stem in names


def test_target_skill_packs_load() -> None:
    for name, category in _TARGET_PACKS.items():
        meta = get_skill_frontmatter(name)
        for field in _REQUIRED_FRONTMATTER:
            assert meta.get(field), f"{name} missing {field}"
        assert meta["category"] == category
        assert isinstance(meta["applies_to"], list) and meta["applies_to"]
        body = load_skills([name], resolve_dependencies=False)[name]
        assert body.startswith("# ")
        resolved = resolve_skill_dependencies([name])
        assert resolved[-1] == name
        requires = meta.get("requires") or []
        assert isinstance(requires, list)
        for dep in requires:
            assert dep in resolved


def test_owasp_masvs_names_published_groups() -> None:
    body = load_skills(["owasp_masvs"], resolve_dependencies=False)["owasp_masvs"]
    for group in _MASVS_GROUPS:
        assert group in body
    assert "MASVS-PRIVACY" in body
    assert "MASTG-TEST-0207" in body
    assert "MASTG-TEST-0235" in body
    assert "MASTG-TEST-0226" in body
    assert "MASTG-TEST-0244" in body
