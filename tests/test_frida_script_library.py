"""Device-free tests for the Frida script registry and named injection."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import maya.tools  # noqa: F401
from maya.tools.frida_scripts import bundled_root, list_scripts, load_script
from maya.tools.frida_tool import frida_run_named_script, frida_run_script
from maya.tools.registry import get_tool

FIXTURE = "// Fixture probe — confirm the loader can read a script\n'use strict';\nconsole.log('fixture-ready');\n"
PACKAGE = "com.example.app"


def _write(root: Path, relative: str, text: str = FIXTURE) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class CliDouble:
    def __init__(self) -> None:
        self.calls: list[tuple[object, dict]] = []
        self.stdout = "script-ok"
        self.stderr = ""
        self.code = 0

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        script = Path(command[command.index("-l") + 1])
        self.seen = script.read_text(encoding="utf-8")
        return subprocess.CompletedProcess(command, self.code, self.stdout, self.stderr)


@pytest.fixture
def cli(monkeypatch: pytest.MonkeyPatch) -> CliDouble:
    double = CliDouble()
    monkeypatch.setattr("maya.tools.proc.subprocess.run", double)
    monkeypatch.delenv("FRIDA_HOST", raising=False)
    return double


def test_registry_tools_are_registered() -> None:
    assert get_tool("frida_list_scripts") is not None
    assert get_tool("frida_load_script") is not None
    assert get_tool("frida_run_named_script") is not None


def test_list_and_load_fixture_by_name_or_unique_stem(tmp_path: Path) -> None:
    root = tmp_path / "scripts"
    _write(root, "enumerate/probe.js")
    listed = list_scripts(roots=[root])
    assert listed["status"] == "ok"
    assert listed["count"] == 1
    entry = listed["scripts"][0]
    assert entry["name"] == "enumerate/probe"
    assert entry["category"] == "enumerate"
    assert entry["readable"] is True
    assert entry["description"] == "Fixture probe — confirm the loader can read a script"
    assert "source" not in entry

    by_name = load_script("enumerate/probe.js", roots=[root])
    by_stem = load_script("probe", roots=[root])
    assert by_name["status"] == "ok"
    assert by_stem["name"] == "enumerate/probe"
    assert by_name["source"] == by_stem["source"]
    assert "console.log('fixture-ready');" in by_name["source"]

    filtered = list_scripts("enumerate", roots=[root])
    assert filtered["count"] == 1
    assert list_scripts("missing", roots=[root])["count"] == 0


def test_invalid_names_and_ambiguous_stems_do_not_read_outside(tmp_path: Path) -> None:
    root = tmp_path / "scripts"
    _write(root, "enumerate/probe.js", "// one\nconsole.log('one');\n")
    _write(root, "extract/probe.js", "// two\nconsole.log('two');\n")
    outside = tmp_path / "outside.js"
    outside.write_text("// outside\nconsole.log('outside');\n", encoding="utf-8")
    link_dir = root / "enumerate"
    link_dir.mkdir(parents=True, exist_ok=True)
    (link_dir / "escaped.js").symlink_to(outside)

    ambiguous = load_script("probe", roots=[root])
    assert ambiguous["status"] == "error"
    assert ambiguous["error"] == "ambiguous frida script"
    assert ambiguous["matches"] == ["enumerate/probe", "extract/probe"]

    invalid = load_script("../outside.js", roots=[root])
    assert invalid["error"] == "invalid script name"
    escaped = load_script("enumerate/escaped", roots=[root])
    assert escaped["status"] == "error"
    assert escaped["error"] == "path escapes script root"
    assert "outside" not in escaped.get("source", "")
    assert "console.log('outside')" not in str(list_scripts(roots=[root]))


def test_empty_binary_and_oversize_scripts_are_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "scripts"
    _write(root, "enumerate/empty.js", "")
    binary = root / "enumerate" / "binary.js"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_bytes(b"\xff\xfe not text")
    _write(root, "enumerate/big.js", "// big\n" + ("a" * 40))
    monkeypatch.setattr("maya.tools.frida_scripts.MAX_SCRIPT_BYTES", 16)

    empty = load_script("enumerate/empty", roots=[root])
    assert empty["error"] == "script is empty"
    assert load_script("enumerate/binary", roots=[root])["error"] == "script is not utf-8"
    assert load_script("enumerate/big", roots=[root])["error"] == "script exceeds size limit"
    assert load_script("enumerate/missing", roots=[root])["error"].startswith("unknown frida script")


def test_unreadable_script_returns_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "scripts"
    path = _write(root, "enumerate/locked.js")
    original = Path.read_text

    def _read(self: Path, *args, **kwargs):
        if self == path:
            raise OSError(13, "Permission denied")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _read)
    loaded = load_script("enumerate/locked", roots=[root])
    assert loaded["status"] == "error"
    assert "unreadable script" in loaded["error"]


def test_earlier_root_overrides_a_bundled_name(tmp_path: Path) -> None:
    bundled = tmp_path / "bundled"
    user = tmp_path / "user"
    _write(bundled, "enumerate/probe.js", "// bundled\nconsole.log('bundled');\n")
    _write(user, "enumerate/probe.js", "// user copy\nconsole.log('user');\n")

    loaded = load_script("enumerate/probe", roots=[user, bundled])
    assert loaded["status"] == "ok"
    assert "console.log('user');" in loaded["source"]
    assert loaded["origin"] == "user"


def test_explicit_script_root_must_be_a_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAYA_FRIDA_SCRIPTS", str(tmp_path / "missing"))
    result = list_scripts()
    assert result["status"] == "error"
    assert result["error"] == "script root is not a directory"


def test_bundled_root_uses_the_first_directory_that_exists(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    missing = tmp_path / "missing"
    present = tmp_path / "present"
    present.mkdir()
    monkeypatch.setattr("maya.tools.frida_scripts._bundled_locations", lambda: (missing, present))
    assert bundled_root() == present


def test_shipped_catalog_matches_assets_and_hides_source(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("MAYA_FRIDA_SCRIPTS", raising=False)
    monkeypatch.setattr("maya.tools.frida_scripts.Path.home", lambda: tmp_path)
    listed = list_scripts()
    root = bundled_root()
    expected = sorted(path.relative_to(root).with_suffix("").as_posix() for path in root.rglob("*.js"))
    assert listed["status"] == "ok"
    assert [item["name"] for item in listed["scripts"]] == expected
    assert all(item["readable"] for item in listed["scripts"])
    assert all("source" not in item for item in listed["scripts"])

    loaded = load_script("enumerate/loaded_classes")
    assert loaded["status"] == "ok"
    assert loaded["category"] == "enumerate"
    assert "Enumerate all loaded Java classes" in loaded["description"]
    assert "enumerateLoadedClasses" in loaded["source"]


def test_named_script_injects_fixture_through_frida_run_script(
    cli: CliDouble, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "scripts"
    _write(root, "enumerate/probe.js")
    monkeypatch.setenv("MAYA_FRIDA_SCRIPTS", str(root))
    monkeypatch.setenv("FRIDA_HOST", "127.0.0.1:27042")

    result = frida_run_named_script(PACKAGE, "probe", timeout="13")

    command, kwargs = cli.calls[0]
    assert cli.seen == FIXTURE
    assert command[:4] == ["frida", "-H", "127.0.0.1:27042", "-n"]
    assert command[4:] == [PACKAGE, "-l", result["script_path"], "--no-pause", "-q"]
    assert kwargs["timeout"] == 13
    assert result["script"] == "enumerate/probe"
    assert result["category"] == "enumerate"
    assert result["stdout"] == "script-ok"
    assert not Path(result["script_path"]).exists()


def test_named_script_errors_do_not_spawn_frida(
    cli: CliDouble, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("MAYA_FRIDA_SCRIPTS", str(tmp_path))
    missing = frida_run_named_script(PACKAGE, "does-not-exist")
    assert missing["status"] == "error"
    assert cli.calls == []

    numeric = frida_run_script(PACKAGE, "console.log('fixture');", timeout="soon")
    assert numeric == {"error": "timeout must be numeric", "exit_code": None}
    assert cli.calls == []
