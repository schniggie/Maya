"""Device-free tests for the headless dynamic smoke and its CLI flag."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from maya.main import cli
from maya.tools.emulator import SdkLayout
from maya.tools.headless_dynamic import judge_injection, run_headless_dynamic, validate_smoke_script


def _sdk(tmp_path: Path) -> SdkLayout:
    return SdkLayout(
        root=tmp_path,
        emulator=tmp_path / "emulator",
        adb=tmp_path / "adb",
        avdmanager=tmp_path / "avdmanager",
        sdkmanager=tmp_path / "sdkmanager",
    )


def test_probe_companion_reports_unavailable_when_nothing_listens() -> None:
    from maya.tools.headless_dynamic import probe_companion

    def runner(argv, timeout, input_text=None):
        assert argv[-2:] == ["tcp:9999", "tcp:9999"]
        return {"stdout": "", "stderr": "", "exit_code": 0}

    result = probe_companion("emulator-5554", Path("adb"), runner=runner)
    assert result["available"] is False
    assert result["status"] == "unavailable"


def test_smoke_script_allowlist() -> None:
    assert validate_smoke_script("enumerate/loaded_classes") is None
    assert validate_smoke_script("enumerate/class_methods.js") is None
    rejected = validate_smoke_script("exploit/webview_rce")
    assert rejected is not None
    assert "enumerate/" in rejected["error"]
    assert validate_smoke_script("../enumerate/loaded_classes") is not None


def test_exploit_script_does_not_touch_the_emulator(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "maya.tools.headless_dynamic.find_sdk",
        lambda *_args, **_kwargs: pytest.fail("sdk lookup"),
    )
    result = run_headless_dynamic(str(tmp_path / "missing.apk"), script="exploit/webview_rce")
    assert result["status"] == "error"
    assert "enumerate/" in result["error"]


def test_judge_injection() -> None:
    assert judge_injection({"exit_code": 0, "stdout": "class", "stderr": ""})["status"] == "ok"
    timed = judge_injection({"exit_code": None, "timed_out": True, "stdout": "{type: class}", "stderr": ""})
    assert timed["status"] == "ok"
    missing = judge_injection({"missing_binary": True, "error": "missing binary: frida", "exit_code": None})
    assert missing["missing"] == "frida"
    refused = judge_injection({"exit_code": 1, "stdout": "", "stderr": "Failed to spawn: timeout"})
    assert refused["status"] == "error"
    quiet = judge_injection({"exit_code": None, "timed_out": True, "stdout": "", "stderr": ""})
    assert quiet["status"] == "error"


def _patch_smoke(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, boot: dict, install: dict | None = None) -> list:
    events: list[str] = []
    sdk = _sdk(tmp_path)

    def record(name, result):
        def _call(*_args, **_kwargs):
            events.append(name)
            return result

        return _call

    monkeypatch.setattr(
        "maya.tools.headless_dynamic.find_sdk",
        lambda *_args, **_kwargs: {"status": "ok", "sdk": sdk},
    )
    monkeypatch.setattr("maya.tools.headless_dynamic.boot_emulator", record("boot", boot))
    monkeypatch.setattr(
        "maya.tools.headless_dynamic.install_apk",
        record("install", install or {"status": "ok"}),
    )
    monkeypatch.setattr("maya.tools.headless_dynamic.device_abi", lambda *_args, **_kwargs: "x86_64")
    monkeypatch.setattr("maya.tools.headless_dynamic.installed_frida_version", lambda: None)
    monkeypatch.setattr(
        "maya.tools.headless_dynamic.provision_frida_server",
        record("frida", {"status": "ok", "version": "16.7.19"}),
    )
    monkeypatch.setattr(
        "maya.tools.headless_dynamic.probe_companion",
        lambda *_args, **_kwargs: {"status": "unavailable", "available": False, "error": "connection refused"},
    )
    monkeypatch.setattr(
        "maya.tools.headless_dynamic.launch_package",
        record("launch", {"status": "ok"}),
    )
    monkeypatch.setattr(
        "maya.tools.headless_dynamic.frida_run_named_script",
        record("inject", {"exit_code": None, "timed_out": True, "stdout": "class com.app.Main", "stderr": ""}),
    )
    monkeypatch.setattr(
        "maya.tools.headless_dynamic.teardown_emulator",
        record("down", {"status": "ok"}),
    )
    return events


def test_smoke_loads_enumerate_script_and_tears_down(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK")
    image = "system-images;android-34;google_apis;x86_64"
    events = _patch_smoke(
        monkeypatch,
        tmp_path,
        boot={
            "status": "ok",
            "serial": "emulator-5554",
            "started_by_us": True,
            "avd": "maya",
            "abi": "x86_64",
            "image": image,
            "reused": False,
        },
    )
    out = tmp_path / "out"
    result = run_headless_dynamic(
        str(apk),
        target="com.example.app",
        script="enumerate/loaded_classes",
        output_dir=str(out),
        env={},
        machine="x86_64",
    )
    assert result["status"] == "ok"
    assert result["script"] == "enumerate/loaded_classes"
    assert result["catalog_count"] >= 1
    assert result["script_bytes"] > 0
    assert result["companion"]["available"] is False
    assert result["torn_down"] is True
    assert result["frida_version"] == "16.7.19"
    assert events[0] == "boot"
    assert "inject" in events
    assert events[-1] == "down"
    saved = (out / "emulator-smoke.json").read_text(encoding="utf-8")
    assert "enumerate/loaded_classes" in saved
    assert "class com.app.Main" in saved


def test_install_failure_still_tears_down(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK")
    events = _patch_smoke(
        monkeypatch,
        tmp_path,
        boot={"status": "ok", "serial": "emulator-5554", "started_by_us": True, "abi": "x86_64"},
        install={"status": "error", "error": "adb install failed"},
    )
    result = run_headless_dynamic(str(apk), target="com.example.app", output_dir=str(tmp_path / "out"), env={})
    assert result["status"] == "error"
    assert result["error"] == "adb install failed"
    assert events == ["boot", "install", "down"]
    assert result["torn_down"] is True


def test_boot_failure_does_not_teardown(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK")
    events = _patch_smoke(
        monkeypatch,
        tmp_path,
        boot={"status": "error", "error": "Android SDK not found", "missing": "sdk"},
    )
    result = run_headless_dynamic(str(apk), target="com.example.app", output_dir=str(tmp_path / "out"), env={})
    assert result["missing"] == "sdk"
    assert events == ["boot"]


def test_keep_emulator_skips_teardown(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK")
    events = _patch_smoke(
        monkeypatch,
        tmp_path,
        boot={"status": "ok", "serial": "emulator-5554", "started_by_us": True, "abi": "x86_64", "image": "img"},
    )
    result = run_headless_dynamic(
        str(apk),
        target="com.example.app",
        keep=True,
        output_dir=str(tmp_path / "out"),
        env={},
    )
    assert result["status"] == "ok"
    assert result["torn_down"] is False
    assert "down" not in events


def test_cli_help_lists_emulator_and_rejects_static_only(tmp_path: Path) -> None:
    runner = CliRunner()
    help_result = runner.invoke(cli, ["--help"])
    assert help_result.exit_code == 0
    assert "--emulator" in help_result.output
    assert "--static-only" in help_result.output
    assert "enumerate/loaded_classes" in help_result.output
    assert "--avd-abi" in help_result.output

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK")
    conflict = runner.invoke(cli, ["--emulator", "--static-only", "-p", str(apk)])
    assert conflict.exit_code != 0
    assert "separate paths" in conflict.output


def test_cli_emulator_runs_smoke(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: dict = {}

    def fake(package: str, **kwargs):
        seen["package"] = package
        seen.update(kwargs)
        return {
            "status": "ok",
            "serial": "emulator-5554",
            "package_name": "com.example.app",
            "image": "system-images;android-34;google_apis;x86_64",
            "frida_version": "16.7.19",
            "frida_source": "pin",
            "script": kwargs["script"],
            "catalog_count": 5,
            "companion": {"available": False},
            "output_dir": str(tmp_path / "out"),
        }

    monkeypatch.setattr("maya.tools.headless_dynamic.run_headless_dynamic", fake)
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK")
    result = CliRunner().invoke(
        cli,
        ["--emulator", "-p", str(apk), "--avd-abi", "x86_64", "--smoke-script", "enumerate/class_methods"],
    )
    assert result.exit_code == 0, result.output
    assert seen["abi"] == "x86_64"
    assert seen["script"] == "enumerate/class_methods"
    assert "serial: emulator-5554" in result.output
    assert "companion: unavailable" in result.output


def test_cli_emulator_failure_exits_2(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "maya.tools.headless_dynamic.run_headless_dynamic",
        lambda *_args, **_kwargs: {"status": "error", "error": "adb root is unavailable", "missing": "root"},
    )
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK")
    result = CliRunner().invoke(cli, ["--emulator", "-p", str(apk)])
    assert result.exit_code == 2
    assert "adb root is unavailable" in result.output
