from __future__ import annotations

import asyncio
import json
import struct
import subprocess
import time
import zipfile
from pathlib import Path

import pytest
from click.testing import CliRunner

import maya.tools  # noqa: F401
from maya.agents.state import AgentState
from maya.main import cli
from maya.static.apk import (
    ApkFacts,
    Component,
    IntentFilter,
    NetworkSecurity,
    _dex_strings,
    _entry_too_large,
    _Interesting,
)
from maya.static.binary_xml import parse_string_pool
from maya.static.limits import MAX_DEX_BYTES, MAX_RETAINED_API_PATHS, MAX_RETAINED_URLS, ScanLimitError
from maya.static.rules import build_findings
from maya.static.sarif import artifact_uri, report_to_sarif
from maya.static.scan import FAIL_ON_LEVELS, run_static_scan, static_scan_exit_code
from maya.telemetry.tracer import Tracer
from maya.tools.executor import execute_tool
from maya.tools.registry import get_tool, should_execute_in_sandbox

REPO_ROOT = Path(__file__).resolve().parents[1]
DVBA_APK = REPO_ROOT / "dvba_v1.1.0.apk"

DVBA_TITLES = {
    "Application allows cleartext traffic",
    "Network security config trusts user-installed certificates",
    "Application data backup is enabled",
    "Exported components are reachable without a permission",
    "Browsable deep link accepts cleartext HTTP",
    "Hardcoded Firebase Realtime Database URL",
    "targetSdkVersion is below the Android 12 exported-component baseline",
    "Client-side root or instrumentation checks are present",
}


def _facts(**overrides: object) -> ApkFacts:
    values: dict[str, object] = {
        "package_name": "com.example.safe",
        "version_name": "1",
        "version_code": 1,
        "min_sdk": 24,
        "target_sdk": 34,
        "permissions": [],
        "allow_backup": False,
        "debuggable": False,
        "uses_cleartext": False,
        "components": [],
        "network_security": NetworkSecurity(),
        "urls": [],
        "api_paths": [],
        "native_libraries": [],
    }
    values.update(overrides)
    return ApkFacts(**values)  # type: ignore[arg-type]


def test_hardened_manifest_has_no_findings() -> None:
    assert build_findings(_facts()) == []


def test_debuggable_flag_is_high() -> None:
    findings = build_findings(_facts(debuggable=True))
    assert [item["title"] for item in findings] == ["Application is debuggable"]
    assert findings[0]["severity"] == "high"


def test_implicit_export_below_api_31_is_reported() -> None:
    component = Component(
        kind="activity",
        name="com.example.safe.Pay",
        exported=None,
        permission="",
        intent_filters=[IntentFilter(actions=["android.intent.action.VIEW"], schemes=["http"], hosts=["bank.example"])],
    )
    findings = build_findings(_facts(target_sdk=29, components=[component]))
    titles = {item["title"] for item in findings}
    assert "Exported components are reachable without a permission" in titles
    assert "Browsable deep link accepts cleartext HTTP" in titles


def test_static_scan_rejects_a_non_apk(tmp_path: Path) -> None:
    bogus = tmp_path / "notes.apk"
    bogus.write_bytes(b"this is not a zip")
    result = run_static_scan(str(bogus), output_dir=str(tmp_path / "out"))
    assert result["status"] == "error"
    assert "zip" in result["error"]


def test_static_scan_rejects_a_zip_without_a_manifest(tmp_path: Path) -> None:
    archive_path = tmp_path / "empty.apk"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("README.txt", "no manifest")
    result = run_static_scan(str(archive_path))
    assert result["status"] == "error"
    assert "AndroidManifest.xml" in result["error"]


def test_tracer_writes_report_json(tmp_path: Path) -> None:
    tracer = Tracer(run_dir=tmp_path)
    tracer.record_finding({"title": "Example", "severity": "low", "category": "test", "description": "n/a"})
    tracer.persist()
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["findings"][0]["title"] == "Example"
    assert report["api_endpoints"] == []


def test_dvba_static_scan_writes_reports_without_apktool(tmp_path: Path) -> None:
    assert DVBA_APK.is_file(), f"bundled DVBA APK missing: {DVBA_APK}"
    out = tmp_path / "run"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["--static-only", "--package", str(DVBA_APK), "--output-dir", str(out), "-n"],
    )
    assert result.exit_code == 0, result.output
    assert "com.app.damnvulnerablebank" in result.output

    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    markdown = (out / "report.md").read_text(encoding="utf-8")
    html = (out / "report.html").read_text(encoding="utf-8")

    assert report["scanner"] == "maya-static"
    assert report["package"] == "com.app.damnvulnerablebank"
    assert report["target_sdk"] == 29
    assert report["cleartext_traffic"] is True
    assert report["trusts_user_cas"] is True
    assert report["allow_backup"] is True
    assert report["debuggable"] is None
    titles = {finding["title"] for finding in report["findings"]}
    assert titles >= DVBA_TITLES
    exported = next(item for item in report["findings"] if item["title"].startswith("Exported components"))
    assert "com.app.damnvulnerablebank.SendMoney" in exported["evidence"]
    assert "com.app.damnvulnerablebank.ViewBalance" in exported["evidence"]
    assert "com.app.damnvulnerablebank.CurrencyRates" in exported["evidence"]
    assert any(endpoint["url"] == "/api/user/login" for endpoint in report["api_endpoints"])
    assert "damn-vulnerable-bank.firebaseio.com" in markdown
    assert "com.app.damnvulnerablebank" in html
    assert "<script" not in html.lower()

    sarif = json.loads((out / "report.sarif").read_text(encoding="utf-8"))
    _assert_sarif_document(sarif, report)
    assert any(rule["shortDescription"]["text"] == "Application allows cleartext traffic" for rule in _rules(sarif))
    cleartext = next(rule for rule in _rules(sarif) if "cleartext traffic" in rule["shortDescription"]["text"])
    assert cleartext["properties"]["security-severity"] == "8.0"
    assert any(item["level"] == "error" and item["ruleId"] == cleartext["id"] for item in _results(sarif))


def test_static_apk_scan_runs_on_the_host_in_strict_mode() -> None:
    assert get_tool("static_apk_scan") is not None
    assert should_execute_in_sandbox("static_apk_scan") is False
    state = AgentState(
        agent_name="static",
        task="static scan",
        sandbox_mode="strict",
        decision_mode="auto_only",
        decision_timeout_seconds=1,
    )
    state.sandbox_info = {"server_url": "", "auth_token": ""}
    result = asyncio.run(execute_tool("static_apk_scan", {"apk_path": str(DVBA_APK)}, state))
    assert isinstance(result, dict)
    assert result.get("status") == "ok"
    assert result["package"] == "com.app.damnvulnerablebank"
    assert "sandbox" not in str(result.get("error", "")).lower()


def test_static_scan_rejects_a_high_ratio_entry(tmp_path: Path) -> None:
    archive_path = tmp_path / "bomb.apk"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", b"\x00" * (256 * 1024))
    started = time.monotonic()
    result = run_static_scan(str(archive_path))
    elapsed = time.monotonic() - started
    assert elapsed < 2
    assert result["status"] == "error"
    assert "ratio" in result["error"]


def test_declared_uncompressed_size_is_rejected_before_inflate() -> None:
    info = zipfile.ZipInfo("classes.dex")
    info.file_size = 2 * 1024 * 1024 * 1024
    info.compress_size = 64
    info.compress_type = zipfile.ZIP_DEFLATED
    reason = _entry_too_large(info, MAX_DEX_BYTES)
    assert reason is not None
    assert "uncompressed size" in reason


def test_string_pool_rejects_an_absurd_count() -> None:
    buf = bytearray(32)
    struct.pack_into("<HHI", buf, 0, 1, 28, 32)
    struct.pack_into("<I", buf, 8, 10_000_000)
    try:
        parse_string_pool(bytes(buf), 0)
    except ScanLimitError as exc:
        assert "string pool count" in str(exc)
    else:
        raise AssertionError("expected ScanLimitError")


def test_retained_urls_and_api_paths_stop_at_the_cap() -> None:
    found = _Interesting()
    for index in range(MAX_RETAINED_URLS + 100):
        found.add(f"https://host{index}.test/path")
    assert len(found.urls) == MAX_RETAINED_URLS
    assert found.urls_truncated is True
    found.add("https://one-more.test/path")
    assert len(found.urls) == MAX_RETAINED_URLS

    paths = _Interesting()
    for index in range(MAX_RETAINED_API_PATHS + 10):
        paths.add(f"/api/item/{index}")
    assert len(paths.api_paths) == MAX_RETAINED_API_PATHS
    assert paths.paths_truncated is True


def test_dex_string_count_is_capped() -> None:
    data = bytearray(112)
    data[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", data, 56, 10_000_000)
    struct.pack_into("<I", data, 60, 112)
    try:
        list(_dex_strings(bytes(data), time.monotonic() + 5))
    except ScanLimitError as exc:
        assert "dex string count" in str(exc)
    else:
        raise AssertionError("expected ScanLimitError")


@pytest.mark.parametrize(
    ("fail_on", "severity", "expected"),
    [
        ("none", "critical", 0),
        ("critical", "critical", 1),
        ("critical", "high", 0),
        ("high", "high", 1),
        ("high", "medium", 0),
        ("medium", "high", 1),
        ("low", "low", 1),
        ("low", "info", 0),
    ],
)
def test_fail_on_threshold(fail_on: str, severity: str, expected: int) -> None:
    result = {"status": "ok", "findings": [{"severity": severity, "title": "Example"}]}
    assert static_scan_exit_code(result, fail_on) == expected


def test_fail_on_hard_failure_wins_over_findings() -> None:
    result = {"status": "error", "error": "not a zip APK", "findings": [{"severity": "critical"}]}
    assert static_scan_exit_code(result, "low") == 2
    assert static_scan_exit_code({"status": "ok", "findings": []}, "high") == 0
    assert static_scan_exit_code({"status": "ok"}, "critical") == 0
    assert static_scan_exit_code({"status": "ok", "findings": [{"severity": "weird"}]}, "low") == 0


def test_fail_on_rejects_an_unknown_threshold() -> None:
    try:
        static_scan_exit_code({"status": "ok", "findings": []}, "info")
    except ValueError as exc:
        assert "fail-on" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_sarif_document_shape() -> None:
    report = {
        "scanner": "maya-static",
        "apk": "app.apk",
        "package": "com.example.app",
        "findings": [
            {
                "id": "abc123",
                "title": "Application is debuggable",
                "severity": "high",
                "category": "platform",
                "description": "android:debuggable is true.",
                "impact": "A debugger can attach.",
                "poc": "adb shell run-as com.example.app",
                "remediation": "Set android:debuggable to false.",
                "evidence": "android:debuggable=true <script>",
            },
            {
                "id": "def456",
                "title": "Client-side root or instrumentation checks are present",
                "severity": "low",
                "category": "resilience",
                "description": "Native checks run in the app process.",
                "remediation": "Enforce the decision on the server.",
                "evidence": "libtool-checker.so",
            },
        ],
    }
    sarif = report_to_sarif(report)
    _assert_sarif_document(sarif, report)
    high = _results(sarif)[0]
    assert high["level"] == "error"
    assert high["kind"] == "fail"
    assert high["partialFingerprints"]["mayaFindingId"] == "abc123"
    assert "Set android:debuggable to false." in high["message"]["text"]
    assert "<script>" in high["message"]["text"]
    assert high["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.apk"
    assert high["locations"][0]["logicalLocations"][0]["name"] == "com.example.app"
    low = _results(sarif)[1]
    assert low["level"] == "note"
    assert _rules(sarif)[1]["properties"]["security-severity"] == "3.0"
    again = report_to_sarif(report)
    assert [item["ruleId"] for item in _results(again)] == [item["ruleId"] for item in _results(sarif)]


def test_artifact_uri_stays_inside_the_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    nested = tmp_path / "apps" / "demo.apk"
    nested.parent.mkdir()
    assert artifact_uri(str(nested)) == "apps/demo.apk"
    assert artifact_uri(str(tmp_path.parent / "other.apk")) == "other.apk"
    assert artifact_uri("../escape.apk") == "escape.apk"
    assert artifact_uri("apps/demo.apk") == "apps/demo.apk"
    assert ".." not in artifact_uri(str(nested))


def test_static_scan_does_not_spawn_a_process(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise AssertionError(f"static scan spawned a process: {args!r} {kwargs!r}")

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(subprocess, "call", boom)
    monkeypatch.setattr(subprocess, "check_call", boom)
    monkeypatch.setattr(subprocess, "check_output", boom)
    result = run_static_scan(str(DVBA_APK), output_dir=str(tmp_path / "out"))
    assert result["status"] == "ok"
    assert (tmp_path / "out" / "report.sarif").is_file()
    assert "apktool" not in json.dumps(result).lower()


def test_cli_fail_on_high_exits_1_and_writes_sarif(tmp_path: Path) -> None:
    out = tmp_path / "run"
    result = CliRunner().invoke(
        cli,
        ["--package", str(DVBA_APK), "--static-only", "--fail-on", "high", "--output-dir", str(out), "-n"],
    )
    assert result.exit_code == 1, result.output
    sarif = json.loads((out / "report.sarif").read_text(encoding="utf-8"))
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    _assert_sarif_document(sarif, report)
    assert _results(sarif)
    assert any(item["severity"] in {"high", "critical"} for item in report["findings"])
    assert (out / "report.md").is_file()
    assert (out / "report.html").is_file()


def test_cli_fail_on_critical_passes_dvba(tmp_path: Path) -> None:
    out = tmp_path / "run"
    result = CliRunner().invoke(
        cli,
        ["--static-only", "--package", str(DVBA_APK), "--fail-on", "critical", "--output-dir", str(out)],
    )
    assert result.exit_code == 0, result.output
    assert (
        static_scan_exit_code(
            json.loads((out / "report.json").read_text(encoding="utf-8")),
            "critical",
        )
        == 0
    )


def test_cli_bad_apk_exits_2(tmp_path: Path) -> None:
    bogus = tmp_path / "notes.apk"
    bogus.write_bytes(b"this is not a zip")
    out = tmp_path / "out"
    result = CliRunner().invoke(
        cli,
        ["--static-only", "--package", str(bogus), "--fail-on", "low", "--output-dir", str(out)],
    )
    assert result.exit_code == 2
    assert not (out / "report.sarif").exists()


def test_cli_scan_crash_exits_2(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def boom(*args: object, **kwargs: object) -> dict:
        raise RuntimeError("parser blew up")

    monkeypatch.setattr("maya.main.run_static_scan", boom)
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK")
    result = CliRunner().invoke(cli, ["--static-only", "--package", str(apk), "--fail-on", "high"])
    assert result.exit_code == 2
    assert "parser blew up" in result.output


def test_fail_on_without_static_only_is_rejected(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK")
    result = CliRunner().invoke(cli, ["--package", str(apk), "--fail-on", "high", "-n"])
    assert result.exit_code != 0
    assert "static-only" in result.output


def test_cli_fail_on_choices_match_the_documented_levels() -> None:
    param = next(item for item in cli.params if item.name == "fail_on")
    assert tuple(param.type.choices) == FAIL_ON_LEVELS


def _rules(sarif: dict) -> list[dict]:
    return sarif["runs"][0]["tool"]["driver"]["rules"]


def _results(sarif: dict) -> list[dict]:
    return sarif["runs"][0]["results"]


def _assert_sarif_document(sarif: dict, report: dict) -> None:
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    assert len(sarif["runs"]) == 1
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "maya-static"
    rules = {rule["id"]: rule for rule in driver["rules"]}
    assert len(_results(sarif)) == len(report["findings"])
    for result, finding in zip(_results(sarif), report["findings"], strict=True):
        assert result["ruleId"] in rules
        assert rules[result["ruleId"]]["defaultConfiguration"]["level"] == result["level"]
        assert result["message"]["text"]
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri
        assert not uri.startswith("/")
        assert ".." not in uri.split("/")
        assert result["properties"]["severity"] == finding["severity"]


def test_cli_static_only_requires_an_apk(tmp_path: Path) -> None:
    runner = CliRunner()
    missing = runner.invoke(cli, ["--static-only"])
    assert missing.exit_code != 0
    ipa = tmp_path / "app.ipa"
    ipa.write_bytes(b"not an ipa")
    wrong_type = runner.invoke(cli, ["--static-only", "--package", str(ipa)])
    assert wrong_type.exit_code != 0
    assert "APK" in wrong_type.output
