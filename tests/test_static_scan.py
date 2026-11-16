from __future__ import annotations

import asyncio
import json
import struct
import time
import zipfile
from pathlib import Path

from click.testing import CliRunner

import maya.tools  # noqa: F401
from maya.agents.state import AgentState
from maya.main import cli
from maya.static.apk import ApkFacts, Component, IntentFilter, NetworkSecurity, _dex_strings, _entry_too_large
from maya.static.binary_xml import parse_string_pool
from maya.static.limits import MAX_DEX_BYTES, ScanLimitError
from maya.static.rules import build_findings
from maya.static.scan import run_static_scan
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


def test_cli_static_only_requires_an_apk(tmp_path: Path) -> None:
    runner = CliRunner()
    missing = runner.invoke(cli, ["--static-only"])
    assert missing.exit_code != 0
    ipa = tmp_path / "app.ipa"
    ipa.write_bytes(b"not an ipa")
    wrong_type = runner.invoke(cli, ["--static-only", "--package", str(ipa)])
    assert wrong_type.exit_code != 0
    assert "APK" in wrong_type.output
