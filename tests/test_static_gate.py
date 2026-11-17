from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from maya.main import cli
from maya.static_gate import (
    collect_findings,
    gate_failed,
    render_sarif,
    run_static_gate,
    write_reports,
)
from maya.tools.apk_tool import analyze_manifest

FIXTURE = Path(__file__).parent / "fixtures" / "sample_android_manifest.xml"

CLEAN_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.clean">
  <application>
    <activity android:name=".MainActivity">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
    <activity android:exported="true" android:name="androidx.biometric.DeviceCredentialHandlerActivity" />
  </application>
</manifest>
"""

USER_CA_CONFIG = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors>
      <certificates src="system" />
      <certificates src="user" />
    </trust-anchors>
  </base-config>
</network-security-config>
"""

DEBUG_CA_CONFIG = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <debug-overrides>
    <trust-anchors>
      <certificates src="user" />
    </trust-anchors>
  </debug-overrides>
</network-security-config>
"""


def _write_tree(root: Path, manifest: str, nsc: str | None = None, smali: dict[str, str] | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "AndroidManifest.xml").write_text(manifest, encoding="utf-8")
    if nsc is not None:
        xml_dir = root / "res" / "xml"
        xml_dir.mkdir(parents=True, exist_ok=True)
        (xml_dir / "network_security_config.xml").write_text(nsc, encoding="utf-8")
    for relative, body in (smali or {}).items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


def _rule_ids(findings: list[dict]) -> set[str]:
    return {item["rule_id"] for item in findings}


def test_fixture_manifest_flags_explicit_risks_and_skips_launcher() -> None:
    text = FIXTURE.read_text(encoding="utf-8")
    analysis = analyze_manifest(str(FIXTURE))
    from maya.static_gate import findings_from_manifest

    findings = findings_from_manifest(analysis, text)
    rules = _rule_ids(findings)

    assert "ANDROID_DEBUGGABLE" in rules
    assert "ANDROID_ALLOW_BACKUP" in rules
    assert "ANDROID_CLEARTEXT_TRAFFIC" in rules
    assert "ANDROID_EXPORTED_PROVIDER" in rules
    assert any(
        item["title"].endswith(".MainActivity") for item in findings if item["rule_id"] == "ANDROID_EXPORTED_ACTIVITY"
    )
    assert any(
        item["title"].endswith(".CurrencyRates") for item in findings if item["rule_id"] == "ANDROID_EXPORTED_DEEPLINK"
    )
    blob = json.dumps(findings)
    assert "SecretActivity" not in blob
    assert "SplashScreen" not in blob
    assert "BackgroundService" not in blob
    assert gate_failed(findings, "none") is False
    assert gate_failed(findings, "critical") is False
    assert gate_failed(findings, "high") is True


def test_clean_manifest_has_no_findings(tmp_path: Path) -> None:
    root = _write_tree(tmp_path / "clean", CLEAN_MANIFEST)
    _analysis, findings, warnings = collect_findings(root)
    assert findings == []
    assert warnings == []


def test_user_ca_is_high_and_debug_override_is_low(tmp_path: Path) -> None:
    user_root = _write_tree(tmp_path / "user", FIXTURE.read_text(encoding="utf-8"), USER_CA_CONFIG)
    _analysis, findings, _warnings = collect_findings(user_root)
    user_ca = next(item for item in findings if item["rule_id"] == "ANDROID_USER_CA_TRUST")
    assert user_ca["severity"] == "high"
    assert "ANDROID_USER_CA_TRUST_DEBUG" not in _rule_ids(findings)
    # Manifest already flags cleartext, so the NSC cleartext line is not a second finding.
    assert sum(1 for item in findings if item["rule_id"] == "ANDROID_CLEARTEXT_TRAFFIC") == 1

    debug_manifest = CLEAN_MANIFEST.replace(
        "<application>",
        '<application android:networkSecurityConfig="@xml/network_security_config">',
    )
    debug_root = _write_tree(tmp_path / "debug", debug_manifest, DEBUG_CA_CONFIG)
    _analysis, debug_findings, _warnings = collect_findings(debug_root)
    assert _rule_ids(debug_findings) == {"ANDROID_USER_CA_TRUST_DEBUG"}
    assert debug_findings[0]["severity"] == "low"


def test_code_search_stays_inside_the_app_package(tmp_path: Path) -> None:
    if not __import__("shutil").which("rg"):
        pytest.skip("ripgrep is required")
    root = _write_tree(
        tmp_path / "code",
        CLEAN_MANIFEST,
        smali={
            "smali/com/example/clean/Ui.smali": "WebSettings.setJavaScriptEnabled\n",
            "smali/com/google/Web.smali": "WebView.addJavascriptInterface\n",
        },
    )
    _analysis, findings, _warnings = collect_findings(root)
    assert _rule_ids(findings) == {"WEBVIEW_JAVASCRIPT_ENABLED"}
    assert "com/example/clean/Ui.smali" in findings[0]["evidence"]
    assert "com/google" not in findings[0]["evidence"]


def test_reports_include_sarif(tmp_path: Path) -> None:
    text = FIXTURE.read_text(encoding="utf-8")
    analysis = analyze_manifest(str(FIXTURE))
    from maya.static_gate import build_report, findings_from_manifest

    findings = findings_from_manifest(analysis, text)
    report = build_report(
        apk_path="app.apk",
        fail_on="high",
        analysis=analysis,
        findings=findings,
        warnings=["rg skipped"],
    )
    write_reports(tmp_path, report)
    written = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert written["failed"] is True
    assert written["mode"] == "static-gate"
    assert "Debuggable application" in (tmp_path / "report.md").read_text(encoding="utf-8")

    sarif = json.loads((tmp_path / "report.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    high = next(item for item in run["results"] if item["ruleId"] == "ANDROID_DEBUGGABLE")
    medium = next(item for item in run["results"] if item["ruleId"] == "ANDROID_ALLOW_BACKUP")
    assert high["level"] == "error"
    assert medium["level"] == "warning"
    assert high["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
    assert {rule["id"] for rule in run["tool"]["driver"]["rules"]} >= {"ANDROID_DEBUGGABLE", "ANDROID_ALLOW_BACKUP"}
    assert render_sarif(report)["version"] == "2.1.0"


def test_static_gate_cli_rejects_missing_apk() -> None:
    runner = CliRunner()
    missing = runner.invoke(cli, ["--static-gate"])
    assert missing.exit_code != 0
    assert "requires --package" in missing.output

    ipa = runner.invoke(cli, ["--static-gate", "--package", "app.ipa"])
    assert ipa.exit_code != 0
    assert "APK" in ipa.output


def test_static_gate_missing_file_exits_2(tmp_path: Path) -> None:
    result = run_static_gate(str(tmp_path / "missing.apk"), str(tmp_path / "out"), fail_on="high")
    assert result.exit_code == 2
    assert result.report["status"] == "error"
    assert (tmp_path / "out" / "report.json").is_file()
