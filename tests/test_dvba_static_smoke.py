from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from maya.main import cli
from maya.static_gate import collect_findings, gate_failed
from maya.tools.apk_tool import analyze_manifest, apktool_decompile, search_decompiled_code

REPO_ROOT = Path(__file__).resolve().parents[1]
DVBA_APK = REPO_ROOT / "dvba_v1.1.0.apk"


pytestmark = pytest.mark.smoke


@pytest.fixture(scope="module")
def dvba_decompiled(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if shutil.which("apktool") is None:
        pytest.skip("apktool is required for DVBA static smoke")
    if not DVBA_APK.exists():
        pytest.skip(f"bundled DVBA APK missing: {DVBA_APK}")

    out = tmp_path_factory.mktemp("dvba") / "decompiled"
    result = apktool_decompile(str(DVBA_APK), str(out))
    assert result["exit_code"] == 0, result
    assert (out / "AndroidManifest.xml").exists()
    return out


def test_dvba_manifest_risk_signals(dvba_decompiled: Path) -> None:
    analysis = analyze_manifest(str(dvba_decompiled / "AndroidManifest.xml"))

    assert analysis["package"] == "com.app.damnvulnerablebank"
    assert "android.permission.INTERNET" in analysis["permissions"]
    assert analysis["risk_signals"]["allow_backup"] is True
    assert analysis["risk_signals"]["cleartext_traffic"] is True
    assert analysis["risk_signals"]["exported_component_count"] >= 1
    assert analysis["components"]["activity"]
    assert analysis["components"]["provider"]


def test_dvba_code_search_finds_bank_package(dvba_decompiled: Path) -> None:
    if shutil.which("rg") is None:
        pytest.skip("ripgrep (rg) is required for decompiled code search")

    result = search_decompiled_code(str(dvba_decompiled), r"com\.app\.damnvulnerablebank")
    # ripgrep exit 0 = matches, 1 = no matches
    assert result["exit_code"] == 0, result
    assert "damnvulnerablebank" in result["stdout"]


def test_dvba_static_gate_finds_known_issues(dvba_decompiled: Path) -> None:
    analysis, findings, _warnings = collect_findings(dvba_decompiled)
    rules = {item["rule_id"] for item in findings}

    assert analysis["package"] == "com.app.damnvulnerablebank"
    assert "ANDROID_ALLOW_BACKUP" in rules
    assert "ANDROID_CLEARTEXT_TRAFFIC" in rules
    assert "ANDROID_USER_CA_TRUST" in rules
    assert "ANDROID_EXPORTED_ACTIVITY" in rules
    assert "ANDROID_EXPORTED_DEEPLINK" in rules
    blob = json.dumps(findings)
    assert "SendMoney" in blob
    assert "ViewBalance" in blob
    assert "CurrencyRates" in blob
    assert "DeviceCredentialHandlerActivity" not in blob
    assert "FederatedSignInActivity" not in blob
    assert "SplashScreen" not in blob
    assert gate_failed(findings, "high") is True
    assert gate_failed(findings, "critical") is False
    if shutil.which("rg"):
        assert "WEBVIEW_JAVASCRIPT_ENABLED" in rules
        assert "com/google" not in next(
            item["evidence"] for item in findings if item["rule_id"] == "WEBVIEW_JAVASCRIPT_ENABLED"
        )


def test_dvba_static_gate_cli_fails_on_high(tmp_path: Path) -> None:
    if shutil.which("apktool") is None:
        pytest.skip("apktool is required for DVBA static smoke")
    if not DVBA_APK.exists():
        pytest.skip(f"bundled DVBA APK missing: {DVBA_APK}")

    result = CliRunner().invoke(
        cli,
        ["--package", str(DVBA_APK), "--static-gate", "--fail-on", "high", "--output-dir", str(tmp_path)],
    )
    assert result.exit_code == 1, result.output
    assert "Fail-on: high → failed" in result.output
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    sarif = json.loads((tmp_path / "report.sarif").read_text(encoding="utf-8"))
    assert report["package"] == "com.app.damnvulnerablebank"
    assert report["failed"] is True
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
    assert gate_failed(report["findings"], "critical") is False
