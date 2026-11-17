from __future__ import annotations

from pathlib import Path

from maya.tools.apk_tool import analyze_manifest

FIXTURE = Path(__file__).parent / "fixtures" / "sample_android_manifest.xml"


def test_analyze_manifest_extracts_risk_signals() -> None:
    result = analyze_manifest(str(FIXTURE))

    assert result["package"] == "com.example.vulnerablebank"
    assert "android.permission.INTERNET" in result["permissions"]
    assert result["application"]["allowBackup"] == "true"
    assert result["application"]["usesCleartextTraffic"] == "true"
    assert result["application"]["debuggable"] == "true"
    assert result["risk_signals"]["allow_backup"] is True
    assert result["risk_signals"]["cleartext_traffic"] is True
    assert result["risk_signals"]["debuggable"] is True
    assert result["risk_signals"]["exported_component_count"] == 2
    exported_names = {item["name"] for item in result["exported_components"]}
    assert ".MainActivity" in exported_names
    assert ".InsecureProvider" in exported_names

    currency = next(item for item in result["components"]["activity"] if item["name"] == ".CurrencyRates")
    assert currency["exported"] == ""
    assert currency["intent_filters"][0]["actions"] == ["android.intent.action.VIEW"]
    assert currency["intent_filters"][0]["schemes"] == ["http", "https"]
    assert currency["intent_filters"][0]["hosts"] == ["xe.com", "xe.com"]


def test_analyze_manifest_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "maya-does-not-exist-manifest.xml"
    result = analyze_manifest(str(missing))
    assert "error" in result
