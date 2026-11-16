from __future__ import annotations

import shutil
from pathlib import Path

import pytest

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
