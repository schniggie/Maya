#!/usr/bin/env python3
"""Run a device-free static smoke against the bundled DVBA APK."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

from maya.tools.apk_tool import analyze_manifest, apktool_decompile, search_decompiled_code

REPO_ROOT = Path(__file__).resolve().parents[1]
DVBA_APK = REPO_ROOT / "dvba_v1.1.0.apk"


def main() -> int:
    if shutil.which("apktool") is None:
        print("error: apktool not found on PATH", file=sys.stderr)
        return 2
    if not DVBA_APK.exists():
        print(f"error: missing {DVBA_APK}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="maya-dvba-smoke-") as tmp:
        out = Path(tmp) / "decompiled"
        decompile = apktool_decompile(str(DVBA_APK), str(out))
        if decompile.get("exit_code") != 0:
            print(json.dumps({"error": "apktool_decompile failed", "detail": decompile}, indent=2))
            return 1

        analysis = analyze_manifest(str(out / "AndroidManifest.xml"))
        search = (
            search_decompiled_code(str(out), r"com\.app\.damnvulnerablebank")
            if shutil.which("rg")
            else {"skipped": True, "reason": "rg not installed"}
        )

        report = {
            "apk": str(DVBA_APK),
            "package": analysis.get("package"),
            "permissions": analysis.get("permissions"),
            "application": analysis.get("application"),
            "risk_signals": analysis.get("risk_signals"),
            "exported_components": analysis.get("exported_components"),
            "component_counts": {k: len(v) for k, v in (analysis.get("components") or {}).items()},
            "code_search": {
                "exit_code": search.get("exit_code"),
                "match_lines": len((search.get("stdout") or "").splitlines()),
                "skipped": search.get("skipped", False),
            },
        }
        print(json.dumps(report, indent=2))

        risks = analysis.get("risk_signals") or {}
        ok = (
            analysis.get("package") == "com.app.damnvulnerablebank"
            and risks.get("allow_backup") is True
            and risks.get("cleartext_traffic") is True
            and int(risks.get("exported_component_count") or 0) >= 1
        )
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
