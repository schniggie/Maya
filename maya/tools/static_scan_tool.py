"""Host-side static APK scan. No device, LLM, or apktool required."""

from __future__ import annotations

from maya.static.scan import run_static_scan

from .registry import register_tool


@register_tool(sandbox_execution=False)
def static_apk_scan(apk_path: str, output_dir: str = "") -> dict:
    """Run deterministic static analysis on an APK.

    Reads the binary manifest, network security config, dex strings, and native
    libraries. Does not decompile with apktool and does not need a device.
    Writes report.json, report.md, and report.html when output_dir is set.
    """
    try:
        return run_static_scan(apk_path, output_dir=output_dir or None)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc), "status": "error"}
