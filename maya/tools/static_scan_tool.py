"""Host-side static APK and IPA scans. No device or LLM required."""

from __future__ import annotations

from pathlib import Path

from maya.static.scan import run_static_ipa_scan, run_static_scan

from .registry import register_tool


@register_tool(sandbox_execution=False)
def static_apk_scan(apk_path: str, output_dir: str = "") -> dict:
    """Run deterministic static analysis on an APK.

    Reads the binary manifest, network security config, dex strings, and native
    libraries. Does not decompile with apktool and does not need a device.
    Writes report.json, report.md, report.html, and report.sarif when output_dir is set.
    An IPA belongs in ``static_ipa_scan``.
    """
    if Path(apk_path).suffix.lower() == ".ipa":
        return {
            "error": "static_apk_scan reads an APK. Use static_ipa_scan for an IPA.",
            "status": "error",
        }
    try:
        return run_static_scan(apk_path, output_dir=output_dir or None)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc), "status": "error"}


@register_tool(sandbox_execution=False)
def static_ipa_scan(ipa_path: str, output_dir: str = "") -> dict:
    """Run deterministic static analysis on an IPA or an unpacked .app bundle.

    Reads Info.plist, the embedded provisioning profile, and the main Mach-O
    with a built-in parser. Does not decrypt FairPlay payloads and does not need
    a device, a Mac, or otool. Writes report.json, report.md, report.html, and
    report.sarif when output_dir is set. otool is used only when it is on PATH.
    """
    try:
        return run_static_ipa_scan(ipa_path, output_dir=output_dir or None)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc), "status": "error"}
