"""Device-free tests for the IPA static scanner. The fixture is built in the test."""

from __future__ import annotations

import json
import plistlib
import struct
import subprocess
import zipfile
from pathlib import Path

import pytest
from click.testing import CliRunner

import maya.tools  # noqa: F401
from maya.agents.state import AgentState
from maya.main import cli
from maya.static.macho import inspect_macho
from maya.static.sarif import report_to_sarif
from maya.static.scan import run_static_ipa_scan
from maya.tools.executor import execute_tool
from maya.tools.registry import get_tool, should_execute_in_sandbox

MH_MAGIC_64 = 0xFEEDFACF
MH_EXECUTE = 2
MH_DYLDLINK = 0x4
MH_PIE = 0x200000
CPU_ARM64 = 0x0100000C
LC_SYMTAB = 0x2
LC_LOAD_DYLIB = 0xC
LC_ENCRYPTION_INFO_64 = 0x2C

BAD_TITLES = {
    "App Transport Security allows arbitrary loads",
    "App Transport Security allows insecure HTTP",
    "App Transport Security allows a weak TLS version",
    "App Transport Security allows arbitrary loads in web content",
    "URL scheme allows an insecure protocol",
    "Custom URL scheme is registered",
    "File sharing is enabled",
    "Documents can be opened in place",
    "Provisioning profile allows a debugger",
    "Keychain access is shared with another group",
    "App shares an application group container",
    "Wi-Fi information entitlement is present",
    "Deployment target is below iOS 13",
    "Mach-O executable is missing PIE",
    "Mach-O executable has no stack-canary marker",
    "Mach-O executable has no ARC marker",
    "Hardcoded cleartext URL",
    "Privacy usage description is empty",
}


def _dylib(path: str) -> bytes:
    name = path.encode() + b"\x00"
    cmdsize = (24 + len(name) + 7) & ~7
    blob = struct.pack("<IIIIII", LC_LOAD_DYLIB, cmdsize, 24, 0, 0x10000, 0x10000) + name
    return blob + b"\x00" * (cmdsize - len(blob))


def build_macho(*, pie: bool, encrypted: bool = False, symbols: bytes = b"", objc: bool = False) -> bytes:
    commands = bytearray()
    commands += _dylib("/usr/lib/libSystem.B.dylib")
    if objc:
        commands += _dylib("/usr/lib/libobjc.A.dylib")
    encryption_at = len(commands)
    commands += struct.pack("<IIIIII", LC_ENCRYPTION_INFO_64, 24, 0, 0, 0, 0)
    symtab_at = len(commands)
    commands += struct.pack("<IIIIII", LC_SYMTAB, 24, 0, 0, 0, 0)
    strings = b"\x00" + symbols
    if not strings.endswith(b"\x00"):
        strings += b"\x00"
    stroff = 32 + len(commands)
    cryptid = 1 if encrypted else 0
    cryptoff = stroff if encrypted else 0
    cryptsize = len(strings) if encrypted else 0
    struct.pack_into("<IIIIII", commands, encryption_at, LC_ENCRYPTION_INFO_64, 24, cryptoff, cryptsize, cryptid, 0)
    struct.pack_into("<IIIIII", commands, symtab_at, LC_SYMTAB, 24, 0, 0, stroff, len(strings))
    flags = MH_DYLDLINK | (MH_PIE if pie else 0)
    ncmds = 3 + (1 if objc else 0)
    header = struct.pack("<IIIIIIII", MH_MAGIC_64, CPU_ARM64, 0, MH_EXECUTE, ncmds, len(commands), flags, 0)
    return header + bytes(commands) + strings


def wrap_fat(thin: bytes) -> bytes:
    offset = 32
    header = struct.pack(">II", 0xCAFEBABE, 1)
    header += struct.pack(">IIIII", CPU_ARM64, 0, offset, len(thin), 2)
    return header + b"\x00" * (offset - len(header)) + thin


def _plist(payload: dict, *, binary: bool = False) -> bytes:
    fmt = plistlib.FMT_BINARY if binary else plistlib.FMT_XML
    return plistlib.dumps(payload, fmt=fmt)


def _profile(entitlements: dict, devices: list[str] | None = None) -> bytes:
    body: dict[str, object] = {"Name": "Fixture", "Entitlements": entitlements}
    if devices is not None:
        body["ProvisionedDevices"] = devices
    return b"CMS-STUB\n" + plistlib.dumps(body, fmt=plistlib.FMT_XML) + b"\nTRAILER"


def _bad_plist() -> dict:
    return {
        "CFBundleIdentifier": "com.example.fixture",
        "CFBundleExecutable": "Fixture",
        "CFBundleName": "Fixture",
        "CFBundleShortVersionString": "1.2.3",
        "CFBundleVersion": "9",
        "MinimumOSVersion": "12.0",
        "UIFileSharingEnabled": True,
        "LSSupportsOpeningDocumentsInPlace": True,
        "NSCameraUsageDescription": "",
        "NSAppTransportSecurity": {
            "NSAllowsArbitraryLoads": True,
            "NSAllowsArbitraryLoadsInWebContent": True,
            "NSAllowsLocalNetworking": True,
            "NSExceptionDomains": {
                "legacy.internal": {
                    "NSExceptionAllowsInsecureHTTPLoads": True,
                    "NSExceptionMinimumTLSVersion": "TLSv1.0",
                    "NSIncludesSubdomains": True,
                }
            },
        },
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["mybank", "http", "https"]}],
    }


def _bad_entitlements() -> dict:
    return {
        "get-task-allow": True,
        "keychain-access-groups": ["TEAM.com.example.fixture", "TEAM.com.example.shared"],
        "com.apple.security.application-groups": ["group.com.example.fixture"],
        "com.apple.developer.networking.wifi-info": True,
    }


def _bad_macho() -> bytes:
    return build_macho(
        pie=False,
        objc=True,
        symbols=b"http://bank.example/login\x00/api/v1/accounts",
    )


def _write_ipa(path: Path, plist: bytes, macho: bytes, profile: bytes | None = None) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        base = "Payload/Fixture.app/"
        archive.writestr(base + "Info.plist", plist)
        archive.writestr(base + "Fixture", macho)
        archive.writestr(base + "Frameworks/Alamofire.framework/Alamofire", b"framework")
        if profile is not None:
            archive.writestr(base + "embedded.mobileprovision", profile)


def _hide_otool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("maya.static.macho.shutil.which", lambda _name: None)


def test_thin_and_fat_macho_markers_are_readable() -> None:
    marked = build_macho(pie=True, objc=True, symbols=b"___stack_chk_fail\x00_objc_release")
    thin = inspect_macho(marked)
    assert thin.parsed is True
    assert thin.pie is True
    assert thin.stack_canary is True
    assert thin.arc is True
    assert thin.encrypted is False
    assert any("libobjc" in name for name in thin.linked)

    fat = inspect_macho(wrap_fat(marked))
    assert fat.parsed is True
    assert fat.pie is True
    assert fat.stack_canary is True
    assert fat.format == "fat"


def test_encrypted_slice_does_not_invent_missing_markers() -> None:
    encrypted = build_macho(
        pie=True,
        encrypted=True,
        objc=True,
        symbols=b"___stack_chk_fail\x00_objc_release",
    )
    facts = inspect_macho(encrypted)
    assert facts.encrypted is True
    assert facts.pie is True
    assert facts.stack_canary is None
    assert facts.arc is None


def test_ipa_scan_flags_ats_schemes_entitlements_and_macho(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _hide_otool(monkeypatch)
    ipa = tmp_path / "Fixture.ipa"
    _write_ipa(ipa, _plist(_bad_plist()), _bad_macho(), _profile(_bad_entitlements(), ["device-a"]))
    out = tmp_path / "run"
    report = run_static_ipa_scan(str(ipa), output_dir=str(out), target="fixture")

    assert report["status"] == "ok"
    assert report["platform"] == "ios"
    assert report["package"] == "com.example.fixture"
    assert report["otool"] == "absent"
    assert report["macho_status"] == "parsed"
    assert report["frameworks"] == ["Alamofire"]
    assert report["plist_format"] == "xml"
    assert report["cleartext_traffic"] is True
    assert report["debuggable"] is True
    assert "device-a" not in json.dumps(report)
    titles = {item["title"] for item in report["findings"]}
    assert titles >= BAD_TITLES
    assert any(item["url"] == "/api/v1/accounts" for item in report["api_endpoints"])
    debugger = next(item for item in report["findings"] if item["title"].startswith("Provisioning profile"))
    assert debugger["severity"] == "high"
    assert debugger["masvs"] == "MASVS-RESILIENCE-4"
    ats = next(item for item in report["findings"] if "arbitrary loads" in item["title"])
    assert "MASVS-NETWORK-1" in ats["description"]

    for name in ("report.json", "report.md", "report.html", "report.sarif"):
        assert (out / name).is_file()
    markdown = (out / "report.md").read_text(encoding="utf-8")
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "Platform: ios" in markdown
    assert "get-task-allow" in markdown
    assert "Capability notes" in markdown
    assert "FairPlay decryption is not performed." in markdown
    assert "com.example.fixture" in html
    assert "<script" not in html.lower()
    sarif = json.loads((out / "report.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert any(item["properties"].get("masvs") == "MASVS-NETWORK-1" for item in sarif["runs"][0]["results"])
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.endswith("Fixture.ipa")
    assert not uri.startswith("/")


def test_clean_ipa_has_no_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _hide_otool(monkeypatch)
    plist = {
        "CFBundleIdentifier": "com.example.clean",
        "CFBundleExecutable": "Clean",
        "CFBundleShortVersionString": "2.0",
        "MinimumOSVersion": "15.0",
        "NSCameraUsageDescription": "Used to scan a payment code.",
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["https"]}],
    }
    macho = build_macho(pie=True, objc=True, symbols=b"___stack_chk_fail\x00_objc_release")
    ipa = tmp_path / "Clean.ipa"
    with zipfile.ZipFile(ipa, "w") as archive:
        archive.writestr("Payload/Clean.app/Info.plist", _plist(plist))
        archive.writestr("Payload/Clean.app/Clean", macho)
    report = run_static_ipa_scan(str(ipa))
    assert report["status"] == "ok"
    assert report["findings"] == []
    assert report["binary"]["pie"] is True
    assert report["binary"]["stack_canary"] is True
    assert report["binary"]["arc"] is True
    assert any("otool is not on PATH" in note for note in report["notes"])


def test_binary_plist_and_app_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _hide_otool(monkeypatch)
    plist = {
        "CFBundleIdentifier": "com.example.bundle",
        "CFBundleExecutable": "Bundle",
        "MinimumOSVersion": "16.0",
    }
    macho = build_macho(pie=True, objc=True, symbols=b"___stack_chk_fail\x00_objc_release")
    app = tmp_path / "Bundle.app"
    app.mkdir()
    (app / "Info.plist").write_bytes(_plist(plist, binary=True))
    (app / "Bundle").write_bytes(macho)
    report = run_static_ipa_scan(str(app))
    assert report["status"] == "ok"
    assert report["package"] == "com.example.bundle"
    assert report["plist_format"] == "binary"
    assert report["macho_status"] == "parsed"
    assert report["findings"] == []


def test_unparsed_executable_skips_hardening_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _hide_otool(monkeypatch)
    ipa = tmp_path / "Broken.ipa"
    _write_ipa(
        ipa,
        _plist({"CFBundleIdentifier": "com.example.broken", "CFBundleExecutable": "Broken"}),
        b"not a macho",
    )
    report = run_static_ipa_scan(str(ipa))
    titles = {item["title"] for item in report["findings"]}
    assert "Mach-O protections were not assessed" in titles
    assert "Mach-O executable is missing PIE" not in titles
    assert report["macho_status"] == "unparsed"
    assert report["package"] == "com.example.broken"


def test_encrypted_ipa_reports_the_limit_without_a_missing_canary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _hide_otool(monkeypatch)
    plist = {"CFBundleIdentifier": "com.example.sealed", "CFBundleExecutable": "Sealed", "MinimumOSVersion": "16.0"}
    macho = build_macho(pie=True, encrypted=True, objc=True, symbols=b"___stack_chk_fail\x00_objc_release")
    ipa = tmp_path / "Sealed.ipa"
    with zipfile.ZipFile(ipa, "w") as archive:
        archive.writestr("Payload/Sealed.app/Info.plist", _plist(plist))
        archive.writestr("Payload/Sealed.app/Sealed", macho)
    report = run_static_ipa_scan(str(ipa))
    titles = {item["title"] for item in report["findings"]}
    assert "FairPlay encryption is present" in titles
    assert "Mach-O executable has no stack-canary marker" not in titles
    assert "Mach-O executable is missing PIE" not in titles
    assert report["binary"]["stack_canary"] is None
    assert any("decrypt" in note.lower() for note in report["notes"])


def test_otool_failure_keeps_the_builtin_parser(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("maya.static.macho.shutil.which", lambda name: "otool" if name == "otool" else None)

    def explode(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="otool", timeout=5)

    monkeypatch.setattr("maya.static.macho.subprocess.run", explode)
    ipa = tmp_path / "Fixture.ipa"
    _write_ipa(ipa, _plist(_bad_plist()), _bad_macho(), _profile(_bad_entitlements(), ["device-a"]))
    report = run_static_ipa_scan(str(ipa))
    assert report["status"] == "ok"
    assert report["otool"] == "failed"
    assert report["binary"]["pie"] is False
    assert any(item["title"] == "Mach-O executable is missing PIE" for item in report["findings"])


def test_cli_static_only_writes_ipa_reports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _hide_otool(monkeypatch)
    ipa = tmp_path / "Fixture.ipa"
    _write_ipa(ipa, _plist(_bad_plist()), _bad_macho(), _profile(_bad_entitlements(), ["device-a"]))
    out = tmp_path / "cli"
    result = CliRunner().invoke(
        cli,
        ["--static-only", "--package", str(ipa), "--output-dir", str(out), "--fail-on", "high", "-n"],
    )
    assert result.exit_code == 1, result.output
    assert "com.example.fixture" in result.output
    assert "fail-on high" in result.output
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    sarif = json.loads((out / "report.sarif").read_text(encoding="utf-8"))
    assert sarif == report_to_sarif(report)
    help_result = CliRunner().invoke(cli, ["--help"])
    assert "IPA" in help_result.output


def test_static_ipa_scan_runs_on_the_host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _hide_otool(monkeypatch)
    assert get_tool("static_ipa_scan") is not None
    assert should_execute_in_sandbox("static_ipa_scan") is False
    ipa = tmp_path / "Clean.ipa"
    plist = {"CFBundleIdentifier": "com.example.clean", "CFBundleExecutable": "Clean", "MinimumOSVersion": "16.0"}
    macho = build_macho(pie=True, objc=True, symbols=b"___stack_chk_fail\x00_objc_release")
    with zipfile.ZipFile(ipa, "w") as archive:
        archive.writestr("Payload/Clean.app/Info.plist", _plist(plist))
        archive.writestr("Payload/Clean.app/Clean", macho)
    state = AgentState(
        agent_name="static",
        task="static scan",
        sandbox_mode="strict",
        decision_mode="auto_only",
        decision_timeout_seconds=1,
    )
    state.sandbox_info = {"server_url": "", "auth_token": ""}
    result = __import__("asyncio").run(execute_tool("static_ipa_scan", {"ipa_path": str(ipa)}, state))
    assert result["status"] == "ok"
    assert result["package"] == "com.example.clean"
    rejected = __import__("asyncio").run(execute_tool("static_apk_scan", {"apk_path": str(ipa)}, state))
    assert rejected["status"] == "error"
    assert "static_ipa_scan" in rejected["error"]


def test_zip_without_a_plist_is_an_error(tmp_path: Path) -> None:
    ipa = tmp_path / "empty.ipa"
    with zipfile.ZipFile(ipa, "w") as archive:
        archive.writestr("Payload/../Info.plist", b"nope")
        archive.writestr("README", b"no bundle")
    report = run_static_ipa_scan(str(ipa))
    assert report["status"] == "error"
    assert "Info.plist" in report["error"]
