"""Read an IPA or .app bundle without a Mac, a device, or a decryption tool."""

from __future__ import annotations

import plistlib
import re
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from maya.static.limits import (
    MAX_COMPRESSION_RATIO,
    MAX_DEX_BYTES,
    MAX_MANIFEST_BYTES,
    MAX_RETAINED_API_PATHS,
    MAX_RETAINED_URLS,
    MAX_TOTAL_BYTES,
    MAX_ZIP_ENTRIES,
    SCAN_DEADLINE_SECONDS,
    ScanBudgetError,
    ScanLimitError,
)
from maya.static.macho import apply_otool, inspect_macho, otool_probe

_PROFILE_CAP = 1024 * 1024
_MAX_XCENT_FILES = 4
_URL_RE = re.compile(r"https?://[^\s\"'<>]{4,200}")
_API_RE = re.compile(r"^/(?:api|rest|graphql)(?:/[A-Za-z0-9_.{}\-]{1,48}){1,8}$")
_IGNORED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "example.com",
    "www.example.com",
    "schemas.apple.com",
    "www.apple.com",
}


@dataclass
class AtsException:
    domain: str
    insecure_http: bool
    minimum_tls: str | None
    includes_subdomains: bool
    requires_forward_secrecy: bool | None


@dataclass
class BinaryView:
    name: str
    parsed: bool
    filetype: str | None
    pie: bool | None
    stack_canary: bool | None
    arc: bool | None
    encrypted: bool | None
    otool: str
    linked: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class IpaFacts:
    bundle_id: str
    bundle_name: str | None
    display_name: str | None
    version: str | None
    build: str | None
    minimum_os: str | None
    executable_name: str | None
    plist_format: str
    usage_strings: dict[str, str]
    url_schemes: list[str]
    allows_arbitrary_loads: bool
    allows_arbitrary_loads_web: bool
    allows_arbitrary_loads_media: bool
    allows_local_networking: bool
    ats_exceptions: list[AtsException]
    file_sharing: bool
    open_in_place: bool
    frameworks: list[str]
    get_task_allow: bool | None
    profile_kind: str
    provisioned_device_count: int | None
    keychain_access_groups: list[str]
    application_groups: list[str]
    associated_domains: list[str]
    wifi_info: bool
    binary: BinaryView | None
    urls: list[str]
    api_paths: list[str]
    urls_truncated: bool
    api_paths_truncated: bool
    notes: list[str]


def load_ipa(path: str) -> IpaFacts:
    """Open an ``.ipa`` zip or an unpacked ``.app`` directory."""
    source = Path(path)
    budget = _Budget()
    if not source.exists():
        raise ValueError(f"IPA not found: {path}")
    if source.is_dir():
        root = _directory_root(source)
        return _collect(_DirBundle(root, budget))
    if not source.is_file():
        raise ValueError(f"IPA not found: {path}")
    try:
        archive = zipfile.ZipFile(source)
    except zipfile.BadZipFile as exc:
        raise ValueError(f"not a zip IPA: {path}") from exc
    with archive:
        budget.check()
        names = [name for name in archive.namelist() if _safe_zip_name(name)]
        if len(names) > MAX_ZIP_ENTRIES:
            raise ScanLimitError(f"IPA has {len(names)} entries; the scan budget is {MAX_ZIP_ENTRIES}")
        prefix = _zip_prefix(names)
        return _collect(_ZipBundle(archive, prefix, names, budget))


class _Budget:
    """Running uncompressed-byte total and wall deadline for one IPA read."""

    def __init__(self) -> None:
        self.deadline = time.monotonic() + SCAN_DEADLINE_SECONDS
        self.used = 0

    def check(self) -> None:
        if time.monotonic() > self.deadline:
            raise ScanBudgetError("static scan exceeded the time budget")

    def charge(self, size: int) -> None:
        self.check()
        self.used += max(size, 0)
        if self.used > MAX_TOTAL_BYTES:
            raise ScanBudgetError(f"IPA entries expand past the {MAX_TOTAL_BYTES} byte scan budget")


def _collect(bundle: _ZipBundle | _DirBundle) -> IpaFacts:
    try:
        plist_bytes = bundle.read("Info.plist", MAX_MANIFEST_BYTES)
    except ScanLimitError:
        raise
    if plist_bytes is None:
        raise ValueError("IPA has no Info.plist")
    plist, plist_format = _load_plist(plist_bytes)
    notes = [
        "Device-free static scan. No device and no dynamic instrumentation was used.",
        "FairPlay decryption is not performed.",
        "Stack canary and ARC results are marker searches, not a compiler-flag proof.",
        "Dynamic iOS testing is not part of this scan. It needs a device and a build you can instrument.",
    ]
    profile, profile_kind, device_count = _read_profile(bundle, notes)
    xcent = _read_xcent(bundle)
    entitlements = _entitlements(profile, xcent)
    executable_name = _plain(plist.get("CFBundleExecutable"))
    binary, sample = _read_binary(bundle, executable_name, notes)
    texts = _plist_strings(plist)
    texts.extend(_utf8_strings(sample))
    urls, urls_truncated = _urls(texts)
    api_paths, api_truncated = _api_paths(texts)
    usage = {key: value[:160] for key, value in sorted(_usage_strings(plist).items())}
    return IpaFacts(
        bundle_id=_plain(plist.get("CFBundleIdentifier")) or "",
        bundle_name=_plain(plist.get("CFBundleName")),
        display_name=_plain(plist.get("CFBundleDisplayName")),
        version=_plain(plist.get("CFBundleShortVersionString")),
        build=_plain(plist.get("CFBundleVersion")),
        minimum_os=_plain(plist.get("MinimumOSVersion")),
        executable_name=executable_name,
        plist_format=plist_format,
        usage_strings=usage,
        url_schemes=_url_schemes(plist),
        allows_arbitrary_loads=_ats_flag(plist, "NSAllowsArbitraryLoads"),
        allows_arbitrary_loads_web=_ats_flag(plist, "NSAllowsArbitraryLoadsInWebContent"),
        allows_arbitrary_loads_media=_ats_flag(plist, "NSAllowsArbitraryLoadsForMedia"),
        allows_local_networking=_ats_flag(plist, "NSAllowsLocalNetworking"),
        ats_exceptions=_ats_exceptions(plist),
        file_sharing=_bool(plist.get("UIFileSharingEnabled")) is True,
        open_in_place=_bool(plist.get("LSSupportsOpeningDocumentsInPlace")) is True,
        frameworks=bundle.frameworks(),
        get_task_allow=_bool(entitlements.get("get-task-allow")),
        profile_kind=profile_kind,
        provisioned_device_count=device_count,
        keychain_access_groups=_str_list(entitlements.get("keychain-access-groups")),
        application_groups=_str_list(entitlements.get("com.apple.security.application-groups")),
        associated_domains=_str_list(entitlements.get("com.apple.developer.associated-domains")),
        wifi_info=_bool(entitlements.get("com.apple.developer.networking.wifi-info")) is True,
        binary=binary,
        urls=urls,
        api_paths=api_paths,
        urls_truncated=urls_truncated,
        api_paths_truncated=api_truncated,
        notes=notes,
    )


class _ZipBundle:
    def __init__(self, archive: zipfile.ZipFile, prefix: str, names: list[str], budget: _Budget) -> None:
        self.archive = archive
        self.prefix = prefix
        self.budget = budget
        self.names = [name[len(prefix) :] for name in names if name.startswith(prefix)]

    def read(self, relative: str, cap: int) -> bytes | None:
        if not _safe_relative(relative):
            return None
        member = self.prefix + relative
        try:
            info = self.archive.getinfo(member)
        except KeyError:
            return None
        reason = _entry_too_large(info, cap)
        if reason:
            raise ScanLimitError(reason)
        self.budget.charge(info.file_size)
        with self.archive.open(info, "r") as handle:
            payload = handle.read(cap + 1)
        if len(payload) > cap:
            raise ScanLimitError(f"{member} expanded past the {cap} byte cap")
        return payload

    def frameworks(self) -> list[str]:
        return _framework_names(self.names)


class _DirBundle:
    def __init__(self, root: Path, budget: _Budget) -> None:
        self.root = root
        self.budget = budget
        self.names = _dir_names(root, budget)

    def read(self, relative: str, cap: int) -> bytes | None:
        path = _resolve_inside(self.root, relative)
        if path is None or not path.is_file():
            return None
        size = path.stat().st_size
        if size > cap:
            raise ScanLimitError(f"{relative} uncompressed size {size} exceeds {cap} bytes")
        self.budget.charge(size)
        return path.read_bytes()

    def frameworks(self) -> list[str]:
        return _framework_names(self.names)


def _directory_root(source: Path) -> Path:
    if source.suffix.lower() == ".app" and (source / "Info.plist").is_file():
        return source
    matches = [item for item in sorted(source.glob("Payload/*.app")) if (item / "Info.plist").is_file()]
    if matches:
        return matches[0]
    if (source / "Info.plist").is_file():
        return source
    raise ValueError("IPA has no Info.plist")


def _zip_prefix(names: list[str]) -> str:
    candidates = []
    for name in names:
        if not name.endswith("/Info.plist") and not name.endswith("Info.plist"):
            continue
        parts = name.split("/")
        if len(parts) < 2 or parts[-1] != "Info.plist" or not parts[-2].endswith(".app"):
            continue
        candidates.append(name[: -len("Info.plist")])
    if not candidates:
        raise ValueError("IPA has no Info.plist")
    payload = [item for item in candidates if item.startswith("Payload/")]
    return sorted(payload or candidates)[0]


def _read_profile(bundle: _ZipBundle | _DirBundle, notes: list[str]) -> tuple[dict | None, str, int | None]:
    try:
        blob = bundle.read("embedded.mobileprovision", _PROFILE_CAP)
    except ScanBudgetError:
        raise
    except ScanLimitError:
        notes.append("embedded.mobileprovision exceeds the scan budget and was not parsed")
        return None, "unparsed", None
    if blob is None:
        return None, "absent", None
    parsed = _plist_in_blob(blob)
    if not isinstance(parsed, dict):
        notes.append("embedded.mobileprovision did not contain a plist this parser understands")
        return None, "unparsed", None
    devices = parsed.get("ProvisionedDevices")
    if isinstance(devices, list) and devices:
        return parsed, "development", len(devices)
    if parsed.get("ProvisionsAllDevices") is True:
        return parsed, "enterprise", None
    return parsed, "distribution", None


def _read_xcent(bundle: _ZipBundle | _DirBundle) -> dict | None:
    seen = 0
    for name in bundle.names:
        if not name.endswith(".xcent") or not _safe_relative(name):
            continue
        seen += 1
        if seen > _MAX_XCENT_FILES:
            break
        try:
            blob = bundle.read(name, _PROFILE_CAP)
        except ScanBudgetError:
            raise
        except ScanLimitError:
            return None
        parsed = _plist_in_blob(blob or b"")
        if isinstance(parsed, dict):
            return parsed
    return None


def _entitlements(profile: dict | None, xcent: dict | None) -> dict:
    merged: dict = {}
    if isinstance(xcent, dict):
        inner = xcent.get("Entitlements")
        merged.update(inner if isinstance(inner, dict) else xcent)
    if isinstance(profile, dict) and isinstance(profile.get("Entitlements"), dict):
        merged.update(profile["Entitlements"])
    return merged


def _read_binary(
    bundle: _ZipBundle | _DirBundle, executable_name: str | None, notes: list[str]
) -> tuple[BinaryView | None, bytes]:
    if not executable_name:
        notes.append("CFBundleExecutable is missing; Mach-O checks were skipped")
        return None, b""
    if not _safe_relative(executable_name):
        notes.append("CFBundleExecutable is not a single file name; Mach-O checks were skipped")
        return None, b""
    try:
        payload = bundle.read(executable_name, MAX_DEX_BYTES)
    except ScanBudgetError:
        raise
    except ScanLimitError:
        notes.append("main executable exceeds the scan budget; Mach-O checks were skipped")
        return BinaryView(executable_name, False, None, None, None, None, None, "not-run"), b""
    if payload is None:
        notes.append("main executable was not in the bundle; Mach-O checks were skipped")
        return BinaryView(executable_name, False, None, None, None, None, None, "not-run"), b""
    parsed = inspect_macho(payload)
    probe = otool_probe(payload)
    apply_otool(parsed, probe)
    if parsed.otool == "absent":
        notes.append("otool is not on PATH. Header flags come from the built-in Mach-O parser.")
    elif parsed.otool == "failed":
        notes.append("otool failed. Header flags come from the built-in Mach-O parser.")
    view = BinaryView(
        name=executable_name,
        parsed=parsed.parsed,
        filetype=parsed.filetype,
        pie=parsed.pie,
        stack_canary=parsed.stack_canary,
        arc=parsed.arc,
        encrypted=parsed.encrypted,
        otool=parsed.otool,
        linked=list(parsed.linked),
        notes=list(parsed.notes),
    )
    if not parsed.parsed:
        notes.append("main executable is not a Mach-O this parser understands; PIE, stack canary, and ARC were skipped")
    return view, parsed.string_sample


def _load_plist(data: bytes) -> tuple[dict, str]:
    try:
        value = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError) as exc:
        raise ValueError(f"Info.plist could not be parsed: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("Info.plist root is not a dictionary")
    kind = "binary" if data.startswith(b"bplist") else "xml"
    return value, kind


def _plist_in_blob(data: bytes) -> dict | None:
    if not data:
        return None
    start = data.find(b"<?xml")
    end = data.find(b"</plist>", start if start >= 0 else 0)
    if start >= 0 and end > start:
        try:
            value = plistlib.loads(data[start : end + len(b"</plist>")])
        except (plistlib.InvalidFileException, ValueError):
            value = None
        if isinstance(value, dict):
            return value
    marker = data.find(b"bplist00")
    if marker >= 0:
        try:
            value = plistlib.loads(data[marker:])
        except (plistlib.InvalidFileException, ValueError):
            return None
        if isinstance(value, dict):
            return value
    return None


def _ats(plist: dict) -> dict:
    raw = plist.get("NSAppTransportSecurity")
    return raw if isinstance(raw, dict) else {}


def _ats_flag(plist: dict, key: str) -> bool:
    return _bool(_ats(plist).get(key)) is True


def _ats_exceptions(plist: dict) -> list[AtsException]:
    raw = _ats(plist).get("NSExceptionDomains")
    if not isinstance(raw, dict):
        return []
    found: list[AtsException] = []
    for domain, config in raw.items():
        if not isinstance(domain, str) or not isinstance(config, dict):
            continue
        forward = _bool(config.get("NSExceptionRequiresForwardSecrecy"))
        found.append(
            AtsException(
                domain=domain[:200],
                insecure_http=_bool(config.get("NSExceptionAllowsInsecureHTTPLoads")) is True,
                minimum_tls=_plain(config.get("NSExceptionMinimumTLSVersion")),
                includes_subdomains=_bool(config.get("NSIncludesSubdomains")) is True,
                requires_forward_secrecy=forward,
            )
        )
    return found


def _url_schemes(plist: dict) -> list[str]:
    raw = plist.get("CFBundleURLTypes")
    if not isinstance(raw, list):
        return []
    schemes: list[str] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        names = entry.get("CFBundleURLSchemes")
        if not isinstance(names, list):
            continue
        for name in names:
            text = _plain(name)
            if text and text not in schemes:
                schemes.append(text[:80])
    return schemes


def _usage_strings(plist: dict) -> dict[str, str]:
    found: dict[str, str] = {}
    for key, value in plist.items():
        if isinstance(key, str) and key.endswith("UsageDescription"):
            found[key] = value if isinstance(value, str) else ""
    return found


def _framework_names(names: list[str]) -> list[str]:
    found: list[str] = []
    for name in names:
        if "Frameworks/" not in name or ".framework" not in name:
            continue
        tail = name.split("Frameworks/", 1)[1]
        framework = tail.split(".framework", 1)[0].split("/")[-1]
        if framework and framework not in found:
            found.append(framework[:120])
        if len(found) >= 64:
            break
    return sorted(found)


def _plist_strings(value: object, found: list[str] | None = None, depth: int = 0) -> list[str]:
    if found is None:
        found = []
    if depth > 8 or len(found) > 4000:
        return found
    if isinstance(value, str):
        found.append(value[:500])
    elif isinstance(value, dict):
        for item in value.values():
            _plist_strings(item, found, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _plist_strings(item, found, depth + 1)
    return found


def _utf8_strings(sample: bytes) -> list[str]:
    found: list[str] = []
    for raw in sample.split(b"\x00"):
        if not 4 <= len(raw) <= 300:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeError:
            continue
        if text.isprintable():
            found.append(text)
        if len(found) >= 8000:
            break
    return found


def _urls(texts: list[str]) -> tuple[list[str], bool]:
    found: list[str] = []
    for text in texts:
        for match in _URL_RE.finditer(text):
            url = match.group(0).rstrip(").,;]}")
            host = (urlparse(url).hostname or "").lower()
            if host in _IGNORED_HOSTS or any(host.endswith("." + item) for item in ("example.com",)):
                continue
            if url not in found:
                found.append(url)
            if len(found) >= MAX_RETAINED_URLS:
                return found, True
    return found, False


def _api_paths(texts: list[str]) -> tuple[list[str], bool]:
    found: list[str] = []
    for text in texts:
        if _API_RE.match(text) and text not in found:
            found.append(text)
            if len(found) >= MAX_RETAINED_API_PATHS:
                return found, True
    return found, False


def _dir_names(root: Path, budget: _Budget) -> list[str]:
    names: list[str] = []
    resolved = root.resolve()
    budget.check()
    for path in root.rglob("*"):
        if len(names) >= MAX_ZIP_ENTRIES:
            break
        if len(names) % 256 == 0:
            budget.check()
        try:
            relative = path.resolve().relative_to(resolved)
        except (OSError, ValueError):
            continue
        if any(part == ".." for part in relative.parts):
            continue
        names.append(relative.as_posix())
    return names


def _resolve_inside(root: Path, relative: str) -> Path | None:
    if not _safe_relative(relative):
        return None
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except (OSError, ValueError):
        return None
    return candidate


def _safe_relative(relative: str) -> bool:
    if not relative or relative.startswith(("/", "\\")):
        return False
    parts = Path(relative).parts
    return bool(parts) and not any(part in {"", ".", ".."} for part in parts)


def _safe_zip_name(name: str) -> bool:
    if not name or name.startswith(("/", "\\")) or "\\" in name:
        return False
    return ".." not in name.split("/")


def _entry_too_large(info: zipfile.ZipInfo, cap: int) -> str | None:
    if info.file_size > cap:
        return f"{info.filename} uncompressed size {info.file_size} exceeds {cap} bytes"
    if info.compress_type != zipfile.ZIP_STORED:
        ratio = info.file_size / max(info.compress_size, 1)
        if ratio > MAX_COMPRESSION_RATIO:
            return f"{info.filename} compression ratio {ratio:.0f} exceeds {MAX_COMPRESSION_RATIO}"
    return None


def _plain(value: object) -> str | None:
    if isinstance(value, str):
        text = value.strip()
        return text[:200] if text else None
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return None


def _bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if value in {1, "1", "true", "True", "YES"}:
        return True
    if value in {0, "0", "false", "False", "NO"}:
        return False
    return None


def _str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    found: list[str] = []
    for item in value:
        text = _plain(item)
        if text and text not in found:
            found.append(text[:200])
        if len(found) >= 32:
            break
    return found
