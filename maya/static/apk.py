"""Read the static facts Maya can recover from an APK without apktool."""

from __future__ import annotations

import re
import struct
import time
import zipfile
from dataclasses import dataclass, field
from urllib.parse import urlparse

from maya.static.binary_xml import XmlNode, iter_string_pool, parse_binary_xml
from maya.static.limits import (
    MAX_ARSC_BYTES,
    MAX_COMPRESSION_RATIO,
    MAX_DEX_BYTES,
    MAX_DEX_FILES,
    MAX_DEX_STRING_BYTES,
    MAX_DEX_STRINGS,
    MAX_MANIFEST_BYTES,
    MAX_TOTAL_BYTES,
    MAX_XML_BYTES,
    MAX_XML_FILES,
    MAX_ZIP_ENTRIES,
    SCAN_DEADLINE_SECONDS,
    ScanLimitError,
)

_URL_RE = re.compile(r"https?://[^\s\"'<>]{4,200}")
_API_RE = re.compile(r"^/(?:api|rest|graphql)(?:/[A-Za-z0-9_.{}\-]{1,48}){1,8}$")
_IGNORED_HOSTS = {
    "schemas.android.com",
    "www.w3.org",
    "xmlpull.org",
    "xml.org",
    "ns.adobe.com",
    "plus.google.com",
    "developer.android.com",
    "localhost",
    "127.0.0.1",
    "example.com",
    "www.example.com",
}


@dataclass
class IntentFilter:
    actions: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    schemes: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)


@dataclass
class Component:
    kind: str
    name: str
    exported: bool | None
    permission: str
    intent_filters: list[IntentFilter] = field(default_factory=list)


@dataclass
class NetworkSecurity:
    present: bool = False
    cleartext: bool | None = None
    trusts_user_cas: bool = False
    trusts_system_cas: bool = False


@dataclass
class ApkFacts:
    package_name: str
    version_name: str | None
    version_code: int | None
    min_sdk: int | None
    target_sdk: int | None
    permissions: list[str]
    allow_backup: bool | None
    debuggable: bool | None
    uses_cleartext: bool | None
    components: list[Component]
    network_security: NetworkSecurity
    urls: list[str]
    api_paths: list[str]
    native_libraries: list[str]


def load_apk(path: str) -> ApkFacts:
    """Open an APK and collect manifest, network-security, string, and native facts."""
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise ValueError(f"not a zip APK: {path}") from exc
    with archive:
        names = archive.namelist()
        if len(names) > MAX_ZIP_ENTRIES:
            raise ScanLimitError(f"APK has {len(names)} entries; the scan budget is {MAX_ZIP_ENTRIES}")
        if "AndroidManifest.xml" not in names:
            raise ValueError("APK has no AndroidManifest.xml")
        session = _ScanSession()
        manifest_bytes = session.read(archive, "AndroidManifest.xml", MAX_MANIFEST_BYTES)
        manifest = parse_binary_xml(manifest_bytes, deadline=session.deadline)
        if manifest is None or manifest.name != "manifest":
            raise ValueError("AndroidManifest.xml has no manifest root")
        network = _network_security(archive, names, session)
        urls, api_paths = _collect_strings(archive, names, session)
    return _facts_from_manifest(manifest, network, urls, api_paths, _native_libraries(names))


class _ScanSession:
    """Tracks uncompressed bytes and wall time for one APK read."""

    def __init__(self) -> None:
        self.deadline = time.monotonic() + SCAN_DEADLINE_SECONDS
        self._used = 0

    def read(self, archive: zipfile.ZipFile, name: str, cap: int) -> bytes:
        self._check_time()
        info = archive.getinfo(name)
        reason = _entry_too_large(info, cap)
        if reason:
            raise ScanLimitError(reason)
        self._used += info.file_size
        if self._used > MAX_TOTAL_BYTES:
            raise ScanLimitError(f"APK entries expand past the {MAX_TOTAL_BYTES} byte scan budget")
        with archive.open(info, "r") as handle:
            payload = handle.read(cap + 1)
        if len(payload) > cap:
            raise ScanLimitError(f"{name} expanded past the {cap} byte cap")
        return payload

    def _check_time(self) -> None:
        if time.monotonic() > self.deadline:
            raise ScanLimitError("static scan exceeded the time budget")


def _entry_too_large(info: zipfile.ZipInfo, cap: int) -> str | None:
    """Reject a declared size or compression ratio before zlib inflates the entry."""
    if info.file_size > cap:
        return f"{info.filename} uncompressed size {info.file_size} exceeds {cap} bytes"
    if info.compress_type != zipfile.ZIP_STORED:
        ratio = info.file_size / max(info.compress_size, 1)
        if ratio > MAX_COMPRESSION_RATIO:
            return f"{info.filename} compression ratio {ratio:.0f} exceeds {MAX_COMPRESSION_RATIO}"
    return None


def _facts_from_manifest(
    manifest: XmlNode,
    network: NetworkSecurity,
    urls: list[str],
    api_paths: list[str],
    native_libraries: list[str],
) -> ApkFacts:
    package_name = _as_str(manifest.attrs.get("package"))
    version_name = _as_optional_str(manifest.attrs.get("versionName"))
    version_code = _as_int(manifest.attrs.get("versionCode"))
    min_sdk = None
    target_sdk = None
    permissions: list[str] = []
    allow_backup: bool | None = None
    debuggable: bool | None = None
    uses_cleartext: bool | None = None
    components: list[Component] = []

    for child in manifest.children:
        if child.name == "uses-sdk":
            min_sdk = _as_int(child.attrs.get("minSdkVersion"))
            target_sdk = _as_int(child.attrs.get("targetSdkVersion"))
        elif child.name == "uses-permission":
            permission = _as_str(child.attrs.get("name"))
            if permission:
                permissions.append(permission)
        elif child.name == "application":
            if "allowBackup" in child.attrs:
                allow_backup = _as_bool(child.attrs.get("allowBackup"))
            if "debuggable" in child.attrs:
                debuggable = _as_bool(child.attrs.get("debuggable"))
            if "usesCleartextTraffic" in child.attrs:
                uses_cleartext = _as_bool(child.attrs.get("usesCleartextTraffic"))
            components = _components(child, package_name)

    return ApkFacts(
        package_name=package_name,
        version_name=version_name,
        version_code=version_code,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        permissions=sorted(set(permissions)),
        allow_backup=allow_backup,
        debuggable=debuggable,
        uses_cleartext=uses_cleartext,
        components=components,
        network_security=network,
        urls=urls,
        api_paths=api_paths,
        native_libraries=native_libraries,
    )


def _components(application: XmlNode, package_name: str) -> list[Component]:
    components: list[Component] = []
    for child in application.children:
        if child.name not in {"activity", "activity-alias", "service", "receiver", "provider"}:
            continue
        exported = None if "exported" not in child.attrs else _as_bool(child.attrs.get("exported"))
        components.append(
            Component(
                kind="activity" if child.name == "activity-alias" else child.name,
                name=_qualify(_as_str(child.attrs.get("name")), package_name),
                exported=exported,
                permission=_as_str(child.attrs.get("permission")),
                intent_filters=[_intent_filter(node) for node in child.children if node.name == "intent-filter"],
            )
        )
    return components


def _intent_filter(node: XmlNode) -> IntentFilter:
    parsed = IntentFilter()
    for child in node.children:
        if child.name == "action":
            name = _as_str(child.attrs.get("name"))
            if name:
                parsed.actions.append(name)
        elif child.name == "category":
            name = _as_str(child.attrs.get("name"))
            if name:
                parsed.categories.append(name)
        elif child.name == "data":
            scheme = _as_str(child.attrs.get("scheme"))
            host = _as_str(child.attrs.get("host"))
            if scheme:
                parsed.schemes.append(scheme)
            if host:
                parsed.hosts.append(host)
    return parsed


def _network_security(archive: zipfile.ZipFile, names: list[str], session: _ScanSession) -> NetworkSecurity:
    summary = NetworkSecurity()
    xml_names = [name for name in names if name.startswith("res/xml/") and name.endswith(".xml")]
    if len(xml_names) > MAX_XML_FILES:
        raise ScanLimitError(f"APK has {len(xml_names)} res/xml files; the scan budget is {MAX_XML_FILES}")
    for name in xml_names:
        payload = session.read(archive, name, MAX_XML_BYTES)
        if len(payload) < 8 or struct.unpack_from("<H", payload, 0)[0] != 0x0003:
            continue
        try:
            root = parse_binary_xml(payload, deadline=session.deadline)
        except ValueError as exc:
            if isinstance(exc, ScanLimitError):
                raise
            continue
        if root is None or root.name != "network-security-config":
            continue
        summary.present = True
        _walk_network_security(root, summary)
    return summary


def _walk_network_security(node: XmlNode, summary: NetworkSecurity) -> None:
    if node.name in {"base-config", "domain-config"} and isinstance(node.attrs.get("cleartextTrafficPermitted"), bool):
        permitted = bool(node.attrs["cleartextTrafficPermitted"])
        summary.cleartext = permitted if summary.cleartext is None else summary.cleartext or permitted
    if node.name == "certificates":
        source = node.attrs.get("src")
        if source == "user":
            summary.trusts_user_cas = True
        elif source == "system":
            summary.trusts_system_cas = True
    for child in node.children:
        _walk_network_security(child, summary)


def _collect_strings(archive: zipfile.ZipFile, names: list[str], session: _ScanSession) -> tuple[list[str], list[str]]:
    urls: list[str] = []
    api_paths: list[str] = []
    seen_urls: set[str] = set()
    seen_paths: set[str] = set()

    def keep(raw: str) -> None:
        if not raw or len(raw) > MAX_DEX_STRING_BYTES:
            return
        if _API_RE.match(raw) and raw not in seen_paths:
            seen_paths.add(raw)
            api_paths.append(raw)
        for match in _URL_RE.findall(raw):
            url = match.rstrip(").,;\"'")
            if url in seen_urls or _ignored_url(url):
                continue
            seen_urls.add(url)
            urls.append(url)

    if "resources.arsc" in names:
        payload = session.read(archive, "resources.arsc", MAX_ARSC_BYTES)
        for raw in _resource_strings(payload, session.deadline):
            keep(raw)
    dex_names = [
        name for name in names if name == "classes.dex" or (name.startswith("classes") and name.endswith(".dex"))
    ]
    if len(dex_names) > MAX_DEX_FILES:
        raise ScanLimitError(f"APK has {len(dex_names)} dex files; the scan budget is {MAX_DEX_FILES}")
    for name in dex_names:
        for raw in _dex_strings(session.read(archive, name, MAX_DEX_BYTES), session.deadline):
            keep(raw)
    return urls, api_paths


def _resource_strings(data: bytes, deadline: float):
    if len(data) < 12:
        return
    chunk_type, header_size, _chunk_size = struct.unpack_from("<HHI", data, 0)
    if chunk_type != 0x0002 or header_size < 12 or header_size + 8 > len(data):
        return
    pool_type = struct.unpack_from("<H", data, header_size)[0]
    if pool_type != 0x0001:
        return
    yield from iter_string_pool(data, header_size, deadline=deadline)


def _dex_strings(data: bytes, deadline: float):
    if len(data) < 112 or not data.startswith(b"dex\n"):
        return
    count = struct.unpack_from("<I", data, 56)[0]
    if count > MAX_DEX_STRINGS:
        raise ScanLimitError(f"dex string count {count} exceeds {MAX_DEX_STRINGS}")
    offset = struct.unpack_from("<I", data, 60)[0]
    for index in range(count):
        if index % 4096 == 0 and time.monotonic() > deadline:
            raise ScanLimitError("static scan exceeded the time budget")
        entry = offset + index * 4
        if entry + 4 > len(data):
            break
        string_at = struct.unpack_from("<I", data, entry)[0]
        if string_at >= len(data):
            continue
        try:
            _utf16_len, cursor = _uleb128(data, string_at)
        except ValueError:
            continue
        if cursor >= len(data):
            continue
        end = data.find(b"\x00", cursor, cursor + MAX_DEX_STRING_BYTES + 1)
        if end == -1:
            continue
        yield data[cursor:end].decode("utf-8", "replace")


def _uleb128(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while offset < len(data) and shift <= 28:
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return result, offset
        shift += 7
    raise ValueError("bad uleb128")


def _ignored_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return True
    if host in _IGNORED_HOSTS or host.endswith(".googlesource.com"):
        return True
    return host.endswith(".android.com") and host.startswith("schemas.")


def _native_libraries(names: list[str]) -> list[str]:
    libraries = [name for name in names if name.startswith("lib/") and name.endswith(".so")]
    return sorted(set(libraries))


def _qualify(name: str, package_name: str) -> str:
    if not name:
        return ""
    if name.startswith("."):
        return f"{package_name}{name}" if package_name else name
    if "." not in name and package_name:
        return f"{package_name}.{name}"
    return name


def _as_str(value: object) -> str:
    return value if isinstance(value, str) else ""


def _as_optional_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _as_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _as_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
    return None
