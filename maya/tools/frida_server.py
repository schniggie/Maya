"""Download and start the frida-server build that matches Maya's Frida client.

The version comes from ``--frida-version``, ``MAYA_FRIDA_VERSION``, the
installed ``frida`` distribution, then the pin in the ``dynamic`` extra.
The download URL is built only for a ``X.Y.Z`` release and a known ABI.
"""

from __future__ import annotations

import lzma
import os
import re
import time
from collections.abc import Callable, Mapping
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

import requests

from maya.tools.emulator import ALLOWED_ABIS, run_command

PINNED_FRIDA_VERSION = "16.7.19"
REMOTE_PATH = "/data/local/tmp/frida-server"
MAX_DOWNLOAD_BYTES = 80 * 1024 * 1024
MAX_BINARY_BYTES = 120 * 1024 * 1024
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_RELEASE_PREFIX = "https://github.com/frida/frida/releases/download/"
FRIDA_ARCH = {
    "x86_64": "x86_64",
    "x86": "x86",
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
}

Fetcher = Callable[[str, Path], dict[str, Any]]
Runner = Callable[..., dict[str, Any]]


def _error(message: str, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"status": "error", "error": message}
    payload.update(extra)
    return payload


def exact_version(value: str) -> str | None:
    cleaned = value.strip()
    if _VERSION_RE.fullmatch(cleaned):
        return cleaned
    return None


def normalize_version(value: str) -> str | None:
    """Accept ``16.7.19`` and an installed version such as ``16.7.19.dev0``."""
    match = re.match(r"^(\d+\.\d+\.\d+)", value.strip())
    if match is None:
        return None
    return match.group(1)


def installed_frida_version() -> str | None:
    try:
        return version("frida")
    except PackageNotFoundError:
        return None


def resolve_frida_version(
    explicit: str | None = None,
    *,
    installed: str | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Choose the frida-server version. An explicit bad version is an error, not a silent fallback."""
    source = os.environ if env is None else env
    if explicit is not None and str(explicit).strip():
        parsed = exact_version(str(explicit))
        if parsed is None:
            return _error(
                f"frida version must look like {PINNED_FRIDA_VERSION}, got {explicit!r}",
                missing="frida-version",
            )
        return {"status": "ok", "version": parsed, "source": "flag"}
    from_env = source.get("MAYA_FRIDA_VERSION", "").strip()
    if from_env:
        parsed = exact_version(from_env)
        if parsed is None:
            return _error(
                f"MAYA_FRIDA_VERSION must look like {PINNED_FRIDA_VERSION}, got {from_env!r}",
                missing="frida-version",
            )
        return {"status": "ok", "version": parsed, "source": "env"}
    if installed:
        parsed = normalize_version(installed)
        if parsed is not None:
            return {"status": "ok", "version": parsed, "source": "package"}
    return {"status": "ok", "version": PINNED_FRIDA_VERSION, "source": "pin"}


def frida_server_asset(version: str, abi: str) -> dict[str, Any]:
    """Map a version and Android ABI to the official frida-server release asset."""
    parsed = exact_version(version)
    if parsed is None:
        return _error(f"frida version must look like {PINNED_FRIDA_VERSION}, got {version!r}")
    if abi not in ALLOWED_ABIS:
        return _error(f"ABI must be one of {', '.join(ALLOWED_ABIS)}, got {abi!r}", missing="abi")
    arch = FRIDA_ARCH[abi]
    asset = f"frida-server-{parsed}-android-{arch}.xz"
    url = f"{_RELEASE_PREFIX}{parsed}/{asset}"
    return {"status": "ok", "version": parsed, "abi": abi, "arch": arch, "asset": asset, "url": url}


def download_file(url: str, dest: Path, *, timeout: int = 180, limit: int = MAX_DOWNLOAD_BYTES) -> dict[str, Any]:
    if not url.startswith(_RELEASE_PREFIX):
        return _error("refusing to download frida-server from an unexpected URL", url=url)
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_name(dest.name + ".part")
    size = 0
    try:
        with requests.get(url, stream=True, timeout=timeout) as response:
            if response.status_code != 200:
                return _error(f"frida-server download failed: HTTP {response.status_code}", url=url)
            with partial.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=256 * 1024):
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > limit:
                        break
                    handle.write(chunk)
        if size > limit:
            partial.unlink(missing_ok=True)
            return _error("frida-server download exceeds the size cap", url=url)
        if size <= 0:
            partial.unlink(missing_ok=True)
            return _error("frida-server download was empty", url=url)
        partial.replace(dest)
    except requests.RequestException as exc:
        partial.unlink(missing_ok=True)
        return _error(f"frida-server download failed: {exc}", url=url)
    return {"status": "ok", "path": str(dest), "bytes": size}


def extract_xz(archive: Path, dest: Path, *, limit: int = MAX_BINARY_BYTES) -> dict[str, Any]:
    try:
        with lzma.open(archive, "rb") as handle:
            payload = handle.read(limit + 1)
    except (lzma.LZMAError, OSError) as exc:
        return _error(f"could not decompress frida-server: {exc}")
    if len(payload) > limit:
        return _error("decompressed frida-server exceeds the size cap")
    if not payload:
        return _error("frida-server archive was empty")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(payload)
    dest.chmod(0o755)
    return {"status": "ok", "path": str(dest), "bytes": len(payload)}


def frida_cache_dir(version: str, abi: str, root: Path | None = None) -> Path:
    if root is None:
        override = os.environ.get("MAYA_FRIDA_CACHE", "").strip()
        base = Path(override).expanduser() if override else Path.home() / ".maya" / "cache" / "frida-server"
    else:
        base = root
    return base / version / abi


def ensure_frida_binary(
    version: str,
    abi: str,
    *,
    cache_dir: Path | None = None,
    fetcher: Fetcher | None = None,
) -> dict[str, Any]:
    asset = frida_server_asset(version, abi)
    if asset.get("status") != "ok":
        return asset
    directory = frida_cache_dir(asset["version"], abi, cache_dir)
    directory.mkdir(parents=True, exist_ok=True)
    binary = directory / "frida-server"
    if binary.is_file() and binary.stat().st_size > 0:
        return {"status": "ok", "path": str(binary), "cached": True, **asset}
    archive = directory / asset["asset"]
    if not archive.is_file():
        fetched = (fetcher or download_file)(asset["url"], archive)
        if fetched.get("status") != "ok":
            return fetched
    extracted = extract_xz(archive, binary)
    if extracted.get("status") != "ok":
        return extracted
    extracted["cached"] = False
    extracted.update({key: asset[key] for key in ("version", "abi", "arch", "asset", "url")})
    return extracted


def root_available(root_result: dict[str, Any], id_result: dict[str, Any] | None = None) -> bool:
    """True when adbd is root or a shell ``id`` already shows ``uid=0``."""
    if root_result.get("missing_binary") or root_result.get("timed_out"):
        return False
    text = f"{root_result.get('stdout') or ''}\n{root_result.get('stderr') or ''}".lower()
    identity = "" if id_result is None else (id_result.get("stdout") or "")
    if "cannot run as root" in text:
        return "uid=0" in identity
    if root_result.get("exit_code") == 0:
        return True
    return "uid=0" in identity


def frida_server_running(stdout: str) -> bool:
    for line in stdout.splitlines():
        cleaned = line.strip()
        if not cleaned or "grep" in cleaned:
            continue
        if "frida-server" in cleaned or cleaned.isdigit():
            return True
    return False


def _adb(runner: Runner, argv: list[str], *, timeout: int, sleep: Callable[[float], None], retries: int = 2) -> dict:
    last: dict[str, Any] = {"exit_code": None, "stdout": "", "stderr": ""}
    for _attempt in range(retries):
        last = runner(argv, timeout=timeout)
        text = f"{last.get('stdout') or ''}\n{last.get('stderr') or ''}".lower()
        if last.get("exit_code") == 0 or last.get("missing_binary"):
            return last
        if "offline" in text or "not found" in text or "closed" in text:
            sleep(1)
            continue
        return last
    return last


def provision_frida_server(
    *,
    serial: str,
    adb: Path,
    abi: str,
    version: str,
    runner: Runner | None = None,
    cache_dir: Path | None = None,
    fetcher: Fetcher | None = None,
    sleep: Callable[[float], None] | None = None,
) -> dict[str, Any]:
    """Push the matching frida-server, start it, and check that the process is up.

    ``adb root`` failure on a production image is an error dict. The emulator is left running.
    """
    run = runner or run_command
    pause = sleep or time.sleep
    binary_info = ensure_frida_binary(version, abi, cache_dir=cache_dir, fetcher=fetcher)
    if binary_info.get("status") != "ok":
        return binary_info
    binary = Path(binary_info["path"])

    root = _adb(run, [str(adb), "-s", serial, "root"], timeout=30, sleep=pause)
    if root.get("missing_binary"):
        return _error(
            "adb is not available. Install platform-tools before provisioning frida-server.",
            missing="adb",
        )
    identity = None
    if not root_available(root):
        identity = run([str(adb), "-s", serial, "shell", "id"], timeout=20)
        if identity.get("missing_binary"):
            return _error("adb is not available", missing="adb")
    if not root_available(root, identity):
        detail = f"{root.get('stderr') or ''} {root.get('stdout') or ''}".strip()
        return _error(
            (
                "adb root is unavailable, so frida-server cannot be started. "
                "Use a google_apis or aosp_atd (userdebug) system image. "
                "Play Store images are production builds and refuse adb root."
            ),
            missing="root",
            detail=detail[-400:],
        )
    if "restarting" in f"{root.get('stdout') or ''} {root.get('stderr') or ''}".lower():
        pause(2)
    # userdebug images often start enforcing. frida-server is instrumentation, not a bypass.
    run([str(adb), "-s", serial, "shell", "setenforce", "0"], timeout=15)

    pushed = _adb(run, [str(adb), "-s", serial, "push", str(binary), REMOTE_PATH], timeout=120, sleep=pause)
    if pushed.get("missing_binary"):
        return _error("adb is not available", missing="adb")
    if pushed.get("exit_code") != 0:
        detail = f"{pushed.get('stderr') or ''}\n{pushed.get('stdout') or ''}".strip()
        return _error("adb push of frida-server failed", detail=detail[-400:], missing="adb")

    mode = _adb(run, [str(adb), "-s", serial, "shell", "chmod", "755", REMOTE_PATH], timeout=20, sleep=pause)
    if mode.get("exit_code") != 0:
        return _error("chmod of frida-server failed", detail=(mode.get("stderr") or "")[-300:])

    started = _adb(run, [str(adb), "-s", serial, "shell", REMOTE_PATH, "-D"], timeout=20, sleep=pause)
    if started.get("timed_out"):
        # -D should return. A timeout can still leave the server up; the health check decides.
        pass
    elif started.get("exit_code") not in (0, None) and not started.get("timed_out"):
        detail = f"{started.get('stderr') or ''}\n{started.get('stdout') or ''}".strip()
        if "address already in use" not in detail.lower():
            return _error("frida-server did not start", detail=detail[-400:])

    health = _adb(run, [str(adb), "-s", serial, "shell", "pidof", "frida-server"], timeout=20, sleep=pause)
    if not frida_server_running(health.get("stdout") or ""):
        ps = run([str(adb), "-s", serial, "shell", "ps"], timeout=20)
        if not frida_server_running(ps.get("stdout") or ""):
            detail = f"{started.get('stderr') or ''}\n{health.get('stdout') or ''}\n{ps.get('stdout') or ''}".strip()
            return _error("frida-server is not running after start", detail=detail[-400:])
    return {
        "status": "ok",
        "serial": serial,
        "version": binary_info.get("version", version),
        "abi": abi,
        "path": str(binary),
        "remote": REMOTE_PATH,
        "cached": bool(binary_info.get("cached")),
    }
