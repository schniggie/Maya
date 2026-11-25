"""Boot an emulator, install an APK, start frida-server, and smoke one enumerate script.

This is orchestration around the existing Frida catalog and companion client.
It does not add scripts. The smoke refuses anything outside ``enumerate/``.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from maya.static.apk import load_apk
from maya.static.limits import ScanLimitError
from maya.tools.companion_client import CompanionClient
from maya.tools.emulator import (
    PACKAGE_RE,
    SdkLayout,
    boot_emulator,
    build_config,
    device_abi,
    find_sdk,
    install_apk,
    launch_package,
    teardown_emulator,
)
from maya.tools.frida_scripts import list_scripts, load_script
from maya.tools.frida_server import installed_frida_version, provision_frida_server, resolve_frida_version
from maya.tools.frida_tool import frida_run_named_script

DEFAULT_SMOKE_SCRIPT = "enumerate/loaded_classes"
_SMOKE_RE = re.compile(r"^enumerate/[A-Za-z0-9_-]+$")
_FAILURE_MARKERS = (
    "unable to connect",
    "failed to spawn",
    "unable to find process",
    "device not found",
    "connection refused",
    "unable to communicate",
)


def _error(message: str, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"status": "error", "error": message}
    payload.update(extra)
    return payload


def validate_smoke_script(name: str) -> dict[str, Any] | None:
    """The headless path only injects an enumerate script."""
    cleaned = name.strip().replace("\\", "/")
    if cleaned.endswith(".js"):
        cleaned = cleaned[: -len(".js")]
    if _SMOKE_RE.fullmatch(cleaned):
        return None
    return _error(
        (
            "the headless smoke only loads one enumerate/ script "
            "(for example enumerate/loaded_classes or enumerate/class_methods)"
        ),
        name=name,
    )


def resolve_package_name(package: str, target: str | None, *, reader: Callable[[str], Any] | None = None) -> dict:
    if target and PACKAGE_RE.fullmatch(target):
        return {"status": "ok", "package_name": target}
    load = reader or load_apk
    try:
        facts = load(package)
    except (OSError, ValueError, ScanLimitError) as exc:
        return _error(f"could not read the APK package name: {exc}. Pass --target com.example.app.")
    name = getattr(facts, "package_name", None)
    if name is None and isinstance(facts, dict):
        name = facts.get("package_name")
    if not isinstance(name, str) or not PACKAGE_RE.fullmatch(name):
        return _error("APK manifest has no usable package name. Pass --target com.example.app.")
    return {"status": "ok", "package_name": name}


def judge_injection(result: dict[str, Any]) -> dict[str, Any]:
    """Decide whether a short Frida attach of an enumerate script counted as a smoke pass."""
    if result.get("missing_binary"):
        return _error(
            "frida CLI is not installed. Install the dynamic extra: pip install -e '.[dynamic]'",
            missing="frida",
        )
    stdout = result.get("stdout") or ""
    stderr = result.get("stderr") or ""
    combined = f"{stdout}\n{stderr}".lower()
    if result.get("exit_code") == 0:
        return {"status": "ok"}
    if any(marker in combined for marker in _FAILURE_MARKERS):
        return _error("frida could not attach to the target on the emulator", detail=stderr[-400:])
    if result.get("timed_out") and (stdout.strip() or "spawned" in combined):
        return {"status": "ok", "note": "frida stayed attached until the smoke timeout"}
    if result.get("timed_out"):
        return _error("enumerate script produced no output before the smoke timeout", detail=stderr[-400:])
    detail = (result.get("error") or stderr or stdout or "frida smoke failed").strip()
    return _error(detail[-400:], exit_code=result.get("exit_code"))


def probe_companion(serial: str, adb: Path, *, runner: Callable[..., dict[str, Any]] | None = None) -> dict[str, Any]:
    """Forward host :9999 and ask the companion client. A missing companion is not a failure."""
    from maya.tools.emulator import run_command

    run = runner or run_command
    forwarded = run([str(adb), "-s", serial, "forward", "tcp:9999", "tcp:9999"], timeout=20)
    client = CompanionClient(
        "http://127.0.0.1:9999",
        read_timeout=2,
        connect_timeout=1,
        attempts=1,
        backoff_seconds=0,
    )
    health = client.health()
    available = bool(health.get("available"))
    return {
        "status": "ok" if available else "unavailable",
        "available": available,
        "forward_exit_code": forwarded.get("exit_code"),
        "health_status": health.get("status"),
        "error": None if available else health.get("error"),
    }


def _trim(value: Any, limit: int = 4000) -> str:
    text = "" if value is None else str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + "\n… truncated …"


def _write_result(directory: Path, result: dict[str, Any]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "emulator-smoke.json").write_text(
        json.dumps(result, indent=2, default=str) + "\n",
        encoding="utf-8",
    )


def _smoke_timeout(explicit: int | None, env: Mapping[str, str]) -> tuple[int | None, dict[str, Any] | None]:
    raw: Any = explicit
    if raw is None:
        raw = env.get("MAYA_EMULATOR_SMOKE_TIMEOUT", "").strip() or 25
    try:
        timeout = int(raw)
    except (TypeError, ValueError):
        return None, _error(f"smoke timeout must be an integer, got {raw!r}")
    if timeout < 5 or timeout > 300:
        return None, _error("smoke timeout must be between 5 and 300 seconds")
    return timeout, None


def run_headless_dynamic(
    package: str,
    *,
    target: str | None = None,
    api: int | None = None,
    abi: str | None = None,
    device: str | None = None,
    avd_name: str | None = None,
    port: int | None = None,
    frida_version: str | None = None,
    script: str = DEFAULT_SMOKE_SCRIPT,
    keep: bool = False,
    output_dir: str | None = None,
    boot_timeout: int | None = None,
    smoke_timeout: int | None = None,
    env: Mapping[str, str] | None = None,
    machine: str | None = None,
) -> dict[str, Any]:
    """Boot, install, provision frida-server, load one enumerate script, then tear down."""
    source = os.environ if env is None else env
    rejected = validate_smoke_script(script)
    if rejected:
        return rejected
    package_path = Path(package)
    if not package_path.is_file():
        return _error(f"APK not found: {package}")
    timeout, problem = _smoke_timeout(smoke_timeout, source)
    if problem or timeout is None:
        return problem or _error("invalid smoke timeout")
    config, problem = build_config(
        source,
        api=api,
        abi=abi,
        device=device,
        name=avd_name,
        port=port,
        boot_timeout=boot_timeout,
        machine=machine,
    )
    if problem or config is None:
        return problem or _error("invalid emulator configuration")
    sdk_result = find_sdk(source)
    if sdk_result.get("status") != "ok":
        return sdk_result
    sdk: SdkLayout = sdk_result["sdk"]
    named = resolve_package_name(str(package_path), target)
    if named.get("status") != "ok":
        return named
    package_name = named["package_name"]
    out = Path(output_dir) if output_dir else Path("maya_runs") / package_name
    out.mkdir(parents=True, exist_ok=True)

    boot = boot_emulator(config, sdk, output_dir=out, env=source)
    if boot.get("status") != "ok":
        boot["output_dir"] = str(out)
        _write_result(out, boot)
        return boot

    holder: dict[str, Any] = {}
    try:
        holder["result"] = _smoke(
            package_path=package_path,
            package_name=package_name,
            script=script,
            sdk=sdk,
            boot=boot,
            frida_version=frida_version,
            env=source,
            timeout=timeout,
            output_dir=out,
        )
        return holder["result"]
    finally:
        torn_down = False
        if boot.get("started_by_us") and not keep:
            teardown_emulator(boot["serial"], sdk.adb)
            torn_down = True
        if "result" in holder:
            holder["result"]["torn_down"] = torn_down
            _write_result(out, holder["result"])


def _smoke(
    *,
    package_path: Path,
    package_name: str,
    script: str,
    sdk: SdkLayout,
    boot: dict[str, Any],
    frida_version: str | None,
    env: Mapping[str, str],
    timeout: int,
    output_dir: Path,
) -> dict[str, Any]:
    serial = boot["serial"]
    base = {
        "serial": serial,
        "avd": boot.get("avd"),
        "image": boot.get("image"),
        "abi": boot.get("abi"),
        "package_name": package_name,
        "script": script,
        "output_dir": str(output_dir),
        "reused": boot.get("reused", False),
    }
    installed = install_apk(serial, sdk.adb, package_path)
    if installed.get("status") != "ok":
        installed.update(base)
        return installed

    running_abi = device_abi(serial, sdk.adb) or str(boot.get("abi") or "")
    chosen = resolve_frida_version(frida_version, installed=installed_frida_version(), env=env)
    if chosen.get("status") != "ok":
        chosen.update(base)
        return chosen
    server = provision_frida_server(serial=serial, adb=sdk.adb, abi=running_abi, version=chosen["version"])
    if server.get("status") != "ok":
        server.update(base)
        server["frida_version"] = chosen.get("version")
        return server

    catalog = list_scripts()
    if catalog.get("status") != "ok":
        catalog.update(base)
        return catalog
    names = [item.get("name") for item in catalog.get("scripts", [])]
    if script not in names:
        return _error(f"frida catalog does not list {script}", **base, catalog_count=catalog.get("count", 0))
    loaded = load_script(script)
    if loaded.get("status") != "ok":
        loaded.update(base)
        return loaded

    companion = probe_companion(serial, sdk.adb)
    launched = launch_package(serial, sdk.adb, package_name)
    if launched.get("status") != "ok":
        launched.update(base)
        launched["companion"] = companion
        launched["frida_version"] = chosen["version"]
        return launched

    injection = frida_run_named_script(package_name, script, timeout=str(timeout))
    judged = judge_injection(injection)
    result = {
        **base,
        "status": judged.get("status", "error"),
        "frida_version": chosen["version"],
        "frida_source": chosen.get("source"),
        "catalog_count": catalog.get("count", 0),
        "script_bytes": loaded.get("bytes"),
        "companion": companion,
        "injection": {
            "exit_code": injection.get("exit_code"),
            "timed_out": bool(injection.get("timed_out")),
            "error": injection.get("error"),
            "stdout": _trim(injection.get("stdout")),
            "stderr": _trim(injection.get("stderr")),
        },
    }
    if judged.get("status") != "ok":
        result["error"] = judged.get("error")
        result["detail"] = judged.get("detail")
    elif judged.get("note"):
        result["note"] = judged["note"]
    return result
