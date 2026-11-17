from __future__ import annotations

import asyncio
import importlib
import json
import os
import subprocess
from pathlib import Path

try:
    websockets = importlib.import_module("websockets")
except Exception:  # noqa: BLE001
    websockets = None

from .companion_client import CompanionClient, build_command_payload
from .proc import run_cli
from .registry import register_tool


def _adb_base_command() -> list[str]:
    # Uses host ADB server when ADB_SERVER_SOCKET is provided.
    socket = os.environ.get("ADB_SERVER_SOCKET")
    if socket:
        return ["adb", "-L", socket]
    return ["adb"]


@register_tool(sandbox_execution=True)
def device_list() -> dict:
    """List connected Android devices via adb devices."""
    return run_cli(_adb_base_command() + ["devices"], timeout=30)


@register_tool(sandbox_execution=True)
def device_shell(command: str, timeout: str = "60") -> dict:
    """Execute shell command on connected Android device."""
    return run_cli(_adb_base_command() + ["shell", command], timeout=int(timeout))


@register_tool(sandbox_execution=True)
def device_install_app(app_path: str, timeout: str = "120") -> dict:
    """Install an APK onto connected Android device."""
    return run_cli(_adb_base_command() + ["install", "-r", app_path], timeout=int(timeout))


@register_tool(sandbox_execution=True)
def device_uninstall_app(package_name: str, timeout: str = "60") -> dict:
    """Uninstall Android package from connected device."""
    cmd = _adb_base_command() + ["uninstall", package_name]
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=int(timeout))
    return {"stdout": proc.stdout, "stderr": proc.stderr, "exit_code": proc.returncode}


@register_tool(sandbox_execution=True)
def device_pull_file(remote_path: str, local_path: str, timeout: str = "120") -> dict:
    """Pull file from device to local path."""
    out = Path(local_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = _adb_base_command() + ["pull", remote_path, str(out)]
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=int(timeout))
    return {"stdout": proc.stdout, "stderr": proc.stderr, "exit_code": proc.returncode, "path": str(out)}


@register_tool(sandbox_execution=True)
def device_push_file(local_path: str, remote_path: str, timeout: str = "120") -> dict:
    """Push file from local path to device."""
    cmd = _adb_base_command() + ["push", local_path, remote_path]
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=int(timeout))
    return {"stdout": proc.stdout, "stderr": proc.stderr, "exit_code": proc.returncode}


@register_tool(sandbox_execution=True)
def device_get_app_info(package_name: str, timeout: str = "60") -> dict:
    """Get package info from device package manager."""
    return device_shell(command=f"dumpsys package {package_name}", timeout=timeout)


@register_tool(sandbox_execution=True)
def device_dump_app_data(package_name: str, platform: str = "android", timeout: str = "120") -> dict:
    """Dump app data with platform-aware logic (android/ios)."""
    if platform == "ios":
        cmd = [
            "ssh",
            "root@localhost",
            "tar",
            "-czf",
            f"/tmp/{package_name}.tar.gz",  # noqa: S108
            f"/var/mobile/Containers/Data/Application/{package_name}",
        ]
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=int(timeout))
        return {"stdout": proc.stdout, "stderr": proc.stderr, "exit_code": proc.returncode, "platform": "ios"}
    return device_shell(
        command=f"su -c 'tar -czf /sdcard/{package_name}.tar.gz /data/data/{package_name}'", timeout=timeout
    )


@register_tool(sandbox_execution=True)
def device_start_frida_server(binary_path: str = "/data/local/tmp/frida-server", timeout: str = "60") -> dict:
    """Start frida-server on Android device if present."""
    return device_shell(command=f"su -c '{binary_path} -D &'", timeout=timeout)


def _parse_companion_args(command: str, params: str, timeout: str) -> dict:
    try:
        timeout_s = float(timeout)
    except (TypeError, ValueError):
        return {"status": "error", "error": "timeout must be numeric"}
    if timeout_s <= 0:
        return {"status": "error", "error": "timeout must be positive"}
    try:
        parsed = json.loads(params or "{}")
    except json.JSONDecodeError as exc:
        return {"status": "error", "error": f"params are not valid JSON: {exc.msg}"}
    if not isinstance(parsed, dict):
        return {"status": "error", "error": "params must be a JSON object"}
    if not str(command).strip():
        return {"status": "error", "error": "command is required"}
    return {"timeout": timeout_s, "params": parsed, "command": str(command).strip()}


def _websocket_command(payload: dict, timeout_s: float) -> dict | None:
    """Use a websocket only when COMPANION_WS_URL is set. Failures do not raise."""
    ws_url = os.environ.get("COMPANION_WS_URL", "").strip()
    if not ws_url:
        return None
    if websockets is None:
        return {"status": "error", "error": "websocket client is not installed"}

    async def _send_ws() -> dict:
        async with websockets.connect(ws_url, open_timeout=timeout_s, close_timeout=min(timeout_s, 5)) as ws:
            await ws.send(json.dumps(payload))
            msg = await asyncio.wait_for(ws.recv(), timeout_s)
            try:
                body = json.loads(msg)
            except (TypeError, json.JSONDecodeError):
                body = {"raw": msg}
            return {"status": "ok", "response": body, "transport": "websocket"}

    try:
        return asyncio.run(_send_ws())
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "error": "companion websocket failed",
            "detail": f"{type(exc).__name__}: {exc}",
        }


@register_tool(sandbox_execution=True)
def companion_app_command(command: str, params: str = "{}", timeout: str = "30") -> dict:
    """Send one command to the companion HTTP server.

    Checks /health first, retries connection failures, and returns an error dict
    when the companion or device is absent.
    """
    parsed = _parse_companion_args(command, params, timeout)
    if parsed.get("error"):
        return parsed

    payload, payload_error = build_command_payload(parsed["command"], parsed["params"], "cmd_local")
    if payload_error is not None or payload is None:
        return payload_error or {"status": "error", "error": "command is required"}
    websocket_result = _websocket_command(payload, parsed["timeout"])
    if websocket_result is not None and websocket_result.get("status") == "ok":
        return websocket_result

    try:
        client = CompanionClient.from_env(read_timeout=parsed["timeout"])
        result = client.command(parsed["command"], parsed["params"], request_id="cmd_local")
    except Exception as exc:  # noqa: BLE001
        result = {
            "status": "error",
            "error": "companion request failed",
            "detail": f"{type(exc).__name__}: {exc}",
            "available": False,
            "degraded": True,
        }
    if websocket_result is not None and result.get("status") != "ok":
        result = {**result, "websocket_error": websocket_result.get("error", "companion websocket failed")}
    return result


@register_tool(sandbox_execution=True)
def ios_decrypt_binary(bundle_id: str, timeout: str = "120") -> dict:
    """Best-effort iOS binary decrypt command wrapper."""
    proc = subprocess.run(
        ["ssh", "root@localhost", "clutch", "-d", bundle_id], text=True, capture_output=True, timeout=int(timeout)
    )
    return {"stdout": proc.stdout, "stderr": proc.stderr, "exit_code": proc.returncode}


@register_tool(sandbox_execution=True)
def ios_dump_keychain(timeout: str = "90") -> dict:
    """Dump iOS keychain entries using keychain-dumper if available."""
    proc = subprocess.run(
        ["ssh", "root@localhost", "keychain-dumper"], text=True, capture_output=True, timeout=int(timeout)
    )
    return {"stdout": proc.stdout, "stderr": proc.stderr, "exit_code": proc.returncode}


@register_tool(sandbox_execution=True)
def device_set_proxy(host: str = "127.0.0.1", port: str = "8080", timeout: str = "30") -> dict:
    """Set system-wide HTTP proxy on Android device via adb settings."""
    result = run_cli(
        _adb_base_command() + ["shell", "settings", "put", "global", "http_proxy", f"{host}:{port}"],
        timeout=int(timeout),
    )
    if result.get("error"):
        return result
    return {"status": "ok", "proxy": f"{host}:{port}", **result}


@register_tool(sandbox_execution=True)
def device_clear_proxy(timeout: str = "30") -> dict:
    """Remove system-wide HTTP proxy from Android device."""
    result = run_cli(
        _adb_base_command() + ["shell", "settings", "put", "global", "http_proxy", ":0"],
        timeout=int(timeout),
    )
    if result.get("error"):
        return result
    return {"status": "ok", **result}
