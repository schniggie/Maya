from __future__ import annotations

from .proc import run_cli
from .registry import register_tool


@register_tool(sandbox_execution=True)
def verify_device_connected() -> dict:
    """Verify at least one device is connected through adb."""
    result = run_cli(["adb", "devices"], timeout=30)
    if result.get("error"):
        return result
    lines = [ln for ln in result["stdout"].splitlines() if "\tdevice" in ln]
    return {"status": "ok" if lines else "error", "devices": lines, "stdout": result["stdout"]}


@register_tool(sandbox_execution=True)
def verify_frida_attached(package_name: str) -> dict:
    """Verify Frida can see target process."""
    result = run_cli(["frida-ps", "-U"], timeout=30)
    if result.get("error"):
        return result
    ok = package_name in result["stdout"]
    return {"status": "ok" if ok else "error", "stdout": result["stdout"], "stderr": result["stderr"]}


@register_tool(sandbox_execution=True)
def verify_ssl_bypass(test_url: str = "https://example.com") -> dict:
    """Verify HTTPS request succeeds after bypass setup."""
    result = run_cli(["curl", "-k", "-I", test_url], timeout=30)
    if result.get("error"):
        return result
    return {
        "status": "ok" if result["exit_code"] == 0 else "error",
        "stdout": result["stdout"],
        "stderr": result["stderr"],
    }


@register_tool(sandbox_execution=True)
def verify_proxy_active(host: str = "127.0.0.1", port: str = "8080") -> dict:
    """Verify proxy endpoint is reachable."""
    result = run_cli(["curl", "-s", f"http://{host}:{port}"], timeout=10)
    if result.get("error"):
        return result
    return {
        "status": "ok" if result["exit_code"] == 0 else "error",
        "stdout": result["stdout"],
        "stderr": result["stderr"],
    }
