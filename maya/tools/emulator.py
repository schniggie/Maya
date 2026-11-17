"""Headless Android emulator (AVD) bring-up for Maya's dynamic path.

Command construction, SDK detection, boot, and teardown live here. Every
public function returns a dict. A missing SDK or binary is an error dict,
not a traceback.

``scripts/emulator_up.sh`` calls ``python -m maya.tools.emulator``. The
full install-and-smoke path is ``maya --emulator``.
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ALLOWED_ABIS = ("x86_64", "x86", "arm64-v8a", "armeabi-v7a")
ALLOWED_IMAGE_TAGS = ("google_apis", "default", "aosp_atd", "google_apis_playstore")
DEFAULT_API = 34
DEFAULT_DEVICE = "pixel_6"
DEFAULT_AVD_NAME = "maya"
DEFAULT_PORT = 5554
DEFAULT_IMAGE_TAG = "google_apis"
DEFAULT_BOOT_TIMEOUT = 360
MIN_API = 21
MAX_API = 36
HEADLESS_FLAGS = (
    "-no-window",
    "-no-audio",
    "-gpu",
    "swiftshader_indirect",
    "-no-boot-anim",
    "-no-snapshot-save",
    "-no-metrics",
    "-memory",
    "2048",
    "-cores",
    "2",
)
_SYSTEM_SDK_ROOTS = (
    Path("/opt/android-sdk"),
    Path("/usr/lib/android-sdk"),
    Path("/usr/local/lib/android/sdk"),
)
_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,31}$")
_DEVICE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_SERIAL_RE = re.compile(r"^emulator-\d+$")
PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")

Which = Callable[[str], str | None]
Runner = Callable[..., dict[str, Any]]


@dataclass(frozen=True)
class EmulatorConfig:
    """One headless AVD. Defaults match a google_apis image so ``adb root`` works."""

    api: int = DEFAULT_API
    abi: str = "x86_64"
    device: str = DEFAULT_DEVICE
    name: str = DEFAULT_AVD_NAME
    port: int = DEFAULT_PORT
    image_tag: str = DEFAULT_IMAGE_TAG
    boot_timeout: int = DEFAULT_BOOT_TIMEOUT

    def system_image(self) -> str:
        return f"system-images;android-{self.api};{self.image_tag};{self.abi}"

    def serial(self) -> str:
        return f"emulator-{self.port}"


@dataclass(frozen=True)
class SdkLayout:
    root: Path | None
    emulator: Path
    adb: Path
    avdmanager: Path | None
    sdkmanager: Path | None


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def run_command(argv: list[str], *, timeout: int, input_text: str | None = None) -> dict[str, Any]:
    """Run a command and return a dict. Missing binaries and timeouts do not raise."""
    try:
        proc = subprocess.run(
            argv,
            text=True,
            capture_output=True,
            timeout=timeout,
            input=input_text,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "error": f"timeout after {timeout}s",
            "stdout": _text(exc.stdout),
            "stderr": _text(exc.stderr),
            "exit_code": None,
            "timed_out": True,
        }
    except FileNotFoundError as exc:
        name = argv[0] if argv else "command"
        return {
            "error": f"missing binary: {name}",
            "stdout": "",
            "stderr": str(exc),
            "exit_code": None,
            "missing_binary": True,
        }
    return {"stdout": proc.stdout or "", "stderr": proc.stderr or "", "exit_code": proc.returncode}


def default_abi(machine: str) -> tuple[str | None, dict[str, Any] | None]:
    """Pick an emulator ABI for the host. Apple Silicon (``arm64``) gets ``arm64-v8a``."""
    key = machine.strip().lower()
    if key in {"x86_64", "amd64"}:
        return "x86_64", None
    if key in {"aarch64", "arm64"}:
        return "arm64-v8a", None
    if key in {"i386", "i686", "x86"}:
        return "x86", None
    if key.startswith("arm"):
        return "armeabi-v7a", None
    return None, {
        "status": "error",
        "missing": "abi",
        "error": (
            f"cannot choose an emulator ABI for host architecture {machine!r}. "
            "Pass --avd-abi or set MAYA_AVD_ABI to x86_64, arm64-v8a, x86, or armeabi-v7a."
        ),
    }


def _error(message: str, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"status": "error", "error": message}
    payload.update(extra)
    return payload


def _parse_int(value: Any, label: str, low: int, high: int) -> tuple[int | None, dict[str, Any] | None]:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None, _error(f"{label} must be an integer, got {value!r}")
    if number < low or number > high:
        return None, _error(f"{label} must be between {low} and {high}, got {number}")
    return number, None


def build_config(
    env: Mapping[str, str] | None = None,
    *,
    api: int | None = None,
    abi: str | None = None,
    device: str | None = None,
    name: str | None = None,
    port: int | None = None,
    image_tag: str | None = None,
    boot_timeout: int | None = None,
    machine: str | None = None,
) -> tuple[EmulatorConfig | None, dict[str, Any] | None]:
    """Merge CLI flags, then environment, then defaults. Invalid values are an error dict."""
    source = os.environ if env is None else env

    def _pick(flag: Any, env_key: str, default: Any = None) -> Any:
        if flag is not None and flag != "":
            return flag
        raw = source.get(env_key, "").strip()
        if raw:
            return raw
        return default

    api_value, problem = _parse_int(_pick(api, "MAYA_AVD_API", DEFAULT_API), "API level", MIN_API, MAX_API)
    if problem:
        return None, problem
    port_value, problem = _parse_int(_pick(port, "MAYA_AVD_PORT", DEFAULT_PORT), "emulator port", 5554, 5682)
    if problem:
        return None, problem
    assert port_value is not None
    if port_value % 2 != 0:
        return None, _error(f"emulator port must be even (console port), got {port_value}")
    timeout_value, problem = _parse_int(
        _pick(boot_timeout, "MAYA_EMULATOR_BOOT_TIMEOUT", DEFAULT_BOOT_TIMEOUT),
        "boot timeout",
        30,
        3600,
    )
    if problem:
        return None, problem

    chosen_abi = _pick(abi, "MAYA_AVD_ABI", None)
    if chosen_abi is None:
        chosen_abi, problem = default_abi(machine if machine is not None else platform.machine())
        if problem:
            return None, problem
    chosen_abi = str(chosen_abi).strip()
    if chosen_abi not in ALLOWED_ABIS:
        return None, _error(
            f"ABI must be one of {', '.join(ALLOWED_ABIS)}, got {chosen_abi!r}",
            missing="abi",
        )

    chosen_tag = str(_pick(image_tag, "MAYA_AVD_IMAGE_TAG", DEFAULT_IMAGE_TAG)).strip()
    if chosen_tag not in ALLOWED_IMAGE_TAGS:
        return None, _error(
            f"system image tag must be one of {', '.join(ALLOWED_IMAGE_TAGS)}, got {chosen_tag!r}",
        )

    chosen_device = str(_pick(device, "MAYA_AVD_DEVICE", DEFAULT_DEVICE)).strip()
    if not _DEVICE_RE.fullmatch(chosen_device):
        return None, _error(f"device profile must match {_DEVICE_RE.pattern}, got {chosen_device!r}")

    chosen_name = str(_pick(name, "MAYA_AVD_NAME", DEFAULT_AVD_NAME)).strip()
    if not _NAME_RE.fullmatch(chosen_name):
        return None, _error(f"AVD name must match {_NAME_RE.pattern}, got {chosen_name!r}")

    assert api_value is not None and timeout_value is not None
    return (
        EmulatorConfig(
            api=api_value,
            abi=chosen_abi,
            device=chosen_device,
            name=chosen_name,
            port=port_value,
            image_tag=chosen_tag,
            boot_timeout=timeout_value,
        ),
        None,
    )


def emulator_argv(emulator: Path, config: EmulatorConfig) -> list[str]:
    """Headless emulator command. CPU virtualization is left to the host (KVM or Hypervisor.framework)."""
    return [
        str(emulator),
        "-avd",
        config.name,
        "-port",
        str(config.port),
        *HEADLESS_FLAGS,
    ]


def boot_completed(stdout: str) -> bool:
    return stdout.strip().replace("\r", "") == "1"


def parse_adb_devices(stdout: str) -> list[dict[str, str]]:
    devices: list[dict[str, str]] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("list of devices"):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        devices.append({"serial": parts[0], "state": parts[1]})
    return devices


def avd_names(stdout: str) -> set[str]:
    names: set[str] = set()
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Name:"):
            names.add(stripped.split(":", 1)[1].strip())
    return names


def avd_create_argv(avdmanager: Path, config: EmulatorConfig) -> list[str]:
    return [
        str(avdmanager),
        "create",
        "avd",
        "--name",
        config.name,
        "--package",
        config.system_image(),
        "--device",
        config.device,
        "--force",
    ]


def system_image_dir(root: Path, config: EmulatorConfig) -> Path:
    return root / "system-images" / f"android-{config.api}" / config.image_tag / config.abi


def missing_image_error(config: EmulatorConfig, sdkmanager: Path | None) -> dict[str, Any]:
    image = config.system_image()
    tool = str(sdkmanager or "sdkmanager")
    return _error(
        (
            f"System image {image} is not installed. "
            f'Install it with: {tool} --install "platform-tools" "emulator" "{image}". '
            "Use a google_apis (userdebug) image so adb root works. "
            "google_apis_playstore images are production builds and cannot start frida-server as root."
        ),
        missing="system-image",
        image=image,
    )


def _first_file(paths: Sequence[Path]) -> Path | None:
    for path in paths:
        if path.is_file():
            return path
    return None


def _tool_names(name: str) -> tuple[str, ...]:
    return (name, f"{name}.bat", f"{name}.exe")


def _cmdline_tool(root: Path, name: str) -> list[Path]:
    found: list[Path] = []
    base = root / "cmdline-tools"
    children: list[str] = []
    if base.is_dir():
        try:
            children = [child.name for child in base.iterdir() if child.is_dir()]
        except OSError:
            children = []
    ordered: list[str] = []
    if "latest" in children:
        ordered.append("latest")
    ordered.extend(sorted(child for child in children if child != "latest"))
    for child in ordered:
        for binary in _tool_names(name):
            found.append(base / child / "bin" / binary)
    for binary in _tool_names(name):
        found.append(base / "bin" / binary)
        found.append(root / "tools" / "bin" / binary)
    return found


def _layout_from_root(root: Path, which: Which, *, required: bool) -> SdkLayout | dict[str, Any] | None:
    emulator = _first_file([root / "emulator" / "emulator", root / "emulator" / "emulator.exe"])
    adb = _first_file([root / "platform-tools" / "adb", root / "platform-tools" / "adb.exe"])
    avdmanager = _first_file(_cmdline_tool(root, "avdmanager"))
    if avdmanager is None:
        found = which("avdmanager")
        avdmanager = Path(found) if found else None
    sdkmanager = _first_file(_cmdline_tool(root, "sdkmanager"))
    if sdkmanager is None:
        found = which("sdkmanager")
        sdkmanager = Path(found) if found else None
    if emulator is not None and adb is not None and avdmanager is not None:
        return SdkLayout(root=root, emulator=emulator, adb=adb, avdmanager=avdmanager, sdkmanager=sdkmanager)
    if not required:
        return None
    if emulator is None:
        missing, relative = "emulator", "emulator/emulator"
    elif adb is None:
        missing, relative = "adb", "platform-tools/adb"
    else:
        missing, relative = "avdmanager", "cmdline-tools/<version>/bin/avdmanager"
    return _error(
        (
            f"{missing} not found ({relative} under {root}). "
            "Install the Android SDK command-line tools, emulator, and platform-tools: "
            'sdkmanager --install "cmdline-tools;latest" "emulator" "platform-tools".'
        ),
        missing=missing,
    )


def _infer_sdk_root(emulator: Path) -> Path | None:
    if emulator.parent.name == "emulator":
        return emulator.parent.parent
    return None


def find_sdk(
    env: Mapping[str, str] | None = None,
    *,
    which: Which | None = None,
    home: Path | None = None,
    system_roots: Sequence[Path] | None = None,
) -> dict[str, Any]:
    """Locate emulator, adb, and avdmanager. Missing tools return an error dict."""
    source = os.environ if env is None else env
    lookup: Which = shutil.which if which is None else which
    home_dir = Path.home() if home is None else home
    roots = _SYSTEM_SDK_ROOTS if system_roots is None else tuple(system_roots)

    explicit: list[Path] = []
    for key in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        raw = source.get(key, "").strip()
        if not raw:
            continue
        path = Path(raw).expanduser()
        if not path.is_dir():
            return _error(
                (
                    f"{key} does not exist: {path}. Install the Android SDK command-line tools, "
                    f"emulator, and platform-tools, then point {key} at the SDK root."
                ),
                missing="sdk",
            )
        explicit.append(path)

    if explicit:
        layout = _layout_from_root(explicit[0], lookup, required=True)
        if isinstance(layout, dict):
            return layout
        assert isinstance(layout, SdkLayout)
        return {"status": "ok", "sdk": layout}

    for root in (home_dir / "Android" / "Sdk", home_dir / "Library" / "Android" / "sdk", *roots):
        if not root.is_dir():
            continue
        layout = _layout_from_root(root, lookup, required=False)
        if isinstance(layout, SdkLayout):
            return {"status": "ok", "sdk": layout}

    emulator = lookup("emulator")
    adb = lookup("adb")
    avdmanager = lookup("avdmanager")
    if emulator and adb and avdmanager:
        sdkmanager = lookup("sdkmanager")
        emulator_path = Path(emulator)
        return {
            "status": "ok",
            "sdk": SdkLayout(
                root=_infer_sdk_root(emulator_path),
                emulator=emulator_path,
                adb=Path(adb),
                avdmanager=Path(avdmanager),
                sdkmanager=Path(sdkmanager) if sdkmanager else None,
            ),
        }
    return _error(
        (
            "Android SDK not found. Install the command-line tools, emulator, and platform-tools, "
            "then set ANDROID_HOME (or ANDROID_SDK_ROOT) to the SDK root. "
            "Expected binaries: emulator, adb, and avdmanager."
        ),
        missing="sdk",
    )


def _command_error(result: dict[str, Any], fallback: str) -> dict[str, Any] | None:
    if result.get("missing_binary"):
        return _error(str(result.get("error") or fallback), missing="binary")
    if result.get("timed_out"):
        return _error(str(result.get("error") or fallback), timed_out=True)
    if result.get("exit_code") not in (0, None):
        detail = ((result.get("stderr") or "") + "\n" + (result.get("stdout") or "")).strip()
        return _error(fallback, detail=detail[-800:], exit_code=result.get("exit_code"))
    return None


def wait_for_boot(
    serial: str,
    adb: Path,
    *,
    timeout: int,
    runner: Runner,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    poll_interval: float = 2.0,
    alive: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Poll ``sys.boot_completed`` until it is ``1`` or the timeout elapses."""
    deadline = monotonic() + timeout
    last = ""
    while True:
        if alive is not None and not alive():
            return _error("emulator exited before sys.boot_completed=1", missing="emulator")
        result = runner([str(adb), "-s", serial, "shell", "getprop", "sys.boot_completed"], timeout=20)
        if result.get("missing_binary"):
            return _error("adb is not available", missing="adb")
        last = (result.get("stdout") or "").strip().replace("\r", "")
        if result.get("exit_code") == 0 and boot_completed(last):
            return {"status": "ok", "boot_completed": True, "serial": serial}
        if monotonic() >= deadline:
            return _error(
                f"timed out after {timeout}s waiting for sys.boot_completed=1",
                last_output=last,
                timed_out=True,
            )
        sleep(poll_interval)


def _log_tail(path: Path, limit: int = 2000) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    return data[-limit:].decode("utf-8", errors="replace")


def spawn_emulator(argv: list[str], log_path: Path) -> dict[str, Any]:
    """Start the emulator detached. The caller stops it with ``adb emu kill`` or the returned process."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handle = log_path.open("ab")
    try:
        proc = subprocess.Popen(
            argv,
            stdout=handle,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    except FileNotFoundError:
        return _error(f"missing binary: {argv[0] if argv else 'emulator'}", missing="emulator")
    except OSError as exc:
        return _error(f"could not start the emulator: {exc}", missing="emulator")
    finally:
        handle.close()
    return {"status": "ok", "pid": proc.pid, "process": proc, "log": str(log_path)}


def stop_process(process: Any) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            process.kill()


def _public_boot(config: EmulatorConfig, *, serial: str, started_by_us: bool, reused: bool, pid: int | None) -> dict:
    return {
        "status": "ok",
        "serial": serial,
        "avd": config.name,
        "api": config.api,
        "abi": config.abi,
        "image": config.system_image(),
        "port": config.port,
        "started_by_us": started_by_us,
        "reused": reused,
        "pid": pid,
    }


def boot_emulator(
    config: EmulatorConfig,
    sdk: SdkLayout,
    *,
    runner: Runner | None = None,
    spawn: Callable[[list[str], Path], dict[str, Any]] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    """Create the AVD if needed, boot headless, and wait for ``sys.boot_completed``."""
    run = runner or run_command
    starter = spawn or spawn_emulator
    if sdk.avdmanager is None:
        return _error("avdmanager is not available", missing="avdmanager")
    serial = config.serial()
    start = run([str(sdk.adb), "start-server"], timeout=30)
    if start.get("missing_binary"):
        return _error(
            "adb is not available. Install Android platform-tools and set ANDROID_HOME, or put adb on PATH.",
            missing="adb",
        )

    listed = run([str(sdk.adb), "devices"], timeout=20)
    if listed.get("missing_binary"):
        return _error("adb is not available", missing="adb")
    if listed.get("timed_out") or listed.get("exit_code") not in (0, None):
        failed = _command_error(listed, "adb devices failed")
        return failed or _error("adb devices failed")
    online = [
        item
        for item in parse_adb_devices(listed.get("stdout") or "")
        if item["serial"] == serial and item["state"] == "device"
    ]
    if online:
        ready = wait_for_boot(
            serial,
            sdk.adb,
            timeout=min(config.boot_timeout, 60),
            runner=run,
            sleep=sleep,
            monotonic=monotonic,
        )
        if ready.get("status") == "ok":
            return _public_boot(config, serial=serial, started_by_us=False, reused=True, pid=None)
        ready["error"] = (
            f"{serial} is already listed by adb but did not finish booting. "
            "Stop it with scripts/emulator_up.sh down, then retry."
        )
        return ready

    if sdk.root is None or not system_image_dir(sdk.root, config).is_dir():
        return missing_image_error(config, sdk.sdkmanager)

    existing = run([str(sdk.avdmanager), "list", "avd"], timeout=60)
    failed = _command_error(existing, "avdmanager list avd failed")
    if failed:
        return failed
    if config.name not in avd_names(existing.get("stdout") or ""):
        created = run(avd_create_argv(sdk.avdmanager, config), timeout=120, input_text="no\n")
        failed = _command_error(created, f"avdmanager could not create AVD {config.name}")
        if failed:
            return failed

    log_dir = output_dir or (Path.home() / ".maya" / "emulator")
    log_path = log_dir / f"{config.name}.log"
    argv = emulator_argv(sdk.emulator, config)
    spawned = starter(argv, log_path)
    if spawned.get("status") != "ok":
        spawned.setdefault("detail", _log_tail(log_path))
        return spawned
    process = spawned.get("process")

    def _alive() -> bool:
        if process is None:
            return True
        return process.poll() is None

    sleep(1)
    if not _alive():
        stop_process(process)
        return _error(
            "emulator exited immediately. On Linux this usually means /dev/kvm is missing or not writable. "
            "On Apple Silicon, use an arm64-v8a system image.",
            missing="emulator",
            detail=_log_tail(log_path),
            log=str(log_path),
        )

    waited = run([str(sdk.adb), "-s", serial, "wait-for-device"], timeout=min(config.boot_timeout, 180))
    if waited.get("missing_binary") or waited.get("timed_out") or waited.get("exit_code") not in (0, None):
        stop_process(process)
        problem = _command_error(waited, f"adb did not see {serial}") or _error(f"adb did not see {serial}")
        problem["detail"] = _log_tail(log_path)
        problem["log"] = str(log_path)
        return problem

    ready = wait_for_boot(
        serial,
        sdk.adb,
        timeout=config.boot_timeout,
        runner=run,
        sleep=sleep,
        monotonic=monotonic,
        alive=_alive,
    )
    if ready.get("status") != "ok":
        stop_process(process)
        run([str(sdk.adb), "-s", serial, "emu", "kill"], timeout=20)
        ready["detail"] = _log_tail(log_path)
        ready["log"] = str(log_path)
        return ready
    booted = _public_boot(config, serial=serial, started_by_us=True, reused=False, pid=spawned.get("pid"))
    booted["log"] = str(log_path)
    return booted


def teardown_emulator(serial: str, adb: Path, *, runner: Runner | None = None, timeout: int = 30) -> dict[str, Any]:
    """Stop one emulator serial. Other adb devices are left alone."""
    if not _SERIAL_RE.fullmatch(serial):
        return _error(f"refusing to stop unexpected serial {serial!r}")
    run = runner or run_command
    result = run([str(adb), "-s", serial, "emu", "kill"], timeout=timeout)
    if result.get("missing_binary"):
        return _error("adb is not available; the emulator was not stopped", missing="adb")
    text = ((result.get("stdout") or "") + "\n" + (result.get("stderr") or "")).lower()
    if result.get("exit_code") in (0, None) or "not found" in text or "no devices" in text:
        return {"status": "ok", "serial": serial, "exit_code": result.get("exit_code")}
    return _error("adb emu kill failed", detail=text[-400:], serial=serial, exit_code=result.get("exit_code"))


def install_apk(
    serial: str,
    adb: Path,
    apk: Path,
    *,
    runner: Runner | None = None,
    timeout: int = 180,
) -> dict[str, Any]:
    run = runner or run_command
    result = run([str(adb), "-s", serial, "install", "-r", str(apk)], timeout=timeout)
    if result.get("missing_binary"):
        return _error("adb is not available", missing="adb")
    text = f"{result.get('stdout') or ''}\n{result.get('stderr') or ''}"
    if result.get("exit_code") == 0 and "Success" in text:
        return {"status": "ok", "serial": serial}
    return _error("adb install failed", detail=text.strip()[-500:], exit_code=result.get("exit_code"))


def launch_package(
    serial: str,
    adb: Path,
    package_name: str,
    *,
    runner: Runner | None = None,
    timeout: int = 40,
) -> dict[str, Any]:
    if not PACKAGE_RE.fullmatch(package_name):
        return _error("refusing to launch an invalid package name", package_name=package_name)
    run = runner or run_command
    result = run(
        [
            str(adb),
            "-s",
            serial,
            "shell",
            "monkey",
            "-p",
            package_name,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
        ],
        timeout=timeout,
    )
    text = f"{result.get('stdout') or ''}\n{result.get('stderr') or ''}"
    if result.get("exit_code") == 0 and "No activities found" not in text:
        return {"status": "ok", "package_name": package_name}
    return _error("could not launch the app", detail=text.strip()[-500:], package_name=package_name)


def device_abi(serial: str, adb: Path, *, runner: Runner | None = None) -> str | None:
    run = runner or run_command
    result = run([str(adb), "-s", serial, "shell", "getprop", "ro.product.cpu.abi"], timeout=20)
    abi = (result.get("stdout") or "").strip().replace("\r", "")
    if abi in ALLOWED_ABIS:
        return abi
    return None


def emulator_up(
    *,
    env: Mapping[str, str] | None = None,
    api: int | None = None,
    abi: str | None = None,
    device: str | None = None,
    name: str | None = None,
    port: int | None = None,
    image_tag: str | None = None,
    boot_timeout: int | None = None,
    machine: str | None = None,
    runner: Runner | None = None,
    spawn: Callable[[list[str], Path], dict[str, Any]] | None = None,
    which: Which | None = None,
    home: Path | None = None,
    system_roots: Sequence[Path] | None = None,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    """Boot a headless AVD and leave it running. Does not install an APK."""
    config, problem = build_config(
        env,
        api=api,
        abi=abi,
        device=device,
        name=name,
        port=port,
        image_tag=image_tag,
        boot_timeout=boot_timeout,
        machine=machine,
    )
    if problem or config is None:
        return problem or _error("invalid emulator configuration")
    sdk_result = find_sdk(env, which=which, home=home, system_roots=system_roots)
    if sdk_result.get("status") != "ok":
        return sdk_result
    return boot_emulator(
        config,
        sdk_result["sdk"],
        runner=runner,
        spawn=spawn,
        output_dir=output_dir,
    )


def emulator_down(
    *,
    env: Mapping[str, str] | None = None,
    port: int | None = None,
    name: str | None = None,
    runner: Runner | None = None,
    which: Which | None = None,
    home: Path | None = None,
    system_roots: Sequence[Path] | None = None,
) -> dict[str, Any]:
    config, problem = build_config(env, port=port, name=name)
    if problem or config is None:
        return problem or _error("invalid emulator configuration")
    sdk_result = find_sdk(env, which=which, home=home, system_roots=system_roots)
    if sdk_result.get("status") != "ok":
        return sdk_result
    return teardown_emulator(config.serial(), sdk_result["sdk"].adb, runner=runner)


def emulator_status(
    *,
    env: Mapping[str, str] | None = None,
    port: int | None = None,
    runner: Runner | None = None,
    which: Which | None = None,
    home: Path | None = None,
    system_roots: Sequence[Path] | None = None,
) -> dict[str, Any]:
    config, problem = build_config(env, port=port)
    if problem or config is None:
        return problem or _error("invalid emulator configuration")
    sdk_result = find_sdk(env, which=which, home=home, system_roots=system_roots)
    if sdk_result.get("status") != "ok":
        return sdk_result
    run = runner or run_command
    sdk: SdkLayout = sdk_result["sdk"]
    listed = run([str(sdk.adb), "devices"], timeout=20)
    if listed.get("missing_binary"):
        return _error("adb is not available", missing="adb")
    serial = config.serial()
    match = next((item for item in parse_adb_devices(listed.get("stdout") or "") if item["serial"] == serial), None)
    if match is None:
        return {"status": "ok", "serial": serial, "online": False, "state": "absent", "boot_completed": False}
    probed = run([str(sdk.adb), "-s", serial, "shell", "getprop", "sys.boot_completed"], timeout=15)
    return {
        "status": "ok",
        "serial": serial,
        "online": match["state"] == "device",
        "state": match["state"],
        "boot_completed": boot_completed(probed.get("stdout") or ""),
    }


def format_result(result: dict[str, Any]) -> str:
    if result.get("status") != "ok":
        lines = [str(result.get("error") or "emulator helper failed")]
        detail = result.get("detail")
        if detail:
            lines.append(str(detail))
        return "\n".join(lines)
    lines = [f"status: {result.get('status')}"]
    for key in ("serial", "avd", "api", "abi", "image", "state", "online", "boot_completed", "reused"):
        if key in result:
            lines.append(f"{key}: {result[key]}")
    return "\n".join(lines)


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--api", type=int, default=None, help=f"API level (default {DEFAULT_API}, or MAYA_AVD_API)")
    parser.add_argument("--abi", default=None, help="ABI: x86_64, arm64-v8a, x86, armeabi-v7a (or MAYA_AVD_ABI)")
    parser.add_argument("--device", default=None, help=f"device profile (default {DEFAULT_DEVICE}, or MAYA_AVD_DEVICE)")
    parser.add_argument("--name", default=None, help=f"AVD name (default {DEFAULT_AVD_NAME}, or MAYA_AVD_NAME)")
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help=f"console port (default {DEFAULT_PORT}, or MAYA_AVD_PORT)",
    )
    parser.add_argument(
        "--image-tag",
        default=None,
        help="system image tag (default google_apis, or MAYA_AVD_IMAGE_TAG)",
    )
    parser.add_argument("--boot-timeout", type=int, default=None, help="seconds to wait for sys.boot_completed")


def main(argv: list[str] | None = None) -> int:
    """CLI for scripts/emulator_up.sh. Prints a summary and returns 0 or 2."""
    parser = argparse.ArgumentParser(
        description="Boot or stop the headless Android emulator used by Maya. Does not install an APK.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    up = sub.add_parser("up", help="create the AVD if needed and boot it headless")
    _add_common(up)
    down = sub.add_parser("down", help="stop emulator-<port> via adb emu kill")
    down.add_argument("--port", type=int, default=None)
    down.add_argument("--name", default=None)
    status = sub.add_parser("status", help="report whether emulator-<port> is online")
    status.add_argument("--port", type=int, default=None)
    args = parser.parse_args(argv)

    if args.command == "up":
        result = emulator_up(
            api=args.api,
            abi=args.abi,
            device=args.device,
            name=args.name,
            port=args.port,
            image_tag=args.image_tag,
            boot_timeout=args.boot_timeout,
        )
    elif args.command == "down":
        result = emulator_down(port=args.port, name=args.name)
    else:
        result = emulator_status(port=args.port)
    stream = sys.stdout if result.get("status") == "ok" else sys.stderr
    print(format_result(result), file=stream)
    return 0 if result.get("status") == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
