"""Device-free tests for headless emulator orchestration.

No Android SDK, emulator, or frida-server is required. Live boot is marked
integration and skips unless MAYA_EMULATOR_INTEGRATION=1.
"""

from __future__ import annotations

import lzma
import os
from pathlib import Path

import pytest

from maya.tools.emulator import (
    EmulatorConfig,
    SdkLayout,
    avd_names,
    boot_completed,
    boot_emulator,
    build_config,
    default_abi,
    emulator_argv,
    emulator_up,
    find_sdk,
    main,
    parse_adb_devices,
    system_image_dir,
    wait_for_boot,
)
from maya.tools.frida_server import (
    PINNED_FRIDA_VERSION,
    download_file,
    ensure_frida_binary,
    exact_version,
    extract_xz,
    frida_server_asset,
    frida_server_running,
    provision_frida_server,
    resolve_frida_version,
    root_available,
)


def _ok(stdout: str = "", code: int = 0) -> dict:
    return {"stdout": stdout, "stderr": "", "exit_code": code}


def _sdk(root: Path) -> SdkLayout:
    emulator = root / "emulator" / "emulator"
    adb = root / "platform-tools" / "adb"
    avdmanager = root / "cmdline-tools" / "latest" / "bin" / "avdmanager"
    sdkmanager = root / "cmdline-tools" / "latest" / "bin" / "sdkmanager"
    for path in (emulator, adb, avdmanager, sdkmanager):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\n", encoding="utf-8")
    return SdkLayout(root=root, emulator=emulator, adb=adb, avdmanager=avdmanager, sdkmanager=sdkmanager)


def test_default_abi_matches_host_and_apple_silicon() -> None:
    assert default_abi("x86_64") == ("x86_64", None)
    assert default_abi("amd64") == ("x86_64", None)
    assert default_abi("arm64") == ("arm64-v8a", None)
    assert default_abi("aarch64") == ("arm64-v8a", None)
    abi, problem = default_abi("riscv64")
    assert abi is None
    assert problem is not None
    assert problem["missing"] == "abi"
    assert "MAYA_AVD_ABI" in problem["error"]


def test_build_config_defaults_and_env_overrides() -> None:
    config, problem = build_config({}, machine="x86_64")
    assert problem is None
    assert config is not None
    assert config.api == 34
    assert config.abi == "x86_64"
    assert config.device == "pixel_6"
    assert config.name == "maya"
    assert config.port == 5554
    assert config.system_image() == "system-images;android-34;google_apis;x86_64"
    assert config.serial() == "emulator-5554"

    overridden, problem = build_config(
        {"MAYA_AVD_API": "33", "MAYA_AVD_ABI": "arm64-v8a", "MAYA_AVD_DEVICE": "pixel_5", "MAYA_AVD_NAME": "lab"},
        machine="x86_64",
    )
    assert problem is None
    assert overridden is not None
    assert (overridden.api, overridden.abi, overridden.device, overridden.name) == (33, "arm64-v8a", "pixel_5", "lab")

    flagged, problem = build_config({"MAYA_AVD_API": "33"}, api=35, abi="x86", machine="x86_64")
    assert problem is None
    assert flagged is not None
    assert flagged.api == 35
    assert flagged.abi == "x86"


@pytest.mark.parametrize(
    ("env", "kwargs"),
    [
        ({"MAYA_AVD_ABI": "mips"}, {}),
        ({"MAYA_AVD_API": "nope"}, {}),
        ({"MAYA_AVD_API": "15"}, {}),
        ({"MAYA_AVD_PORT": "5555"}, {}),
        ({"MAYA_AVD_NAME": "../maya"}, {}),
        ({"MAYA_AVD_IMAGE_TAG": "playstore"}, {}),
    ],
)
def test_build_config_rejects_bad_values(env: dict, kwargs: dict) -> None:
    config, problem = build_config(env, machine="x86_64", **kwargs)
    assert config is None
    assert problem is not None
    assert problem["status"] == "error"
    assert problem["error"]


def test_emulator_argv_is_headless() -> None:
    config = EmulatorConfig()
    argv = emulator_argv(Path("/sdk/emulator/emulator"), config)
    assert argv[:5] == ["/sdk/emulator/emulator", "-avd", "maya", "-port", "5554"]
    assert "-no-window" in argv
    assert "-no-audio" in argv
    assert argv[argv.index("-gpu") + 1] == "swiftshader_indirect"
    assert "-no-boot-anim" in argv


def test_boot_and_device_parsers() -> None:
    assert boot_completed("1\r\n")
    assert boot_completed(" 1 ")
    assert not boot_completed("0")
    assert not boot_completed("")
    devices = parse_adb_devices("List of devices attached\nemulator-5554\tdevice\nusb-serial\toffline\n")
    assert devices == [
        {"serial": "emulator-5554", "state": "device"},
        {"serial": "usb-serial", "state": "offline"},
    ]
    assert avd_names("Available Android Virtual Devices:\n    Name: maya\n    Name: other\n") == {"maya", "other"}


def test_find_sdk_under_android_home(tmp_path: Path) -> None:
    root = tmp_path / "sdk"
    _sdk(root)
    found = find_sdk({"ANDROID_HOME": str(root)}, which=lambda _name: None, home=tmp_path, system_roots=())
    assert found["status"] == "ok"
    assert found["sdk"].emulator == root / "emulator" / "emulator"
    assert found["sdk"].adb == root / "platform-tools" / "adb"
    assert found["sdk"].avdmanager == root / "cmdline-tools" / "latest" / "bin" / "avdmanager"


def test_find_sdk_missing_home_is_an_error(tmp_path: Path) -> None:
    missing = tmp_path / "no-sdk"
    result = find_sdk({"ANDROID_HOME": str(missing)}, which=lambda _name: None, home=tmp_path, system_roots=())
    assert result["status"] == "error"
    assert result["missing"] == "sdk"
    assert "ANDROID_HOME does not exist" in result["error"]
    assert "emulator" in result["error"]


def test_find_sdk_missing_emulator_binary(tmp_path: Path) -> None:
    root = tmp_path / "sdk"
    layout = _sdk(root)
    layout.emulator.unlink()
    result = find_sdk({"ANDROID_SDK_ROOT": str(root)}, which=lambda _name: None, home=tmp_path, system_roots=())
    assert result["status"] == "error"
    assert result["missing"] == "emulator"
    assert "sdkmanager" in result["error"]


def test_find_sdk_absent_without_env(tmp_path: Path) -> None:
    result = find_sdk({}, which=lambda _name: None, home=tmp_path / "empty-home", system_roots=())
    assert result["status"] == "error"
    assert result["missing"] == "sdk"
    assert "ANDROID_HOME" in result["error"]


def test_find_sdk_uses_path_when_home_is_unset(tmp_path: Path) -> None:
    root = tmp_path / "sdk"
    layout = _sdk(root)
    tools = {
        "emulator": str(layout.emulator),
        "adb": str(layout.adb),
        "avdmanager": str(layout.avdmanager),
        "sdkmanager": str(layout.sdkmanager),
    }
    result = find_sdk({}, which=tools.get, home=tmp_path / "empty-home", system_roots=())
    assert result["status"] == "ok"
    assert result["sdk"].root == root
    assert result["sdk"].adb == layout.adb


def test_wait_for_boot_succeeds_and_times_out() -> None:
    clock = {"now": 0.0}

    def monotonic() -> float:
        return clock["now"]

    def sleep(seconds: float) -> None:
        clock["now"] += seconds

    outputs = iter(["0\n", "1\r\n"])

    def runner(argv, timeout, input_text=None):
        assert argv[-2:] == ["getprop", "sys.boot_completed"]
        return _ok(next(outputs))

    ready = wait_for_boot(
        "emulator-5554",
        Path("adb"),
        timeout=10,
        runner=runner,
        sleep=sleep,
        monotonic=monotonic,
    )
    assert ready["status"] == "ok"

    def stalled(argv, timeout, input_text=None):
        return _ok("")

    clock["now"] = 0.0
    timed = wait_for_boot(
        "emulator-5554",
        Path("adb"),
        timeout=5,
        runner=stalled,
        sleep=sleep,
        monotonic=monotonic,
        poll_interval=2,
    )
    assert timed["status"] == "error"
    assert timed["timed_out"] is True
    assert "sys.boot_completed" in timed["error"]


def test_boot_reports_missing_system_image_without_spawning(tmp_path: Path) -> None:
    sdk = _sdk(tmp_path / "sdk")

    def runner(argv, timeout, input_text=None):
        if argv[-1] == "start-server":
            return _ok()
        if argv[-1] == "devices":
            return _ok("List of devices attached\n")
        raise AssertionError(argv)

    def spawn(argv, log_path):
        raise AssertionError("emulator should not start without a system image")

    config, problem = build_config({}, abi="x86_64", machine="x86_64")
    assert problem is None and config is not None
    result = boot_emulator(config, sdk, runner=runner, spawn=spawn, output_dir=tmp_path)
    assert result["status"] == "error"
    assert result["missing"] == "system-image"
    assert result["image"] == config.system_image()
    assert not system_image_dir(sdk.root, config).exists()  # type: ignore[arg-type]


def test_boot_reuses_an_already_booted_emulator(tmp_path: Path) -> None:
    sdk = _sdk(tmp_path / "sdk")

    def runner(argv, timeout, input_text=None):
        if argv[-1] == "start-server":
            return _ok()
        if argv[-1] == "devices":
            return _ok("List of devices attached\nemulator-5554\tdevice\n")
        if argv[-1] == "sys.boot_completed":
            return _ok("1\n")
        raise AssertionError(argv)

    config, _problem = build_config({}, abi="x86_64", machine="x86_64")
    assert config is not None
    result = boot_emulator(
        config,
        sdk,
        runner=runner,
        spawn=lambda *_args, **_kwargs: pytest.fail("spawned"),
        output_dir=tmp_path,
    )
    assert result["status"] == "ok"
    assert result["reused"] is True
    assert result["started_by_us"] is False
    assert result["serial"] == "emulator-5554"
    assert "process" not in result


def test_boot_creates_the_avd_and_starts_headless(tmp_path: Path) -> None:
    root = tmp_path / "sdk"
    sdk = _sdk(root)
    config, problem = build_config({}, abi="x86_64", machine="x86_64")
    assert problem is None and config is not None
    system_image_dir(root, config).mkdir(parents=True)
    spawned: dict[str, list[str]] = {}

    def runner(argv, timeout, input_text=None):
        if argv[-1] == "start-server":
            return _ok()
        if argv[-1] == "devices":
            return _ok("List of devices attached\n")
        if argv[-2:] == ["list", "avd"]:
            return _ok("Available Android Virtual Devices:\n")
        if "create" in argv:
            assert input_text == "no\n"
            assert config.system_image() in argv
            assert config.device in argv
            return _ok()
        if argv[-1] == "wait-for-device":
            assert argv[1:3] == ["-s", "emulator-5554"]
            return _ok()
        if argv[-1] == "sys.boot_completed":
            return _ok("1\n")
        raise AssertionError(argv)

    class _Alive:
        pid = 4242

        def poll(self):
            return None

    def spawn(argv, log_path):
        spawned["argv"] = list(argv)
        log_path.write_text("", encoding="utf-8")
        return {"status": "ok", "pid": 4242, "process": _Alive(), "log": str(log_path)}

    result = boot_emulator(config, sdk, runner=runner, spawn=spawn, sleep=lambda _seconds: None, output_dir=tmp_path)
    assert result["status"] == "ok"
    assert result["started_by_us"] is True
    assert result["reused"] is False
    assert "-no-window" in spawned["argv"]
    assert "-no-audio" in spawned["argv"]
    assert spawned["argv"][spawned["argv"].index("-gpu") + 1] == "swiftshader_indirect"


def test_boot_reports_an_emulator_that_exits_immediately(tmp_path: Path) -> None:
    root = tmp_path / "sdk"
    sdk = _sdk(root)
    config, problem = build_config({}, abi="x86_64", machine="x86_64")
    assert config is not None and problem is None
    system_image_dir(root, config).mkdir(parents=True)

    def runner(argv, timeout, input_text=None):
        if argv[-1] == "start-server" or argv[-1] == "devices":
            return _ok("List of devices attached\n" if argv[-1] == "devices" else "")
        if argv[-2:] == ["list", "avd"]:
            return _ok("    Name: maya\n")
        raise AssertionError(argv)

    class _Dead:
        pid = 7

        def poll(self):
            return 1

        def wait(self, timeout=None):
            return 1

        def terminate(self):
            return None

        def kill(self):
            return None

    def spawn(argv, log_path):
        log_path.write_text("x86_64 emulation currently requires hardware acceleration\n", encoding="utf-8")
        return {"status": "ok", "pid": 7, "process": _Dead(), "log": str(log_path)}

    result = boot_emulator(config, sdk, runner=runner, spawn=spawn, sleep=lambda _seconds: None, output_dir=tmp_path)
    assert result["status"] == "error"
    assert result["missing"] == "emulator"
    assert "hardware acceleration" in result["detail"]
    assert "/dev/kvm" in result["error"]


def test_emulator_up_returns_sdk_error_without_raising(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "maya.tools.emulator.find_sdk",
        lambda *_args, **_kwargs: {"status": "error", "error": "Android SDK not found", "missing": "sdk"},
    )
    result = emulator_up(env={}, abi="x86_64", machine="x86_64")
    assert result == {"status": "error", "error": "Android SDK not found", "missing": "sdk"}


def test_emulator_cli_missing_sdk_exits_2(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(
        "maya.tools.emulator.find_sdk",
        lambda *_args, **_kwargs: {"status": "error", "error": "Android SDK not found", "missing": "sdk"},
    )
    assert main(["status"]) == 2
    captured = capsys.readouterr()
    assert "Android SDK not found" in captured.err
    assert captured.out == ""


def test_frida_version_resolution_order() -> None:
    flagged = resolve_frida_version("16.7.19", installed="17.0.0", env={"MAYA_FRIDA_VERSION": "16.1.0"})
    assert flagged == {"status": "ok", "version": "16.7.19", "source": "flag"}

    from_env = resolve_frida_version(None, installed="17.0.0", env={"MAYA_FRIDA_VERSION": "16.5.9"})
    assert from_env["source"] == "env"
    assert from_env["version"] == "16.5.9"

    packaged = resolve_frida_version(None, installed="16.7.19.dev0", env={})
    assert packaged == {"status": "ok", "version": "16.7.19", "source": "package"}

    pinned = resolve_frida_version(None, installed=None, env={})
    assert pinned == {"status": "ok", "version": PINNED_FRIDA_VERSION, "source": "pin"}

    rejected = resolve_frida_version("16.7.19/../../evil", env={})
    assert rejected["status"] == "error"
    assert exact_version("16.7.19") == "16.7.19"
    assert exact_version("16.7") is None


def test_frida_server_asset_names_and_url() -> None:
    x86 = frida_server_asset("16.7.19", "x86_64")
    assert x86["asset"] == "frida-server-16.7.19-android-x86_64.xz"
    assert x86["url"] == ("https://github.com/frida/frida/releases/download/16.7.19/" + x86["asset"])
    arm = frida_server_asset("16.7.19", "arm64-v8a")
    assert arm["arch"] == "arm64"
    assert arm["asset"].endswith("-android-arm64.xz")
    assert frida_server_asset("16.7.19", "armeabi-v7a")["arch"] == "arm"
    assert frida_server_asset("16.7.19", "x86")["arch"] == "x86"
    bad = frida_server_asset("../16.7.19", "x86_64")
    assert bad["status"] == "error"
    assert "url" not in bad


def test_download_refuses_unexpected_host(tmp_path: Path) -> None:
    result = download_file("https://example.com/frida-server.xz", tmp_path / "server.xz")
    assert result["status"] == "error"
    assert "unexpected URL" in result["error"]
    assert not (tmp_path / "server.xz").exists()


def test_extract_xz_round_trip(tmp_path: Path) -> None:
    payload = b"\x7fELFfrida-server-fixture"
    archive = tmp_path / "frida-server.xz"
    archive.write_bytes(lzma.compress(payload))
    dest = tmp_path / "frida-server"
    result = extract_xz(archive, dest)
    assert result["status"] == "ok"
    assert dest.read_bytes() == payload
    assert dest.stat().st_mode & 0o111


def test_root_and_process_detection() -> None:
    assert root_available({"exit_code": 0, "stdout": "restarting adbd as root", "stderr": ""})
    assert not root_available({"exit_code": 1, "stdout": "", "stderr": "adbd cannot run as root in production builds"})
    assert root_available(
        {"exit_code": 1, "stdout": "", "stderr": "adbd cannot run as root in production builds"},
        {"stdout": "uid=0(root)", "exit_code": 0},
    )
    assert frida_server_running("4321\n")
    assert frida_server_running("root 4321 1 frida-server\n")
    assert not frida_server_running("grep frida-server\n")
    assert not frida_server_running("")


def test_provision_missing_adb_and_missing_root(tmp_path: Path) -> None:
    binary_dir = tmp_path / "16.7.19" / "x86_64"
    binary_dir.mkdir(parents=True)
    binary = binary_dir / "frida-server"
    binary.write_bytes(b"\x7fELF")

    def missing(argv, timeout, input_text=None):
        return {"error": "missing binary: adb", "missing_binary": True, "stdout": "", "stderr": "", "exit_code": None}

    absent = provision_frida_server(
        serial="emulator-5554",
        adb=Path("adb"),
        abi="x86_64",
        version="16.7.19",
        runner=missing,
        cache_dir=tmp_path,
        fetcher=lambda *_args, **_kwargs: pytest.fail("download"),
    )
    assert absent["status"] == "error"
    assert absent["missing"] == "adb"

    def no_root(argv, timeout, input_text=None):
        if argv[-1] == "root":
            return {"stdout": "", "stderr": "adbd cannot run as root in production builds", "exit_code": 1}
        if argv[-1] == "id":
            return _ok("uid=2000(shell) gid=2000(shell)")
        raise AssertionError(argv)

    denied = provision_frida_server(
        serial="emulator-5554",
        adb=Path("adb"),
        abi="x86_64",
        version="16.7.19",
        runner=no_root,
        cache_dir=tmp_path,
        sleep=lambda _seconds: None,
        fetcher=lambda *_args, **_kwargs: pytest.fail("download"),
    )
    assert denied["status"] == "error"
    assert denied["missing"] == "root"
    assert "google_apis" in denied["error"]


def test_provision_pushes_cached_server_and_health_checks(tmp_path: Path) -> None:
    binary = tmp_path / "16.7.19" / "x86_64" / "frida-server"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"\x7fELF")
    calls: list[list[str]] = []

    def runner(argv, timeout, input_text=None):
        calls.append(list(argv))
        if argv[-1] == "root":
            return _ok("restarting adbd as root")
        if argv[-1] == "pidof" or (len(argv) >= 2 and argv[-2] == "pidof"):
            return _ok("4321")
        return _ok()

    slept: list[float] = []
    result = provision_frida_server(
        serial="emulator-5554",
        adb=Path("/sdk/platform-tools/adb"),
        abi="x86_64",
        version="16.7.19",
        runner=runner,
        cache_dir=tmp_path,
        sleep=slept.append,
        fetcher=lambda *_args, **_kwargs: pytest.fail("download"),
    )
    assert result["status"] == "ok"
    assert result["cached"] is True
    assert result["remote"] == "/data/local/tmp/frida-server"
    assert slept == [2]
    push = next(argv for argv in calls if "push" in argv)
    assert push[-2:] == [str(binary), "/data/local/tmp/frida-server"]
    assert any(argv[-2:] == ["/data/local/tmp/frida-server", "-D"] for argv in calls)
    assert all(argv[1:3] == ["-s", "emulator-5554"] for argv in calls)


def test_ensure_binary_reuses_cache(tmp_path: Path) -> None:
    binary = tmp_path / "16.7.19" / "arm64-v8a" / "frida-server"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"cached")
    result = ensure_frida_binary(
        "16.7.19",
        "arm64-v8a",
        cache_dir=tmp_path,
        fetcher=lambda *_args, **_kwargs: pytest.fail("download"),
    )
    assert result["status"] == "ok"
    assert result["cached"] is True
    assert result["arch"] == "arm64"


@pytest.mark.integration
def test_live_emulator_is_opt_in() -> None:
    if os.environ.get("MAYA_EMULATOR_INTEGRATION") != "1":
        pytest.skip("set MAYA_EMULATOR_INTEGRATION=1 to boot a real emulator")
    result = emulator_up(boot_timeout=60)
    assert result["status"] in {"ok", "error"}
