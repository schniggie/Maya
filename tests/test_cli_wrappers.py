"""Unit tests for CLI wrappers.

Subprocess is mocked. These tests do not need a device, Frida, or network.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from maya.tools.apk_tool import (
    apktool_decompile,
    apktool_rebuild,
    extract_strings,
    ios_class_dump,
    jadx_decompile,
    search_decompiled_code,
    sign_apk,
)
from maya.tools.compliance_tool import _frida_cmd, _run_script, run_compliance_check
from maya.tools.device_bridge import device_install_app, device_list, device_set_proxy, device_shell
from maya.tools.frida_tool import frida_attach, frida_run_script, frida_spawn
from maya.tools.objection_tool import objection_explore, objection_run_command
from maya.tools.proc import run_cli
from maya.tools.reflutter_tool import reflutter_analyze
from maya.tools.terminal import nuclei_scan, python_execute, semgrep_scan, terminal_execute
from maya.tools.verification import verify_device_connected, verify_frida_attached, verify_proxy_active

PACKAGE = "com.example.app"


class CliDouble:
    def __init__(self) -> None:
        self.calls: list[tuple[object, dict]] = []
        self.stdout = ""
        self.stderr = ""
        self.code = 0
        self.mode = "ok"
        self.hook = None

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        if self.hook is not None:
            self.hook(command, kwargs)
        if self.mode == "timeout":
            raise subprocess.TimeoutExpired(command, kwargs.get("timeout", 0), output=self.stdout, stderr=self.stderr)
        if self.mode == "missing":
            name = command if isinstance(command, str) else command[0]
            raise FileNotFoundError(2, "No such file or directory", name)
        return subprocess.CompletedProcess(command, self.code, self.stdout, self.stderr)


@pytest.fixture
def cli(monkeypatch: pytest.MonkeyPatch) -> CliDouble:
    double = CliDouble()
    monkeypatch.setattr("maya.tools.proc.subprocess.run", double)
    monkeypatch.delenv("FRIDA_HOST", raising=False)
    monkeypatch.delenv("ADB_SERVER_SOCKET", raising=False)
    return double


def test_run_cli_forwards_env_and_keeps_nonzero_exit(cli: CliDouble) -> None:
    cli.code = 2
    cli.stdout = "partial table"
    cli.stderr = "rules failed"

    result = run_cli(["semgrep", "--config", "auto", "src"], timeout=15, env={"SEMGREP_SEND_METRICS": "off"})

    command, kwargs = cli.calls[0]
    assert command == ["semgrep", "--config", "auto", "src"]
    assert kwargs["timeout"] == 15
    assert kwargs["env"] == {"SEMGREP_SEND_METRICS": "off"}
    assert kwargs["shell"] is False
    assert result["exit_code"] == 2
    assert result["stdout"] == "partial table"
    assert result["stderr"] == "rules failed"
    assert "error" not in result


def test_run_cli_timeout_and_missing_binary(cli: CliDouble) -> None:
    cli.mode = "timeout"
    cli.stdout = "partial-out"
    cli.stderr = "partial-err"
    timed_out = run_cli(["frida", "-U", "-n", PACKAGE, "-q"], timeout=5)
    assert timed_out["timed_out"] is True
    assert timed_out["exit_code"] is None
    assert timed_out["error"] == "timeout after 5s"
    assert timed_out["stdout"] == "partial-out"
    assert timed_out["stderr"] == "partial-err"

    cli.mode = "missing"
    missing = run_cli(["apktool", "d", "app.apk"], timeout=10)
    assert missing["missing_binary"] is True
    assert missing["error"] == "missing binary: apktool"
    assert missing["exit_code"] is None


def test_frida_argv_uses_usb_or_frida_host(cli: CliDouble, monkeypatch: pytest.MonkeyPatch) -> None:
    attached = frida_attach(PACKAGE, timeout="11")
    assert cli.calls[0][0] == ["frida", "-U", "-n", PACKAGE, "-q"]
    assert cli.calls[0][1]["timeout"] == 11
    assert cli.calls[0][1]["env"] is None
    assert attached["exit_code"] == 0

    spawned = frida_spawn(PACKAGE, timeout="12")
    assert cli.calls[1][0] == ["frida", "-U", "-f", PACKAGE, "-q"]
    assert spawned["exit_code"] == 0

    monkeypatch.setenv("FRIDA_HOST", "10.0.0.8:27042")
    frida_attach(PACKAGE, timeout="7")
    frida_spawn(PACKAGE, timeout="8")
    assert cli.calls[2][0] == ["frida", "-H", "10.0.0.8:27042", "-n", PACKAGE, "-q"]
    assert cli.calls[3][0] == ["frida", "-H", "10.0.0.8:27042", "-f", PACKAGE, "-q"]


def test_frida_run_script_writes_fixture_then_deletes_it(cli: CliDouble, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FRIDA_HOST", "127.0.0.1:27042")
    seen: list[str] = []

    def hook(command, _kwargs) -> None:
        script = Path(command[command.index("-l") + 1])
        seen.append(script.read_text(encoding="utf-8"))

    cli.hook = hook
    cli.stdout = "script-ok"
    cli.stderr = ""
    result = frida_run_script(PACKAGE, "console.log('fixture');", timeout="13")

    command, kwargs = cli.calls[0]
    assert seen == ["console.log('fixture');"]
    assert command == [
        "frida",
        "-H",
        "127.0.0.1:27042",
        "-n",
        PACKAGE,
        "-l",
        result["script_path"],
        "--no-pause",
        "-q",
    ]
    assert kwargs["timeout"] == 13
    assert result["stdout"] == "script-ok"
    assert result["exit_code"] == 0
    assert not Path(result["script_path"]).exists()


def test_frida_attach_timeout_is_a_result(cli: CliDouble) -> None:
    cli.mode = "timeout"
    cli.stderr = "still waiting"
    result = frida_attach(PACKAGE, timeout="4")
    assert result["timed_out"] is True
    assert result["error"] == "timeout after 4s"
    assert result["stderr"] == "still waiting"
    assert result["exit_code"] is None


def test_apktool_and_jadx_argv_and_missing_binary(cli: CliDouble, tmp_path: Path) -> None:
    out = tmp_path / "decoded"
    cli.stdout = "I: Using Apktool"
    decoded = apktool_decompile(str(tmp_path / "app.apk"), str(out))
    assert cli.calls[0][0] == ["apktool", "d", str(tmp_path / "app.apk"), "-f", "-o", str(out)]
    assert cli.calls[0][1]["timeout"] == 180
    assert decoded["stdout"] == "I: Using Apktool"
    assert decoded["output_dir"] == str(out)
    assert out.is_dir()

    jadx_out = tmp_path / "jadx"
    jadx_decompile(str(tmp_path / "app.apk"), str(jadx_out))
    assert cli.calls[1][0] == ["jadx", "-d", str(jadx_out), str(tmp_path / "app.apk")]

    cli.mode = "missing"
    missing = apktool_decompile(str(tmp_path / "app.apk"), str(tmp_path / "again"))
    assert missing["missing_binary"] is True
    assert missing["error"] == "missing binary: apktool"
    assert missing["output_dir"] == str(tmp_path / "again")


def test_search_and_strings_parse_exit_codes(cli: CliDouble, tmp_path: Path) -> None:
    cli.code = 1
    cli.stdout = ""
    no_match = search_decompiled_code(str(tmp_path), "NotARealSymbol")
    assert cli.calls[0][0] == ["rg", "-n", "NotARealSymbol", str(tmp_path)]
    assert no_match["exit_code"] == 1
    assert "error" not in no_match

    cli.code = 0
    cli.stdout = "https://example.invalid/health\n"
    strings = extract_strings(str(tmp_path / "classes.dex"), min_length="6")
    assert cli.calls[1][0] == ["strings", "-n", "6", str(tmp_path / "classes.dex")]
    assert strings["stdout"].startswith("https://example.invalid/health")
    assert strings["exit_code"] == 0

    rejected = extract_strings(str(tmp_path / "classes.dex"), min_length="four")
    assert rejected == {"error": "min_length must be numeric"}
    assert len(cli.calls) == 2


def test_class_dump_and_rebuild_status(cli: CliDouble, tmp_path: Path) -> None:
    headers = tmp_path / "headers"
    ios_class_dump(str(tmp_path / "App"), str(headers))
    assert cli.calls[0][0] == ["class-dump", "-H", str(tmp_path / "App"), "-o", str(headers)]
    assert headers.is_dir()

    missing = apktool_rebuild(str(tmp_path / "does-not-exist"))
    assert missing["error"].startswith("Decompiled directory not found")
    assert len(cli.calls) == 1

    src = tmp_path / "decoded"
    src.mkdir()
    cli.code = 1
    cli.stderr = "brut.androlib.AndrolibException: fixture"
    built = apktool_rebuild(str(src), timeout="30")
    assert cli.calls[1][0] == ["apktool", "b", str(src), "-o", str(src.parent / "decoded-rebuilt.apk")]
    assert cli.calls[1][1]["timeout"] == 30
    assert built["status"] == "build_failed"
    assert built["exit_code"] == 1
    assert "AndrolibException" in built["stderr"]

    cli.mode = "timeout"
    timed_out = apktool_rebuild(str(src), output_apk=str(tmp_path / "out.apk"), timeout="9")
    assert timed_out["timed_out"] is True
    assert timed_out["output_apk"] == str(tmp_path / "out.apk")
    assert "status" not in timed_out


def test_sign_apk_checks_inputs_before_subprocess(
    cli: CliDouble,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_apk = sign_apk(str(tmp_path / "missing.apk"))
    assert "APK not found" in missing_apk["error"]
    assert cli.calls == []

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK fixture")
    monkeypatch.setattr("maya.tools.apk_tool._SIGNER_JAR", tmp_path / "missing-signer.jar")
    missing_jar = sign_apk(str(apk))
    assert "Signer JAR not found" in missing_jar["error"]
    assert cli.calls == []

    signer = tmp_path / "signer.jar"
    signer.write_bytes(b"jar")
    monkeypatch.setattr("maya.tools.apk_tool._SIGNER_JAR", signer)
    cli.stdout = "signed"
    signed = sign_apk(str(apk), timeout="15")
    assert cli.calls[0][0] == ["java", "-jar", str(signer), "--apks", str(apk), "--overwrite"]
    assert cli.calls[0][1]["timeout"] == 15
    assert signed["status"] == "ok"
    assert signed["signed_apk"] == str(apk)
    assert signed["stdout"] == "signed"


def test_objection_and_reflutter_commands(cli: CliDouble, tmp_path: Path) -> None:
    cli.stdout = "help text"
    explored = objection_explore(PACKAGE)
    assert cli.calls[0][0] == ["objection", "-g", PACKAGE, "explore", "-c", "help"]
    assert explored["stdout"] == "help text"

    cli.code = 4
    cli.stderr = "objection failed"
    failed = objection_run_command(PACKAGE, "env", timeout="6")
    assert cli.calls[1] == (
        ["objection", "-g", PACKAGE, "explore", "-c", "env"],
        cli.calls[1][1],
    )
    assert cli.calls[1][1]["timeout"] == 6
    assert failed["exit_code"] == 4
    assert failed["stderr"] == "objection failed"

    cli.code = 0
    cli.stdout = "flutter engine fixture"
    apk = tmp_path / "app.apk"
    analyzed = reflutter_analyze(str(apk))
    assert cli.calls[2][0] == ["reflutter", str(apk)]
    assert cli.calls[2][1]["timeout"] == 120
    assert analyzed["stdout"] == "flutter engine fixture"

    cli.mode = "missing"
    missing = reflutter_analyze(str(apk))
    assert missing["error"] == "missing binary: reflutter"


def test_terminal_python_and_scanners_build_argv(cli: CliDouble, tmp_path: Path) -> None:
    cli.stdout = "ok\n"
    shell = terminal_execute("echo ok", timeout="3")
    assert cli.calls[0][0] == "echo ok"
    assert cli.calls[0][1]["shell"] is True
    assert cli.calls[0][1]["timeout"] == 3
    assert shell["stdout"] == "ok\n"

    python_execute("print(1)", timeout="4")
    assert cli.calls[1][0] == ["python", "-c", "print(1)"]
    assert cli.calls[1][1]["timeout"] == 4

    semgrep_scan(str(tmp_path), timeout="20")
    assert cli.calls[2][0] == ["semgrep", "--config", "auto", str(tmp_path)]

    nuclei_scan("http://example.invalid", timeout="25")
    assert cli.calls[3][0] == ["nuclei", "-u", "http://example.invalid"]
    assert cli.calls[3][1]["timeout"] == 25

    cli.mode = "missing"
    missing = python_execute("print(1)")
    assert missing["missing_binary"] is True
    assert missing["error"] == "missing binary: python"


def test_adb_env_and_proxy_parsing(cli: CliDouble, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cli.stdout = "List of devices attached\n"
    listed = device_list()
    assert cli.calls[0][0] == ["adb", "devices"]
    assert listed["stdout"].startswith("List of devices attached")
    assert listed["exit_code"] == 0

    monkeypatch.setenv("ADB_SERVER_SOCKET", "tcp:127.0.0.1:5037")
    cli.stdout = "ok"
    device_shell("echo ok", timeout="9")
    assert cli.calls[1][0] == ["adb", "-L", "tcp:127.0.0.1:5037", "shell", "echo ok"]
    assert cli.calls[1][1]["timeout"] == 9

    cli.code = 1
    cli.stderr = "Failure [INSTALL_FAILED_FIXTURE]"
    apk = tmp_path / "app.apk"
    installed = device_install_app(str(apk), timeout="12")
    assert cli.calls[2][0] == ["adb", "-L", "tcp:127.0.0.1:5037", "install", "-r", str(apk)]
    assert installed["exit_code"] == 1
    assert "INSTALL_FAILED_FIXTURE" in installed["stderr"]

    cli.code = 0
    cli.stderr = ""
    proxy = device_set_proxy(host="127.0.0.1", port="8080", timeout="5")
    assert cli.calls[3][0] == [
        "adb",
        "-L",
        "tcp:127.0.0.1:5037",
        "shell",
        "settings",
        "put",
        "global",
        "http_proxy",
        "127.0.0.1:8080",
    ]
    assert proxy["status"] == "ok"
    assert proxy["proxy"] == "127.0.0.1:8080"

    cli.mode = "timeout"
    timed_out = device_set_proxy(timeout="2")
    assert timed_out["timed_out"] is True
    assert "status" not in timed_out


def test_verification_parsers(cli: CliDouble) -> None:
    cli.stdout = "List of devices attached\nemulator-5554\tdevice\n"
    connected = verify_device_connected()
    assert connected["status"] == "ok"
    assert connected["devices"] == ["emulator-5554\tdevice"]

    cli.stdout = " PID  Name\n  42  com.example.other\n"
    absent = verify_frida_attached(PACKAGE)
    assert absent["status"] == "error"

    cli.stdout = f" PID  Name\n  42  {PACKAGE}\n"
    present = verify_frida_attached(PACKAGE)
    assert cli.calls[-1][0] == ["frida-ps", "-U"]
    assert present["status"] == "ok"

    cli.code = 7
    cli.stdout = ""
    proxy = verify_proxy_active(host="127.0.0.1", port="9")
    assert cli.calls[-1][0] == ["curl", "-s", "http://127.0.0.1:9"]
    assert cli.calls[-1][1]["timeout"] == 10
    assert proxy["status"] == "error"

    cli.mode = "missing"
    missing = verify_device_connected()
    assert missing["missing_binary"] is True
    assert missing["error"] == "missing binary: adb"


def test_compliance_runner_uses_host_and_reports_timeout(
    cli: CliDouble,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    script = tmp_path / "fixture.js"
    script.write_text("console.log('fixture');\n", encoding="utf-8")

    monkeypatch.delenv("FRIDA_HOST", raising=False)
    assert _frida_cmd(PACKAGE, str(script))[:4] == ["frida", "-U", "-n", PACKAGE]
    monkeypatch.setenv("FRIDA_HOST", "10.0.0.9:27042")
    assert _frida_cmd(PACKAGE, str(script)) == [
        "frida",
        "-H",
        "10.0.0.9:27042",
        "-n",
        PACKAGE,
        "-l",
        str(script),
        "--no-pause",
        "-q",
    ]

    missing = _run_script(PACKAGE, tmp_path / "absent.js", timeout=3)
    assert missing["error"].startswith("Script not found")
    assert cli.calls == []

    cli.stdout = "fixture-ran"
    cli.code = 0
    ran = _run_script(PACKAGE, script, timeout=6)
    assert cli.calls[0][0][0] == "frida"
    assert cli.calls[0][0][cli.calls[0][0].index("-l") + 1] == str(script)
    assert cli.calls[0][1]["timeout"] == 6
    assert ran["stdout"] == "fixture-ran"
    assert ran["exit_code"] == 0

    cli.mode = "timeout"
    cli.stderr = "hung"
    timed_out = _run_script(PACKAGE, script, timeout=2)
    assert timed_out["exit_code"] == -1
    assert timed_out["error"] == "Script timed out after 2s"
    assert timed_out["stderr"] == "hung"

    unknown = run_compliance_check(PACKAGE, "not-a-check")
    assert unknown["error"].startswith("Unknown check")
    assert len(cli.calls) == 2
