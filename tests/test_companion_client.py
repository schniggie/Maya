"""Device-free tests for the companion HTTP client."""

from __future__ import annotations

import json

import pytest
import requests

from maya.tools.companion_client import CompanionClient, normalize_companion_base
from maya.tools.device_bridge import companion_app_command
from maya.tools.drozer_tool import drozer_device_info


class FakeResponse:
    def __init__(self, status_code: int, body, content_type: str = "application/json") -> None:
        self.status_code = status_code
        self.text = body if isinstance(body, str) else json.dumps(body)
        self.headers = {"Content-Type": content_type}

    def json(self):
        return json.loads(self.text)


class ScriptedSession:
    def __init__(self, outcomes: list) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[dict] = []

    def request(self, method, url, json=None, timeout=None, **kwargs):
        self.calls.append({"method": method, "url": url, "json": json, "timeout": timeout})
        if not self.outcomes:
            raise AssertionError(f"unexpected {method} {url}")
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _client(session: ScriptedSession, sleeps: list[float], **kwargs) -> CompanionClient:
    options = {
        "read_timeout": 5,
        "connect_timeout": 2,
        "attempts": 3,
        "backoff_seconds": 0.2,
        "sleep": sleeps.append,
        "session": session,
    }
    options.update(kwargs)
    return CompanionClient("http://127.0.0.1:9999/command", **options)


def _health_ok() -> FakeResponse:
    return FakeResponse(200, {"status": "ok", "service": "maya-companion-android"})


@pytest.fixture
def companion_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COMPANION_HTTP_URL", "http://127.0.0.1:9999/command")
    monkeypatch.delenv("COMPANION_WS_URL", raising=False)
    monkeypatch.setenv("COMPANION_ATTEMPTS", "3")
    monkeypatch.setenv("COMPANION_BACKOFF_SECONDS", "0.2")
    monkeypatch.setenv("COMPANION_CONNECT_TIMEOUT", "2")


def test_normalize_accepts_origin_or_command_url() -> None:
    assert normalize_companion_base("http://127.0.0.1:9999/command") == "http://127.0.0.1:9999"
    assert normalize_companion_base("http://127.0.0.1:9999/") == "http://127.0.0.1:9999"


def test_command_checks_health_then_posts_once() -> None:
    sleeps: list[float] = []
    session = ScriptedSession(
        [
            _health_ok(),
            FakeResponse(200, {"id": "cmd_local", "status": "success", "data": {"platform": "android"}}),
        ]
    )
    result = _client(session, sleeps).command("get_status", {"verbose": True})

    assert sleeps == []
    assert [call["method"] for call in session.calls] == ["GET", "POST"]
    assert session.calls[0]["url"] == "http://127.0.0.1:9999/health"
    assert session.calls[1]["url"] == "http://127.0.0.1:9999/command"
    assert session.calls[1]["timeout"] == (2, 5)
    assert session.calls[1]["json"] == {
        "id": "cmd_local",
        "command": "get_status",
        "params": {"verbose": "true"},
    }
    assert result["status"] == "ok"
    assert result["response"]["status"] == "success"
    assert result["attempts"] == 1


def test_connection_failures_retry_then_degrade_without_raising() -> None:
    sleeps: list[float] = []
    session = ScriptedSession([requests.ConnectionError("connection refused") for _ in range(3)])
    result = _client(session, sleeps).command("get_status", {})

    assert result["status"] == "unavailable"
    assert result["error"] == "companion unreachable"
    assert result["available"] is False
    assert result["degraded"] is True
    assert result["attempts"] == 3
    assert result["timed_out"] is False
    assert "ConnectionError" in result["detail"]
    assert sleeps == [0.2, 0.4]
    assert [call["method"] for call in session.calls] == ["GET", "GET", "GET"]


def test_unhealthy_companion_skips_the_command() -> None:
    sleeps: list[float] = []
    session = ScriptedSession([FakeResponse(200, {"status": "error", "error": "not ready"})])
    result = _client(session, sleeps).command("get_status", {})

    assert result["error"] == "companion unhealthy"
    assert result["available"] is False
    assert [call["method"] for call in session.calls] == ["GET"]
    assert sleeps == []


def test_gateway_errors_retry_and_client_errors_do_not() -> None:
    sleeps: list[float] = []
    retrying = ScriptedSession(
        [
            _health_ok(),
            FakeResponse(503, {"error": "busy"}),
            FakeResponse(200, {"status": "success"}),
        ]
    )
    retried = _client(retrying, sleeps).command("get_status", {})
    assert retried["status"] == "ok"
    assert retried["attempts"] == 2
    assert sleeps == [0.2]
    assert [call["method"] for call in retrying.calls] == ["GET", "POST", "POST"]

    rejected = ScriptedSession(
        [_health_ok(), FakeResponse(400, {"id": "cmd_local", "status": "error", "error": "unknown command: nope"})]
    )
    result = _client(rejected, []).command("nope", {})
    assert result["status"] == "error"
    assert result["error"] == "companion rejected command"
    assert result["http_status"] == 400
    assert result["detail"] == "unknown command: nope"
    assert result["attempts"] == 1
    assert len(rejected.calls) == 2


def test_post_read_timeout_is_not_retried() -> None:
    sleeps: list[float] = []
    session = ScriptedSession([_health_ok(), requests.ReadTimeout("timed out")])
    result = _client(session, sleeps).command("get_status", {})

    assert result["error"] == "companion timeout"
    assert result["timed_out"] is True
    assert result["attempts"] == 1
    assert sleeps == []
    assert [call["method"] for call in session.calls] == ["GET", "POST"]


def test_health_read_timeout_is_retried() -> None:
    sleeps: list[float] = []
    session = ScriptedSession([requests.ReadTimeout("slow"), _health_ok()])
    result = _client(session, sleeps).health()

    assert result["status"] == "ok"
    assert result["available"] is True
    assert result["attempts"] == 2
    assert sleeps == [0.2]


def test_invalid_input_and_url_do_not_touch_the_network() -> None:
    session = ScriptedSession([])
    client = _client(session, [])
    assert client.command("  ", {})["error"] == "command is required"
    nested = client.command("get_status", {"bad": {"nested": True}})
    assert nested["error"] == "param values must be strings, numbers, or booleans"
    invalid = CompanionClient("ftp://files.example", read_timeout=1, session=session).health()
    assert invalid["error"] == "companion url is invalid"
    assert session.calls == []


def test_unexpected_client_exception_becomes_an_error_dict() -> None:
    session = ScriptedSession([RuntimeError("socket blew up")])
    result = _client(session, []).health()
    assert result["status"] == "error"
    assert result["error"] == "companion request failed"
    assert "RuntimeError" in result["detail"]


def test_from_env_clamps_attempts_and_ignores_bad_numbers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COMPANION_HTTP_URL", "http://10.0.0.4:9999/health")
    monkeypatch.setenv("COMPANION_ATTEMPTS", "99")
    monkeypatch.setenv("COMPANION_CONNECT_TIMEOUT", "nope")
    monkeypatch.setenv("COMPANION_BACKOFF_SECONDS", "-4")
    client = CompanionClient.from_env(read_timeout=8, session=ScriptedSession([]))
    assert client.base_url == "http://10.0.0.4:9999"
    assert client.attempts == 5
    assert client.connect_timeout == 2.0
    assert client.backoff_seconds == 0.2
    assert client.read_timeout == 8


def test_companion_app_command_rejects_bad_args_without_a_request(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_args, **_kwargs):
        raise AssertionError("network client should not be built")

    monkeypatch.setattr("maya.tools.device_bridge.CompanionClient.from_env", _boom)
    bad_json = companion_app_command("get_status", params="[1]", timeout="5")
    assert bad_json == {"status": "error", "error": "params must be a JSON object"}
    bad_timeout = companion_app_command("get_status", params="{}", timeout="soon")
    assert bad_timeout["error"] == "timeout must be numeric"
    blank = companion_app_command("  ", params="{}", timeout="5")
    assert blank["error"] == "command is required"


def test_companion_app_command_uses_http_and_reports_absent_device(
    monkeypatch: pytest.MonkeyPatch, companion_env: None
) -> None:
    sleeps: list[float] = []
    session = ScriptedSession([requests.ConnectTimeout("connect timed out") for _ in range(3)])
    monkeypatch.setattr("maya.tools.companion_client.requests.Session", lambda: session)
    monkeypatch.setattr("maya.tools.companion_client.time.sleep", sleeps.append)

    result = companion_app_command("get_status", params="{}", timeout="4")

    assert result["error"] == "companion timeout"
    assert result["available"] is False
    assert result["degraded"] is True
    assert result["attempts"] == 3
    assert sleeps == [0.2, 0.4]
    assert all(call["url"].endswith("/health") for call in session.calls)


def test_websocket_failure_falls_back_to_http(monkeypatch: pytest.MonkeyPatch, companion_env: None) -> None:
    class _Sockets:
        @staticmethod
        def connect(*_args, **_kwargs):
            raise OSError("websocket unavailable")

    session = ScriptedSession([_health_ok(), FakeResponse(200, {"status": "success", "id": "cmd_local"})])
    monkeypatch.setenv("COMPANION_WS_URL", "ws://127.0.0.1:9999/command")
    monkeypatch.setattr("maya.tools.device_bridge.websockets", _Sockets())
    monkeypatch.setattr("maya.tools.companion_client.requests.Session", lambda: session)

    result = companion_app_command("get_status", params="{}", timeout="4")
    assert result["status"] == "ok"
    assert result["response"]["status"] == "success"
    assert "websocket_error" not in result


def test_drozer_returns_command_body_and_degrades_when_health_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COMPANION_HTTP_URL", "http://127.0.0.1:9999/command")
    monkeypatch.setenv("COMPANION_ATTEMPTS", "1")
    ok = ScriptedSession(
        [
            _health_ok(),
            FakeResponse(200, {"id": "drozer_device_info", "status": "success", "data": {"sdk": "34"}}),
        ]
    )
    monkeypatch.setattr("maya.tools.companion_client.requests.Session", lambda: ok)
    body = drozer_device_info()
    assert body["status"] == "success"
    assert body["data"]["sdk"] == "34"
    assert ok.calls[1]["json"]["id"] == "drozer_device_info"
    assert ok.calls[1]["json"]["command"] == "device_info"

    down = ScriptedSession([requests.ConnectionError("device absent")])
    monkeypatch.setattr("maya.tools.companion_client.requests.Session", lambda: down)
    missing = drozer_device_info()
    assert missing["error"] == "companion unreachable"
    assert missing["available"] is False
    assert missing.get("status") != "success"
