"""HTTP client for the Android companion on port 9999.

Calls check ``GET /health`` before posting a command. Connection failures are
retried with backoff. Read timeouts on ``POST`` are not retried, because the
device may already have accepted the command. Every public method returns a
dict and does not raise.
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
from collections.abc import Callable, Mapping
from typing import Any

import requests

_HEALTHY = {"ok", "healthy", "success", "up"}
_RETRY_STATUS = {502, 503, 504}
_SCALAR = (str, int, float, bool)


def normalize_companion_base(url: str) -> str:
    """Accept either the server origin or a ``/command`` URL."""
    cleaned = url.strip().rstrip("/")
    for suffix in ("/command", "/health", "/commands"):
        if cleaned.endswith(suffix):
            cleaned = cleaned[: -len(suffix)]
            break
    return cleaned.rstrip("/")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _content_type(response: Any) -> str:
    headers = getattr(response, "headers", {}) or {}
    getter = getattr(headers, "get", None)
    if getter is None:
        return ""
    value = getter("Content-Type")
    if not value:
        value = getter("content-type")
    return "" if value is None else str(value)


def _parse_body(response: Any) -> tuple[Any, bool]:
    text = str(getattr(response, "text", "") or "")
    content_type = _content_type(response).lower()
    if "json" in content_type or text.lstrip().startswith(("{", "[")):
        try:
            decoder = getattr(response, "json", None)
            if callable(decoder) and "json" in content_type:
                return decoder(), False
            return json.loads(text), False
        except (TypeError, ValueError, json.JSONDecodeError):
            return text, True
    return text, False


def build_command_payload(
    command: str,
    params: Mapping[str, Any] | None = None,
    request_id: str = "cmd_local",
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Validate one companion command and return the JSON body."""
    if not str(command).strip():
        return None, {"status": "error", "error": "command is required"}
    converted, problem = _string_params(params)
    if problem is not None:
        return None, problem
    identifier = request_id.strip() or "cmd_local"
    return {"id": identifier, "command": str(command).strip(), "params": converted or {}}, None


def _string_params(params: Mapping[str, Any] | None) -> tuple[dict[str, str] | None, dict[str, Any] | None]:
    if params is None:
        return {}, None
    if not isinstance(params, Mapping):
        return None, {"status": "error", "error": "params must be a JSON object"}
    converted: dict[str, str] = {}
    for key, value in params.items():
        if not isinstance(key, str) or not key.strip():
            return None, {"status": "error", "error": "param names must be non-empty strings"}
        if value is None:
            converted[key] = ""
        elif isinstance(value, bool):
            converted[key] = "true" if value else "false"
        elif isinstance(value, _SCALAR) and not isinstance(value, bool):
            converted[key] = str(value)
        else:
            return None, {"status": "error", "error": "param values must be strings, numbers, or booleans"}
    return converted, None


class CompanionClient:
    """Small retrying client for the companion HTTP server."""

    def __init__(
        self,
        base_url: str,
        *,
        read_timeout: float,
        connect_timeout: float = 2.0,
        attempts: int = 3,
        backoff_seconds: float = 0.2,
        sleep: Callable[[float], None] = time.sleep,
        session: Any = None,
    ) -> None:
        self.base_url = normalize_companion_base(base_url)
        self.read_timeout = float(read_timeout)
        self.connect_timeout = float(connect_timeout)
        self.attempts = min(5, max(1, int(attempts)))
        self.backoff_seconds = max(0.0, float(backoff_seconds))
        self._sleep = sleep
        self._session = session if session is not None else requests.Session()

    @classmethod
    def from_env(
        cls,
        *,
        read_timeout: float,
        sleep: Callable[[float], None] | None = None,
        session: Any = None,
    ) -> CompanionClient:
        raw = os.environ.get("COMPANION_HTTP_URL", "http://127.0.0.1:9999/command")
        connect_timeout = _env_float("COMPANION_CONNECT_TIMEOUT", 2.0)
        backoff_seconds = _env_float("COMPANION_BACKOFF_SECONDS", 0.2)
        if connect_timeout <= 0:
            connect_timeout = 2.0
        if backoff_seconds < 0:
            backoff_seconds = 0.2
        return cls(
            raw,
            read_timeout=read_timeout,
            connect_timeout=connect_timeout,
            attempts=_env_int("COMPANION_ATTEMPTS", 3),
            backoff_seconds=backoff_seconds,
            sleep=time.sleep if sleep is None else sleep,
            session=session,
        )

    def health(self) -> dict[str, Any]:
        """GET /health. Connection failures and read timeouts are retried."""
        problem = self._preflight()
        if problem is not None:
            return problem
        result = self._exchange("GET", "/health", None, retry_read_timeout=True)
        if result.get("status") != "ok":
            result["available"] = False
            result["degraded"] = True
            return result
        body = result.get("response")
        if isinstance(body, dict) and "status" in body:
            reported = str(body.get("status", "")).lower()
            if reported not in _HEALTHY:
                return {
                    "status": "unavailable",
                    "error": "companion unhealthy",
                    "response": body,
                    "http_status": result.get("http_status"),
                    "endpoint": result.get("endpoint"),
                    "attempts": result.get("attempts", 1),
                    "available": False,
                    "degraded": True,
                }
        result["available"] = True
        return result

    def command(
        self,
        command: str,
        params: Mapping[str, Any] | None = None,
        *,
        request_id: str = "cmd_local",
    ) -> dict[str, Any]:
        """Health-check, then POST one command. Does not raise."""
        prepared, problem = build_command_payload(command, params, request_id)
        if problem is not None:
            return problem
        health = self.health()
        if health.get("status") != "ok":
            return health
        return self._exchange("POST", "/command", prepared, retry_read_timeout=False)

    def _preflight(self) -> dict[str, Any] | None:
        if self.read_timeout <= 0 or self.connect_timeout <= 0:
            return {"status": "error", "error": "timeout must be positive"}
        parts = urllib.parse.urlsplit(self.base_url)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            return {"status": "error", "error": "companion url is invalid", "endpoint": self.base_url}
        return None

    def _endpoint(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _delay(self, failed_attempts: int) -> float:
        return min(self.backoff_seconds * (2 ** (failed_attempts - 1)), 2.0)

    def _exchange(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
        *,
        retry_read_timeout: bool,
    ) -> dict[str, Any]:
        endpoint = self._endpoint(path)
        result: dict[str, Any] = {
            "status": "unavailable",
            "error": "companion unreachable",
            "endpoint": endpoint,
            "attempts": 0,
            "available": False,
            "degraded": True,
        }
        for attempt in range(1, self.attempts + 1):
            result, retry = self._once(method, endpoint, payload, attempt, retry_read_timeout=retry_read_timeout)
            if not retry or attempt >= self.attempts:
                return result
            self._sleep(self._delay(attempt))
        return result

    def _once(
        self,
        method: str,
        endpoint: str,
        payload: dict[str, Any] | None,
        attempt: int,
        *,
        retry_read_timeout: bool,
    ) -> tuple[dict[str, Any], bool]:
        try:
            response = self._session.request(
                method,
                endpoint,
                json=payload,
                timeout=(self.connect_timeout, self.read_timeout),
            )
        except requests.Timeout as exc:
            retry = retry_read_timeout or isinstance(exc, requests.ConnectTimeout)
            return self._transport_failure(
                "companion timeout",
                endpoint,
                attempt,
                exc,
                timed_out=True,
            ), retry
        except requests.ConnectionError as exc:
            return self._transport_failure("companion unreachable", endpoint, attempt, exc, timed_out=False), True
        except requests.RequestException as exc:
            failure = self._transport_failure("companion request failed", endpoint, attempt, exc, timed_out=False)
            failure["status"] = "error"
            return failure, False
        except Exception as exc:  # noqa: BLE001
            failure = self._transport_failure("companion request failed", endpoint, attempt, exc, timed_out=False)
            failure["status"] = "error"
            return failure, False

        interpreted = self._interpret(response, endpoint, attempt)
        if getattr(response, "status_code", None) in _RETRY_STATUS:
            interpreted["available"] = False
            interpreted["degraded"] = True
            return interpreted, True
        return interpreted, False

    def _transport_failure(
        self,
        error: str,
        endpoint: str,
        attempt: int,
        exc: Exception,
        *,
        timed_out: bool,
    ) -> dict[str, Any]:
        return {
            "status": "unavailable",
            "error": error,
            "detail": f"{type(exc).__name__}: {exc}",
            "endpoint": endpoint,
            "attempts": attempt,
            "available": False,
            "degraded": True,
            "timed_out": timed_out,
        }

    def _interpret(self, response: Any, endpoint: str, attempt: int) -> dict[str, Any]:
        status_code = int(getattr(response, "status_code", 0) or 0)
        body, invalid_json = _parse_body(response)
        if invalid_json:
            return {
                "status": "error",
                "error": "companion returned invalid json",
                "response": body,
                "http_status": status_code,
                "endpoint": endpoint,
                "attempts": attempt,
            }
        if 200 <= status_code < 300:
            return {
                "status": "ok",
                "response": body,
                "http_status": status_code,
                "endpoint": endpoint,
                "attempts": attempt,
            }
        detail = body.get("error") if isinstance(body, dict) else None
        if status_code in _RETRY_STATUS or status_code >= 500:
            error = "companion request failed"
            status = "unavailable" if status_code in _RETRY_STATUS else "error"
        else:
            error = "companion rejected command"
            status = "error"
        result: dict[str, Any] = {
            "status": status,
            "error": error,
            "response": body,
            "http_status": status_code,
            "endpoint": endpoint,
            "attempts": attempt,
        }
        if detail:
            result["detail"] = str(detail)
        return result
