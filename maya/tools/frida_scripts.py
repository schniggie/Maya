"""Discover and load Frida scripts that already ship with Maya.

The registry names a script, checks that it stays inside a script root, and
reads it as UTF-8. Injection stays in ``frida_run_script``.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .registry import register_tool

MAX_SCRIPT_BYTES = 64 * 1024


def _bundled_locations() -> tuple[Path, Path]:
    """Checkout tree first, then the path used by the sandbox image."""
    repo = Path(__file__).resolve().parents[2] / "assets" / "frida-scripts"
    image = Path("/opt/maya-assets/frida-scripts")
    return repo, image


def bundled_root() -> Path:
    """Directory of scripts shipped with Maya."""
    repo, image = _bundled_locations()
    if repo.is_dir():
        return repo
    if image.is_dir():
        return image
    return repo


@dataclass(frozen=True)
class ScriptRecord:
    name: str
    stem: str
    category: str
    origin: str
    description: str
    size: int
    readable: bool
    error: str | None = None
    source: str | None = None


def _origin_for(root: Path) -> str:
    try:
        if root.resolve() == bundled_root().resolve():
            return "bundled"
    except OSError:
        return "user"
    return "user"


def _normalize_name(name: str) -> str | None:
    cleaned = name.strip().replace("\\", "/")
    if not cleaned or cleaned.startswith("/"):
        return None
    if cleaned.endswith(".js"):
        cleaned = cleaned[: -len(".js")]
    parts = [part for part in cleaned.split("/") if part != ""]
    if not parts or any(part in {".", ".."} or part.startswith(".") for part in parts):
        return None
    if any(not _safe_part(part) for part in parts):
        return None
    return "/".join(parts)


def _safe_part(part: str) -> bool:
    if len(part) > 128:
        return False
    return all(char.isalnum() or char in {"_", "-"} for char in part)


def _inside_root(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def _first_comment(text: str) -> str:
    for raw in text.splitlines()[:15]:
        line = raw.strip()
        if not line:
            continue
        if line.startswith("//"):
            return line[2:].strip()
        if line.startswith("/*"):
            body = line[2:].strip()
            if body.endswith("*/"):
                body = body[:-2].strip()
            return body
        if line.startswith("*") and not line.startswith("*/"):
            return line.lstrip("*").strip()
        return ""
    return ""


def _description(text: str, stem: str) -> str:
    line = _first_comment(text)
    for prefix in (f"{stem}.js — ", f"{stem}.js - ", f"{stem}.js: ", f"{stem}.js "):
        if line.startswith(prefix):
            line = line[len(prefix) :].strip(" —-:")
            break
    return " ".join(line.split())[:200]


def _inspect(root: Path, path: Path, name: str) -> ScriptRecord:
    stem = name.rsplit("/", 1)[-1]
    category = name.split("/", 1)[0] if "/" in name else ""
    origin = _origin_for(root)
    record = ScriptRecord(
        name=name,
        stem=stem,
        category=category,
        origin=origin,
        description="",
        size=0,
        readable=False,
    )
    if not _inside_root(path, root):
        return _replace(record, error="path escapes script root")
    try:
        if not path.is_file():
            return _replace(record, error="script is not a file")
        size = path.stat().st_size
    except OSError as exc:
        return _replace(record, error=f"unreadable script: {exc.strerror or exc}")
    if size <= 0:
        return _replace(record, error="script is empty", size=size)
    if size > MAX_SCRIPT_BYTES:
        return _replace(record, error="script exceeds size limit", size=size)
    try:
        source = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return _replace(record, error="script is not utf-8", size=size)
    except OSError as exc:
        return _replace(record, error=f"unreadable script: {exc.strerror or exc}", size=size)
    return _replace(
        record,
        description=_description(source, stem),
        size=size,
        readable=True,
        source=source,
    )


def _replace(record: ScriptRecord, **changes: Any) -> ScriptRecord:
    data = {
        "name": record.name,
        "stem": record.stem,
        "category": record.category,
        "origin": record.origin,
        "description": record.description,
        "size": record.size,
        "readable": record.readable,
        "error": record.error,
        "source": record.source,
    }
    data.update(changes)
    return ScriptRecord(**data)


def resolve_roots(roots: Sequence[Path] | None = None) -> tuple[list[Path], dict[str, Any] | None]:
    """Return script roots, or an error dict when an explicit root is missing."""
    if roots is not None:
        return [Path(root) for root in roots], None

    override = os.environ.get("MAYA_FRIDA_SCRIPTS", "").strip()
    if override:
        path = Path(override).expanduser()
        if not path.is_dir():
            return [], {"status": "error", "error": "script root is not a directory", "root": str(path)}
        chosen = [path]
    else:
        chosen = []
        user = Path.home() / ".maya" / "frida-scripts"
        if user.is_dir():
            chosen.append(user)

    bundled = bundled_root()
    if bundled.is_dir() and all(bundled.resolve() != root.resolve() for root in chosen):
        chosen.append(bundled)
    if not chosen:
        return [], {"status": "error", "error": "no frida script roots found"}
    return chosen, None


def discover(roots: Sequence[Path]) -> dict[str, ScriptRecord]:
    """Map ``category/stem`` to a record. Earlier roots win on duplicate names."""
    found: dict[str, ScriptRecord] = {}
    for root in roots:
        if not root.is_dir():
            continue
        try:
            paths = sorted(root.rglob("*.js"))
        except OSError:
            continue
        for path in paths:
            try:
                relative_parts = path.relative_to(root).parts
            except ValueError:
                continue
            if any(part.startswith(".") for part in relative_parts):
                continue
            try:
                relative = path.resolve().relative_to(root.resolve())
            except (OSError, ValueError):
                relative = path.relative_to(root)
            name = "/".join(relative.with_suffix("").parts)
            if not _normalize_name(name) or name in found:
                continue
            found[name] = _inspect(root, path, name)
    return found


def _public(record: ScriptRecord, *, include_source: bool) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": record.name,
        "stem": record.stem,
        "category": record.category,
        "description": record.description,
        "origin": record.origin,
        "bytes": record.size,
        "readable": record.readable,
    }
    if record.error:
        payload["error"] = record.error
    if include_source and record.source is not None:
        payload["source"] = record.source
    return payload


def _lookup(name: str, roots: Sequence[Path] | None) -> dict[str, Any]:
    normalized = _normalize_name(name)
    if normalized is None:
        return {"status": "error", "error": "invalid script name", "name": name}
    chosen, problem = resolve_roots(roots)
    if problem is not None:
        problem["name"] = name
        return problem
    catalog = discover(chosen)
    selected = normalized
    if selected not in catalog and "/" not in selected:
        matches = [item for item in catalog if item == selected or item.endswith("/" + selected)]
        if len(matches) == 1:
            selected = matches[0]
        elif len(matches) > 1:
            return {
                "status": "error",
                "error": "ambiguous frida script",
                "name": name,
                "matches": sorted(matches),
            }
    record = catalog.get(selected)
    if record is None:
        stem = selected.rsplit("/", 1)[-1]
        suggestions = [item for item in catalog if item == stem or item.endswith("/" + stem)]
        return {
            "status": "error",
            "error": f"unknown frida script: {name}",
            "name": name,
            "matches": sorted(suggestions),
        }
    if not record.readable or record.source is None:
        payload = _public(record, include_source=False)
        payload["status"] = "error"
        payload["error"] = record.error or "unreadable script"
        return payload
    payload = _public(record, include_source=True)
    payload["status"] = "ok"
    return payload


def list_scripts(category: str = "", *, roots: Sequence[Path] | None = None) -> dict[str, Any]:
    """List scripts by name and metadata. Source text is not included."""
    chosen, problem = resolve_roots(roots)
    if problem is not None:
        return problem
    wanted = category.strip().strip("/")
    if wanted and _normalize_name(wanted) is None:
        return {"status": "error", "error": "invalid script category", "category": category}
    scripts = []
    for record in discover(chosen).values():
        if wanted and record.category != wanted and record.name != wanted:
            continue
        scripts.append(_public(record, include_source=False))
    scripts.sort(key=lambda item: item["name"])
    result: dict[str, Any] = {"status": "ok", "count": len(scripts), "scripts": scripts}
    if wanted:
        result["category"] = wanted
    return result


def load_script(name: str, *, roots: Sequence[Path] | None = None) -> dict[str, Any]:
    """Read one script by ``category/name`` or a unique file stem."""
    return _lookup(name, roots)


@register_tool(sandbox_execution=False)
def frida_list_scripts(category: str = "") -> dict:
    """List Frida scripts shipped with Maya, plus the user script directory when present.

    Returns name, category, description, and whether each file is readable.
    """
    return list_scripts(category)


@register_tool(sandbox_execution=False)
def frida_load_script(name: str) -> dict:
    """Read one Frida script by name. Returns source text or an error dict."""
    return load_script(name)
