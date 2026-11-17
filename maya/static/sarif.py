"""SARIF 2.1.0 export for the device-free static scan.

The document describes the same findings ``report.json`` already carries.
It does not run a second scanner.
"""

from __future__ import annotations

import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from urllib.parse import quote

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
_SECURITY_SEVERITY = {
    "critical": "9.1",
    "high": "8.0",
    "medium": "5.0",
    "low": "3.0",
    "info": "1.0",
}
_SLUG = re.compile(r"[^a-z0-9]+")


def report_to_sarif(report: dict) -> dict:
    """Build a SARIF 2.1.0 document from a successful static-scan report."""
    findings = [item for item in report.get("findings") or [] if isinstance(item, dict)]
    uri = artifact_uri(str(report.get("apk") or "app.apk"))
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    results: list[dict] = []
    for finding in findings:
        rule_id = _rule_id(finding, rule_index, rules)
        severity = _severity(finding)
        result: dict = {
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "level": _LEVEL[severity],
            "kind": "review" if severity == "info" else "fail",
            "message": {"text": _message(finding)},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                    }
                }
            ],
            "partialFingerprints": {"mayaFindingId": str(finding.get("id") or rule_id)},
            "properties": {
                "severity": severity,
                "category": str(finding.get("category") or ""),
            },
        }
        package = str(report.get("package") or "")
        if package:
            result["locations"][0]["logicalLocations"] = [
                {"name": package, "fullyQualifiedName": package, "kind": "module"}
            ]
        results.append(result)

    run: dict = {
        "tool": {
            "driver": {
                "name": "maya-static",
                "version": _tool_version(),
                "informationUri": "https://github.com/schniggie/Maya",
                "rules": rules,
            }
        },
        "automationDetails": {"id": "maya-static/"},
        "invocations": [{"executionSuccessful": True}],
        "results": results,
        "properties": {
            "scanner": "maya-static",
            "package": str(report.get("package") or ""),
        },
    }
    return {"$schema": _SCHEMA, "version": "2.1.0", "runs": [run]}


def artifact_uri(apk: str) -> str:
    """Repo-relative SARIF URI for an APK path.

    Absolute paths outside the working directory, and any path that climbs
    with ``..``, become the file name. GitHub code scanning rejects both.
    """
    normalized = apk.replace("\\", "/").strip()
    path = Path(normalized)
    if path.is_absolute():
        try:
            candidate = path.resolve().relative_to(Path.cwd().resolve()).as_posix()
        except ValueError:
            candidate = path.name
    else:
        candidate = path.as_posix()
    parts = [part for part in candidate.split("/") if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        parts = [path.name or "app.apk"]
    return quote("/".join(parts), safe="/")


def _rule_id(finding: dict, rule_index: dict[str, int], rules: list[dict]) -> str:
    slug = _SLUG.sub("-", str(finding.get("title") or "finding").lower()).strip("-") or "finding"
    base = f"maya-static/{slug[:80]}"
    finding_id = str(finding.get("id") or "")
    if base not in rule_index:
        rule_index[base] = len(rules)
        rules.append(_rule(finding, base))
        return base
    existing = rules[rule_index[base]]
    if existing.get("properties", {}).get("findingId") == finding_id:
        return base
    unique = f"{base}-{finding_id}" if finding_id else f"{base}-{len(rules)}"
    if unique not in rule_index:
        rule_index[unique] = len(rules)
        rules.append(_rule(finding, unique))
    return unique


def _rule(finding: dict, rule_id: str) -> dict:
    severity = _severity(finding)
    title = _clip(finding.get("title") or rule_id, 240)
    category = str(finding.get("category") or "")
    tags = ["security"]
    if category:
        tags.append(category)
    return {
        "id": rule_id,
        "name": title,
        "shortDescription": {"text": title},
        "fullDescription": {"text": _clip(finding.get("description") or title, 4000)},
        "help": {"text": _clip(finding.get("remediation") or finding.get("description") or title, 4000)},
        "defaultConfiguration": {"level": _LEVEL[severity]},
        "properties": {
            "security-severity": _SECURITY_SEVERITY[severity],
            "tags": tags,
            "severity": severity,
            "findingId": str(finding.get("id") or ""),
            "category": category,
        },
    }


def _message(finding: dict) -> str:
    parts = [_clip(finding.get("description") or finding.get("title") or "Static finding", 4000)]
    if finding.get("impact"):
        parts.append("Impact: " + _clip(finding["impact"], 2000))
    if finding.get("poc"):
        parts.append("Proof: " + _clip(finding["poc"], 2000))
    if finding.get("evidence"):
        parts.append("Evidence:\n" + _clip(finding["evidence"], 2000))
    if finding.get("remediation"):
        parts.append("Remediation: " + _clip(finding["remediation"], 2000))
    return "\n\n".join(parts)[:8000]


def _severity(finding: dict) -> str:
    severity = str(finding.get("severity") or "info").lower()
    if severity not in _LEVEL:
        return "info"
    return severity


def _clip(value: object, limit: int) -> str:
    return str(value or "").replace("\x00", "").strip()[:limit]


def _tool_version() -> str:
    try:
        return version("maya-agent")
    except PackageNotFoundError:
        return "0.0.0"
