"""Run a device-free APK static scan and write the documented reports."""

from __future__ import annotations

import html
import json
from pathlib import Path

from maya.static.apk import ApkFacts, load_apk
from maya.static.rules import build_endpoints, build_findings, severity_stats
from maya.static.sarif import report_to_sarif

FAIL_ON_LEVELS = ("none", "low", "medium", "high", "critical")
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def run_static_scan(apk_path: str, output_dir: str | None = None, target: str | None = None) -> dict:
    """Analyze an APK and, when output_dir is set, write json, markdown, html, and SARIF."""
    path = Path(apk_path)
    if not path.is_file():
        return {"error": f"APK not found: {apk_path}", "status": "error"}
    try:
        facts = load_apk(str(path))
    except ValueError as exc:
        return {"error": str(exc), "status": "error"}

    findings = build_findings(facts)
    endpoints = build_endpoints(facts)
    report = _report(path, facts, findings, endpoints, target)
    if output_dir:
        _write_reports(Path(output_dir), report)
        report["output_dir"] = str(output_dir)
    return report


def _report(
    path: Path,
    facts: ApkFacts,
    findings: list[dict[str, str]],
    endpoints: list[dict[str, str]],
    target: str | None,
) -> dict:
    stats = severity_stats(findings)
    package = facts.package_name or target or path.stem
    return {
        "status": "ok",
        "scanner": "maya-static",
        "summary": f"{stats['findings']} static findings for {package}",
        "target": target or package,
        "apk": str(path),
        "package": facts.package_name,
        "version_name": facts.version_name,
        "version_code": facts.version_code,
        "min_sdk": facts.min_sdk,
        "target_sdk": facts.target_sdk,
        "permissions": facts.permissions,
        "allow_backup": facts.allow_backup,
        "debuggable": facts.debuggable,
        "cleartext_traffic": facts.uses_cleartext or facts.network_security.cleartext is True,
        "trusts_user_cas": facts.network_security.trusts_user_cas,
        "native_libraries": facts.native_libraries,
        "urls": facts.urls,
        "urls_truncated": facts.urls_truncated,
        "api_paths_truncated": facts.api_paths_truncated,
        "findings": findings,
        "api_endpoints": endpoints,
        "stats": stats,
    }


def static_scan_exit_code(result: dict, fail_on: str = "none") -> int:
    """Return 2 when the scan failed, 1 when a finding meets ``fail_on``, else 0.

    ``none`` never fails on findings. A threshold matches that severity and
    anything more severe. ``info`` is below ``low`` and cannot fail the gate.
    """
    if fail_on not in FAIL_ON_LEVELS:
        raise ValueError(f"fail-on must be one of {', '.join(FAIL_ON_LEVELS)}")
    if result.get("status") == "error" or result.get("error"):
        return 2
    if fail_on == "none":
        return 0
    threshold = _SEVERITY_RANK[fail_on]
    for finding in result.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        rank = _SEVERITY_RANK.get(str(finding.get("severity", "info")).lower(), 0)
        if rank >= threshold:
            return 1
    return 0


def _write_reports(output_dir: Path, report: dict) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (output_dir / "report.md").write_text(_markdown(report), encoding="utf-8")
    (output_dir / "report.html").write_text(_html(report), encoding="utf-8")
    (output_dir / "report.sarif").write_text(json.dumps(report_to_sarif(report), indent=2) + "\n", encoding="utf-8")


def _markdown(report: dict) -> str:
    stats = report["stats"]
    lines = [
        "# Mobile Security Assessment Report",
        "",
        "## Executive Summary",
        "",
        f"- Package: `{report.get('package') or 'unknown'}`",
        f"- Scanner: `{report['scanner']}`",
        (
            f"- Findings: {stats['critical']} Critical, {stats['high']} High, "
            f"{stats['medium']} Medium, {stats['low']} Low, {stats['info']} Info"
        ),
        f"- targetSdkVersion: {report.get('target_sdk')}",
        f"- Cleartext traffic: {report.get('cleartext_traffic')}",
        f"- Trusts user CAs: {report.get('trusts_user_cas')}",
        "",
        "## Findings",
        "",
    ]
    if not report["findings"]:
        lines.append("No deterministic findings.")
        lines.append("")
    for finding in report["findings"]:
        lines.extend(
            [
                f"### {finding['title']}",
                "",
                f"- Severity: {finding['severity']}",
                f"- Category: {finding['category']}",
                f"- Description: {finding['description']}",
                f"- Impact: {finding['impact']}",
                f"- Proof: {finding['poc']}",
                f"- Remediation: {finding['remediation']}",
                "",
                "Evidence:",
                "",
                "```",
                finding.get("evidence", ""),
                "```",
                "",
            ]
        )
    lines.append("## API Endpoints")
    lines.append("")
    if not report["api_endpoints"]:
        lines.append("None discovered in embedded strings.")
    for endpoint in report["api_endpoints"]:
        lines.append(f"- {endpoint.get('method', 'UNKNOWN')} {endpoint.get('url', '')}")
    lines.append("")
    return "\n".join(lines)


def _html(report: dict) -> str:
    stats = report["stats"]
    package = html.escape(str(report.get("package") or "unknown"))
    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Maya static report</title></head><body>",
        "<h1>Mobile Security Assessment Report</h1>",
        f"<p>Package: {package}</p>",
        (
            "<p>Findings: "
            f"{stats['critical']} critical, {stats['high']} high, {stats['medium']} medium, "
            f"{stats['low']} low, {stats['info']} info</p>"
        ),
        "<h2>Findings</h2><ul>",
    ]
    for finding in report["findings"]:
        title = html.escape(finding["title"])
        severity = html.escape(finding["severity"])
        description = html.escape(finding["description"])
        parts.append(f"<li><b>{title}</b> [{severity}]<br>{description}</li>")
    parts.append("</ul><h2>API Endpoints</h2><ul>")
    for endpoint in report["api_endpoints"]:
        method = html.escape(str(endpoint.get("method", "UNKNOWN")))
        url = html.escape(str(endpoint.get("url", "")))
        parts.append(f"<li>{method} {url}</li>")
    parts.append("</ul></body></html>")
    return "".join(parts)
