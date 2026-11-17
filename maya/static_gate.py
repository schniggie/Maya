"""Device-free static gate.

Decompile an APK, turn a small set of explicit manifest and app-code signals into
findings, and write ``report.json``, ``report.md``, and ``report.sarif``. The
process exit code honors ``--fail-on``. No LLM and no device.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from maya.tools.apk_tool import analyze_manifest, apktool_decompile

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}

_LAUNCHER_ACTION = "android.intent.action.MAIN"
_LAUNCHER_CATEGORY = "android.intent.category.LAUNCHER"

RULES: dict[str, dict[str, str]] = {
    "ANDROID_DEBUGGABLE": {
        "title": "Debuggable application",
        "severity": "high",
        "category": "resilience",
        "masvs": "MASVS-RESILIENCE",
        "description": "android:debuggable is explicitly true. A shipped debug build accepts a debugger.",
        "impact": "An attacker with local access can attach a debugger and read process memory.",
        "remediation": 'Set android:debuggable="false" on any build you distribute.',
    },
    "ANDROID_ALLOW_BACKUP": {
        "title": "Android backup enabled",
        "severity": "medium",
        "category": "storage",
        "masvs": "MASVS-STORAGE",
        "description": (
            "android:allowBackup is explicitly true. "
            "This gate does not infer the SDK default when the attribute is absent."
        ),
        "impact": "adb backup can extract app data from an unlocked device.",
        "remediation": 'Set android:allowBackup="false" unless backup contents are reviewed and safe.',
    },
    "ANDROID_CLEARTEXT_TRAFFIC": {
        "title": "Cleartext traffic permitted",
        "severity": "high",
        "category": "network",
        "masvs": "MASVS-NETWORK",
        "description": "The app explicitly permits cleartext HTTP.",
        "impact": "Network attackers can read or modify traffic that does not use TLS.",
        "remediation": (
            'Set android:usesCleartextTraffic="false" and do not permit cleartext in the network security config.'
        ),
    },
    "ANDROID_USER_CA_TRUST": {
        "title": "User-installed CAs are trusted",
        "severity": "high",
        "category": "network",
        "masvs": "MASVS-NETWORK",
        "description": (
            "The network security config trusts user-installed certificate authorities outside debug-overrides."
        ),
        "impact": "Anyone who can install a CA on the device can intercept TLS.",
        "remediation": "Trust system CAs only. Limit user CAs to debug-overrides if a debug build needs them.",
    },
    "ANDROID_USER_CA_TRUST_DEBUG": {
        "title": "Debug builds trust user-installed CAs",
        "severity": "low",
        "category": "network",
        "masvs": "MASVS-NETWORK",
        "description": "User-installed CAs are trusted only under debug-overrides.",
        "impact": "Debug builds can be intercepted. Release builds are unaffected by this entry.",
        "remediation": "Confirm release builds do not include this debug-overrides block.",
    },
    "ANDROID_EXPORTED_PROVIDER": {
        "title": "Exported content provider without a permission",
        "severity": "high",
        "category": "platform",
        "masvs": "MASVS-PLATFORM",
        "description": "An app content provider is exported and has no android:permission.",
        "impact": "Other apps on the device may be able to query or write the provider.",
        "remediation": 'Set android:exported="false", or require a signature-level permission.',
    },
    "ANDROID_EXPORTED_ACTIVITY": {
        "title": "Exported activity without a permission",
        "severity": "medium",
        "category": "platform",
        "masvs": "MASVS-PLATFORM",
        "description": "An app activity is explicitly exported, is not only a launcher, and has no android:permission.",
        "impact": "Other apps can start this activity. Confirm it does not expose privileged actions.",
        "remediation": (
            'Set android:exported="false" unless an external caller is required, '
            "and protect that caller with a permission."
        ),
    },
    "ANDROID_EXPORTED_DEEPLINK": {
        "title": "Implicitly exported deep link",
        "severity": "medium",
        "category": "platform",
        "masvs": "MASVS-PLATFORM",
        "description": (
            "An app activity has a non-launcher intent-filter and does not set android:exported. "
            "Before targetSdk 31 that defaults to exported."
        ),
        "impact": "Browsers and other apps can open this activity. An http scheme is an extra cleartext entry point.",
        "remediation": "Set android:exported explicitly. Prefer https deep links and verify the caller.",
    },
    "ANDROID_EXPORTED_SERVICE": {
        "title": "Exported service without a permission",
        "severity": "medium",
        "category": "platform",
        "masvs": "MASVS-PLATFORM",
        "description": "An app service is explicitly exported and has no android:permission.",
        "impact": "Other apps can bind to or start this service.",
        "remediation": 'Set android:exported="false", or require a signature-level permission.',
    },
    "ANDROID_EXPORTED_RECEIVER": {
        "title": "Exported receiver without a permission",
        "severity": "medium",
        "category": "platform",
        "masvs": "MASVS-PLATFORM",
        "description": "An app receiver is explicitly exported and has no android:permission.",
        "impact": "Other apps can send broadcasts this receiver handles.",
        "remediation": 'Set android:exported="false", or require a signature-level permission.',
    },
    "WEBVIEW_JAVASCRIPT_ENABLED": {
        "title": "WebView JavaScript enabled",
        "severity": "low",
        "category": "platform",
        "masvs": "MASVS-PLATFORM",
        "description": "App code calls WebSettings.setJavaScriptEnabled. This is app smali only, not library code.",
        "impact": "JavaScript in a WebView expands the impact of any page the view loads.",
        "remediation": "Disable JavaScript unless the view needs it, and only load trusted HTTPS content.",
    },
    "WEBVIEW_JAVASCRIPT_INTERFACE": {
        "title": "WebView JavaScript interface",
        "severity": "high",
        "category": "platform",
        "masvs": "MASVS-PLATFORM",
        "description": "App code calls WebView.addJavascriptInterface.",
        "impact": "JavaScript loaded in the WebView can call into annotated Java methods.",
        "remediation": "Remove the interface, or expose it only to trusted first-party content on a current WebView.",
    },
}

_CODE_RULES: tuple[tuple[str, str], ...] = (
    ("WEBVIEW_JAVASCRIPT_INTERFACE", r"addJavascriptInterface"),
    ("WEBVIEW_JAVASCRIPT_ENABLED", r"setJavaScriptEnabled"),
)


def tool_version() -> str:
    try:
        return version("maya-agent")
    except PackageNotFoundError:
        return "0.1.1"


@dataclass
class GateResult:
    exit_code: int
    report: dict[str, Any]
    output_dir: Path
    warnings: list[str] = field(default_factory=list)


def gate_failed(findings: list[dict[str, Any]], fail_on: str) -> bool:
    """True when any finding is at or above ``fail_on``. ``none`` never fails."""
    if fail_on == "none":
        return False
    threshold = SEVERITY_RANK[fail_on]
    return any(SEVERITY_RANK.get(str(item.get("severity", "info")), 0) >= threshold for item in findings)


def _finding_id(rule_id: str, subject: str) -> str:
    return hashlib.sha256(f"{rule_id}|{subject}".encode()).hexdigest()[:16]


def _line_of(text: str, needle: str) -> int:
    for index, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return index
    return 1


def _resolve_name(package: str, name: str) -> str:
    if not name:
        return ""
    if name.startswith("."):
        return f"{package}{name}"
    if "." not in name:
        return f"{package}.{name}"
    return name


def _is_app_component(package: str, name: str) -> bool:
    resolved = _resolve_name(package, name)
    return bool(package) and (resolved == package or resolved.startswith(f"{package}."))


def _non_launcher_filters(filters: list[dict[str, list[str]]]) -> list[dict[str, list[str]]]:
    extra: list[dict[str, list[str]]] = []
    for item in filters:
        actions = set(item.get("actions") or [])
        categories = set(item.get("categories") or [])
        if _LAUNCHER_ACTION in actions and _LAUNCHER_CATEGORY in categories:
            continue
        extra.append(item)
    return extra


def _make_finding(
    rule_id: str,
    *,
    subject: str,
    evidence: str,
    location_file: str,
    location_line: int = 1,
    title_suffix: str = "",
    description_extra: str = "",
) -> dict[str, Any]:
    rule = RULES[rule_id]
    title = rule["title"] if not title_suffix else f"{rule['title']}: {title_suffix}"
    description = rule["description"]
    if description_extra:
        description = f"{description} {description_extra}"
    return {
        "id": _finding_id(rule_id, subject),
        "rule_id": rule_id,
        "title": title,
        "severity": rule["severity"],
        "category": rule["category"],
        "masvs": rule["masvs"],
        "description": description,
        "impact": rule["impact"],
        "remediation": rule["remediation"],
        "evidence": evidence[:2000],
        "location": {"file": location_file, "line": location_line},
    }


def findings_from_manifest(analysis: dict[str, Any], manifest_text: str) -> list[dict[str, Any]]:
    """Build findings from an ``analyze_manifest`` result. Library components are ignored."""
    if analysis.get("error"):
        return []

    findings: list[dict[str, Any]] = []
    package = str(analysis.get("package") or "")
    application = analysis.get("application") or {}
    components = analysis.get("components") or {}

    if application.get("debuggable") == "true":
        findings.append(
            _make_finding(
                "ANDROID_DEBUGGABLE",
                subject=package or "application",
                evidence='android:debuggable="true"',
                location_file="AndroidManifest.xml",
                location_line=_line_of(manifest_text, 'android:debuggable="true"'),
            )
        )
    if application.get("allowBackup") == "true":
        findings.append(
            _make_finding(
                "ANDROID_ALLOW_BACKUP",
                subject=package or "application",
                evidence='android:allowBackup="true"',
                location_file="AndroidManifest.xml",
                location_line=_line_of(manifest_text, 'android:allowBackup="true"'),
            )
        )
    if application.get("usesCleartextTraffic") == "true":
        findings.append(
            _make_finding(
                "ANDROID_CLEARTEXT_TRAFFIC",
                subject=package or "application",
                evidence='android:usesCleartextTraffic="true"',
                location_file="AndroidManifest.xml",
                location_line=_line_of(manifest_text, 'android:usesCleartextTraffic="true"'),
            )
        )

    findings.extend(_component_findings(package, components, manifest_text))
    return findings


def _component_findings(package: str, components: dict[str, Any], manifest_text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for component in components.get("activity") or []:
        if not _is_app_component(package, component.get("name", "")):
            continue
        if component.get("permission"):
            continue
        filters = component.get("intent_filters") or []
        extra = _non_launcher_filters(filters)
        name = component.get("name", "")
        exported = component.get("exported", "")
        launcher_only = bool(filters) and not extra
        if exported == "true" and not launcher_only:
            findings.append(_component_finding("ANDROID_EXPORTED_ACTIVITY", name, manifest_text, "explicitly exported"))
        elif exported != "false" and extra:
            schemes = sorted({scheme for item in extra for scheme in item.get("schemes") or []})
            hosts = sorted({host for item in extra for host in item.get("hosts") or []})
            detail = "implicitly exported"
            if schemes or hosts:
                detail = f"implicitly exported schemes={','.join(schemes) or '-'} hosts={','.join(hosts) or '-'}"
            findings.append(_component_finding("ANDROID_EXPORTED_DEEPLINK", name, manifest_text, detail))

    for rule_id, kind in (
        ("ANDROID_EXPORTED_SERVICE", "service"),
        ("ANDROID_EXPORTED_RECEIVER", "receiver"),
        ("ANDROID_EXPORTED_PROVIDER", "provider"),
    ):
        for component in components.get(kind) or []:
            if not _is_app_component(package, component.get("name", "")):
                continue
            if component.get("exported") != "true" or component.get("permission"):
                continue
            findings.append(
                _component_finding(rule_id, component.get("name", ""), manifest_text, "explicitly exported")
            )
    return findings


def _component_finding(rule_id: str, name: str, manifest_text: str, evidence: str) -> dict[str, Any]:
    return _make_finding(
        rule_id,
        subject=name or rule_id,
        title_suffix=name,
        evidence=f"{name}: {evidence}",
        location_file="AndroidManifest.xml",
        location_line=_line_of(manifest_text, name) if name else 1,
    )


def findings_from_network_security(
    decompiled_dir: Path, analysis: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[str]]:
    """Read the network security config when the manifest points at one."""
    application = analysis.get("application") or {}
    ref = str(application.get("networkSecurityConfig") or "")
    if not ref.startswith("@xml/"):
        return [], []
    config_path = decompiled_dir / "res" / "xml" / f"{ref.removeprefix('@xml/')}.xml"
    if not config_path.is_file():
        return [], [f"network security config not found: {config_path.name}"]

    text = config_path.read_text(encoding="utf-8", errors="replace")
    try:
        root = ET.fromstring(text)  # noqa: S314
    except ET.ParseError as exc:
        return [], [f"network security config parse error: {exc}"]

    findings: list[dict[str, Any]] = []
    manifest_cleartext = (analysis.get("application") or {}).get("usesCleartextTraffic") == "true"
    if not manifest_cleartext and 'cleartextTrafficPermitted="true"' in text:
        findings.append(
            _make_finding(
                "ANDROID_CLEARTEXT_TRAFFIC",
                subject=str(analysis.get("package") or config_path.name),
                evidence='cleartextTrafficPermitted="true"',
                location_file=str(config_path.relative_to(decompiled_dir)),
                location_line=_line_of(text, 'cleartextTrafficPermitted="true"'),
                description_extra="The manifest attribute is unset; the network security config allows cleartext.",
            )
        )

    parents = {child: parent for parent in root.iter() for child in list(parent)}
    user_outside_debug = False
    user_inside_debug = False
    for element in root.iter():
        src = element.attrib.get("src", "")
        if element.tag != "certificates" or src != "user":
            continue
        if _under_debug_overrides(element, parents):
            user_inside_debug = True
        else:
            user_outside_debug = True

    relative = str(config_path.relative_to(decompiled_dir))
    package = str(analysis.get("package") or relative)
    if user_outside_debug:
        findings.append(
            _make_finding(
                "ANDROID_USER_CA_TRUST",
                subject=package,
                evidence='<certificates src="user" /> outside debug-overrides',
                location_file=relative,
                location_line=_line_of(text, 'src="user"'),
            )
        )
    elif user_inside_debug:
        findings.append(
            _make_finding(
                "ANDROID_USER_CA_TRUST_DEBUG",
                subject=package,
                evidence='<certificates src="user" /> inside debug-overrides',
                location_file=relative,
                location_line=_line_of(text, 'src="user"'),
            )
        )
    return findings, []


def _under_debug_overrides(element: ET.Element, parents: dict[ET.Element, ET.Element]) -> bool:
    current: ET.Element | None = element
    while current is not None:
        if current.tag == "debug-overrides":
            return True
        current = parents.get(current)
    return False


def findings_from_app_code(decompiled_dir: Path, package: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Search app-owned smali only. Library trees are not findings."""
    if not package:
        return [], []
    if shutil.which("rg") is None:
        return [], ["ripgrep (rg) is not installed; app-code checks were skipped"]

    relative = Path(*package.split("."))
    search_dirs = [path for path in sorted(decompiled_dir.glob("smali*")) if (path / relative).is_dir()]
    if not search_dirs:
        return [], []

    findings: list[dict[str, Any]] = []
    warnings: list[str] = []
    for rule_id, pattern in _CODE_RULES:
        cmd = ["rg", "-n", "--glob", "*.smali", pattern, *[str(path / relative) for path in search_dirs]]
        try:
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=60)
        except subprocess.TimeoutExpired:
            warnings.append(f"{rule_id}: code search timed out")
            continue
        if proc.returncode not in (0, 1):
            warnings.append(f"{rule_id}: rg exit {proc.returncode}")
            continue
        if proc.returncode == 1 or not proc.stdout.strip():
            continue
        lines = []
        for raw in proc.stdout.splitlines():
            if len(lines) >= 8:
                break
            lines.append(_relative_smali_hit(decompiled_dir, raw))
        first = lines[0]
        file_name, _, _rest = first.partition(":")
        line_no = 1
        parts = first.split(":", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            line_no = int(parts[1])
        findings.append(
            _make_finding(
                rule_id,
                subject=package,
                evidence="\n".join(lines),
                location_file=file_name,
                location_line=line_no,
            )
        )
    return findings, warnings


def _relative_smali_hit(decompiled_dir: Path, raw: str) -> str:
    path_text, sep, rest = raw.partition(":")
    if not sep:
        return raw
    try:
        relative = str(Path(path_text).resolve().relative_to(decompiled_dir.resolve()))
    except ValueError:
        relative = path_text
    return f"{relative}:{rest}"


def collect_findings(decompiled_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    manifest_path = decompiled_dir / "AndroidManifest.xml"
    analysis = analyze_manifest(str(manifest_path))
    if analysis.get("error"):
        return analysis, [], [str(analysis["error"])]
    manifest_text = manifest_path.read_text(encoding="utf-8", errors="replace")
    findings = findings_from_manifest(analysis, manifest_text)
    network_findings, network_warnings = findings_from_network_security(decompiled_dir, analysis)
    code_findings, code_warnings = findings_from_app_code(decompiled_dir, str(analysis.get("package") or ""))
    findings.extend(network_findings)
    findings.extend(code_findings)
    findings.sort(key=lambda item: (-SEVERITY_RANK.get(item["severity"], 0), item["rule_id"], item["title"]))
    return analysis, findings, network_warnings + code_warnings


def summarize(findings: list[dict[str, Any]]) -> dict[str, int]:
    summary = {name: 0 for name in SEVERITY_RANK}
    for item in findings:
        severity = str(item.get("severity", "info"))
        if severity not in summary:
            summary["info"] += 1
        else:
            summary[severity] += 1
    return summary


def build_report(
    *,
    apk_path: str,
    fail_on: str,
    analysis: dict[str, Any],
    findings: list[dict[str, Any]],
    warnings: list[str],
    status: str = "ok",
    error: str = "",
) -> dict[str, Any]:
    failed = gate_failed(findings, fail_on) if status == "ok" else False
    return {
        "tool": "maya",
        "version": tool_version(),
        "mode": "static-gate",
        "status": status,
        "error": error,
        "apk": str(apk_path),
        "package": analysis.get("package", ""),
        "fail_on": fail_on,
        "failed": failed,
        "summary": summarize(findings),
        "warnings": warnings,
        "findings": findings,
    }


def render_sarif(report: dict[str, Any]) -> dict[str, Any]:
    rules = []
    seen: set[str] = set()
    results = []
    for finding in report.get("findings") or []:
        rule_id = finding["rule_id"]
        if rule_id not in seen:
            seen.add(rule_id)
            rule = RULES[rule_id]
            rules.append(
                {
                    "id": rule_id,
                    "shortDescription": {"text": rule["title"]},
                    "fullDescription": {"text": rule["description"]},
                    "help": {"text": rule["remediation"]},
                    "defaultConfiguration": {"level": SARIF_LEVEL[rule["severity"]]},
                    "properties": {"masvs": rule["masvs"], "security-severity": _security_severity(rule["severity"])},
                }
            )
        location = finding.get("location") or {}
        results.append(
            {
                "ruleId": rule_id,
                "level": SARIF_LEVEL.get(finding.get("severity", "note"), "note"),
                "message": {"text": f"{finding['title']}. {finding['description']} Evidence: {finding['evidence']}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": location.get("file") or Path(report.get("apk", "app.apk")).name
                            },
                            "region": {"startLine": int(location.get("line") or 1)},
                        }
                    }
                ],
                "partialFingerprints": {"mayaFindingId": finding["id"]},
                "properties": {"masvs": finding.get("masvs", ""), "severity": finding.get("severity", "")},
            }
        )
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "maya",
                        "version": report.get("version") or tool_version(),
                        "informationUri": "https://github.com/schniggie/Maya",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _security_severity(severity: str) -> str:
    return {"critical": "9.0", "high": "7.5", "medium": "5.0", "low": "3.0", "info": "1.0"}[severity]


def render_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary") or {}
    lines = [
        "# Maya static gate",
        "",
        f"- Package: `{report.get('package') or 'unknown'}`",
        f"- APK: `{report.get('apk', '')}`",
        f"- Fail-on: `{report.get('fail_on', 'none')}`",
        f"- Result: {'failed' if report.get('failed') else 'passed'}",
        (
            "- Findings: "
            f"{summary.get('critical', 0)} critical, {summary.get('high', 0)} high, "
            f"{summary.get('medium', 0)} medium, {summary.get('low', 0)} low, {summary.get('info', 0)} info"
        ),
        "",
    ]
    if report.get("error"):
        lines.extend([f"Gate error: {report['error']}", ""])
    for warning in report.get("warnings") or []:
        lines.append(f"- Warning: {warning}")
    if report.get("warnings"):
        lines.append("")
    lines.append("## Findings")
    lines.append("")
    findings = report.get("findings") or []
    if not findings:
        lines.append("No static-gate findings.")
    for finding in findings:
        location = finding.get("location") or {}
        lines.extend(
            [
                f"### {finding.get('title', 'Untitled')}",
                "",
                f"- Severity: {finding.get('severity', 'unknown')}",
                f"- Rule: `{finding.get('rule_id', '')}`",
                f"- MASVS: {finding.get('masvs', '')}",
                f"- Location: `{location.get('file', '')}:{location.get('line', '')}`",
                f"- Description: {finding.get('description', '')}",
                f"- Impact: {finding.get('impact', '')}",
                f"- Evidence: {finding.get('evidence', '')}",
                f"- Remediation: {finding.get('remediation', '')}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def write_reports(output_dir: Path, report: dict[str, Any]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (output_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")
    (output_dir / "report.sarif").write_text(json.dumps(render_sarif(report), indent=2) + "\n", encoding="utf-8")


def run_static_gate(package_path: str, output_dir: str, fail_on: str = "none") -> GateResult:
    """Decompile ``package_path`` and write the static-gate reports.

    Exit 0 when no finding meets ``fail_on``. Exit 1 when one does. Exit 2 when
    the APK or apktool step fails.
    """
    if fail_on not in {"none", *SEVERITY_RANK}:
        raise ValueError(f"unsupported fail_on: {fail_on}")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    apk = Path(package_path)
    if not apk.is_file():
        report = build_report(
            apk_path=package_path,
            fail_on=fail_on,
            analysis={},
            findings=[],
            warnings=[],
            status="error",
            error=f"APK not found: {package_path}",
        )
        write_reports(out, report)
        return GateResult(2, report, out)

    if shutil.which("apktool") is None:
        report = build_report(
            apk_path=str(apk),
            fail_on=fail_on,
            analysis={},
            findings=[],
            warnings=[],
            status="error",
            error="apktool not found on PATH",
        )
        write_reports(out, report)
        return GateResult(2, report, out, warnings=["apktool not found on PATH"])

    with tempfile.TemporaryDirectory(prefix="maya-static-gate-") as tmp:
        decompiled = Path(tmp) / "decompiled"
        decompile = apktool_decompile(str(apk), str(decompiled))
        if decompile.get("exit_code") != 0 or not (decompiled / "AndroidManifest.xml").is_file():
            detail = (decompile.get("stderr") or decompile.get("stdout") or "apktool failed").strip()
            report = build_report(
                apk_path=str(apk),
                fail_on=fail_on,
                analysis={},
                findings=[],
                warnings=[],
                status="error",
                error=f"apktool_decompile failed: {detail[:1000]}",
            )
            write_reports(out, report)
            return GateResult(2, report, out)
        analysis, findings, warnings = collect_findings(decompiled)

    report = build_report(apk_path=str(apk), fail_on=fail_on, analysis=analysis, findings=findings, warnings=warnings)
    write_reports(out, report)
    return GateResult(0 if not report["failed"] else 1, report, out, warnings=warnings)


def format_summary(result: GateResult) -> str:
    report = result.report
    summary = report.get("summary") or {}
    state = "failed" if report.get("failed") else "passed"
    lines = [
        f"Static gate: {report.get('package') or report.get('apk')}",
        f"Findings: {summary.get('critical', 0)} critical, {summary.get('high', 0)} high, "
        f"{summary.get('medium', 0)} medium, {summary.get('low', 0)} low, {summary.get('info', 0)} info",
        f"Fail-on: {report.get('fail_on')} → {state}",
        f"Reports: {result.output_dir / 'report.sarif'}",
    ]
    if report.get("error"):
        lines.insert(1, f"Error: {report['error']}")
    for finding in report.get("findings") or []:
        lines.append(f"  [{finding['severity']}] {finding['rule_id']}: {finding['title']}")
    return "\n".join(lines)
