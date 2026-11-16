"""Deterministic MASVS-oriented checks over APK facts."""

from __future__ import annotations

import hashlib
from urllib.parse import urlparse

from maya.static.apk import ApkFacts, Component, IntentFilter

_SEV_ORDER = ("critical", "high", "medium", "low", "info")
_CLIENT_CHECK_MARKERS = ("frida", "tool-checker", "rootbeer", "magisk", "jailbreak")


def build_findings(facts: ApkFacts) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    findings.extend(_platform_findings(facts))
    findings.extend(_network_findings(facts))
    findings.extend(_component_findings(facts))
    findings.extend(_secret_findings(facts))
    findings.extend(_native_findings(facts))
    return findings


def build_endpoints(facts: ApkFacts) -> list[dict[str, str]]:
    return [
        {
            "url": path,
            "method": "UNKNOWN",
            "auth_type": "unknown",
            "source": "dex",
        }
        for path in facts.api_paths
    ]


def severity_stats(findings: list[dict[str, str]]) -> dict[str, int]:
    counts = {name: 0 for name in _SEV_ORDER}
    for finding in findings:
        severity = str(finding.get("severity", "info")).lower()
        if severity not in counts:
            severity = "info"
        counts[severity] += 1
    counts["findings"] = len(findings)
    return counts


def _platform_findings(facts: ApkFacts) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if facts.debuggable is True:
        findings.append(
            _finding(
                title="Application is debuggable",
                severity="high",
                category="platform",
                description="android:debuggable is true, so a debugger can attach to the release process.",
                poc="adb shell run-as " + (facts.package_name or "<package>"),
                impact="Attackers with ADB or a compromised workstation can inspect memory and bypass client checks.",
                remediation="Set android:debuggable to false on every build that leaves the developer machine.",
                evidence="android:debuggable=true",
            )
        )
    if facts.allow_backup is True:
        findings.append(
            _finding(
                title="Application data backup is enabled",
                severity="medium",
                category="storage",
                description="android:allowBackup is true, so adb backup can copy private app data off the device.",
                poc=f"adb backup -f dvba.ab -noapk {facts.package_name or '<package>'}",
                impact="Tokens, preferences, and databases in the app sandbox can be extracted without root.",
                remediation="Set android:allowBackup to false, or ship dataExtractionRules that exclude secrets.",
                evidence="android:allowBackup=true",
            )
        )
    if facts.target_sdk is not None and facts.target_sdk < 31:
        findings.append(
            _finding(
                title="targetSdkVersion is below the Android 12 exported-component baseline",
                severity="medium",
                category="platform",
                description=(
                    f"targetSdkVersion is {facts.target_sdk}. Below API 31, components with an intent filter "
                    "are exported unless android:exported is set."
                ),
                poc="Inspect the <uses-sdk> element and every component that omits android:exported.",
                impact="Intent filters become reachable from other apps without an explicit export decision.",
                remediation="Raise targetSdkVersion to 31 or newer and set android:exported on every component.",
                evidence=f"targetSdkVersion={facts.target_sdk}",
            )
        )
    return findings


def _network_findings(facts: ApkFacts) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    sources: list[str] = []
    if facts.uses_cleartext is True:
        sources.append("android:usesCleartextTraffic=true")
    if facts.network_security.cleartext is True:
        sources.append("network security config cleartextTrafficPermitted=true")
    if sources:
        findings.append(
            _finding(
                title="Application allows cleartext traffic",
                severity="high",
                category="network",
                description="The app permits HTTP. Traffic to those endpoints can be read and modified on the network.",
                poc="Proxy the device and request any http:// endpoint the app calls.",
                impact="Credentials and session tokens sent in cleartext are exposed to a network attacker.",
                remediation="Disable cleartext in the manifest and network security config. Serve the API over HTTPS.",
                evidence="; ".join(sources),
            )
        )
    if facts.network_security.trusts_user_cas:
        findings.append(
            _finding(
                title="Network security config trusts user-installed certificates",
                severity="high",
                category="network",
                description="base-config trust anchors include src=user, so a user-installed CA is trusted for TLS.",
                poc="Install a proxy CA on the device and intercept HTTPS from the app.",
                impact="Any user or malware that installs a CA can decrypt the app's TLS sessions.",
                remediation="Trust system CAs only. Pin the first-party API certificate or public key.",
                evidence="certificates src=user",
            )
        )
    cleartext_urls = [url for url in facts.urls if url.lower().startswith("http://")]
    if cleartext_urls:
        findings.append(
            _finding(
                title="Hardcoded cleartext URL",
                severity="medium",
                category="network",
                description="The package embeds an http:// URL outside the Android schema and localhost defaults.",
                poc="Open the URL from a hostile network and confirm the app sends the request.",
                impact="The embedded endpoint is reachable without TLS.",
                remediation="Replace the URL with https:// and reject cleartext in the network security config.",
                evidence="\n".join(cleartext_urls[:20]),
            )
        )
    return findings


def _component_findings(facts: ApkFacts) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    exposed = [
        component
        for component in facts.components
        if _in_app(component, facts.package_name)
        and _effectively_exported(component, facts.target_sdk)
        and not component.permission
        and not _launcher_only(component)
    ]
    if exposed:
        lines = [_component_line(component) for component in exposed]
        sample = exposed[0].name
        findings.append(
            _finding(
                title="Exported components are reachable without a permission",
                severity="high",
                category="ipc",
                description=(
                    "App components are exported, explicitly or by an intent filter on targetSdk below 31, "
                    "and they declare no android:permission."
                ),
                poc=f"adb shell am start -n {facts.package_name}/{sample}",
                impact="Another app on the device can launch privileged screens or pass data into these components.",
                remediation="Set android:exported=false, or guard the component with a signature permission.",
                evidence="\n".join(lines),
            )
        )
    deep_links = [component for component in exposed if _has_scheme(component, "http")]
    if deep_links:
        evidence = "\n".join(_component_line(component) for component in deep_links)
        findings.append(
            _finding(
                title="Browsable deep link accepts cleartext HTTP",
                severity="high",
                category="ipc",
                description="A browsable intent filter accepts the http scheme, so a web page can open the component.",
                poc="From a browser on the device, open an http:// link that matches the filter host.",
                impact="A malicious page can launch the activity and pass attacker-controlled URI data into it.",
                remediation="Require https App Links with autoVerify, and remove the http scheme.",
                evidence=evidence,
            )
        )
    return findings


def _secret_findings(facts: ApkFacts) -> list[dict[str, str]]:
    firebase = [
        url
        for url in facts.urls
        if _host_endswith(url, (".firebaseio.com", ".firebaseapp.com", ".firebasedatabase.app"))
    ]
    if not firebase:
        return []
    return [
        _finding(
            title="Hardcoded Firebase Realtime Database URL",
            severity="high",
            category="data",
            description="The package embeds a Firebase database URL. Open rules on that project expose user data.",
            poc="Fetch <url>/.json and <url>/.json?shallow=true without credentials.",
            impact="If the database rules allow public reads, customer records are world-readable.",
            remediation="Move the URL out of the client, require Firebase Auth, and deny unauthenticated reads.",
            evidence="\n".join(firebase),
        )
    ]


def _native_findings(facts: ApkFacts) -> list[dict[str, str]]:
    matched = [name for name in facts.native_libraries if _looks_like_client_check(name)]
    if not matched:
        return []
    basenames = sorted({name.rsplit("/", 1)[-1] for name in matched})
    return [
        _finding(
            title="Client-side root or instrumentation checks are present",
            severity="low",
            category="resilience",
            description=(
                "Native libraries in the APK implement root or Frida checks. Those checks run in the app process."
            ),
            poc="Hook the check's JNI entry with Frida and force the safe return value.",
            impact="A local attacker who can instrument the process bypasses the check.",
            remediation="Treat the check as a signal, not a boundary. Enforce sensitive actions on the server.",
            evidence="\n".join(basenames),
        )
    ]


def _in_app(component: Component, package_name: str) -> bool:
    if not package_name:
        return False
    return component.name == package_name or component.name.startswith(package_name + ".")


def _effectively_exported(component: Component, target_sdk: int | None) -> bool:
    if component.exported is True:
        return True
    if component.exported is False:
        return False
    if not component.intent_filters:
        return False
    return target_sdk is None or target_sdk < 31


def _launcher_only(component: Component) -> bool:
    if len(component.intent_filters) != 1:
        return False
    intent_filter = component.intent_filters[0]
    return (
        "android.intent.action.MAIN" in intent_filter.actions
        and "android.intent.category.LAUNCHER" in intent_filter.categories
        and not intent_filter.schemes
    )


def _has_scheme(component: Component, scheme: str) -> bool:
    return any(scheme in intent_filter.schemes for intent_filter in component.intent_filters)


def _component_line(component: Component) -> str:
    filters = "; ".join(_filter_text(intent_filter) for intent_filter in component.intent_filters)
    exported = "unset" if component.exported is None else str(component.exported).lower()
    suffix = f" filters=[{filters}]" if filters else ""
    return f"{component.kind} {component.name} exported={exported}{suffix}"


def _filter_text(intent_filter: IntentFilter) -> str:
    parts = []
    if intent_filter.actions:
        parts.append("action=" + ",".join(intent_filter.actions))
    if intent_filter.schemes:
        parts.append("scheme=" + ",".join(intent_filter.schemes))
    if intent_filter.hosts:
        parts.append("host=" + ",".join(intent_filter.hosts))
    return " ".join(parts)


def _host_endswith(url: str, suffixes: tuple[str, ...]) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return any(host.endswith(suffix) for suffix in suffixes)


def _looks_like_client_check(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    return any(marker in name for marker in _CLIENT_CHECK_MARKERS)


def _finding(
    *,
    title: str,
    severity: str,
    category: str,
    description: str,
    poc: str,
    impact: str,
    remediation: str,
    evidence: str,
) -> dict[str, str]:
    digest = hashlib.sha256(f"{title.lower().strip()}|{category.lower().strip()}".encode()).hexdigest()[:16]
    return {
        "id": digest,
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "poc": poc,
        "impact": impact,
        "remediation": remediation,
        "evidence": evidence[:2000],
    }
