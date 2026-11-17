"""Deterministic MASVS-oriented checks over an IPA or app bundle."""

from __future__ import annotations

import hashlib

from maya.static.ipa import IpaFacts

_INSECURE_SCHEMES = {"http", "javascript", "file", "data", "ftp"}
_WEAK_TLS = {"tlsv1.0", "tlsv1.1", "1.0", "1.1"}


def build_ipa_findings(facts: IpaFacts) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    findings.extend(_ats_findings(facts))
    findings.extend(_scheme_findings(facts))
    findings.extend(_storage_findings(facts))
    findings.extend(_entitlement_findings(facts))
    findings.extend(_binary_findings(facts))
    findings.extend(_url_findings(facts))
    findings.extend(_privacy_findings(facts))
    return findings


def _ats_findings(facts: IpaFacts) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if facts.allows_arbitrary_loads:
        findings.append(
            _finding(
                title="App Transport Security allows arbitrary loads",
                severity="high",
                category="network",
                masvs="MASVS-NETWORK-1",
                description=(
                    "MASVS-NETWORK-1. NSAllowsArbitraryLoads is true, so the app-wide ATS policy "
                    "permits cleartext HTTP."
                ),
                poc="Read NSAppTransportSecurity.NSAllowsArbitraryLoads in Info.plist.",
                impact="Network traffic the app sends over HTTP can be read or modified.",
                remediation="Remove NSAllowsArbitraryLoads. Name any HTTP exception domain instead.",
                evidence="NSAllowsArbitraryLoads=true",
            )
        )
    insecure = [item.domain for item in facts.ats_exceptions if item.insecure_http]
    if insecure:
        findings.append(
            _finding(
                title="App Transport Security allows insecure HTTP",
                severity="high",
                category="network",
                masvs="MASVS-NETWORK-1",
                description=("MASVS-NETWORK-1. An NSExceptionDomains entry sets NSExceptionAllowsInsecureHTTPLoads."),
                poc="Read NSExceptionDomains in Info.plist and note each domain with insecure HTTP enabled.",
                impact="HTTP to the listed domains is permitted by ATS.",
                remediation="Set NSExceptionAllowsInsecureHTTPLoads to false and serve those hosts with HTTPS.",
                evidence="\n".join(insecure),
            )
        )
    weak = [f"{item.domain} {item.minimum_tls}" for item in facts.ats_exceptions if _weak_tls(item.minimum_tls)]
    if weak:
        findings.append(
            _finding(
                title="App Transport Security allows a weak TLS version",
                severity="medium",
                category="network",
                masvs="MASVS-NETWORK-1",
                description="MASVS-NETWORK-1. An exception domain sets NSExceptionMinimumTLSVersion below TLSv1.2.",
                poc="Read NSExceptionMinimumTLSVersion for each NSExceptionDomains entry.",
                impact="The app can negotiate a TLS version that current clients should not offer.",
                remediation="Remove the exception or set NSExceptionMinimumTLSVersion to TLSv1.2 or later.",
                evidence="\n".join(weak),
            )
        )
    if facts.allows_arbitrary_loads_web:
        findings.append(
            _finding(
                title="App Transport Security allows arbitrary loads in web content",
                severity="medium",
                category="network",
                masvs="MASVS-NETWORK-1",
                description="MASVS-NETWORK-1. NSAllowsArbitraryLoadsInWebContent is true.",
                poc="Read NSAllowsArbitraryLoadsInWebContent in Info.plist.",
                impact="Web views can load cleartext content even when the app-wide ATS policy is stricter.",
                remediation="Leave NSAllowsArbitraryLoadsInWebContent unset unless a named page cannot move to HTTPS.",
                evidence="NSAllowsArbitraryLoadsInWebContent=true",
            )
        )
    if facts.allows_arbitrary_loads_media:
        findings.append(
            _finding(
                title="App Transport Security allows arbitrary loads for media",
                severity="medium",
                category="network",
                masvs="MASVS-NETWORK-1",
                description="MASVS-NETWORK-1. NSAllowsArbitraryLoadsForMedia is true.",
                poc="Read NSAllowsArbitraryLoadsForMedia in Info.plist.",
                impact="Media loaded by the platform can use cleartext HTTP.",
                remediation="Serve media over HTTPS and remove NSAllowsArbitraryLoadsForMedia.",
                evidence="NSAllowsArbitraryLoadsForMedia=true",
            )
        )
    if facts.allows_local_networking:
        findings.append(
            _finding(
                title="App Transport Security allows local networking",
                severity="info",
                category="network",
                masvs="MASVS-NETWORK-1",
                description=(
                    "MASVS-NETWORK-1. NSAllowsLocalNetworking is true. Local HTTP is a common "
                    "development exception and is not, by itself, an app-wide cleartext policy."
                ),
                poc="Read NSAllowsLocalNetworking in Info.plist.",
                impact="The app may open cleartext connections to local network addresses.",
                remediation="Keep the exception only for the local services that need it.",
                evidence="NSAllowsLocalNetworking=true",
            )
        )
    return findings


def _scheme_findings(facts: IpaFacts) -> list[dict[str, str]]:
    insecure = [scheme for scheme in facts.url_schemes if scheme.lower() in _INSECURE_SCHEMES]
    custom = [scheme for scheme in facts.url_schemes if scheme.lower() not in _INSECURE_SCHEMES | {"https"}]
    findings: list[dict[str, str]] = []
    if insecure:
        findings.append(
            _finding(
                title="URL scheme allows an insecure protocol",
                severity="high",
                category="platform",
                masvs="MASVS-PLATFORM-1",
                description=(
                    "MASVS-PLATFORM-1. CFBundleURLTypes registers a scheme such as http, file, or javascript."
                ),
                poc="Read CFBundleURLSchemes in Info.plist.",
                impact="Another app, or a web page, can hand this app a URL the scheme was not meant to carry.",
                remediation="Remove insecure schemes. Prefer universal links for content the app should open.",
                evidence="\n".join(insecure),
            )
        )
    if custom:
        findings.append(
            _finding(
                title="Custom URL scheme is registered",
                severity="low",
                category="platform",
                masvs="MASVS-PLATFORM-1",
                description=(
                    "MASVS-PLATFORM-1. A custom URL scheme is not exclusive to this app. "
                    "Any other app can register the same scheme."
                ),
                poc="Read CFBundleURLSchemes in Info.plist and confirm the handler checks the URL.",
                impact="A different app installed later can claim the scheme and receive URLs meant for this one.",
                remediation="Use universal links for sensitive flows. Treat custom-scheme URLs as untrusted input.",
                evidence="\n".join(custom),
            )
        )
    return findings


def _storage_findings(facts: IpaFacts) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if facts.file_sharing:
        findings.append(
            _finding(
                title="File sharing is enabled",
                severity="medium",
                category="storage",
                masvs="MASVS-STORAGE-2",
                description="MASVS-STORAGE-2. UIFileSharingEnabled is true, so Documents is visible over USB.",
                poc="Read UIFileSharingEnabled in Info.plist.",
                impact="Files the app writes under Documents can be copied off the device without a jailbreak.",
                remediation="Set UIFileSharingEnabled to false, or keep secrets out of Documents.",
                evidence="UIFileSharingEnabled=true",
            )
        )
    if facts.open_in_place:
        findings.append(
            _finding(
                title="Documents can be opened in place",
                severity="low",
                category="storage",
                masvs="MASVS-STORAGE-2",
                description="MASVS-STORAGE-2. LSSupportsOpeningDocumentsInPlace is true.",
                poc="Read LSSupportsOpeningDocumentsInPlace in Info.plist.",
                impact="The Files app can open documents inside the app container.",
                remediation="Leave the key unset unless this app is a document provider.",
                evidence="LSSupportsOpeningDocumentsInPlace=true",
            )
        )
    return findings


def _entitlement_findings(facts: IpaFacts) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if facts.get_task_allow is True:
        kind = facts.profile_kind
        device_note = ""
        if facts.provisioned_device_count:
            device_note = f"; provisioned_devices={facts.provisioned_device_count} (identifiers omitted)"
        findings.append(
            _finding(
                title="Provisioning profile allows a debugger",
                severity="high",
                category="platform",
                masvs="MASVS-RESILIENCE-4",
                description=(
                    "MASVS-RESILIENCE-4. get-task-allow is true, so a debugger can attach. "
                    "Development profiles set this on purpose. A distribution build should not."
                ),
                poc="Read get-task-allow in the embedded.mobileprovision Entitlements dictionary.",
                impact="A debugger on a paired machine can inspect the process.",
                remediation="Ship distribution profiles with get-task-allow false.",
                evidence=f"get-task-allow=true; profile={kind}{device_note}",
            )
        )
    if len(facts.keychain_access_groups) > 1:
        findings.append(
            _finding(
                title="Keychain access is shared with another group",
                severity="info",
                category="storage",
                masvs="MASVS-STORAGE-1",
                description=(
                    "MASVS-STORAGE-1. keychain-access-groups lists more than the app's own group. "
                    "Apps in those groups can share keychain items."
                ),
                poc="Read keychain-access-groups in the embedded entitlements. Confirm each group is intentional.",
                impact="A keychain item placed in a shared group is readable by every app that holds that group.",
                remediation="Keep credentials in the app's own access group unless sharing is required.",
                evidence="\n".join(facts.keychain_access_groups),
            )
        )
    if facts.application_groups:
        findings.append(
            _finding(
                title="App shares an application group container",
                severity="info",
                category="storage",
                masvs="MASVS-STORAGE-2",
                description="MASVS-STORAGE-2. com.apple.security.application-groups is present.",
                poc="Read com.apple.security.application-groups in the embedded entitlements.",
                impact="Every app signed for that group can read the shared container.",
                remediation="Store secrets in the app sandbox unless another extension must read them.",
                evidence="\n".join(facts.application_groups),
            )
        )
    if facts.wifi_info:
        findings.append(
            _finding(
                title="Wi-Fi information entitlement is present",
                severity="low",
                category="privacy",
                masvs="MASVS-PRIVACY-1",
                description="MASVS-PRIVACY-1. com.apple.developer.networking.wifi-info is present.",
                poc="Read the wifi-info entitlement. Confirm the app needs the current network name.",
                impact="The SSID can be used as a coarse location signal.",
                remediation="Drop the entitlement unless a feature reads the current Wi-Fi network.",
                evidence="com.apple.developer.networking.wifi-info=true",
            )
        )
    major = _major(facts.minimum_os)
    if major is not None and major < 13:
        findings.append(
            _finding(
                title="Deployment target is below iOS 13",
                severity="low",
                category="code",
                masvs="MASVS-CODE-1",
                description=(
                    f"MASVS-CODE-1. MinimumOSVersion is {facts.minimum_os}. "
                    "The finding names the declared target. It does not assign a CVE."
                ),
                poc="Read MinimumOSVersion in Info.plist.",
                impact="The build still runs on an OS release that no longer receives platform fixes.",
                remediation="Raise the deployment target to a supported iOS release.",
                evidence=f"MinimumOSVersion={facts.minimum_os}",
            )
        )
    return findings


def _binary_findings(facts: IpaFacts) -> list[dict[str, str]]:
    binary = facts.binary
    if binary is None or not binary.parsed:
        evidence = "executable missing" if binary is None else f"{binary.name} not parsed"
        if binary and binary.notes:
            evidence = "; ".join(binary.notes[:4]) or evidence
        return [
            _finding(
                title="Mach-O protections were not assessed",
                severity="info",
                category="resilience",
                masvs="MASVS-RESILIENCE-2",
                description=(
                    "MASVS-RESILIENCE-2. PIE, the stack-canary marker, and ARC were not assessed. "
                    "otool was not required for this result."
                ),
                poc="Confirm CFBundleExecutable points at a Mach-O in the bundle, then re-run the static scan.",
                impact="Binary hardening is unknown for this input.",
                remediation="Scan an unpacked development build whose main executable is a readable Mach-O.",
                evidence=evidence,
            )
        ]
    findings: list[dict[str, str]] = []
    if binary.encrypted is True:
        findings.append(
            _finding(
                title="FairPlay encryption is present",
                severity="info",
                category="resilience",
                masvs="MASVS-RESILIENCE-2",
                description=(
                    "cryptid is set. Maya does not decrypt IPAs. Stack-canary and ARC markers inside "
                    "the encrypted range were not assessed. The PIE bit is read from the Mach-O header."
                ),
                poc="Read LC_ENCRYPTION_INFO.cryptid on the main executable.",
                impact="String-based binary checks are incomplete until the tester has an unencrypted build.",
                remediation="Scan an unencrypted development build. Maya will not decrypt this file.",
                evidence=f"{binary.name} cryptid!=0; otool={binary.otool}",
            )
        )
    if binary.filetype == "execute" and binary.pie is False:
        findings.append(
            _finding(
                title="Mach-O executable is missing PIE",
                severity="low",
                category="resilience",
                masvs="MASVS-RESILIENCE-2",
                description=(
                    "MASVS-RESILIENCE-2. The main executable's Mach-O header does not set MH_PIE. "
                    "This is a hardening signal."
                ),
                poc="Read the Mach-O header flags for the main executable.",
                impact="The executable is not marked position-independent.",
                remediation="Link the executable as position-independent. App Store builds require PIE.",
                evidence=f"{binary.name} MH_PIE unset; otool={binary.otool}",
            )
        )
    if binary.stack_canary is False:
        findings.append(
            _finding(
                title="Mach-O executable has no stack-canary marker",
                severity="low",
                category="resilience",
                masvs="MASVS-RESILIENCE-2",
                description=(
                    "MASVS-RESILIENCE-2. stack_chk_fail was not found in the unencrypted bytes that were scanned. "
                    "A stripped binary or a non-standard runtime can hide the marker."
                ),
                poc="Search the unencrypted bytes for stack_chk_fail, or run otool -I when it is installed.",
                impact="Stack-canary use was not confirmed.",
                remediation="Rebuild with stack protectors and rescan an unstripped, unencrypted binary.",
                evidence=f"{binary.name} stack_chk_fail absent; otool={binary.otool}",
            )
        )
    if binary.arc is False:
        findings.append(
            _finding(
                title="Mach-O executable has no ARC marker",
                severity="low",
                category="resilience",
                masvs="MASVS-RESILIENCE-2",
                description=(
                    "MASVS-RESILIENCE-2. The executable looks like Objective-C and objc_release was not found "
                    "in the scanned bytes. A stripped binary can hide the marker."
                ),
                poc="Search the unencrypted bytes for objc_release after confirming the binary links libobjc.",
                impact="ARC use was not confirmed for this Objective-C executable.",
                remediation="Enable ARC for Objective-C targets and rescan if this is unexpected.",
                evidence=f"{binary.name} objc_release absent; otool={binary.otool}",
            )
        )
    return findings


def _url_findings(facts: IpaFacts) -> list[dict[str, str]]:
    cleartext = [url for url in facts.urls if url.lower().startswith("http://")]
    if not cleartext:
        return []
    return [
        _finding(
            title="Hardcoded cleartext URL",
            severity="medium",
            category="network",
            masvs="MASVS-NETWORK-1",
            description="MASVS-NETWORK-1. The bundle embeds an http:// URL outside localhost and example hosts.",
            poc="Search Info.plist strings and the unencrypted Mach-O string table for http://.",
            impact="The embedded endpoint is declared without TLS.",
            remediation="Replace the URL with https:// and keep ATS from allowing that host in cleartext.",
            evidence="\n".join(cleartext[:20]),
        )
    ]


def _privacy_findings(facts: IpaFacts) -> list[dict[str, str]]:
    empty = [key for key, value in facts.usage_strings.items() if not value.strip()]
    if not empty:
        return []
    return [
        _finding(
            title="Privacy usage description is empty",
            severity="low",
            category="privacy",
            masvs="MASVS-PRIVACY-3",
            description="MASVS-PRIVACY-3. A UsageDescription key is present and the string is empty.",
            poc="Read each *UsageDescription value in Info.plist.",
            impact="The system prompt for that permission has no purpose text.",
            remediation="Set a specific purpose string for every permission the app requests.",
            evidence="\n".join(empty),
        )
    ]


def _weak_tls(value: str | None) -> bool:
    if not value:
        return False
    return value.strip().lower().replace(" ", "") in _WEAK_TLS


def _major(version: str | None) -> int | None:
    if not version:
        return None
    token = version.split(".", 1)[0]
    if token.isdigit():
        return int(token)
    return None


def _finding(
    *,
    title: str,
    severity: str,
    category: str,
    masvs: str,
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
        "masvs": masvs,
        "description": description,
        "poc": poc,
        "impact": impact,
        "remediation": remediation,
        "evidence": evidence[:2000],
    }
