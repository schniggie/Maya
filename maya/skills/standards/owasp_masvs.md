---
name: owasp_masvs
description: MASVS v2 control groups mapped to Maya static and dynamic checks
category: standards
version: "1.0"
last_updated: "2026-11-17"
requires: [static_analysis]
applies_to: [static, dynamic, root]
platform: [android, ios]
---

# OWASP MASVS

Use this skill to map a finding to MASVS v2. The groups and the control statements below are the published standard (https://mas.owasp.org/MASVS/). Tests live in the MASTG (https://mas.owasp.org/MASTG/tests/). Profiles such as L1, L2, and R belong on MASTG tests, not on v2 controls. Do not cite retired v1 ids (`MSTG-STORAGE-1` and the old level tags) as if they were v2 controls.

MASVS v2 groups used here:

| Group | Id | What it covers |
| --- | --- | --- |
| STORAGE | MASVS-STORAGE | Sensitive data at rest, and unintended leakage |
| CRYPTO | MASVS-CRYPTO | Algorithms and key management |
| AUTH | MASVS-AUTH | Remote and local authentication, step-up |
| NETWORK | MASVS-NETWORK | Traffic security and identity pinning |
| PLATFORM | MASVS-PLATFORM | IPC, WebViews, and the user interface |
| CODE | MASVS-CODE | Platform and dependency freshness, input handling |
| RESILIENCE | MASVS-RESILIENCE | Reverse engineering and tampering resistance |

MASVS-PRIVACY is also part of v2. It is summarized at the end. It is not a substitute for a privacy regulation review.

When `static_apk_scan` already emitted a finding, keep its severity and add the control id. Use the rubric for manual findings. `report_vulnerability` requires a `poc` field: write what you inspected and the pass/fail observation, not a payload.

Resilience controls are defense in depth. The standard says their absence is not, by itself, a vulnerability. Do not raise a missing obfuscation or root check above low unless some other control actually failed.

## Maya static findings

`static_apk_scan` reads the APK without a device. Attach controls as follows.

| Finding | Scanner severity | Controls |
| --- | --- | --- |
| Application is debuggable | high | MASVS-RESILIENCE. MASTG-TEST-0226 (Debuggable Flag Enabled in the AndroidManifest) |
| Application data backup is enabled | medium | MASVS-STORAGE-2. Raise to high only if the backup contains secrets |
| targetSdkVersion below the Android 12 exported-component baseline | medium | MASVS-PLATFORM-1 and MASVS-CODE-1 |
| Application allows cleartext traffic | high | MASVS-NETWORK-1. MASTG-TEST-0235 (cleartext in the manifest or network security config) |
| Network security config trusts user-installed certificates | high | MASVS-NETWORK-1. Pinning (MASVS-NETWORK-2) cannot be claimed while this trust anchor is active for that host |
| Hardcoded cleartext URL | medium | MASVS-NETWORK-1 |
| Exported components are reachable without a permission | high | MASVS-PLATFORM-1 |
| Browsable deep link accepts cleartext HTTP | high | MASVS-PLATFORM-1 and MASVS-NETWORK-1 |
| Hardcoded Firebase Realtime Database URL | high | MASVS-STORAGE-2 and MASVS-AUTH-1. Confirm whether unauthenticated reads are enabled before you call data exposed |
| Client-side root or instrumentation checks are present | low | MASVS-RESILIENCE-1. Presence is a signal, not a passed control |

Dynamic evidence uses the same ids. `device_dump_app_data` and `objection_enum_storage` support MASVS-STORAGE. Log capture supports MASVS-STORAGE-2. Proxy capture supports MASVS-NETWORK. `analyze_manifest` supports MASVS-PLATFORM and MASVS-CODE. `search_decompiled_code`, `semgrep_scan`, and MobSF support CRYPTO, CODE, and PLATFORM. Flutter engine traffic is judged with `flutter_apps`, not with a Java pinning hook.

## MASVS-STORAGE

- MASVS-STORAGE-1: The app securely stores sensitive data.
- MASVS-STORAGE-2: The app prevents leakage of sensitive data.

Check private storage (preferences, DataStore, SQLite, Room, files, Keychain, UserDefaults), external storage, backups, logs, crash keys, the keyboard cache, and the pasteboard. MASTG-TEST-0207 (Runtime Storage of Unencrypted Data in the App Sandbox) is the sandbox half: copy private data, exercise the app, copy again, and read what changed. Decode base64 and hex before you call a value protected. A hardcoded wrapping key in the client fails STORAGE-1.

Pass: secrets are in the Keystore or Keychain, backups exclude them, and logs do not contain them. Fail: tokens, credentials, or PAN are recoverable from a file, a backup, or a log. Scanner backup findings stay medium until content is confirmed.

## MASVS-CRYPTO

- MASVS-CRYPTO-1: The app employs current strong cryptography and uses it according to industry best practices.
- MASVS-CRYPTO-2: The app performs key management according to industry best practices.

Search for algorithm and mode (ECB, static IV, broken ciphers), short keys, `java.util.Random` or a fixed seed used for security, and keys embedded in code or resources. Prefer platform primitives (Keystore, Keychain, CommonCrypto, CryptoKit) over bundled copies with a hardcoded key. A strong algorithm with the key next to the ciphertext fails CRYPTO-2.

Pass: current algorithms, random IVs, and keys that are generated and kept in the platform key store. Fail: ECB or a static IV for sensitive data, a hardcoded symmetric key, or a custom cipher. High when the data is credentials or payment data. Medium when it is other sensitive app data. Low when the weak call is on non-sensitive cache.

## MASVS-AUTH

- MASVS-AUTH-1: The app uses secure authentication and authorization protocols and follows the relevant best practices.
- MASVS-AUTH-2: The app performs local authentication securely according to the platform best practices.
- MASVS-AUTH-3: The app secures sensitive operations with additional authentication.

AUTH-1 is enforced on the server. The app's job is to use the protocol correctly: authorization code with PKCE (or the platform equivalent) for a public client, no tokens in URLs or logs, and no client-side authorization decision. AUTH-2 is local: Android biometric prompt bound to a Keystore key, iOS Keychain access control bound to biometry. A success callback that sets a boolean and then reads a stored token fails AUTH-2. AUTH-3 is step-up on sensitive operations (new payee, limit change, high-value transfer), checked on the server.

Pass and fail details for payment apps are in `fintech_mobile_banking`. A local gate that releases a payment token is high. A missing step-up on a sensitive operation is high when the server then performs it, medium when the server still refuses.

## MASVS-NETWORK

- MASVS-NETWORK-1: The app secures all network traffic according to the current best practices.
- MASVS-NETWORK-2: The app performs identity pinning for all remote endpoints under the developer's control.

Check cleartext flags, ATS exceptions, custom trust managers, hostname verification, and certificate or public-key pins for hosts the developer controls. MASTG-TEST-0235 covers Android cleartext configuration. MASTG-TEST-0244 (Missing Certificate Pinning in Network Traffic) is the runtime idea: a lab CA that can read first-party HTTPS means pinning is missing or wrong. Do not fail a third-party host the developer does not control. Flutter `dart:io` ignores the platform trust store; use `flutter_apps` before you pass NETWORK-2.

Pass: TLS 1.2 or newer, platform hostname checks, no user-CA trust in production, pins on developer-controlled hosts. Fail: cleartext, a trust-all callback, or a missing pin on a first-party host. Keep scanner severities (cleartext and user CAs high, hardcoded `http://` URL medium).

## MASVS-PLATFORM

- MASVS-PLATFORM-1: The app uses IPC mechanisms securely.
- MASVS-PLATFORM-2: The app uses WebViews securely.
- MASVS-PLATFORM-3: The app uses the user interface securely.

PLATFORM-1: exported activities, services, receivers, and providers; intent permissions; `PendingIntent` mutability; custom schemes and verified App Links; iOS URL schemes and universal links. Unexported is the default you want for anything that is not a deliberate entry point. Maya's exported-component and browsable-http findings stay high.

PLATFORM-2: JavaScript enabled only where required, no unrestricted file access, no JavaScript bridge into native secrets, mixed-content blocked, and WebView TLS errors not ignored. A bridge that exposes tokens or a file read is high. A debug WebView setting in a release build is medium and also touches RESILIENCE-4.

PLATFORM-3: `FLAG_SECURE` and recents screenshots, notification contents, the pasteboard, and keyboard caching on PIN and PAN fields. PAN or OTP in a recents thumbnail is high. A missing flag on a screen that does not show secrets is low.

Report a missing IPC or WebView control from the manifest and the code. Do not include an intent or script payload in `poc`.

## MASVS-CODE

- MASVS-CODE-1: The app requires an up-to-date platform version.
- MASVS-CODE-2: The app has a mechanism for enforcing app updates.
- MASVS-CODE-3: The app only uses software components without known vulnerabilities.
- MASVS-CODE-4: The app validates and sanitizes all untrusted inputs.

CODE-1: `minSdkVersion`, `targetSdkVersion`, and the iOS deployment target. Maya's targetSdk-below-31 finding stays medium because of the exported-component default. A very old minimum OS is a separate low or medium gap; say which APIs are missing, do not invent a CVE.

CODE-2: a forced-update path (version check or the store's immediate update API) for issues that cannot wait for a normal release. Absence is info or low unless you already have a critical client bug and no way to retire the build.

CODE-3: dependency manifests, embedded native libraries, and known vulnerable versions. Use `semgrep_scan` and the package's dependency files when they are present. A confirmed vulnerable component is medium, or high when the vulnerable code is reachable with sensitive data.

CODE-4: intents, deep-link parameters, WebView URLs, file paths, and API fields treated as trusted. The fail is missing validation before SQL, a file path, a WebView load, or a native call. Describe the sink and the source. Do not include injection strings.

## MASVS-RESILIENCE

- MASVS-RESILIENCE-1: The app validates the integrity of the platform.
- MASVS-RESILIENCE-2: The app implements anti-tampering mechanisms.
- MASVS-RESILIENCE-3: The app implements anti-static analysis mechanisms.
- MASVS-RESILIENCE-4: The app implements anti-dynamic analysis techniques.

Look for Play Integrity or App Attest verified on the server (RESILIENCE-1), signature or checksum checks (RESILIENCE-2), stripping and obfuscation (RESILIENCE-3), and debugger or instrumentation detection (RESILIENCE-4). MASTG-TEST-0226 sits in the MASVS-RESILIENCE group and fails when `android:debuggable` is true. Maya already rates that high because a debugger can attach, which is a concrete exposure and not merely a missing hardening layer.

Pass: the control the threat model asks for is present, and any verdict that gates a sensitive action is checked on the server. Fail of the debuggable flag: high, keep the scanner severity. Missing obfuscation, or a client-side root check with no server decision: info or low. A client-side check that is the only gate on a payment or token is not a resilience finding; file it under AUTH or STORAGE.

## MASVS-PRIVACY

v2 also defines MASVS-PRIVACY. Use it when the question is data collection rather than a security control above.

- MASVS-PRIVACY-1: The app minimizes access to sensitive data and resources.
- MASVS-PRIVACY-2: The app prevents identification of the user.
- MASVS-PRIVACY-3: The app is transparent about data collection and usage.
- MASVS-PRIVACY-4: The app offers user control over their data.

Check dangerous permissions against the features you can actually exercise, third-party SDK initialization before consent, and store-listing privacy labels versus observed network calls. A permission with no matching feature is a privacy gap (low or medium). Do not treat this group as a legal opinion.

## Severity Guidance

- Keep `static_apk_scan` severities. Add the control id in `description` or `evidence`.
- Critical is reserved for confirmed exposure of payment secrets or an unbound server action that moves money. MASVS itself does not assign that word.
- High: credentials or PAN at rest, cleartext or trust-all TLS, debuggable release, exported entry into an authenticated flow.
- Medium: backup enabled, missing pin on a non-payment first-party host, vulnerable but reachable dependency, OTP in a log.
- Low or info: resilience gaps that do not break another control.

## Remediation

State the control that failed and the platform fix: Keystore or Keychain, network security config without user CAs and with pins, `android:exported` and a permission, WebView lockdown, a current target SDK, and server-side checks for auth and integrity verdicts. A resilience gap is a hardening recommendation, not a stand-in for those fixes.

## Related skills

`fintech_mobile_banking` for payment-specific pass/fail rules. `flutter_apps` when NETWORK or STORAGE evidence may be inside `libapp.so`. `static_analysis` for the scanner and decompile order.
