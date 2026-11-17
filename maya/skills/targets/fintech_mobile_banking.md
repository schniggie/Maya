---
name: fintech_mobile_banking
description: Verification playbook for banking, wallet, and payment apps
category: targets
version: "1.0"
last_updated: "2026-11-17"
requires: [insecure_storage, data_leakage, insecure_crypto, static_analysis]
applies_to: [static, dynamic, api]
platform: [android, ios]
---

# Fintech and Mobile Banking

Use this skill for banking, wallet, card, trading, BNPL, and payment apps. It is a verification checklist: what to inspect, how to decide pass or fail, and how to rate the result. Record evidence with `report_vulnerability`. Put the observation in `poc` (what was reviewed and what failed). Do not put a bypass script, payload, or request template there.

Load `owasp_masvs` when you map a finding to a control. Load `flutter_apps` when the package embeds Flutter. `static_apk_scan` severities stay as the scanner emitted them; attach the control id and use the rubric below only for findings the scanner did not emit.

## Verification boundary

Confirm a weakness class on an authorized build and test account. A missing client control is evidence. Building an overlay, an accessibility service, a pinning bypass, or a forged payment request is out of scope for this pack. Server behavior is in scope only as the pass/fail result of an authorized check (duplicate request accepted or rejected, amount booked matches the server quote).

Sensitive authentication data means card verification values, PINs, and full track data. Those must not be stored after authorization. A full PAN must be unreadable at rest. Maya does not issue a PCI attestation; flag storage of PAN or sensitive authentication data for a human reviewer.

## Discovery Workflow

1. Run `static_apk_scan` and read backup, cleartext, user-CA trust, exported components, deep links, Firebase URLs, and client-side root checks.
2. Run `analyze_manifest` when an apktool manifest exists. On iOS, review Info.plist ATS exceptions, URL schemes, and associated domains.
3. Use `search_decompiled_code` or `mobsf_search_code` for storage, crypto, biometric, logging, and WebView APIs.
4. On an authorized device, exercise login, balance, card reveal, payee add, and a low-value transfer. Then use `device_dump_app_data` or `objection_enum_storage` and compare files created during the session.
5. Review logs and, if a lab proxy is in use, first-party API hosts only. Hand endpoints to `report_api_endpoint`.

## Tool Quick Reference

- `static_apk_scan`: device-free manifest, network security config, strings, and native-library signals.
- `analyze_manifest`: exported components, permissions, schemes, backup, debuggable.
- `search_decompiled_code`: storage, crypto, biometric, and logging call sites.
- `device_dump_app_data` / `objection_enum_storage`: private files after real workflows.
- `report_vulnerability`: one finding per weakness class, with the MASVS control in the description.

## Secure storage of tokens and PANs

Inspect Android SharedPreferences, DataStore, SQLite, Room, files under the app sandbox, external storage, and backups. Inspect iOS Keychain accessibility, files in the container, and UserDefaults. Search for PAN, token, refresh-token, and PIN field names.

Pass: refresh tokens and PANs are protected by the Android Keystore or the iOS Keychain with a device-bound key. The key is not a string in the package. CVV, PIN, and track data are absent after the authorization call returns. Backups exclude those files.

Fail: a session token, refresh token, PAN, PIN, or CVV is readable in preferences, a database, a file, a backup, or external storage. Encoding (base64, hex) is not protection. A hardcoded database passphrase in the client is a fail even when the file looks encrypted.

Maps to MASVS-STORAGE-1 and MASVS-STORAGE-2. The sandbox diff is the idea in MASTG-TEST-0207 (Runtime Storage of Unencrypted Data in the App Sandbox). Maya's "Application data backup is enabled" finding is the backup half of MASVS-STORAGE-2; keep its medium severity unless the backup actually contains tokens or PAN, which raises it to high.

## TLS and certificate pinning

Inspect `usesCleartextTraffic`, network security config (`cleartextTrafficPermitted`, `pin-set`, `trust-anchors`), OkHttp `CertificatePinner`, custom `TrustManager` / `X509TrustManager` implementations, and iOS ATS exceptions. Flutter traffic is a separate stack; use `flutter_apps` before you conclude the app has no network calls.

Pass: first-party banking and payment hosts are HTTPS, TLS 1.2 or newer, and reject a lab CA the developer does not pin. Hostname verification is the platform default.

Fail: cleartext on an account or payment host; a trust manager or ATS exception that accepts any certificate; user-installed CAs trusted for first-party hosts; no identity pin on a first-party host the developer controls. Third-party hosts the developer does not control are a note, not a pinning fail. That split is the evaluation rule in MASTG-TEST-0244 (Missing Certificate Pinning in Network Traffic). Cleartext configuration is MASTG-TEST-0235.

Maya already rates cleartext and user-CA trust as high, and a hardcoded `http://` URL as medium. Keep those severities. Missing pinning on a first-party banking host that otherwise uses TLS is high.

## Root, jailbreak, and tamper signals

Search for Play Integrity, SafetyNet, root-package or su path checks, Frida or debugger checks, iOS jailbreak path checks, DeviceCheck, and App Attest. Note whether a server endpoint receives the verdict or the branch exists only on the client.

Pass: a banking policy that requires a platform integrity verdict checks that verdict on the server, and the server refuses sensitive operations when the verdict is missing. Client signals may also exist.

Fail: the only enforcement is a client branch, or a payment or session decision is taken locally from that branch. Absence of any root or jailbreak check is not itself a vulnerability. MASVS-RESILIENCE says these controls are defense in depth. Record absence as info or low unless the client is the only control, in which case the finding is the client-side trust decision and follows the storage or auth severity.

Maya's "Client-side root or instrumentation checks are present" finding stays low. It shows the check runs in-process. It is not evidence the control holds, and it is not evidence of a bypass.

## Screen capture, overlay, and accessibility

On payment, card, PIN, and OTP screens, look for Android `FLAG_SECURE`, `setRecentsScreenshotEnabled(false)`, and Compose secure dialogs, and for iOS hiding on `UIScreen.captured` plus `isSecureTextEntry` on PIN fields. Look for `filterTouchesWhenObscured` or `setHideOverlayWindows` on confirm actions. Look for whether the app treats an unknown accessibility service as a risk signal.

Pass: balance, PAN, PIN, and OTP are not readable from the recents thumbnail or a screenshot on a lab device, and the confirm action filters obscured touches or hides overlays.

Fail: PAN, PIN, or OTP is visible in the recents image or an ordinary screenshot. A one-tap transfer confirmation with neither an overlay filter nor step-up authentication is a fail of the UI control. Report that from static references and the lab screenshot of the app's own screen. Do not build an overlay or an accessibility client to demonstrate it.

Maps to MASVS-PLATFORM-3. PAN or OTP visible in a captured frame is high. A missing flag on a non-sensitive marketing screen is low.

## Transaction integrity and replay

Read the payment API the app calls. Note whether amount, currency, and beneficiary are a server-issued quote or client-supplied fields the server posts. Note idempotency keys, nonces, and timestamps.

Pass: the server books the transfer it previously authorized. Repeating one authorized low-value request returns the original result or a rejection, and does not create a second debit. Adding a payee or raising a limit requires step-up authentication (MASVS-AUTH-3).

Fail: a second debit is created from the same request, or the booked amount or beneficiary follows a client body that was not the server quote. Describe the server result in `evidence`. Do not include a rewritten request.

Critical when money moves or a payee changes without server binding. High when the replay is accepted but limited to the same already-authorized transfer details and the user can still see it. Medium when a nonce is missing but the server still rejects duplicates.

## Deep links and intents

Enumerate browsable filters, custom schemes, and iOS associated domains. Mark handlers whose paths or query parameters mention pay, transfer, oauth, token, redirect, amount, or account. Confirm Android App Links use `android:autoVerify` and iOS universal links use associated domains. A custom scheme is not an exclusive owner of that scheme.

Pass: the link opens UI only. Authorization is the existing server session. HTTPS App Links are verified. Exported payment components declare a signature permission or are not exported.

Fail: the link's parameters choose the amount, source, or beneficiary the server will post; a token is in the URL; a browsable `http` filter reaches an in-app flow; an exported activity opens an authenticated screen with no permission. Maya's "Exported components are reachable without a permission" and "Browsable deep link accepts cleartext HTTP" findings stay high and map to MASVS-PLATFORM-1.

## Biometric and step-up authentication

Read the local-auth implementation, not the button label.

Pass: Android `BiometricPrompt` unlocks a Keystore key (`CryptoObject`, `setUserAuthenticationRequired`, invalidated when biometrics change). iOS Keychain items use an access control that requires biometry or user presence. A new payee, a limit change, and a high-value transfer each require a fresh server-side step-up. A failed biometric does not issue a session.

Fail: the success callback sets a boolean and then reads a token that was already in preferences or memory. The biometric result is not bound to the key that protects the token. That is a local authentication weakness (MASVS-AUTH-2), high when the token then authorizes payments.

Remote login still has to meet MASVS-AUTH-1: public mobile clients use an authorization-code flow with PKCE or the platform equivalent, tokens are not placed in URLs or logs, and the server enforces authorization.

## Logging and analytics

Search for `Log`, Timber, `NSLog`, `os_log`, `print`, Crashlytics custom keys, and analytics event properties. Capture logs during login and a transfer on the lab device.

Pass: logs and analytics contain non-sensitive operational events. Tokens, PAN, CVV, PIN, OTP, and passwords are redacted.

Fail: any of those values appear in logcat, the device console, a crash report, or an analytics payload. Credentials, PAN, or a refresh token are high. A partial account number or an OTP in a debug log is medium. Maps to MASVS-STORAGE-2.

## Severity Guidance

- Critical: stored CVV, PIN, or track data, or a server that moves money or changes a payee from an unbound or replayed client request.
- High: recoverable refresh token or PAN, cleartext or missing pinning on a first-party banking host, debuggable release, exported payment flow, biometric gate that does not protect the token.
- Medium: backup that includes session material, OTP or partial account data in logs, missing secure-screen flag on a payment screen.
- Low: client-only root or tamper signal while the server still enforces the sensitive action.
- Info: a resilience control is present, or a third-party host lacks a pin the developer cannot set.

## Remediation

- Keep PAN, tokens, and keys in Keystore or Keychain, and keep payment authorization on the server.
- Pin developer-controlled hosts, refuse cleartext, and do not trust user-installed CAs in production.
- Treat Play Integrity, App Attest, and root checks as signals the server evaluates.
- Set secure-display flags on PAN, PIN, and OTP surfaces, and require step-up for new payees and high-value transfers.
- Redact secrets in logs, crashes, and analytics.

## Related skills

`owasp_masvs`, `insecure_storage`, `data_leakage`, `insecure_crypto`, `flutter_apps` when the binary is Flutter. `flutter_analysis` is the Flutter tool workflow, not this checklist.
