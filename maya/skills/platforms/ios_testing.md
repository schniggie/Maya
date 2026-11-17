---
name: ios_testing
description: Device-free IPA review, ATS and Mach-O checks, and observation-only iOS instrumentation
category: platforms
version: "2.0"
last_updated: "2026-11-17"
requires: [static_analysis, frida_operations]
applies_to: [ios, dynamic, static]
platform: [ios]
---

# iOS Testing

Use this skill to decide what Maya can already show, and what still needs a person with a device. Keep scanner severities. Do not invent a dynamic result the report says was skipped.

## Device-free scan

For an `.ipa` or an unpacked `.app` directory, run `static_ipa_scan`. The CLI is `maya --static-only --package <path>`. It writes `report.json`, `report.md`, `report.html`, and `report.sarif`. It does not need a Mac, a device, or `otool`.

```
static_ipa_scan(ipa_path="<ipa_or_app>", output_dir="/tmp/maya-static")
```

Read the capability notes in the report before you grade binary hardening.

The scan covers:

- `NSAppTransportSecurity` (arbitrary loads, web content, media, local networking, exception domains, insecure HTTP, minimum TLS)
- `CFBundleURLTypes` schemes
- `UIFileSharingEnabled` and `LSSupportsOpeningDocumentsInPlace`
- Empty `*UsageDescription` strings
- Embedded framework names
- `get-task-allow`, shared keychain groups, application groups, and the Wi-Fi information entitlement from the provisioning profile or a `.xcent` file. Device identifiers are not copied into the report
- `MH_PIE` from the Mach-O header
- A marker search for `stack_chk_fail` and, when the binary looks like Objective-C, `objc_release`
- `cryptid` on the main executable

`otool` fills gaps only when it is on `PATH`. A missing `otool` is recorded. It is not a failed scan.

## What you must not claim

- App Store IPAs are often FairPlay-encrypted. Maya does not decrypt them. When the report says `cryptid` is set, do not grade stack canary or ARC inside that range.
- A missing executable, or a file that is not a Mach-O the parser understands, is "not assessed". Do not report missing PIE from that input.
- Stack canary and ARC findings mean the marker string was absent in the bytes that were scanned. Say that. A stripped binary can hide the marker.
- `maya --emulator` is Android only. There is no iOS Simulator path.
- The iOS companion is a scaffold. Do not treat it as a keychain or container dump.
- Maya does not jailbreak a device, insert a Frida Gadget, or re-sign an IPA.

Scan a build you are allowed to test: a development build, an enterprise build you operate, or a CI artifact you produced. Acquiring or decrypting an App Store package is out of scope for this skill.

## Dynamic attachment, high level

Instrumentation needs a process you can already attach to. Two setups exist. Both are manual.

- A jailbroken device can run `frida-server`. Attach by bundle id. Maya does not provide a jailbreak.
- A non-jailbroken debug build can include a Frida Gadget and be signed by the developer. Maya does not embed the gadget or sign the package.

After attach, use the bundled observation scripts. They keep the original implementation. Run one script per `frida_run_named_script` call.

| Script | Use it to record | Do not expect |
| --- | --- | --- |
| `ios/keychain_access` | SecItem class, service, account, access group, accessibility, status | Password, key, or value bytes |
| `ios/pasteboard_monitor` | Change count, UTI, length | Pasteboard text or data |
| `ios/file_io` | Paths, protection class, byte length | File bytes |
| `ios/commoncrypto` | Operation, algorithm, ECB flag, lengths | Key, IV, or input bytes |
| `ios/wkwebview_load` | URL, scheme, host, MIME, HTML or data length | HTML, bodies, or a navigation the script starts |
| `ios/nsurlsession_hook` | URL, method, truncated headers | A changed request, or the body |
| `ios/data_protection` | Path and file-protection class | File bytes |

`frida_generate_hook` can write one more observation script with `platform: ios`. The denylist is unchanged. There is no bundled iOS pinning bypass and no bundled jailbreak-detection bypass. Android `bypass/` scripts are unchanged and do not run on iOS.

## Keychain and Data Protection

Keychain items are the right place for credentials. The static scan cannot see item values. The runtime script records metadata so you can see which protection class the app asked for.

| Accessibility | Expectation |
| --- | --- |
| `kSecAttrAccessibleWhenUnlocked` / `WhenPasscodeSetThisDeviceOnly` | Appropriate for credentials |
| `kSecAttrAccessibleAfterFirstUnlock` | Weaker. The item remains available while the device is locked after first unlock |
| `kSecAttrAccessibleAlways` | Weak. Available without the device unlocked |

File protection on data the app writes:

| Class | Expectation |
| --- | --- |
| `NSFileProtectionComplete` | Unavailable while locked |
| `NSFileProtectionCompleteUnlessOpen` | Stays readable only if it was opened while unlocked |
| `NSFileProtectionCompleteUntilFirstUserAuthentication` | Default-class behavior. Available after first unlock |
| `NSFileProtectionNone` | No file protection |

A shared keychain access group or an application group is an info finding when the scanner sees more than the app's own group. Confirm the sharing is intentional. Do not copy item values into the report.

## ATS

| plist signal | Scanner severity | Control |
| --- | --- | --- |
| `NSAllowsArbitraryLoads` | high | MASVS-NETWORK-1 |
| `NSExceptionAllowsInsecureHTTPLoads` | high | MASVS-NETWORK-1 |
| Minimum TLS below TLSv1.2 | medium | MASVS-NETWORK-1 |
| `NSAllowsArbitraryLoadsInWebContent` or `ForMedia` | medium | MASVS-NETWORK-1 |
| `NSAllowsLocalNetworking` | info | MASVS-NETWORK-1 |
| Embedded `http://` URL | medium | MASVS-NETWORK-1 |

Local networking is recorded because it is an exception, not because it is the same as an app-wide cleartext policy.

## Other scanner mappings

| Finding | Severity | Control |
| --- | --- | --- |
| Insecure URL scheme (`http`, `file`, `javascript`, `data`, `ftp`) | high | MASVS-PLATFORM-1 |
| Custom URL scheme | low | MASVS-PLATFORM-1 |
| File sharing enabled | medium | MASVS-STORAGE-2 |
| Documents opened in place | low | MASVS-STORAGE-2 |
| `get-task-allow` | high | MASVS-RESILIENCE-4 |
| Missing PIE, stack-canary marker, or ARC marker | low | MASVS-RESILIENCE-2 |
| FairPlay `cryptid` set, or Mach-O not assessed | info | MASVS-RESILIENCE-2 |
| Empty usage description | low | MASVS-PRIVACY-3 |
| Deployment target below iOS 13 | low | MASVS-CODE-1 |

`get-task-allow` is normal on a development profile and a problem on a distribution build. The evidence names the profile kind. Keep the high severity and say which profile you scanned.

Custom URL schemes are not exclusive to the app. Describe that. Do not send crafted URLs from this skill. Universal links are the associated-domains list in the report; they are inventory, not an automatic finding.

PIE, canaries, and ARC are hardening signals. Do not raise them above the scanner severity.

## Manual follow-up

After the static report:

1. Say which checks ran and which the capability notes skipped.
2. If you have an instrumentable build, run the observation script that matches the question. Record `ready`, `hook`, `hit`, and `miss`.
3. Map any extra observation to `owasp_masvs` without raising the scanner's severity.
4. Stop when the remaining question needs a device, a decrypted build, or a signature you do not have. Say that gap.
