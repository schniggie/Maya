# iOS support

Maya's iOS arm is a device-free static scan plus a small set of observation-only Frida scripts. It is not an iOS equivalent of the Android emulator path, and it does not decrypt App Store binaries.

## What runs without a device

`maya --static-only` accepts an `.ipa` zip or an unpacked `.app` directory, alongside the existing `.apk` path. `static_ipa_scan` is the same scan for the agent. Neither needs a Mac, a device, `otool`, or apktool.

```bash
maya --static-only --package app.ipa --output-dir maya_runs/app
maya --static-only --package Payload/App.app --fail-on high
```

The scan writes `report.json`, `report.md`, `report.html`, and `report.sarif`. `--fail-on` uses the same severities as the APK scan. `info` never fails the gate.

It reads:

| Input | What is reported |
| --- | --- |
| `Info.plist` | ATS (`NSAppTransportSecurity`), URL schemes, `UIFileSharingEnabled`, `LSSupportsOpeningDocumentsInPlace`, usage-description keys, `MinimumOSVersion` |
| `embedded.mobileprovision` and `.xcent` | `get-task-allow`, keychain access groups, application groups, the Wi-Fi information entitlement. Provisioned-device identifiers are counted and not copied into the report |
| `Frameworks/*.framework` | Framework names |
| Main Mach-O | `MH_PIE` from the header, a marker search for `stack_chk_fail` and `objc_release`, and `cryptid` |

`otool` is used only when it is on `PATH`. If it is missing or fails, the built-in parser stands and the report says so. A binary that is not a Mach-O this parser understands produces "Mach-O protections were not assessed" and does not invent a missing-PIE result.

Stack canary and ARC are marker searches. A stripped binary can hide the marker. Those findings stay low and say that.

## What this path does not do

- It does not decrypt FairPlay. An App Store IPA can still be scanned for the plist, the profile, and the Mach-O header. When `cryptid` is set, the report says marker checks inside the encrypted range were skipped.
- It does not jailbreak a phone, embed a Frida Gadget, or re-sign an IPA.
- It does not boot an iOS Simulator. `maya --emulator` is the Android emulator path and rejects an IPA.
- The iOS companion under `companion_app/ios/` is still a scaffold. It does not dump a keychain or a container.

A full `maya --target ... --package app.ipa` run still starts the agent loop. That loop can plan dynamic steps it cannot execute. The device-free result is `--static-only`.

## Dynamic scripts

The bundled `assets/frida-scripts/ios/` scripts are observation-only. `Interceptor.attach` leaves the original implementation in place. They need a process you can already attach to. Maya does not create that setup.

| Script | Reports | Leaves out |
| --- | --- | --- |
| `ios/keychain_access` | SecItem class, service, account, access group, accessibility, status | Passwords, keys, and value bytes |
| `ios/pasteboard_monitor` | Change count, UTI, length | Pasteboard text and data |
| `ios/file_io` | Paths, protection class, byte length | File bytes |
| `ios/commoncrypto` | Operation, algorithm, mode, lengths | Key, IV, and input bytes |
| `ios/wkwebview_load` | URL, scheme, host, MIME type, HTML or data length | HTML and bodies. It does not navigate |
| `ios/nsurlsession_hook` | URL, method, truncated headers | Request bodies. It does not change the request |
| `ios/data_protection` | Path and file-protection class on create and `NSData` write | File bytes |

`frida_generate_hook` still accepts `platform: ios` for an observation goal, and the same detection-bypass kinds it already allows (`ssl_pinning`, `root`, `debug`, `emulator`, `rasp`). This tree does not add a bundled iOS pinning bypass or a bundled jailbreak-detection bypass. The generator denylist is unchanged. See [Frida hook generation](frida-hook-generation.md).

Two attachment setups exist, and both stay manual:

- On a jailbroken device, a `frida-server` you installed can attach by bundle id. Maya does not ship a jailbreak.
- On a non-jailbroken phone, a debug build can include a Frida Gadget and be signed by the developer. Maya does not insert the gadget or sign the package.

## Skill

`maya/skills/platforms/ios_testing.md` is the knowledge pack for this workflow: which scan to run, what the report is allowed to claim, keychain and Data Protection classes, ATS, and the MASVS ids the scanner already attaches. `owasp_masvs` lists the same iOS finding titles.
