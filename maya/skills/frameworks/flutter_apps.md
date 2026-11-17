---
name: flutter_apps
description: Assessment checklist for Flutter and Dart AOT applications
category: frameworks
version: "1.0"
last_updated: "2026-11-17"
requires: [static_analysis, reflutter_operations]
applies_to: [static, dynamic, flutter]
platform: [android, ios]
---

# Flutter Apps

Use this skill when the target ships Flutter. It covers how to recognize the package, where the Dart code and secrets live, why Java-layer hooks and the system proxy often see nothing, and how to judge a lab interception. `flutter_analysis` remains the tool workflow (`reflutter_analyze`, symbol extraction, install). This pack is the assessment. Do not paste engine patches, proxy redirects, or runtime scripts into the finding.

## Discovery Workflow

1. Confirm Flutter before treating empty proxy history as "no traffic".
2. Run `static_apk_scan` for manifest and network-security findings. Those still apply to plugins that use the platform HTTP stack.
3. Run `reflutter_analyze` to confirm packaging. Use `reflutter_extract_dart_symbols` when the build still exposes Dart names.
4. Extract strings from `libapp.so` (Android) or `App.framework/App` (iOS) and review `flutter_assets`.
5. Split every network conclusion by stack: `dart:io` in the engine, or a plugin on OkHttp, Cronet, or `NSURLSession`.

## How to identify a Flutter app

Android:

- `lib/<abi>/libflutter.so`, the engine.
- `lib/<abi>/libapp.so`, the Dart AOT snapshot in a release build.
- `assets/flutter_assets/` (asset manifest, fonts, images, bundled JSON).
- An activity or fragment in `io.flutter.embedding.android`, or a generated `FlutterApplication` / embedding class.

iOS:

- `Frameworks/Flutter.framework` (engine).
- `Frameworks/App.framework/App` (Dart AOT snapshot).
- `flutter_assets` inside the bundle.

One engine library without `libapp.so` or `App.framework` is an incomplete match. Add-to-app embeddings still count when both the engine and an AOT snapshot are present.

## Snapshot and asset layout

Release builds compile Dart ahead of time into `libapp.so` or `App`. String literals, including URLs and keys, stay in that binary. Dart method names are often stripped. Missing symbols are an anti-static property (MASVS-RESILIENCE-3), not a vulnerability.

Debug and profile builds, and older release layouts, may also ship `assets/flutter_assets/kernel_blob.bin`, `isolate_snapshot_data`, or `vm_snapshot_data`. A kernel blob in a store package means the app is not a release AOT build. The kernel is far easier to read than the AOT library and is a high finding in a production package.

`flutter_assets` commonly contains `AssetManifest.json` or `AssetManifest.bin`, `FontManifest.json`, `NativeAssetsManifest.json`, `NOTICES`, fonts, images, and bundled configuration. `AssetManifest.bin` is a binary catalog of asset paths, not an encrypted store.

Platform channels (`MethodChannel`, `EventChannel`, `BasicMessageChannel`) are the bridge to Kotlin, Swift, and other native plugins. Channel names are ordinary strings in the snapshot. Business logic on the far side of a channel is reviewed as native code. Logic that never crosses a channel is invisible to Java or Swift hooks.

## Why standard hooks and proxies see nothing

`dart:io` `HttpClient`, and the default adapters in `package:http` and Dio, link the BoringSSL copy inside `libflutter.so` / `Flutter.framework`. That stack does not use Android's `TrustManager`, Network Security Config, or the system HTTP proxy, and it does not use the iOS trust store or ATS for those calls. A Java OkHttp pinning hook, a system proxy, and a user-installed CA can all be correct and still show no Dart traffic.

Plugins can use a different stack on purpose. `cronet_http`, `cupertino_http`, and native payment SDKs often use Cronet, OkHttp, or `NSURLSession`. Those calls do follow the platform trust store, proxy, and ATS or network security config. Record which host used which stack. A cleartext or user-CA finding from `static_apk_scan` is about the platform stack until you show the Dart client uses it.

A certificate callback on the Dart client that accepts every server certificate is a fail of MASVS-NETWORK-1. Search for that callback as a static indicator. Do not ship a hook that forces it.

## Observing traffic in a lab

MASTG-TECH-0109 (Intercepting Flutter HTTPS Traffic) describes two approaches, both of which exist so a tester can see whether first-party TLS is pinned:

- Repackage the engine so the test build uses a lab proxy and the tester can observe certificate checks (reFlutter). `reflutter_analyze` is the Maya entry point. Confirm Flutter packaging before assuming a patch is required.
- Instrument the engine's TLS verification at runtime, and separately direct packets at the proxy, because the engine ignores the device proxy setting.

The result to record, per first-party host:

- The connection fails closed when a lab CA is presented, and application data is not visible. Identity pinning or engine trust held.
- The connection completes and the body is visible. Pinning is absent or not applied on that stack (MASVS-NETWORK-2, same evaluation idea as MASTG-TEST-0244).
- The host appears on the platform stack instead. Judge it with the network security config and ATS, not with the engine result.

Follow MASTG-TECH-0109 for lab procedure. This skill does not restate patch options, ports, or scripts. Third-party hosts the developer does not control are a note, not a pinning fail.

## Where secrets and endpoints hide

Search these locations before you call the client clean:

- Strings in `libapp.so` or `App.framework/App` (API hosts, keys, bucket names).
- `flutter_assets` JSON, `.env`, and other bundled config.
- `google-services.json`, `GoogleService-Info.plist`, and the compiled Firebase options that used to live in `firebase_options.dart`.
- `--dart-define` and flavor constants. They are compiled into the snapshot. They are not a runtime secret store.
- `kernel_blob.bin` when a debug or profile snapshot is present.
- Native plugin manifests and the platform network security config.

A publishable client identifier (a Stripe publishable key, a Firebase project id) is low or info unless a matching database or storage rule is open. Maya's "Hardcoded Firebase Realtime Database URL" finding stays high and still applies when the URL is only a string in `libapp.so`. A secret API key, a private key, or a long-lived token in the snapshot or assets is high. A production kernel blob, or a release package that still enables the Dart VM service, is high.

## Asset and manifest review

Review the embedding the same way as any other app:

- `INTERNET` and cleartext flags. They constrain plugins and the embedding, not `dart:io`.
- Exported Flutter activities and deep-link filters. Deep links are still intents. Use the deep-link checks in `fintech_mobile_banking` when the link can move money.
- Debuggable and backup flags on the host application. `android:debuggable=true` is MASTG-TEST-0226 and stays high.
- Debug or profile engine artifacts left in a store build.

Impeller versus Skia is a renderer choice. It is not a security control.

## Severity Guidance

- High: secret or long-lived token in `libapp.so`, `App`, or `flutter_assets`; production kernel blob or VM service; `dart:io` callback that accepts every certificate; first-party banking host whose engine TLS accepts a lab CA.
- Medium: first-party non-payment host without identity pinning; platform-stack cleartext already covered by `static_apk_scan` keeps that finding's severity.
- Low: publishable client identifiers with no open backend; stripped Dart symbols.
- Info: engine traffic invisible to a system proxy. That is expected. It is not a finding.

## Remediation

- Keep secrets and authorization on the server. `--dart-define` does not hide a key from the binary.
- Pin developer-controlled hosts inside the HTTP stack that actually dials them.
- Ship release AOT builds. Do not ship `kernel_blob.bin` or an open VM service.
- Apply network security config and ATS to every plugin that uses the platform stack, and review deep links on the embedding activity.

## Related skills

`flutter_analysis` and `reflutter_operations` for the tool workflow. `owasp_masvs` for control mapping. `fintech_mobile_banking` when the Flutter app moves money.
