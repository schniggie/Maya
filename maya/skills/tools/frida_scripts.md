---
name: frida_scripts
description: Pre-built Frida script library - when and how to use each module
category: tools
version: "1.1"
last_updated: "2026-11-17"
applies_to: [dynamic, bypass, extract, exploit]
---

# Frida Script Library Guide

## Overview

The 23 bundled scripts live in `assets/frida-scripts/<category>/<name>.js`. The sandbox image copies them to `/opt/maya-assets/frida-scripts`. A user directory at `~/.maya/frida-scripts/` is included when it exists, and `MAYA_FRIDA_SCRIPTS` replaces that extra directory.

1. `frida_list_scripts` returns name, category, and the first `//` description. It does not return source.
2. `frida_run_named_script(package_name="...", name="enumerate/loaded_classes")` loads one readable script and injects it with `frida_run_script`.
3. `frida_load_script(name)` returns the source, or an error dict when the name is unknown, ambiguous, or unreadable.

Each script is self-contained. The loader does not prepend a shared runtime. Results use `send({ tag, event, data })` and the same JSON object on stdout:

| Field | Meaning |
| --- | --- |
| `tag` | Script stem, such as `ssl_pinning_universal` |
| `event` | `ready`, `hook`, `hit`, `miss`, `error`, or `done` |
| `data` | Plain object for that event |

`miss` means an optional class or export is absent and the rest of the script kept going. Parse stdout as one JSON object per line. Details and the per-script constants (`TARGET_CLASS`, `FILTER`, `LIB_NAME`) are in `assets/frida-scripts/README.md`.

## One script per session when hooks overlap

`frida_run_named_script` injects a single file. Concatenate sources only when the scripts do not replace the same Java method. A later `implementation` replaces the earlier one. Do not combine `root_detection_universal` with `emulator_detection` (both hook `File.exists`), or `network_requests` with `tls_version_check` (both hook `URL.openConnection`). `ssl_pinning_universal` and `root_detection_universal` touch different methods and can be concatenated. Each file closes over its own `tag`.

## Module Categories

Scripts that are not in this list are not in the catalog. Do not call `frida_load_script` for a name that is not listed.

### Bypass Modules

| Module | When to Use |
| --- | --- |
| `ssl_pinning_universal` | Android TLS pinning. Hooks OkHttp3 `CertificatePinner`, `X509TrustManager` via `SSLContext.init`, Conscrypt trust checks, and WebView SSL errors when those classes exist. |
| `ssl_pinning_flutter` | Flutter/BoringSSL only. Hooks `SSL_CTX_set_custom_verify` in `libflutter.so` if the export exists. Pair with the universal script for Java pins. |
| `root_detection_universal` | App checks `su` paths, `su`/`magisk` commands, `Build.TAGS`, RootBeer, or known root packages. |
| `emulator_detection` | App checks Build properties, qemu system properties, telephony identifiers, or emulator device files. Telephony values are synthetic lab fixtures. |
| `debug_detection` | App checks `Debug.isDebuggerConnected`, `FLAG_DEBUGGABLE`, `ptrace(PTRACE_TRACEME)`, or `TracerPid`. |
| `integrity_check` | Report signature lookups and digest algorithms. Does not forge signatures or replace digest output. |
| `secure_boot_check` | Read verified-boot properties, patch level, and whether SafetyNet or Play Integrity classes are present. Does not fake attestation. |

### Extract Modules

| Module | When to Use |
| --- | --- |
| `crypto_keys` | Observe `Cipher`, `SecretKeySpec`, and `Mac` key material in the local Frida session. Non-exportable keys are reported as `exportable: false`. |
| `shared_preferences` | Observe preference reads and writes. Values are truncated. |
| `sqlite_queries` | Observe SQL text for query, exec, insert, update, and delete. |
| `network_requests` | Observe OkHttp and `URLConnection` method and URL. Bodies and headers are not recorded. |
| `tls_version_check` | Report negotiated TLS versions, enabled protocols, and cleartext `http://` URLs. |
| `data_containerization_check` | Report sandbox paths, world-readable preference modes, and writes outside `/data/data` or `/data/user`. |

### Enumerate Modules

| Module | When to Use |
| --- | --- |
| `loaded_classes` | List loaded Java classes in batches. Set `FILTER` to a package substring, or leave it empty. |
| `class_methods` | List methods of one class. Set `TARGET_CLASS` before injecting. `REPLACE_ME` returns an error event. |
| `native_exports` | Summarize app native modules. Set `LIB_NAME` to include export names. |
| `intent_monitor` | Observe activity, broadcast, and service intents the app sends. Does not forge intents. |
| `rasp_detection` | Report known RASP or packer classes, anti-instrumentation commands, and a short-name ratio. Does not disable RASP. |

### Exploit Modules

These stay observation scripts for an authorized lab app. Do not treat them as remote exploit executors.

| Module | When to Use |
| --- | --- |
| `webview_rce` | Report JavaScript interfaces and risky WebView settings. Does not inject script or call `loadUrl`. |
| `deeplink_injection` | Report deeplink URIs and query parameters the app reads, and flag redirect-like keys. Does not send intents. |
| `content_provider_dump` | Report provider queries and writes the app already performs, including column names and row counts. Does not query providers itself or read row values. |

### iOS Modules

| Module | When to Use |
| --- | --- |
| `nsurlsession_hook` | Observe `NSURLSession` data-task URL, method, and headers. Requires `ObjC.available`. |
| `data_protection` | Report the file-protection class on `NSFileManager` creates and `NSData` writes. |

## Decision Flow

1. Run `framework_detect` to identify the app framework.
2. Run `protection_detect` to identify active protections.
3. Pick one bypass module that matches the protection. Use `ssl_pinning_flutter` only when the app is Flutter, and still load `ssl_pinning_universal` in a separate injection if Java pins are present.
4. Read `ready`, `hook`, and `miss` events before deciding the bypass installed.
5. Add one enumerate or extract module in its own injection for the test objective.
6. For `exploit/` names, record the observation. Do not extend those scripts into an injection or query tool during the run.
