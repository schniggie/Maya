# Bundled Frida scripts

These 23 scripts are the catalog behind `frida_list_scripts` and `frida_run_named_script`. They are for authorized testing of an app you control, including the bundled Damn Vulnerable Bank sample. The loader injects one file per call through `frida_run_script`, so each script carries its own copy of the message helper. There is no shared prelude.

`frida_list_scripts` uses the first `//` line as the description. Keep it in this shape, under 200 characters after the prefix:

```javascript
// <stem>.js — One sentence that says what the script reports or changes.
// category: bypass | enumerate | extract | exploit | ios
// platform: android | ios
// usage: frida_run_named_script("<package>", "<category>/<stem>")
// maya-frida-message: { tag, event, data }
```

## Messages

Every result is one object:

```javascript
send({ tag: "<stem>", event: "<event>", data: { } });
```

The same object is written with `console.log(JSON.stringify(...))` so the Frida CLI stdout captured by `frida_run_script` is one JSON object per line.

| `event` | Meaning |
| --- | --- |
| `ready` | The script finished installing the hooks it could find. |
| `hook` | One hook was installed. |
| `hit` | A hooked call observed something, or a bypass neutralized one check. |
| `miss` | An optional class, method, or export is absent. The session stays up. |
| `error` | A hook failed for a reason other than a missing target. |
| `done` | A finite scan finished. |

`data` is a plain object of strings, numbers, booleans, and arrays. Do not put Java or ObjC objects in it.

Java work runs inside `Java.perform`, and only after `Java.available` is true. iOS scripts exit with `error` when `ObjC.available` is false. Each `Java.use` and native `Interceptor.attach` sits in its own try/catch. Call the original method through the saved overload (`.call`), not `this.method(...)`, which recurses.

Noisy monitors cap `hit` events and then emit one `truncated` hit.

## What each category does

| Category | Scripts | Scope |
| --- | --- | --- |
| `bypass/` | `ssl_pinning_universal`, `ssl_pinning_flutter`, `root_detection_universal`, `debug_detection`, `emulator_detection`, `integrity_check`, `secure_boot_check` | Pinning and environment checks for a lab app. `integrity_check` and `secure_boot_check` only report; they do not forge signatures or attestation. |
| `enumerate/` | `loaded_classes`, `class_methods`, `native_exports`, `intent_monitor`, `rasp_detection` | Class, export, and intent inspection. `rasp_detection` reports libraries and probes; it does not disable them. |
| `extract/` | `crypto_keys`, `shared_preferences`, `sqlite_queries`, `network_requests`, `tls_version_check`, `data_containerization_check` | In-process observation. Values stay in the Frida session and are truncated. |
| `exploit/` | `webview_rce`, `deeplink_injection`, `content_provider_dump` | Observation of bridges, deeplink parameters, and provider calls the app already makes. They do not inject script, send intents, or issue their own queries. |
| `ios/` | `nsurlsession_hook`, `data_protection` | NSURLSession metadata and file-protection classes. Requests are not modified and file bytes are not read. |

## Hooks that do not compose

Concatenating two scripts is safe only when they do not replace the same method. Each script closes over its own `tag`, but a second `implementation` replaces the first. In particular, `root_detection_universal` and `emulator_detection` both hook `java.io.File.exists`. `network_requests` and `tls_version_check` both hook `java.net.URL.openConnection`. Run those pairs as separate `frida_run_named_script` calls.

`class_methods` reads `TARGET_CLASS`, `loaded_classes` reads `FILTER`, and `native_exports` reads `LIB_NAME`. Edit the constant at the top of the file before injecting. The catalog does not pass extra arguments.

## SSL pinning coverage

`ssl_pinning_universal` installs, when the class exists:

- `SSLContext.init` plus the default `SSLContext`, using a permissive `X509TrustManager`
- the default `HostnameVerifier`, OkHttp's `OkHostnameVerifier`, and `CertificatePinner.check` / `check$okhttp`
- Conscrypt `TrustManagerImpl` and `Platform` trust checks whose chain type is known
- `NetworkSecurityTrustManager.checkPins` when that hidden API is present
- `WebViewClient.onReceivedSslError` on loaded client subclasses

`ssl_pinning_flutter` hooks `SSL_CTX_set_custom_verify` and `SSL_set_custom_verify` in `libflutter.so` and replaces the callback with one that returns `ssl_verify_ok` (`0`). It waits for the library to load. If the export was stripped, it emits `miss`. It does not scan byte patterns.

## Generated scripts

`frida_generate_hook` can save a new script under `~/.maya/frida-scripts/<category>/`. Those files use this same header and `send({ tag, event, data })` shape. The generator only accepts observation goals and the detection-bypass kinds already in `bypass/`. It does not add scripts to this bundled directory. See [Frida hook generation](../../docs/frida-hook-generation.md).
