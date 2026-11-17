# Frida hook generation

`frida_generate_hook` writes one Frida script for a class and method you name, using the LiteLLM client Maya is already configured with. The script has to match the bundled catalog, and the tool rejects it when the request or the source leaves the policy below. There is no separate injector. A saved script is loaded by `frida_list_scripts` / `frida_run_named_script`. `run=true` calls `frida_run_script` with the validated source.

This is for an app you are allowed to test, including the bundled Damn Vulnerable Bank sample.

## Intent

The tool takes fields, not a free-form program. `description` is the only natural-language field, and it is data for the model. It does not change the policy.

| Field | Required | Values |
| --- | --- | --- |
| `goal` | yes | `log_arguments`, `log_return`, `trace_calls`, `dump_field`, `time_call`, `bypass_detection` |
| `platform` | no, default `android` | `android`, `ios` |
| `target_class` | for observation, unless `description` is set | Java or ObjC class, such as `com.example.Auth` |
| `target_method` | with `target_class`, except `dump_field` | Method or selector, such as `login` or `dataTaskWithRequest:` |
| `field` | with `target_class` for `dump_field` | One field name |
| `description` | when class and method are omitted | What to observe, at most 500 characters |
| `bypass_kind` | only for `bypass_detection` | `ssl_pinning`, `root`, `debug`, `emulator`, `rasp` |
| `category` | no | Must match the goal: `extract`, `enumerate`, or `bypass`. Any other value is refused |
| `package_name` | when `run` is true | Process name passed to `frida_run_script` |
| `persist` | no, default `true` | Save under the user script directory |
| `run` | no, default `false` | Inject through `frida_run_script` after validation |
| `timeout` | no, default `90` | Seconds for that injection |
| `use_cache` | no, default `true` | Reuse a script already generated for this intent |

`log_arguments`, `log_return`, and `dump_field` are saved under `extract/`. `trace_calls` and `time_call` are saved under `enumerate/`. `bypass_detection` is saved under `bypass/`. An iOS script keeps that category and sets `platform: ios`. Identifiers are letters, digits, `_`, `$`, `.`, and `:`.

```python
from maya.tools.frida_generate import frida_generate_hook
from maya.tools.frida_tool import frida_run_named_script

generated = frida_generate_hook(
    goal="log_arguments",
    platform="android",
    target_class="com.example.Auth",
    target_method="login",
    description="Log the arguments of the login method",
)
# generated["name"] is "extract/gen_log_arguments_<hash>"
frida_run_named_script("com.example.app", generated["name"])
```

`persist=true` writes `~/.maya/frida-scripts/<category>/<stem>.js`. If `MAYA_FRIDA_SCRIPTS` points at a directory, the file is written there instead, because that directory is the one the catalog loads. A missing override path is an error, and the tool does not create it. Creating it would hide the bundled catalog.

The same intent always gets the same stem: `gen_<goal>_<12 hex chars of the sha256>`. Platform and kind are normalized before the hash, so `Android` and `android` match.

## What the script must look like

The prompt gives the model the header, the `send()` helper, and two excerpts from the bundled library (`enumerate/class_methods`, plus `ios/nsurlsession_hook` or, for a detection bypass, `bypass/debug_detection`). Validation still rejects the file unless all of these are true:

- First line is `// <stem>.js`, with `// category:`, `// platform:`, and `maya-frida-message: { tag, event, data }` in the header
- `'use strict'`, one `var tag = "<stem>"`, `send(...)`, and `console.log(JSON.stringify(...))`
- String events `ready`, `hit`, and `miss`
- `try` / `catch` around the hook work
- Android Java hooks sit behind `Java.available` and `Java.perform`. A Java-free Android hook may use `Interceptor.attach` instead, which is how the Flutter pin bypass is shaped
- iOS scripts check `ObjC.available`
- Observation goals call the saved method with `.call`
- The requested class, method, and field appear in the file
- A bypass names the check it neutralizes (`TrustManager` / `CertificatePinner` / `SSL_CTX_set_custom_verify` / `HostnameVerifier`, a root path or `isRooted`, `isDebuggerConnected` / `TracerPid` / `ptrace`, an emulator property, or a RASP detection token)
- UTF-8 size is at most the catalog limit (64 KiB)

`node --check` runs when `node` is on `PATH`. A syntax error rejects the script. If `node` is absent, the syntax step is skipped and the static checks still apply. The result records `node_check` as `ok` or `skipped`.

A script that passes is written to a temporary catalog root and read back with `load_script`, the same loader the bundled files use.

## Safety policy

The policy lives in `maya/tools/frida_generate.py` (`prepare_intent`, `source_violations`, `lint_script`). The prompt repeats it. A model reply cannot widen it.

**Allowed.** Observation of a call the app already makes. For `bypass_detection`, only the five bundled kinds: TLS pinning, root detection, debugger detection, emulator detection, and RASP *detection* booleans. An `ssl_pinning` script may install a permissive `TrustManager` or `CertificatePinner` hook, or replace the Flutter `SSL_CTX_set_custom_verify` callback with one that returns 0. The other kinds may report the "not detected" value. They may not forge a signature, SafetyNet response, or Play Integrity token, and they may not unload a library.

**Refused before the model is called.** The intent is refused when the goal, platform, or bypass kind is unknown, the category does not match the goal, or any field asks for forging attestation or signatures, injection, a new intent or component start, a content-provider query, exfiltration, a network URL, a native memory patch, an arbitrary native call, a process start, an exploit chain, credential theft, hiding Frida, disabling RASP, or an instruction to ignore this policy. An observation goal that asks to bypass a control or replace a return value is refused too. The caller has to use `bypass_detection` for that, and only for a kind in the list.

**Rejected after the model replies, and not injected.** The denylist runs on the raw script. A comment, a string, or a regex literal such as `/[//]/` or `/[/*]/` cannot hide a denied call later on the line, and naming a denied API in a comment is rejected too. The source is rejected when it contains, among other tokens:

- `Memory.*`, native `writeByteArray` / `writeUtf8String` / `writePointer`
- `evaluateJavascript(`, `addJavascriptInterface(`, `.loadUrl(`, `.loadData(`
- `.startActivity(`, `.sendBroadcast(`, `.startService(` and the related starters
- `getContentResolver(`, a `content://` URI, a `javascript:` URL
- `XMLHttpRequest`, `fetch(`, `WebSocket`, `java.net.Socket`, `Socket(`
- `ProcessBuilder`, `java.lang.Runtime`, `Runtime.exec`
- `Interceptor.replace`, `NativeFunction`, `Stalker.follow`, `recv(`, `eval(`, `new Function`
- a hardcoded `http://` or `https://` URL

Hooking a method by naming it, such as `WebView.loadUrl.overload(...)` or `Activity.startActivity.overload(...)`, is observation and stays allowed. Calling that method from the script is not.

`Java.registerClass`, `NativeCallback`, and `args[n] =` are allowed only for `bypass_kind=ssl_pinning`. `retval.replace` is allowed only for `bypass_detection`.

A refusal or a rejection returns `{"status": "error", "error": "..."}` and does not include the script. Nothing is passed to `frida_run_script`. The static denylist does not execute the file, and a determined model can obfuscate a token. The audit log is there so a person can read what the model actually wrote before a script is reused.

## Cache and audit

Successful scripts are stored under `~/.maya/frida-generated/p<policy>-r<prompt>/<sha256>/`:

| File | Contents |
| --- | --- |
| `intent.json` | Canonical intent |
| `prompt.json` | System and user messages |
| `output.txt` | Raw model text |
| `script.js` | Validated script |
| `meta.json` | Hash, stem, policy version, timestamp |

`MAYA_FRIDA_GENERATED` moves that directory. It is not a catalog root, so the cache is not injected by name. A later request with the same intent reuses the file after the linter and, when Node is available, `node --check` run again. A failed validation is not cached. `use_cache=false` calls the model again and replaces the entry.

Every request appends one JSON object to `~/.maya/frida-generated/audit.jsonl`, including refusals. The object has the intent, the prompt, the model output, and the violations. Rejected output is truncated in that line when it is larger than twice the catalog size limit. Files are written mode `0600`.

## Result

A success dict has `status`, `summary`, `name`, `stem`, `category`, `source`, `path` (when persisted), `cache` (`hit` or `miss`), `node_check`, `intent_hash`, and `audit_path`. When `run` is true, `run` is the `frida_run_script` dict. Generation can succeed and the injection can still report a missing `frida` binary. That injection error stays on `run`.

The tool runs on the host (`sandbox_execution` is false) so it can read the LiteLLM config and write `~/.maya`. The usual dynamic path is to persist, then call `frida_run_named_script`, which is the sandboxed injector. There is no new `maya` CLI flag.
